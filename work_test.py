import tempfile
import sys
import os
import shutil
import time
import socket
import subprocess
import platform
import requests
import psutil
import re
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------- НАСТРОЙКИ -------------------------------
INPUT_FILE = "sidr_vless.txt"
OUTPUT_FILE = "sidr_vless_work.txt"
TEST_DOMAIN = "https://www.google.com/generate_204"
TIMEOUT = 30
THREADS = 100 # Ограничено для стабильности при разбивке батчей
PROXIES_PER_BATCH = 50
LOCAL_PORT_START = 10000
CORE_STARTUP_TIMEOUT = 4.0
CORE_KILL_DELAY = 0.05

# ------------------------------- RICH -------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    console = Console()
except ImportError:
    print("Ошибка: pip install rich")
    sys.exit(1)

logger = console

# ------------------------------- ПАРСЕР И ГЕНЕРАЦИЯ (ТВОИ ОРИГИНАЛЬНЫЕ) -------------------------------
def clean_url(url):
    return url.strip().replace('\ufeff', '').replace('\u200b', '').replace('\n', '').replace('\r', '')

REALITY_PBK_RE = re.compile(r"^[A-Za-z0-9_-]{43,44}$")
REALITY_SID_RE = re.compile(r"^[0-9a-fA-F]{0,32}$")
FLOW_ALLOWED = {"", "xtls-rprx-vision", "xtls-rprx-direct", "xtls-rprx-splice"}

def parse_vless(url):
    try:
        url = clean_url(url)
        if not url.startswith("vless://"): return None
        if '#' in url:
            main_part, tag_raw = url.split('#', 1)
            tag = urllib.parse.unquote(tag_raw).strip()
        else:
            main_part, tag = url, "vless"
        parsed_url = urllib.parse.urlparse(main_part)
        uuid = urllib.parse.unquote(parsed_url.username or "")
        address = parsed_url.hostname or ""
        port = parsed_url.port or 443
        if not uuid or not address: return None
        query_params = urllib.parse.parse_qs(parsed_url.query)
        def get_p(key, default=""):
            vals = query_params.get(key, [default])
            return vals[0].strip()
        
        encryption = get_p("encryption", "none").lower()
        net_type = get_p("type", "tcp").lower()
        if net_type in ["ws", "websocket"]: net_type = "ws"
        elif net_type in ["grpc", "gun"]: net_type = "grpc"
        elif net_type in ["http", "h2", "httpupgrade"]: net_type = "http"
        else: net_type = "tcp"

        flow = get_p("flow", "").lower()
        if flow not in FLOW_ALLOWED: flow = ""
        stream_security = get_p("security", "none").lower()
        pbk = get_p("pbk", "")
        if pbk and REALITY_PBK_RE.match(pbk): stream_security = "reality"
        
        return {
            "protocol": "vless", "uuid": uuid, "address": address, "port": port,
            "flow": flow, "security": stream_security, "encryption": encryption,
            "pbk": pbk, "sid": re.sub(r"[^a-fA-F0-9]", "", get_p("sid", "")),
            "sni": get_p("sni", "") or address, "fp": get_p("fp", "chrome"),
            "alpn": [x.strip() for x in get_p("alpn", "").split(",")] if get_p("alpn", "") else [],
            "type": net_type, "host": get_p("host", ""), "path": urllib.parse.unquote(get_p("path", "")),
            "serviceName": get_p("serviceName", ""), "headerType": get_p("headerType", "none"), "tag": tag
        }
    except: return None

def make_outbound(parsed, tag):
    if not parsed: return None
    user = {"id": parsed["uuid"], "encryption": "none"}
    if parsed["flow"]: user["flow"] = parsed["flow"]
    stream = {"network": parsed["type"], "security": parsed["security"]}
    if parsed["security"] in ["tls", "reality"]:
        tls = {"serverName": parsed["sni"], "allowInsecure": True}
        if parsed["alpn"]: tls["alpn"] = parsed["alpn"]
        if parsed["security"] == "tls": stream["tlsSettings"] = tls
        else: stream["realitySettings"] = {"publicKey": parsed["pbk"], "shortId": parsed["sid"], "serverName": parsed["sni"], "fingerprint": parsed["fp"], "spiderX": "/"}
    
    if parsed["type"] == "ws":
        stream["wsSettings"] = {"path": parsed["path"] or "/", "headers": {"Host": parsed["host"] or parsed["sni"]}}
    elif parsed["type"] == "grpc":
        stream["grpcSettings"] = {"serviceName": parsed["serviceName"]}
    elif parsed["type"] == "http":
        stream["httpSettings"] = {"path": parsed["path"] or "/", "host": [parsed["host"] or parsed["sni"]]}
    elif parsed["type"] == "tcp" and parsed["headerType"] != "none":
        stream["tcpSettings"] = {"header": {"type": parsed["headerType"]}}

    return {"protocol": "vless", "tag": tag, "settings": {"vnext": [{"address": parsed["address"], "port": parsed["port"], "users": [user]}]}, "streamSettings": stream}

# ------------------------------- ЯДРО И ПРОВЕРКА -------------------------------
def create_cfg_file(proxy_list, start_port, work_dir, suffix):
    inbounds, outbounds, rules, mapping = [], [], [], []
    for i, url in enumerate(proxy_list):
        port = start_port + i
        parsed = parse_vless(url)
        outbound = make_outbound(parsed, f"out_{port}")
        if not outbound: continue
        inbounds.append({"port": port, "listen": "127.0.0.1", "protocol": "socks", "tag": f"in_{port}"})
        outbounds.append(outbound)
        rules.append({"type": "field", "inboundTag": [f"in_{port}"], "outboundTag": f"out_{port}"})
        mapping.append((url, port, parsed))
    if not mapping: return None, None
    config = {"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"rules": rules}}
    path = os.path.join(work_dir, f"cfg_{start_port}_{suffix}.json")
    with open(path, 'w', encoding='utf-8') as f: json.dump(config, f)
    return path, mapping

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1)
        return s.connect_ex(('127.0.0.1', port)) == 0

def kill_core(proc):
    if not proc: return
    try:
        proc.kill()
        proc.wait()
    except: pass

def check_batch(chunk, start_port, core_path, temp_dir, progress, task):
    cfg_path, mapping = create_cfg_file(chunk, start_port, temp_dir, "batch")
    if not mapping: return []
    
    proc = subprocess.Popen([core_path, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Ждем старта первого порта
    started = False
    for _ in range(int(CORE_STARTUP_TIMEOUT * 10)):
        if is_port_in_use(mapping[0][1]):
            started = True
            break
        time.sleep(0.1)
        if proc.poll() is not None: break

    batch_live = []
    if started:
        for url, port, parsed in mapping:
            proxies = {'http': f'socks5://127.0.0.1:{port}', 'https': f'socks5://127.0.0.1:{port}'}
            try:
                st = time.time()
                r = requests.get(TEST_DOMAIN, proxies=proxies, timeout=TIMEOUT, verify=False)
                if r.status_code == 204:
                    ms = round((time.time() - st) * 1000)
                    batch_live.append((url, ms))
                    logger.print(f"[green]LIVE[/] {parsed['address']:<22} | {ms:>4}ms")
                else: logger.print(f"[red]DEAD[/] {parsed['address']:<22} | HTTP{r.status_code}")
            except: logger.print(f"[red]DEAD[/] {parsed['address']:<22} | Timeout")
            progress.advance(task)
        kill_core(proc)
    else:
        # FALLBACK: РАЗФОРМИРОВЫВАЕМ БАТЧ
        kill_core(proc)
        logger.print(f"[yellow]Батч {start_port} упал. Проверка по одному...[/]")
        for url, port, parsed in mapping:
            s_cfg, _ = create_cfg_file([url], port, temp_dir, "single")
            s_proc = subprocess.Popen([core_path, "run", "-c", s_cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            s_ok = False
            for _ in range(20):
                if is_port_in_use(port):
                    s_ok = True; break
                time.sleep(0.1)
                if s_proc.poll() is not None: break
            
            if s_ok:
                try:
                    st = time.time()
                    r = requests.get(TEST_DOMAIN, proxies={'http': f'socks5://127.0.0.1:{port}', 'https': f'socks5://127.0.0.1:{port}'}, timeout=TIMEOUT, verify=False)
                    if r.status_code == 204:
                        ms = round((time.time() - st) * 1000)
                        batch_live.append((url, ms))
                        logger.print(f"[bold green]LIVE (SINGLE)[/] {parsed['address']:<22} | {ms:>4}ms")
                    else: logger.print(f"[bold red]DEAD (SINGLE)[/] {parsed['address']:<22}")
                except: logger.print(f"[bold red]DEAD (SINGLE)[/] {parsed['address']:<22}")
            else:
                logger.print(f"[bold white on red]ОШИБКА ЗАПУСКА ОДИНОЧНОГО ПРОКСИ[/] {parsed['address']}")
            
            kill_core(s_proc)
            progress.advance(task)
            try: os.remove(s_cfg)
            except: pass
            
    try: os.remove(cfg_path)
    except: pass
    return batch_live

# ------------------------------- ДЕДУПЛИКАЦИЯ (ТВОЯ) -------------------------------
def _are_equal(a, b): return (a == b) or (not a and not b)
def compare_parsed(a, b):
    if not a or not b: return False
    return (_are_equal(a.get("address"), b.get("address")) and a.get("port") == b.get("port") and 
            _are_equal(a.get("uuid"), b.get("uuid")) and _are_equal(a.get("sni"), b.get("sni")) and
            _are_equal(a.get("path"), b.get("path")) and _are_equal(a.get("security"), b.get("security")))

def deduplicate_proxies(proxies_with_latency):
    lst_keep = []
    removed = 0
    for url, lat in proxies_with_latency:
        p = parse_vless(url)
        exists = False
        for k_url, _ in lst_keep:
            if compare_parsed(parse_vless(k_url), p):
                exists = True; break
        if not exists: lst_keep.append((url, lat))
        else: removed += 1
    return lst_keep, removed

# ------------------------------- MAIN -------------------------------
def main():
    core = shutil.which("xray") or shutil.which("xray.exe") or "./xray.exe"
    if not os.path.exists(INPUT_FILE):
        logger.print(f"[bold red]{INPUT_FILE} не найден![/]"); return
    
    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        proxies = [clean_url(l) for l in f if l.strip().startswith("vless://")]

    temp_dir = tempfile.mkdtemp()
    chunks = [proxies[i:i + PROXIES_PER_BATCH] for i in range(0, len(proxies), PROXIES_PER_BATCH)]
    all_live = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("[cyan]Проверка...", total=len(proxies))
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            port = LOCAL_PORT_START
            for chunk in chunks:
                futures.append(executor.submit(check_batch, chunk, port, core, temp_dir, progress, task))
                port += PROXIES_PER_BATCH + 10
            for f in as_completed(futures): all_live.extend(f.result())

    all_live, rem = deduplicate_proxies(all_live)
    all_live.sort(key=lambda x: x[1])
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for url, _ in all_live: f.write(url + '\n')

    table = Table(title=f"Рабочих: {len(all_live)} (Удалено дублей: {rem})")
    table.add_column("Пинг", style="green"); table.add_column("Адрес")
    for url, ping in all_live[:20]:
        p = parse_vless(url)
        table.add_row(f"{ping} ms", p['address'])
    console.print(table)
    shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt: pass
