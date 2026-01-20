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
THREADS = 200
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

# ------------------------------- ВСПОМОГАТЕЛЬНЫЕ -------------------------------
def clean_url(url):
    return url.strip().replace('\ufeff', '').replace('\u200b', '').replace('\n', '').replace('\r', '')

# Регулярки для Reality
REALITY_PBK_RE = re.compile(r"^[A-Za-z0-9_-]{43,44}$")
REALITY_SID_RE = re.compile(r"^[0-9a-fA-F]{0,32}$")
FLOW_ALLOWED = {"", "xtls-rprx-vision", "xtls-rprx-direct", "xtls-rprx-splice"}

# ------------------------------- ПОЛНЫЙ ПАРСЕР VLESS -------------------------------
def parse_vless(url):
    try:
        url = clean_url(url)
        if not url.startswith("vless://"):
            return None
        # Разбор тега (remarks)
        if '#' in url:
            main_part, tag_raw = url.split('#', 1)
            tag = urllib.parse.unquote(tag_raw).strip()
        else:
            main_part = url
            tag = "vless"
        parsed_url = urllib.parse.urlparse(main_part)
        if parsed_url.scheme != "vless":
            return None
        uuid = urllib.parse.unquote(parsed_url.username or "")
        address = parsed_url.hostname or ""
        port = parsed_url.port or 443
        if not uuid or not address:
            return None
        query_params = urllib.parse.parse_qs(parsed_url.query)
        def get_p(key, default=""):
            vals = query_params.get(key, [default])
            return vals[0].strip()
        # encryption (VLESS uses 'encryption' for user encryption param in v2rayN)
        encryption = get_p("encryption", "none").lower()
        net_type = get_p("type", "tcp").lower()
        if net_type in ["ws", "websocket"]:
            net_type = "ws"
        elif net_type in ["grpc", "gun"]:
            net_type = "grpc"
        elif net_type in ["http", "h2", "httpupgrade"]:
            net_type = "http"
        else:
            net_type = "tcp"
        flow = get_p("flow", "").lower()
        if flow not in FLOW_ALLOWED:
            flow = ""
        # stream security (tls/reality/none)
        stream_security = get_p("security", "none").lower()
        if stream_security not in ["tls", "reality", "none"]:
            stream_security = "none"
        pbk = get_p("pbk", "")
        if pbk and REALITY_PBK_RE.match(pbk):
            if stream_security != "reality":
                stream_security = "reality"
        else:
            pbk = ""
        sid = get_p("sid", "")
        sid = re.sub(r"[^a-fA-F0-9]", "", sid)
        if len(sid) > 32 or len(sid) % 2 != 0:
            sid = ""
        if sid and not REALITY_SID_RE.match(sid):
            sid = ""
        sni = get_p("sni", "")
        fp = get_p("fp", "chrome")
        alpn_str = get_p("alpn", "")
        alpn = [x.strip() for x in alpn_str.split(",")] if alpn_str else []
        return {
            "protocol": "vless",
            "uuid": uuid,
            "address": address,
            "port": port,
            "flow": flow,
            "security": stream_security, # streamSecurity in v2rayN
            "encryption": encryption, # Security/encryption in v2rayN (user encryption field)
            "pbk": pbk,
            "sid": sid,
            "sni": sni or address,
            "fp": fp,
            "alpn": alpn,
            "type": net_type,
            "host": get_p("host", ""), # RequestHost equivalent
            "path": urllib.parse.unquote(get_p("path", "")),
            "serviceName": get_p("serviceName", ""),
            "headerType": get_p("headerType", "none"),
            "tag": tag
        }
    except Exception:
        return None

def get_proxy_info(parsed):
    if not parsed:
        return "unknown", "error"
    addr = f"{parsed['address']}:{parsed['port']}"
    tag = parsed['tag'][:50]
    return addr, tag

# ------------------------------- ГЕНЕРАЦИЯ OUTBOUND -------------------------------
def make_outbound(parsed, tag):
    if not parsed:
        return None
    user = {
        "id": parsed["uuid"],
        "encryption": "none"
    }
    if parsed["flow"]:
        user["flow"] = parsed["flow"]
    vnext = [{"address": parsed["address"], "port": parsed["port"], "users": [user]}]
    stream = {"network": parsed["type"], "security": parsed["security"]}
    # TLS / Reality
    tls_settings = {
        "serverName": parsed["sni"],
        "allowInsecure": True
    }
    if parsed["alpn"]:
        tls_settings["alpn"] = parsed["alpn"]
    if parsed["security"] == "tls":
        stream["tlsSettings"] = tls_settings
    elif parsed["security"] == "reality":
        stream["realitySettings"] = {
            "publicKey": parsed["pbk"],
            "shortId": parsed["sid"],
            "serverName": parsed["sni"],
            "fingerprint": parsed["fp"],
            "spiderX": "/"
        }
    # WS / GRPC / HTTP
    if parsed["type"] == "ws":
        host = parsed["host"] or parsed["sni"]
        stream["wsSettings"] = {
            "path": parsed["path"] or "/",
            "headers": {"Host": host} if host else {}
        }
    elif parsed["type"] == "grpc":
        stream["grpcSettings"] = {
            "serviceName": parsed["serviceName"],
            "multiMode": False
        }
    elif parsed["type"] == "http":
        host = parsed["host"] or parsed["sni"]
        stream["httpSettings"] = {
            "path": parsed["path"] or "/",
            "host": [host] if host else []
        }
    # TCP с headerType
    elif parsed["type"] == "tcp" and parsed["headerType"] != "none":
        stream["tcpSettings"] = {
            "header": {"type": parsed["headerType"]}
        }
    return {
        "protocol": "vless",
        "tag": tag,
        "settings": {"vnext": vnext},
        "streamSettings": stream
    }

# ------------------------------- КОНФИГ ПАЧКИ -------------------------------
def create_batch_config_file(proxy_list, start_port, work_dir):
    inbounds = []
    outbounds = []
    rules = []
    valid_proxies = []
    for i, url in enumerate(proxy_list):
        port = start_port + i
        in_tag = f"in_{port}"
        out_tag = f"out_{port}"
        inbounds.append({
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "tag": in_tag,
            "settings": {"udp": False}
        })
        parsed = parse_vless(url)
        outbound = make_outbound(parsed, out_tag)
        if not outbound:
            continue
        outbounds.append(outbound)
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})
        valid_proxies.append((url, port, parsed))
    if not valid_proxies:
        return None, None, None
    config = {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": rules, "domainStrategy": "AsIs"}
    }
    path = os.path.join(work_dir, f"batch_{start_port}.json")
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)
    return path, valid_proxies, None

# ------------------------------- ОСТАЛЬНОЕ -------------------------------
def is_port_in_use(port):
    try:
        with socket.socket() as s:
            s.settimeout(0.1)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except:
        return False

def run_core(core_path, config_path):
    cmd = [core_path, "run", "-c", config_path]
    startupinfo = subprocess.STARTUPINFO() if platform.system() == "Windows" else None
    if startupinfo:
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, startupinfo=startupinfo)
    except Exception as e:
        logger.print(f"[bold red]Ошибка запуска: {e}[/]")
        return None

def kill_core(proc):
    if not proc:
        return
    try:
        proc.kill()
        if psutil.pid_exists(proc.pid):
            for child in psutil.Process(proc.pid).children(recursive=True):
                child.kill()
    except:
        pass

def check_connection(port):
    proxies = {'http': f'socks5://127.0.0.1:{port}', 'https': f'socks5://127.0.0.1:{port}'}
    try:
        start = time.time()
        r = requests.get(TEST_DOMAIN, proxies=proxies, timeout=TIMEOUT, verify=False)
        latency = round((time.time() - start) * 1000)
        if r.status_code == 204:
            return latency, None
        return False, f"HTTP{r.status_code}"
    except requests.exceptions.ConnectTimeout:
        return False, "ConnTimeout"
    except requests.exceptions.ReadTimeout:
        return False, "ReadTimeout"
    except Exception as e:
        return False, str(e)[:30]

# ------------------------------- ДЕДУПЛИЦИЯ (как в v2rayN) -------------------------------
def _are_equal(a, b):
    return (a == b) or (not a and not b)

def _alpn_equal(a_list, b_list):
    a = a_list or []
    b = b_list or []
    return a == b

def compare_parsed(a, b, remarks=False):
    """Сравнивает два распарсенных vless-прокси в духе CompareProfileItem из v2rayN.
    ИЗМЕНЕНИЕ: НЕ сравниваем host — если отличаются только host, считаем дубликатами."""
    if not a or not b:
        return False
    return (
        _are_equal(a.get("protocol"), b.get("protocol"))
        and _are_equal(a.get("address"), b.get("address"))
        and a.get("port") == b.get("port")
        and _are_equal(a.get("uuid"), b.get("uuid"))
        and _are_equal(a.get("encryption"), b.get("encryption"))
        and _are_equal(a.get("type"), b.get("type"))
        and _are_equal(a.get("headerType"), b.get("headerType"))
        # and _are_equal(a.get("host"), b.get("host"))  # <-- УБРАНО! host игнорируется
        and _are_equal(a.get("path"), b.get("path"))
        and _are_equal(a.get("security"), b.get("security"))
        and _are_equal(a.get("flow"), b.get("flow"))
        and _are_equal(a.get("sni"), b.get("sni"))
        and _alpn_equal(a.get("alpn"), b.get("alpn"))
        and _are_equal(a.get("fp"), b.get("fp"))
        and _are_equal(a.get("pbk"), b.get("pbk"))
        and _are_equal(a.get("sid"), b.get("sid"))
        and (not remarks or a.get("tag") == b.get("tag"))
    )

def deduplicate_proxies(proxies_with_latency):
    """
    Удаляет дубликаты в стиле v2rayN:
    - Сравниваются полные профили (см. compare_parsed)
    - Сохраняется первый встретившийся (с наименьшим пингом)
    Возвращает (result_list, removed_count)
    """
    lst_keep = []
    lst_remove = []
    for url, latency in proxies_with_latency:
        parsed = parse_vless(url)
        if not parsed:
            lst_keep.append((url, latency))
            continue
        exists = False
        for k_url, k_latency in lst_keep:
            k_parsed = parse_vless(k_url)
            if compare_parsed(k_parsed, parsed, remarks=False):
                exists = True
                break
        if not exists:
            lst_keep.append((url, latency))
        else:
            lst_remove.append((url, latency))
    removed_count = len(lst_remove)
    return lst_keep, removed_count

# ------------------------------- MAIN -------------------------------
def main():
    global CORE_PATH
    TEMP_DIR = tempfile.mkdtemp()
    CORE_PATH = shutil.which("xray") or shutil.which("xray.exe")
    if not CORE_PATH:
        for c in ["xray", "xray.exe", "./xray", "./xray.exe"]:
            if os.path.exists(c):
                CORE_PATH = os.path.abspath(c)
                break
    if not CORE_PATH:
        logger.print("[bold red]xray не найден! Положите рядом.[/]")
        sys.exit(1)
    logger.print(f"[green]Ядро: {CORE_PATH}[/]")
    if not os.path.exists(INPUT_FILE):
        logger.print(f"[bold red]{INPUT_FILE} не найден![/]")
        sys.exit(1)
    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        raw_lines = f.readlines()
    proxies = [clean_url(l) for l in raw_lines if l.strip().startswith("vless://")]
    if not proxies:
        logger.print("[bold red]Нет VLESS ссылок в файле.[/]")
        sys.exit(1)
    logger.print(f"[cyan]Загружено {len(proxies)} VLESS → проверка в {THREADS} потоках[/]")
    chunks = [proxies[i:i + PROXIES_PER_BATCH] for i in range(0, len(proxies), PROXIES_PER_BATCH)]
    live = []
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Проверка...", total=len(proxies))
        def check_batch(chunk, start_port):
            cfg_path, mapping, _ = create_batch_config_file(chunk, start_port, TEMP_DIR)
            if not mapping:
                return []
            proc = run_core(CORE_PATH, cfg_path)
            if not proc:
                return []
            started = False
            for _ in range(int(CORE_STARTUP_TIMEOUT * 20)):
                if mapping and is_port_in_use(mapping[0][1]):
                    started = True
                    break
                time.sleep(0.05)
            if not started:
                kill_core(proc)
                return []
            time.sleep(0.4)
            batch_live = []
            for url, port, parsed in mapping:
                lat, err = check_connection(port)
                addr, tag = get_proxy_info(parsed)
                if lat:
                    logger.print(f"[green]LIVE[/] {addr:<22} | {lat:>4}ms | {tag}")
                    batch_live.append((url, lat))
                else:
                    logger.print(f"[red]DEAD[/] {addr:<22} | {'':>8} | {tag} → {err}")
                progress.advance(task)
            kill_core(proc)
            time.sleep(CORE_KILL_DELAY)
            try:
                os.remove(cfg_path)
            except:
                pass
            return batch_live
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = []
            port_offset = LOCAL_PORT_START
            for chunk in chunks:
                futures.append(executor.submit(check_batch, chunk, port_offset))
                port_offset += len(chunk) + 20
            for future in as_completed(futures):
                live.extend(future.result())
    # Финальное удаление дубликатов (в стиле v2rayN)
    live_before = len(live)
    live, removed_count = deduplicate_proxies(live)
    logger.print(f"[yellow]Дубликатов обнаружено/удалено: {removed_count}[/]")
    live.sort(key=lambda x: x[1])
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for url, _ in live:
            f.write(url + '\n')
    table = Table(title=f"Готово! Рабочих: {len(live)} из {len(proxies)} (после дедупликации)")
    table.add_column("Пинг", style="green")
    table.add_column("Тег")
    for url, ping in live[:20]:
        parsed = parse_vless(url)
        _, tag = get_proxy_info(parsed)
        table.add_row(f"{ping} ms", tag)
    console.print(table)
    logger.print(f"\n[bold green]Рабочие VLESS сохранены в {OUTPUT_FILE}[/]")
    try:
        shutil.rmtree(TEMP_DIR)
    except:
        pass

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.print("\n[red]Остановлено пользователем.[/]")
    except Exception as e:
        logger.print(f"[bold red]Ошибка: {e}[/]")
        import traceback
        traceback.print_exc()
