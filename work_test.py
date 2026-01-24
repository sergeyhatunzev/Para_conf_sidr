import tempfile
import sys
import os
import shutil
import time
import socket
import subprocess
import requests
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
TIMEOUT = 12
THREADS = 200            
PROXIES_PER_BATCH = 80   
LOCAL_PORT_START = 1025   # Твое предложение: начинаем с самого начала свободных портов
LOCAL_PORT_END = 65000   
CORE_STARTUP_TIMEOUT = 5.0

processed_count = 0
total_proxies_count = 0

# ------------------------------- ПОМОЩНИКИ -------------------------------
def clean_url(url):
    return url.strip().replace('\ufeff', '').replace('\u200b', '').replace('\n', '').replace('\r', '')

def parse_vless(url):
    try:
        url = clean_url(url)
        if not url.startswith("vless://"): return None
        parsed_url = urllib.parse.urlparse(url.split('#')[0])
        query = urllib.parse.parse_qs(parsed_url.query)
        get_p = lambda k: query.get(k, [""])[0].strip()
        net_type = get_p("type").lower() or "tcp"
        return {
            "uuid": urllib.parse.unquote(parsed_url.username or ""),
            "address": parsed_url.hostname or "",
            "port": parsed_url.port or 443,
            "flow": get_p("flow") if get_p("flow") in ["xtls-rprx-vision", "xtls-rprx-direct"] else "",
            "security": get_p("security") or "none",
            "pbk": get_p("pbk"),
            "sid": re.sub(r"[^a-fA-F0-9]", "", get_p("sid")),
            "sni": get_p("sni") or parsed_url.hostname,
            "fp": get_p("fp") or "chrome",
            "alpn": [x.strip() for x in get_p("alpn").split(",")] if get_p("alpn") else [],
            "type": "ws" if net_type in ["ws", "websocket"] else "grpc" if net_type in ["grpc", "gun"] else "http" if net_type in ["http", "h2"] else "tcp",
            "host": get_p("host"),
            "path": urllib.parse.unquote(get_p("path")),
            "serviceName": get_p("serviceName"),
            "headerType": get_p("headerType") or "none"
        }
    except: return None

def make_outbound(p, tag):
    if not p: return None
    user = {"id": p["uuid"], "encryption": "none"}
    if p["flow"]: user["flow"] = p["flow"]
    stream = {"network": p["type"], "security": p["security"]}
    if p["security"] in ["tls", "reality"]:
        tls = {"serverName": p["sni"], "allowInsecure": True}
        if p["alpn"]: tls["alpn"] = p["alpn"]
        if p["security"] == "tls": stream["tlsSettings"] = tls
        else: stream["realitySettings"] = {"publicKey": p["pbk"], "shortId": p["sid"], "serverName": p["sni"], "fingerprint": p["fp"], "spiderX": "/"}
    if p["type"] == "ws": stream["wsSettings"] = {"path": p["path"] or "/", "headers": {"Host": p["host"] or p["sni"]}}
    elif p["type"] == "grpc": stream["grpcSettings"] = {"serviceName": p["serviceName"]}
    return {"protocol": "vless", "tag": tag, "settings": {"vnext": [{"address": p["address"], "port": p["port"], "users": [user]}]}, "streamSettings": stream}

def is_port_in_use(port):
    if not (1024 <= port <= 65535): return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except: return False

def kill_core(proc):
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except:
            try: proc.kill()
            except: pass

def print_progress(addr, ms, is_single=False):
    global processed_count, total_proxies_count
    pct = (processed_count / total_proxies_count) * 100 if total_proxies_count > 0 else 0
    mode = "(S)" if is_single else ""
    sys.stdout.write(f"\r[{pct:3.0f}%] LIVE {mode} {addr:<25} | {ms:>4}ms\n")
    sys.stdout.flush()

# ------------------------------- ЧЕКЕР -------------------------------
def check_batch(chunk, start_port, core_path, temp_dir):
    global processed_count
    inbounds, outbounds, rules, mapping = [], [], [], []
    for i, url in enumerate(chunk):
        p = parse_vless(url)
        if not p: continue
        port = start_port + i
        inbounds.append({"port": port, "listen": "127.0.0.1", "protocol": "socks", "tag": f"in_{port}"})
        outbounds.append(make_outbound(p, f"out_{port}"))
        rules.append({"type": "field", "inboundTag": [f"in_{port}"], "outboundTag": f"out_{port}"})
        mapping.append((url, port, p))

    if not mapping: return []
    cfg_path = os.path.join(temp_dir, f"cfg_{start_port}.json")
    with open(cfg_path, 'w') as f: 
        json.dump({"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"rules": rules}}, f)

    batch_live = []
    proc = subprocess.Popen([core_path, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    started = False
    for _ in range(int(CORE_STARTUP_TIMEOUT * 10)):
        if is_port_in_use(mapping[0][1]): started = True; break
        time.sleep(0.1)

    if started:
        for url, port, p in mapping:
            processed_count += 1
            try:
                st = time.time()
                r = requests.get(TEST_DOMAIN, proxies={'http': f'socks5://127.0.0.1:{port}', 'https': f'socks5://127.0.0.1:{port}'}, timeout=TIMEOUT, verify=False)
                if r.status_code == 204:
                    ms = round((time.time() - st) * 1000)
                    batch_live.append((url, ms))
                    print_progress(p['address'], ms)
            except: pass
        kill_core(proc)
    else:
        kill_core(proc)
        for url, port, p in mapping:
            processed_count += 1
            s_cfg = os.path.join(temp_dir, f"s_{port}.json")
            with open(s_cfg, 'w') as f:
                json.dump({"log": {"loglevel": "none"}, "inbounds": [{"port": port, "protocol": "socks"}], "outbounds": [make_outbound(p, "out")]}, f)
            sproc = subprocess.Popen([core_path, "run", "-c", s_cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.6)
            try:
                st = time.time()
                r = requests.get(TEST_DOMAIN, proxies={'http': f'socks5://127.0.0.1:{port}', 'https': f'socks5://127.0.0.1:{port}'}, timeout=TIMEOUT, verify=False)
                if r.status_code == 204:
                    ms = round((time.time() - st) * 1000)
                    batch_live.append((url, ms))
                    print_progress(p['address'], ms, True)
            except: pass
            kill_core(sproc)
            try: os.remove(s_cfg)
            except: pass
    
    try: os.remove(cfg_path)
    except: pass
    return batch_live

# ------------------------------- MAIN -------------------------------
def main():
    global total_proxies_count
    core = shutil.which("xray") or "./xray"
    if not os.path.exists(INPUT_FILE): return
    
    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        proxies = [clean_url(l) for l in f if l.strip().startswith("vless://")]

    total_proxies_count = len(proxies)
    print(f"Старт: {total_proxies_count} прокси | Потоки: {THREADS}")
    
    temp_dir = tempfile.mkdtemp()
    chunks = [proxies[i:i + PROXIES_PER_BATCH] for i in range(0, len(proxies), PROXIES_PER_BATCH)]
    all_live = []

    # Увеличили окно портов до максимума
    PORT_STEP = PROXIES_PER_BATCH + 20
    PORT_RANGE = LOCAL_PORT_END - LOCAL_PORT_START

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = []
        for i, chunk in enumerate(chunks):
            offset = (i * PORT_STEP) % PORT_RANGE
            safe_port = LOCAL_PORT_START + offset
            futures.append(executor.submit(check_batch, chunk, safe_port, core, temp_dir))
        
        for f in as_completed(futures):
            try:
                res = f.result()
                if res: all_live.extend(res)
            except: continue

    all_live.sort(key=lambda x: x[1])
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for url, _ in all_live: f.write(url + '\n')

    print(f"\nГотово! Рабочих: {len(all_live)}")
    shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    main()
