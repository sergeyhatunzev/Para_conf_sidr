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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------- НАСТРОЙКИ -------------------------------
INPUT_FILE = "sidr_vless.txt"
OUTPUT_FILE = "sidr_vless_work.txt"
TEST_DOMAIN = "https://www.google.com/generate_204"
TIMEOUT_HTTP = 60  
CORE_STARTUP_TIMEOUT = 20.0  
THREADS = 500
processed_count = 0
total_proxies_count = 0

counter_lock = threading.Lock()
print_lock = threading.Lock()

# ------------------------------- ПОМОЩНИКИ -------------------------------
def clean_url(url):
    return url.strip().replace('\ufeff', '').replace('\u200b', '').replace('\n', '').replace('\r', '')

def parse_vless(url):
    try:
        url = clean_url(url)
        if not url.startswith("vless://"): return None
        main_part = url.split('#')[0]
        parsed_url = urllib.parse.urlparse(main_part)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        def get_p(key, default=""): return query_params.get(key, [default])[0].strip()

        net_type = get_p("type", "tcp").lower()
        if net_type in ["ws", "websocket"]: net_type = "ws"
        elif net_type in ["grpc", "gun"]: net_type = "grpc"
        elif net_type in ["http", "h2", "httpupgrade"]: net_type = "http"
        else: net_type = "tcp"

        return {
            "uuid": urllib.parse.unquote(parsed_url.username or ""),
            "address": parsed_url.hostname or "",
            "port": parsed_url.port or 443,
            "flow": get_p("flow").lower() if get_p("flow") in ["xtls-rprx-vision", "xtls-rprx-direct"] else "",
            "security": get_p("security", "none").lower(),
            "pbk": get_p("pbk"),
            "sid": re.sub(r"[^a-fA-F0-9]", "", get_p("sid")),
            "sni": get_p("sni") or parsed_url.hostname,
            "fp": get_p("fp") or "chrome",
            "alpn": [x.strip() for x in get_p("alpn").split(",")] if get_p("alpn") else [],
            "type": net_type,
            "host": get_p("host"),
            "path": urllib.parse.unquote(get_p("path")),
            "serviceName": get_p("serviceName"),
            "headerType": get_p("headerType", "none"),
        }
    except: return None

def compare_proxies(p1, p2):
    if not p1 or not p2: return False
    keys_to_compare = ["address", "port", "uuid", "type", "security", "sni", "path", "pbk", "sid", "flow"]
    for key in keys_to_compare:
        if p1.get(key) != p2.get(key): return False
    return True

def deduplicate(live_results):
    unique_list = []
    seen_parsed = []
    for url, ms in live_results:
        p_current = parse_vless(url)
        if not p_current: continue
        is_duplicate = False
        for p_seen in seen_parsed:
            if compare_proxies(p_current, p_seen):
                is_duplicate = True
                break
        if not is_duplicate:
            unique_list.append((url, ms))
            seen_parsed.append(p_current)
    return unique_list

def make_full_config(p, local_port):
    user = {"id": p["uuid"], "encryption": "none"}
    if p["flow"]: user["flow"] = p["flow"]
    stream = {"network": p["type"], "security": p["security"]}
    if p["security"] in ["tls", "reality"]:
        tls_set = {"serverName": p["sni"], "allowInsecure": True}
        if p["alpn"]: tls_set["alpn"] = p["alpn"]
        if p["security"] == "tls": stream["tlsSettings"] = tls_set
        else:
            stream["realitySettings"] = {
                "publicKey": p["pbk"], "shortId": p["sid"],
                "serverName": p["sni"], "fingerprint": p["fp"], "spiderX": "/"
            }
    if p["type"] == "ws":
        stream["wsSettings"] = {"path": p["path"] or "/", "headers": {"Host": p["host"] or p["sni"]}}
    elif p["type"] == "grpc":
        stream["grpcSettings"] = {"serviceName": p["serviceName"] or ""}
    elif p["type"] == "http":
        stream["httpSettings"] = {"path": p["path"] or "/", "host": [p["host"] or p["sni"]]}
    elif p["type"] == "tcp" and p["headerType"] != "none":
        stream["tcpSettings"] = {"header": {"type": p["headerType"]}}
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": local_port, "listen": "127.0.0.1", "protocol": "socks"}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": p["address"], "port": p["port"], "users": [user]}]},
            "streamSettings": stream
        }]
    }

def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1)
        return s.connect_ex(('127.0.0.1', port)) == 0

def check_single_proxy(url, index, core_path, temp_dir):
    global processed_count
    p = parse_vless(url)
    if not p: return None
    local_port = 10000 + (index % 45000)
    config_path = os.path.join(temp_dir, f"cfg_{index}.json")
    proc = None
    res = None
    try:
        with open(config_path, "w") as f: json.dump(make_full_config(p, local_port), f)
        
        # Запуск с подавлением окон в Windows
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        proc = subprocess.Popen(
            [core_path, "run", "-c", config_path], 
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            startupinfo=startupinfo
        )
        
        start_t = time.time()
        ready = False
        while time.time() - start_t < CORE_STARTUP_TIMEOUT:
            if is_port_open(local_port):
                ready = True
                break
            if proc.poll() is not None: break
            time.sleep(0.3)

        if ready:
            proxies = {"http": f"socks5h://127.0.0.1:{local_port}", "https": f"socks5h://127.0.0.1:{local_port}"}
            st = time.time()
            try:
                r = requests.get(TEST_DOMAIN, proxies=proxies, timeout=TIMEOUT_HTTP, verify=False)
                if r.status_code == 204:
                    ms = int((time.time() - st) * 1000)
                    res = (url, ms)
                    with print_lock:
                        print(f"LIVE | {p['address']:<20} | {ms:>4}ms | {p['type']}")
            except: pass
    except: pass
    finally:
        if proc:
            try:
                proc.kill()  # ПРИНУДИТЕЛЬНОЕ УБИЙСТВО
                proc.wait(timeout=0.5) # Ждем освобождения ресурсов
            except: pass
        try: os.remove(config_path)
        except: pass
        with counter_lock: processed_count += 1
    return res

def main():
    global total_proxies_count
    core = shutil.which("xray") or "./xray"
    
    # Очистка старых процессов xray перед запуском
    if os.name == 'nt': os.system("taskkill /f /im xray.exe >nul 2>&1")
    else: os.system("killall -9 xray >/dev/null 2>&1")

    if not os.path.exists(INPUT_FILE): return
    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        proxies = [clean_url(line) for line in f if line.strip().startswith("vless://")]

    total_proxies_count = len(proxies)
    if total_proxies_count == 0: return

    temp_dir = tempfile.mkdtemp()
    print(f"Проверка {total_proxies_count} прокси в {THREADS} потоках...")

    all_live = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(check_single_proxy, url, i, core, temp_dir) for i, url in enumerate(proxies)]
        for f in as_completed(futures):
            result = f.result()
            if result: all_live.append(result)

    all_live.sort(key=lambda x: x[1])
    final_proxies = deduplicate(all_live)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for url, _ in final_proxies:
            f.write(url + "\n")

    try: shutil.rmtree(temp_dir)
    except: pass

    print(f"\nНайдено живых: {len(all_live)}")
    print(f"После дедупликации: {len(final_proxies)}")
    print(f"Результат сохранен в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()



