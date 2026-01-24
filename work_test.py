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
TIMEOUT_HTTP = 20  # Тайм-аут на сам запрос
CORE_STARTUP_TIMEOUT = 10.0  # Сколько ждать поднятия порта Xray
THREADS = 500  # 200 потоков = 200 одновременно запущенных Xray

processed_count = 0
total_proxies_count = 0

counter_lock = threading.Lock()
print_lock = threading.Lock()
file_lock = threading.Lock()

# ------------------------------- ПОМОЩНИКИ -------------------------------
def clean_url(url):
    return url.strip().replace('\ufeff', '').replace('\u200b', '').replace('\n', '').replace('\r', '')

def parse_vless(url):
    try:
        url = clean_url(url)
        if not url.startswith("vless://"): return None
        parsed = urllib.parse.urlparse(url.split('#')[0])
        q = urllib.parse.parse_qs(parsed.query)
        g = lambda k: q.get(k, [""])[0].strip()
        net = g("type").lower() or "tcp"
        return {
            "uuid": urllib.parse.unquote(parsed.username or ""),
            "address": parsed.hostname or "",
            "port": parsed.port or 443,
            "flow": g("flow") if g("flow") in ["xtls-rprx-vision", "xtls-rprx-direct"] else "",
            "security": g("security") or "none",
            "pbk": g("pbk"),
            "sid": re.sub(r"[^a-fA-F0-9]", "", g("sid")),
            "sni": g("sni") or parsed.hostname,
            "fp": g("fp") or "chrome",
            "alpn": [x.strip() for x in g("alpn").split(",")] if g("alpn") else [],
            "type": "ws" if net in ["ws", "websocket"] else "grpc" if net in ["grpc", "gun"] else "http" if net in ["http", "h2"] else "tcp",
            "host": g("host"),
            "path": urllib.parse.unquote(g("path")),
            "serviceName": g("serviceName"),
        }
    except: return None

def make_full_config(p, local_port):
    user = {"id": p["uuid"], "encryption": "none"}
    if p["flow"]: user["flow"] = p["flow"]
    stream = {"network": p["type"], "security": p["security"]}
    
    if p["security"] in ["tls", "reality"]:
        tls = {"serverName": p["sni"], "allowInsecure": True}
        if p["alpn"]: tls["alpn"] = p["alpn"]
        if p["security"] == "tls": stream["tlsSettings"] = tls
        else:
            stream["realitySettings"] = {
                "publicKey": p["pbk"], "shortId": p["sid"],
                "serverName": p["sni"], "fingerprint": p["fp"], "spiderX": "/"
            }
    if p["type"] == "ws":
        stream["wsSettings"] = {"path": p["path"] or "/", "headers": {"Host": p["host"] or p["sni"]}}
    elif p["type"] == "grpc":
        stream["grpcSettings"] = {"serviceName": p["serviceName"]}

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

# ------------------------------- ЯДРО ПРОВЕРКИ -------------------------------
def check_single_proxy(url, index, core_path, temp_dir):
    global processed_count
    p = parse_vless(url)
    if not p: return None

    # Выделяем уникальный порт для потока (от 10000 до 60000)
    local_port = 10000 + (index % 50000)
    config_path = os.path.join(temp_dir, f"cfg_{index}_{local_port}.json")
    
    with open(config_path, "w") as f:
        json.dump(make_full_config(p, local_port), f)

    proc = None
    res = None
    try:
        # Запуск процесса
        proc = subprocess.Popen(
            [core_path, "run", "-c", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # 1. Ждем открытия порта (защита от зависания старта)
        start_t = time.time()
        ready = False
        while time.time() - start_t < CORE_STARTUP_TIMEOUT:
            if is_port_open(local_port):
                ready = True
                break
            if proc.poll() is not None: break # Процесс упал сам
            time.sleep(0.1)

        if ready:
            # 2. Делаем запрос
            st = time.time()
            proxies = {"http": f"socks5h://127.0.0.1:{local_port}", "https": f"socks5h://127.0.0.1:{local_port}"}
            r = requests.get(TEST_DOMAIN, proxies=proxies, timeout=TIMEOUT_HTTP, verify=False)
            
            if r.status_code == 204:
                ms = int((time.time() - st) * 1000)
                res = (url, ms)
                with print_lock:
                    pct = (processed_count / total_proxies_count) * 100
                    print(f"[{pct:3.0f}%] LIVE | {p['address']:<20} | {ms:>4}ms")

    except Exception:
        pass
    finally:
        # ПРИНУДИТЕЛЬНОЕ УБИЙСТВО
        if proc:
            try:
                proc.terminate() # Сначала мягко
                proc.wait(timeout=0.2)
            except:
                try: proc.kill() # Если не понял, то жестко
                except: pass
        
        # Очистка конфига
        try: os.remove(config_path)
        except: pass
        
        with counter_lock:
            processed_count += 1
            
    return res

# ------------------------------- MAIN -------------------------------
def main():
    global total_proxies_count
    core = shutil.which("xray") or "./xray"
    
    if not os.path.exists(INPUT_FILE):
        print(f"Файл {INPUT_FILE} не найден")
        return

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        proxies = [clean_url(line) for line in f if line.strip().startswith("vless://")]

    total_proxies_count = len(proxies)
    if total_proxies_count == 0:
        print("Прокси не найдены.")
        return

    temp_dir = tempfile.mkdtemp()
    print(f"Запуск проверки {total_proxies_count} прокси в {THREADS} потоках...")

    all_live = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        # Передаем индекс для генерации порта и имени файла
        futures = [executor.submit(check_single_proxy, url, i, core, temp_dir) 
                   for i, url in enumerate(proxies)]
        
        for f in as_completed(futures):
            result = f.result()
            if result:
                all_live.append(result)

    # Сохранение результатов
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for url, _ in all_live:
            f.write(url + "\n")

    try: shutil.rmtree(temp_dir)
    except: pass

    print(f"\nГотово! Найдено рабочих: {len(all_live)}")
    print(f"Результаты сохранены в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
