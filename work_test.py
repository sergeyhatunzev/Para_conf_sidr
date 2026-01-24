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
TIMEOUT = (4, 6)  # connect, read
THREADS = 200
PROXIES_PER_BATCH = 80
LOCAL_PORT_START = 1025
LOCAL_PORT_END = 65000
CORE_STARTUP_TIMEOUT = 5.0

chek_vivod = 0
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
        if not url.startswith("vless://"):
            return None
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
    except:
        return None

def is_same_config(a, b):
    p1, p2 = parse_vless(a), parse_vless(b)
    if not p1 or not p2:
        return False
    return (
        p1["address"] == p2["address"] and
        p1["port"] == p2["port"] and
        p1["uuid"] == p2["uuid"] and
        p1["sni"] == p2["sni"] and
        p1["type"] == p2["type"] and
        p1["path"] == p2["path"] and
        p1["pbk"] == p2["pbk"]
    )

def make_outbound(p, tag):
    user = {"id": p["uuid"], "encryption": "none"}
    if p["flow"]:
        user["flow"] = p["flow"]

    stream = {"network": p["type"], "security": p["security"]}
    if p["security"] in ["tls", "reality"]:
        tls = {"serverName": p["sni"], "allowInsecure": True}
        if p["alpn"]:
            tls["alpn"] = p["alpn"]
        if p["security"] == "tls":
            stream["tlsSettings"] = tls
        else:
            stream["realitySettings"] = {
                "publicKey": p["pbk"],
                "shortId": p["sid"],
                "serverName": p["sni"],
                "fingerprint": p["fp"],
                "spiderX": "/"
            }

    if p["type"] == "ws":
        stream["wsSettings"] = {"path": p["path"] or "/", "headers": {"Host": p["host"] or p["sni"]}}
    elif p["type"] == "grpc":
        stream["grpcSettings"] = {"serviceName": p["serviceName"]}

    return {
        "protocol": "vless",
        "tag": tag,
        "settings": {"vnext": [{"address": p["address"], "port": p["port"], "users": [user]}]},
        "streamSettings": stream
    }

def is_port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
            return True
    except:
        return False

def wait_port_or_die(proc, port, timeout):
    start = time.time()
    while time.time() - start < timeout:
        if proc.poll() is not None:
            return False
        if is_port_open(port):
            return True
        time.sleep(0.05)
    return False

def kill_core(proc):
    if not proc:
        return
    try:
        proc.kill()
        proc.wait(timeout=1)
    except:
        pass

def print_progress(addr, ms, single=False):
    global chek_vivod
    with print_lock:
        if chek_vivod >= 50:
            mode = "(S)" if single else ""
            pct = (processed_count / total_proxies_count) * 100 if total_proxies_count else 0
            print(f"[{pct:3.0f}%] LIVE {mode} {addr:<25} | {ms:>4}ms")
            chek_vivod = 0
        else:
            chek_vivod += 1

# ------------------------------- ЧЕКЕР -------------------------------
def check_batch(chunk, start_port, core_path, temp_dir):
    global processed_count
    inbounds, outbounds, rules, mapping = [], [], [], []

    for i, url in enumerate(chunk):
        p = parse_vless(url)
        if not p:
            continue
        port = start_port + i
        inbounds.append({"port": port, "listen": "127.0.0.1", "protocol": "socks", "tag": f"in_{port}"})
        outbounds.append(make_outbound(p, f"out_{port}"))
        rules.append({"type": "field", "inboundTag": [f"in_{port}"], "outboundTag": f"out_{port}"})
        mapping.append((url, port, p))

    if not mapping:
        return []

    cfg = os.path.join(temp_dir, f"cfg_{start_port}.json")
    with open(cfg, "w") as f:
        json.dump({"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"rules": rules}}, f)

    live = []
    proc = subprocess.Popen([core_path, "run", "-c", cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    started = wait_port_or_die(proc, mapping[0][1], CORE_STARTUP_TIMEOUT)

    targets = mapping if started else []
    if not started:
        kill_core(proc)

    for url, port, p in targets:
        with counter_lock:
            processed_count += 1
        try:
            st = time.time()
            r = requests.get(TEST_DOMAIN, proxies={
                "http": f"socks5://127.0.0.1:{port}",
                "https": f"socks5://127.0.0.1:{port}"
            }, timeout=TIMEOUT, verify=False)
            if r.status_code == 204:
                ms = int((time.time() - st) * 1000)
                live.append((url, ms))
                print_progress(p["address"], ms)
        except:
            pass

    kill_core(proc)
    try:
        os.remove(cfg)
    except:
        pass

    return live

# ------------------------------- MAIN -------------------------------
def main():
    global total_proxies_count
    core = shutil.which("xray") or "./xray"
    if not os.path.exists(INPUT_FILE):
        return

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        proxies = [clean_url(x) for x in f if x.strip().startswith("vless://")]

    total_proxies_count = len(proxies)
    temp_dir = tempfile.mkdtemp()

    chunks = [proxies[i:i + PROXIES_PER_BATCH] for i in range(0, len(proxies), PROXIES_PER_BATCH)]
    all_live = []

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = []
        port = LOCAL_PORT_START
        for chunk in chunks:
            futures.append(ex.submit(check_batch, chunk, port, core, temp_dir))
            port += PROXIES_PER_BATCH + 5

        for f in as_completed(futures):
            try:
                res = f.result()
                if res:
                    all_live.extend(res)
            except:
                pass

    unique = []
    for url, ms in all_live:
        if not any(is_same_config(url, u) for u, _ in unique):
            unique.append((url, ms))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for url, _ in unique:
            f.write(url + "\n")

if __name__ == "__main__":
    main()
