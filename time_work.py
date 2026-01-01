import re
import time
import os
import urllib.parse
from collections import defaultdict

WORK_FILE = "sidr_vless_work.txt"
TIME_FILE = "sidr_vless_time.txt"
OUTPUT_TIME_FILE = "sidr_vless_time.txt"

if not os.path.exists(WORK_FILE):
    print(f"Ошибка: файл {WORK_FILE} не найден в репозитории!")
    exit(1)

print(f"Читаю {WORK_FILE}...")
with open(WORK_FILE, 'r', encoding='utf-8') as f:
    lines = f.readlines()

current_urls = [
    line.strip().replace('\ufeff', '').replace('\u200b', '')
    for line in lines if line.strip().startswith("vless://")
]

print(f"Найдено {len(current_urls)} рабочих конфигов.")

# --- Простой парсер VLESS (ключевые поля для сравнения) ---
def clean_url(url):
    return url.strip().replace('\ufeff', '').replace('\u200b', '').replace('\n', '').replace('\r', '')

def parse_vless_key(url):
    url = clean_url(url)
    if not url.startswith("vless://"):
        return None
    try:
        if '#' in url:
            main_part, _ = url.split('#', 1)
        else:
            main_part = url
        parsed_url = urllib.parse.urlparse(main_part)
        uuid = urllib.parse.unquote(parsed_url.username or "")
        address = parsed_url.hostname or ""
        port = parsed_url.port or 443
        query = urllib.parse.parse_qs(parsed_url.query)
        def get_p(key, default=""):
            vals = query.get(key, [default])
            return vals[0].strip()
        security = get_p("security", "none").lower()
        if get_p("pbk") and security != "reality":
            security = "reality"
        pbk = get_p("pbk", "")
        sni = get_p("sni", "") or address
        flow = get_p("flow", "").lower()
        type_ = get_p("type", "tcp").lower()
        if type_ in ["ws", "websocket"]: type_ = "ws"
        elif type_ in ["grpc", "gun"]: type_ = "grpc"
        elif type_ in ["http", "h2", "httpupgrade"]: type_ = "http"
        
        # Ключ для сравнения (кортеж)
        return (
            address.lower(), port, uuid,
            type_, flow, security,
            sni.lower(), pbk, get_p("sid", ""),
            get_p("fp", ""), tuple(sorted(get_p("alpn", "").split(","))) if get_p("alpn") else ()
        )
    except:
        return None

# --- Читаем старые timestamps по ключам ---
old_key_times = defaultdict(int)  # key -> самый старый timestamp
old_exact_times = {}  # url -> ts (fallback)

if os.path.exists(TIME_FILE):
    print("Найден предыдущий sidr_vless_time.txt, переношу timestamps по параметрам...")
    with open(TIME_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        match = re.search(r'\(unixtime\s*(\d+)\)', line) or re.search(r'unix:\s*(\d+)', line)
        if match:
            add_ts = int(match.group(1))
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('vless://'):
                i += 1
            if i < len(lines):
                url = lines[i].strip().replace('\ufeff', '').replace('\u200b', '')
                if url.startswith('vless://'):
                    key = parse_vless_key(url)
                    if key:
                        if old_key_times[key] == 0 or add_ts < old_key_times[key]:
                            old_key_times[key] = add_ts
                    old_exact_times[url] = add_ts
        i += 1
else:
    print("Предыдущий sidr_vless_time.txt не найден — все конфиги считаются новыми.")

# --- Функция склонений ---
def plural(n, one, few, many):
    if 11 <= n % 100 <= 14:
        return many
    if n % 10 == 1:
        return one
    if 2 <= n % 10 <= 4:
        return few
    return many

current_unix = int(time.time())
configs = []

for url in current_urls:
    key = parse_vless_key(url)
    if key and key in old_key_times and old_key_times[key] > 0:
        add_ts = old_key_times[key]  # самый старый для этого конфига
    else:
        add_ts = old_exact_times.get(url, current_unix)  # fallback или новый

    uptime_sec = current_unix - add_ts
    days = uptime_sec // 86400
    hours = (uptime_sec % 86400) // 3600
    minutes = (uptime_sec % 3600) // 60
    seconds = uptime_sec % 60
    parts = []
    if days > 0:
        parts.append(f"{days} {plural(days,'день','дня','дней')}")
    if hours > 0 or days > 0:
        parts.append(f"{hours} {plural(hours,'час','часа','часов')}")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes} {plural(minutes,'минута','минуты','минут')}")
    parts.append(f"{seconds} {plural(seconds,'секунда','секунды','секунд')}")
    uptime_str = " ".join(parts)
    configs.append((add_ts, uptime_str, url))

configs.sort(key=lambda x: x[0])  # от старых к новым

with open(OUTPUT_TIME_FILE, 'w', encoding='utf-8') as f:
    for add_ts, uptime_str, url in configs:
        f.write(f"# работает {uptime_str} (unixtime {add_ts})\n")
        f.write(url + "\n\n")

print(f"Готово! Файл {OUTPUT_TIME_FILE} обновлён с сортировкой от старых к новым (с умным переносом времени по параметрам).")
