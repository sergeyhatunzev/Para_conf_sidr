import re
import time
import os

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

# --- функция склонений ---
def plural(n, one, few, many):
    if 11 <= n % 100 <= 14:
        return many
    if n % 10 == 1:
        return one
    if 2 <= n % 10 <= 4:
        return few
    return many

# --- читаем старые timestamps ---
old_add_times = {}

if os.path.exists(TIME_FILE):
    print("Найден предыдущий sidr_vless_time.txt, переношу timestamps...")
    with open(TIME_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # поддержка старого и нового формата
        match = re.search(r'\(unixtime\s*(\d+)\)', line) or re.search(r'unix:\s*(\d+)', line)

        if match:
            add_ts = int(match.group(1))
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('vless://'):
                i += 1
            if i < len(lines):
                url = lines[i].strip().replace('\ufeff', '').replace('\u200b', '')
                if url.startswith('vless://'):
                    old_add_times[url] = add_ts
        i += 1
else:
    print("Предыдущий sidr_vless_time.txt не найден — все конфиги считаются новыми.")

current_unix = int(time.time())

configs = []

for url in current_urls:
    add_ts = old_add_times.get(url, current_unix)
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

configs.sort(key=lambda x: x[0])

with open(OUTPUT_TIME_FILE, 'w', encoding='utf-8') as f:
    for add_ts, uptime_str, url in configs:
        f.write(f"# работает {uptime_str} (unixtime {add_ts})\n")
        f.write(url + "\n\n")

print(f"Готово! Файл {OUTPUT_TIME_FILE} обновлён с сортировкой от старых к новым.")
