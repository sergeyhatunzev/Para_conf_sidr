import requests
import re
import time

WORK_URL = "https://raw.githubusercontent.com/sergeyhatunzev/Para_conf_sidr/main/sidr_vless_work.txt"
TIME_URL = "https://raw.githubusercontent.com/sergeyhatunzev/Para_conf_sidr/main/sidr_vless_time.txt"
OUTPUT_TIME_FILE = "sidr_vless_time.txt"

# Убрал ненужный sleep и datetime
# time.sleep(10)  # Если нужно — раскомментируй, но обычно не требуется

def clean_url(url):
    return url.strip().replace('\ufeff', '').replace('\u200b', '').replace('\n', '').replace('\r', '')

print("Скачиваю sidr_vless_work.txt...")
response_work = requests.get(WORK_URL)
if response_work.status_code != 200:
    print("Ошибка скачивания work.txt")
    exit(1)

current_urls = [clean_url(line) for line in response_work.text.splitlines() if line.strip().startswith("vless://")]
print(f"Найдено {len(current_urls)} рабочих конфигов.")

old_add_times = {}
try:
    response_time = requests.get(TIME_URL, timeout=10)
    if response_time.status_code == 200:
        print("Найден предыдущий sidr_vless_time.txt, переношу timestamps...")
        lines = response_time.text.splitlines()
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
                    url = clean_url(lines[i].strip())
                    if url.startswith('vless://'):
                        old_add_times[url] = add_ts
            i += 1
    else:
        print("Предыдущий sidr_vless_time.txt не найден — все конфиги новые.")
except Exception as e:
    print(f"Ошибка скачивания старого time.txt — все конфиги новые. ({e})")

current_unix = int(time.time())

# Собираем список с timestamp'ами для сортировки
configs = []

for url in current_urls:
    if url in old_add_times:
        add_ts = old_add_times[url]
    else:
        add_ts = current_unix  # Новые получают текущий timestamp

    uptime_sec = current_unix - add_ts

    if uptime_sec < 3600:
        uptime_str = f"{uptime_sec // 60} минут" if uptime_sec >= 60 else "0 минут"
    elif uptime_sec < 86400:
        hours = uptime_sec // 3600
        uptime_str = f"{hours} час" if hours == 1 else f"{hours} часов"
    else:
        days = uptime_sec // 86400
        uptime_str = f"{days} день" if days == 1 else f"{days} дней"

    configs.append((add_ts, uptime_str, url))

# Сортируем по add_ts по возрастанию: от старых (маленький timestamp) к новым
configs.sort(key=lambda x: x[0])

# Записываем в файл в отсортированном порядке
with open(OUTPUT_TIME_FILE, 'w', encoding='utf-8') as f:
    for add_ts, uptime_str, url in configs:
        f.write(f"# работает {uptime_str} (unixtime {add_ts})\n")
        f.write(url + '\n\n')

print(f"Готово! Файл {OUTPUT_TIME_FILE} создан с сортировкой от старых к новым.")
