import requests
import re
import time
import datetime

WORK_URL = "https://raw.githubusercontent.com/sergeyhatunzev/Para_conf_sidr/main/sidr_vless_work.txt"
TIME_URL = "https://raw.githubusercontent.com/sergeyhatunzev/Para_conf_sidr/main/sidr_vless_time.txt"

OUTPUT_TIME_FILE = "sidr_vless_time.txt"
time.sleep(10)
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
            # Парсим unixtime из скобок, даже если формат старый или новый
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
except:
    print("Ошибка скачивания старого time.txt — все конфиги новые.")

current_unix = int(time.time())

with open(OUTPUT_TIME_FILE, 'w', encoding='utf-8') as f:
    for url in current_urls:
        if url in old_add_times:
            add_ts = old_add_times[url]
            uptime_sec = current_unix - add_ts
        else:
            add_ts = current_unix
            uptime_sec = 0

        # Упрощённый uptime как в твоём примере
        if uptime_sec < 3600:
            uptime_str = f"{uptime_sec // 60} минут" if uptime_sec >= 60 else "0 минут"
        elif uptime_sec < 86400:
            uptime_str = f"{uptime_sec // 3600} часа" if uptime_sec // 3600 == 1 else f"{uptime_sec // 3600} часов"
        else:
            days = uptime_sec // 86400
            uptime_str = f"{days} день" if days == 1 else f"{days} дней"

        f.write(f"# работает {uptime_str} (unixtime {add_ts})\n")
        f.write(url + '\n\n')

print(f"Готово! Файл {OUTPUT_TIME_FILE} создан в твоём формате.")
print("Загрузи его в репо, чтобы в следующий раз правильно посчитало.")