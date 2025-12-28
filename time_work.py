import re
import time
import os

# Локальные пути к файлам (они находятся в корне репозитория)
WORK_FILE = "sidr_vless_work.txt"
TIME_FILE = "sidr_vless_time.txt"        # Старый файл с таймстампами (если есть)
OUTPUT_TIME_FILE = "sidr_vless_time.txt" # Тот же файл, перезапишем его

# Проверка наличия рабочего файла
if not os.path.exists(WORK_FILE):
    print(f"Ошибка: файл {WORK_FILE} не найден в репозитории!")
    exit(1)

print(f"Читаю {WORK_FILE}...")
with open(WORK_FILE, 'r', encoding='utf-8') as f:
    lines = f.readlines()

current_urls = [line.strip().replace('\ufeff', '').replace('\u200b', '') for line in lines if line.strip().startswith("vless://")]

print(f"Найдено {len(current_urls)} рабочих конфигов.")

# Загружаем старые timestamps, если файл существует
old_add_times = {}
if os.path.exists(TIME_FILE):
    print("Найден предыдущий sidr_vless_time.txt, переношу timestamps...")
    with open(TIME_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        match = re.search(r'\(unixtime\s*(\d+)\)', line) or re.search(r'unix:\s*(\d+)', line)
        if match:
            add_ts = int(match.group(1))
            i += 1
            # Пропускаем возможные пустые строки или комментарии
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

# Собираем конфиги с таймстампами
configs = []
for url in current_urls:
    if url in old_add_times:
        add_ts = old_add_times[url]
    else:
        add_ts = current_unix  # Новые конфиги получают текущий timestamp

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

# Сортировка: от старых (меньший timestamp) к новым
configs.sort(key=lambda x: x[0])

# Записываем обновлённый файл
with open(OUTPUT_TIME_FILE, 'w', encoding='utf-8') as f:
    for add_ts, uptime_str, url in configs:
        f.write(f"# работает {uptime_str} (unixtime {add_ts})\n")
        f.write(url + '\n\n')

print(f"Готово! Файл {OUTPUT_TIME_FILE} обновлён с сортировкой от старых к новым.")
