import re
import time

input_file  = "sidr_vless_time.txt"
output_file = "sidr_vless_time_one_ip.txt"

seen_ips = set()
entries = []

# Регулярка для IP
pattern_ip = re.compile(r'@([0-9]{1,3}(?:\.[0-9]{1,3}){3})[:]')
# Регулярка для unixtime
pattern_unixtime = re.compile(r'unixtime\s*(\d+)')

with open(input_file, encoding="utf-8") as f:
    lines = [line.rstrip() for line in f]

i = 0
while i < len(lines) - 1:
    comment = lines[i].strip()
    vless   = lines[i + 1].strip()

    if comment.startswith("# работает"):
        ut_match = pattern_unixtime.search(comment)

        # если нет unixtime — пропускаем
        if not ut_match:
            i += 2
            continue

        start_time = int(ut_match.group(1))
        now = int(time.time())

        # сколько прошло времени
        uptime_seconds = now - start_time

        # только если >= 2 часа
        if uptime_seconds >= 2 * 3600:
            ip_match = pattern_ip.search(vless)

            if ip_match:
                ip = ip_match.group(1)

                if ip not in seen_ips:
                    seen_ips.add(ip)
                    entries.append((comment, vless))

        i += 2
        continue

    i += 1

# Запись результата
with open(output_file, "w", encoding="utf-8") as f:
    count = len(entries)
    f.write(f"#ОСТАЛОСЬ {count} С УНИКАЛЬНЫМ ip\n\n")
    f.write(f'''
    #profile-update-interval: 1
    #profile-title: Morty подписка
    #support-url: https://t.me/FullNOOBS
    #profile-web-page-url: https://t.me/FullNOOBS
    #announce: Эта подписка создана морти для его друзей дальнешее распространение подписки карается баном!
    ''')
    for comment, vless in entries:
        f.write(comment + "\n")
        f.write(vless + "\n\n")

print(f"Готово. Уникальных IP: {count}")
print(f"Сохранено в: {output_file}")
