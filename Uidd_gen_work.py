# =============================================================================
# СКРИПТ: Генератор + Тестер VLESS-конфигов (улучшенная версия 2025)
# =============================================================================
# 1. Читает sidr_vless.txt
# 2. Находит уникальные UUID и рабочие серверы (по открытому TCP-порту)
# 3. Генерирует все комбинации: каждый UUID × каждый рабочий хвост
# 4. Тестирует ВСЕ конфиги через xray (батчами по 50)
# 5. Убирает дубликаты в стиле v2rayN (игнорируя host)
# 6. Сохраняет только рабочие в sidr_vless_work.txt
# =============================================================================

import re
import asyncio
import socket
import tempfile
import sys
import os
import shutil
import time
import subprocess
import platform
import requests
import psutil
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------- НАСТРОЙКИ -------------------------------
INPUT_FILE        = "sidr_vless.txt"
OUTPUT_FILE       = "Wow_work_uidd.txt"
TEST_DOMAIN       = "https://www.google.com/generate_204"
TIMEOUT           = 30
TEST_THREADS      = 200          # сколько потоков для запуска батчей xray
PROXIES_PER_BATCH = 50
LOCAL_PORT_START  = 10000
CORE_STARTUP_TIMEOUT = 4.0
CORE_KILL_DELAY   = 0.05
MAX_CONCURRENT_CHECKS = 500     # ограничение параллельных проверок портов

# ------------------------------- RICH -------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    console = Console()
except ImportError:
    print("Ошибка: pip install rich")
    sys.exit(1)

logger = console

# ------------------------------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ -------------------------------
def clean_url(url: str) -> str:
    return url.strip().replace('\ufeff', '').replace('\u200b', '').replace('\n', '').replace('\r', '')

REALITY_PBK_RE = re.compile(r"^[A-Za-z0-9_-]{43,44}$")
REALITY_SID_RE = re.compile(r"^[0-9a-fA-F]{0,32}$")
FLOW_ALLOWED = {"", "xtls-rprx-vision", "xtls-rprx-direct", "xtls-rprx-splice"}

# ------------------------------- ПАРСЕР VLESS -------------------------------
def parse_vless(url: str):
    try:
        url = clean_url(url)
        if not url.startswith("vless://"):
            return None
        if '#' in url:
            main_part, tag_raw = url.split('#', 1)
            tag = urllib.parse.unquote(tag_raw).strip()
        else:
            main_part = url
            tag = "vless"

        parsed_url = urllib.parse.urlparse(main_part)
        uuid = urllib.parse.unquote(parsed_url.username or "")
        address = parsed_url.hostname or ""
        port = parsed_url.port or 443
        if not uuid or not address:
            return None

        query_params = urllib.parse.parse_qs(parsed_url.query)

        def get_p(key, default=""):
            return query_params.get(key, [default])[0].strip()

        encryption = get_p("encryption", "none").lower()
        net_type = get_p("type", "tcp").lower()
        if net_type in ["ws", "websocket"]:     net_type = "ws"
        elif net_type in ["grpc", "gun"]:       net_type = "grpc"
        elif net_type in ["http", "h2", "httpupgrade"]: net_type = "http"
        else:                                   net_type = "tcp"

        flow = get_p("flow", "").lower()
        if flow not in FLOW_ALLOWED:
            flow = ""

        security = get_p("security", "none").lower()
        if security not in ["tls", "reality", "none"]:
            security = "none"

        pbk = get_p("pbk", "")
        if pbk and REALITY_PBK_RE.match(pbk):
            if security != "reality":
                security = "reality"
        else:
            pbk = ""

        sid = re.sub(r"[^a-fA-F0-9]", "", get_p("sid", ""))
        if len(sid) > 32 or len(sid) % 2 != 0:
            sid = ""
        if sid and not REALITY_SID_RE.match(sid):
            sid = ""

        sni = get_p("sni", "") or address
        fp = get_p("fp", "chrome")
        alpn_str = get_p("alpn", "")
        alpn = [x.strip() for x in alpn_str.split(",")] if alpn_str else []

        return {
            "protocol": "vless",
            "uuid": uuid.lower(),
            "address": address,
            "port": port,
            "flow": flow,
            "security": security,
            "encryption": encryption,
            "pbk": pbk,
            "sid": sid,
            "sni": sni,
            "fp": fp,
            "alpn": alpn,
            "type": net_type,
            "host": get_p("host", ""),
            "path": urllib.parse.unquote(get_p("path", "")),
            "serviceName": get_p("serviceName", ""),
            "headerType": get_p("headerType", "none"),
            "tag": tag
        }
    except Exception:
        return None

def extract_uuid(vless: str) -> str | None:
    match = re.search(r'vless://([^@]+)@', vless)
    if match:
        uuid = match.group(1).lower()
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', uuid):
            return uuid
    return None

def extract_tail(vless: str) -> str | None:
    if '@' in vless:
        return vless.split('@', 1)[1]
    return None

# ------------------------------- ГЕНЕРАЦИЯ OUTBOUND -------------------------------
def make_outbound(parsed, tag: str):
    if not parsed:
        return None
    user = {"id": parsed["uuid"], "encryption": "none"}
    if parsed["flow"]:
        user["flow"] = parsed["flow"]
    vnext = [{"address": parsed["address"], "port": parsed["port"], "users": [user]}]
    stream = {"network": parsed["type"], "security": parsed["security"]}

    tls_settings = {"serverName": parsed["sni"], "allowInsecure": True}
    if parsed["alpn"]:
        tls_settings["alpn"] = parsed["alpn"]

    if parsed["security"] == "tls":
        stream["tlsSettings"] = tls_settings
    elif parsed["security"] == "reality":
        stream["realitySettings"] = {
            "publicKey": parsed["pbk"],
            "shortId": parsed["sid"],
            "serverName": parsed["sni"],
            "fingerprint": parsed["fp"],
            "spiderX": "/"
        }

    if parsed["type"] == "ws":
        host = parsed["host"] or parsed["sni"]
        stream["wsSettings"] = {"path": parsed["path"] or "/", "headers": {"Host": host} if host else {}}
    elif parsed["type"] == "grpc":
        stream["grpcSettings"] = {"serviceName": parsed["serviceName"], "multiMode": False}
    elif parsed["type"] == "http":
        host = parsed["host"] or parsed["sni"]
        stream["httpSettings"] = {"path": parsed["path"] or "/", "host": [host] if host else []}
    elif parsed["type"] == "tcp" and parsed["headerType"] != "none":
        stream["tcpSettings"] = {"header": {"type": parsed["headerType"]}}

    return {
        "protocol": "vless",
        "tag": tag,
        "settings": {"vnext": vnext},
        "streamSettings": stream
    }

# ------------------------------- СОЗДАНИЕ КОНФИГА БАТЧА -------------------------------
def create_batch_config_file(proxy_list: List[str], start_port: int, work_dir: str):
    inbounds = []
    outbounds = []
    rules = []
    valid = []

    for i, url in enumerate(proxy_list):
        port = start_port + i
        in_tag = f"in_{port}"
        out_tag = f"out_{port}"

        inbounds.append({
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "tag": in_tag,
            "settings": {"udp": False}
        })

        parsed = parse_vless(url)
        outbound = make_outbound(parsed, out_tag)
        if outbound:
            outbounds.append(outbound)
            rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})
            valid.append((url, port, parsed))

    if not valid:
        return None, None

    config = {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": rules, "domainStrategy": "AsIs"}
    }

    path = os.path.join(work_dir, f"batch_{start_port}.json")
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)

    return path, valid

# ------------------------------- ЗАПУСК / УБИЙСТВО XRAY -------------------------------
def is_port_in_use(port: int) -> bool:
    try:
        with socket.socket() as s:
            s.settimeout(0.1)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except:
        return False

def run_core(core_path: str, config_path: str):
    cmd = [core_path, "run", "-c", config_path]
    startupinfo = subprocess.STARTUPINFO() if platform.system() == "Windows" else None
    if startupinfo:
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, startupinfo=startupinfo)
    except:
        return None

def kill_core(proc):
    if not proc:
        return
    try:
        proc.kill()
        if psutil.pid_exists(proc.pid):
            for child in psutil.Process(proc.pid).children(recursive=True):
                child.kill()
    except:
        pass

# ------------------------------- ПРОВЕРКА СОЕДИНЕНИЯ -------------------------------
def check_connection(port: int) -> Tuple[bool | int, str | None]:
    proxies = {
        'http':  f'socks5://127.0.0.1:{port}',
        'https': f'socks5://127.0.0.1:{port}'
    }
    try:
        start = time.time()
        r = requests.get(TEST_DOMAIN, proxies=proxies, timeout=TIMEOUT, verify=False)
        latency = round((time.time() - start) * 1000)
        if r.status_code == 204:
            return latency, None
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)[:40]

# ------------------------------- ПРОВЕРКА ОТКРЫТОГО ПОРТА (асинхронно) -------------------------------
async def check_vless_port_open(vless_str: str, sem: asyncio.Semaphore, timeout: float = 3.0) -> bool:
    async with sem:
        match = re.search(r'@([^:]+):(\d+)(?:\?|$|#)', vless_str)
        if not match:
            return False
        host = match.group(1)
        try:
            port = int(match.group(2))
        except ValueError:
            return False

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

# ------------------------------- ДЕДУПЛИКАЦИЯ В СТИЛЕ v2rayN -------------------------------
def _are_equal(a, b):
    return (a == b) or (not a and not b)

def _alpn_equal(a_list, b_list):
    return (a_list or []) == (b_list or [])

def compare_parsed(a, b):
    if not a or not b:
        return False
    return (
        _are_equal(a.get("protocol"),    b.get("protocol"))    and
        _are_equal(a.get("address"),     b.get("address"))     and
        a.get("port") == b.get("port")                         and
        _are_equal(a.get("uuid"),        b.get("uuid"))        and
        _are_equal(a.get("encryption"),  b.get("encryption"))  and
        _are_equal(a.get("type"),        b.get("type"))        and
        _are_equal(a.get("headerType"),  b.get("headerType"))  and
        # _are_equal(a.get("host"),      b.get("host"))        # <--- ИГНОРИРУЕМ HOST !!!
        _are_equal(a.get("path"),        b.get("path"))        and
        _are_equal(a.get("security"),    b.get("security"))    and
        _are_equal(a.get("flow"),        b.get("flow"))        and
        _are_equal(a.get("sni"),         b.get("sni"))         and
        _alpn_equal(a.get("alpn"),       b.get("alpn"))        and
        _are_equal(a.get("fp"),          b.get("fp"))          and
        _are_equal(a.get("pbk"),         b.get("pbk"))         and
        _are_equal(a.get("sid"),         b.get("sid"))
    )

def deduplicate_proxies(proxies_with_latency: List[Tuple[str, int]]):
    keep = []
    removed = 0
    for url, latency in proxies_with_latency:
        parsed = parse_vless(url)
        if not parsed:
            keep.append((url, latency))
            continue
        exists = any(compare_parsed(parse_vless(k_url), parsed) for k_url, _ in keep)
        if not exists:
            keep.append((url, latency))
        else:
            removed += 1
    return keep, removed

# =============================================================================
# ОСНОВНАЯ ЛОГИКА
# =============================================================================
async def main():
    logger.print("[bold cyan]=== Генератор + Тестер VLESS-конфигов (2025) ===[/]\n")

    # 1. Чтение файла
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            lines = [clean_url(l) for l in f if l.strip().startswith('vless://')]
    except Exception as e:
        logger.print(f"[bold red]Ошибка чтения файла: {e}[/]")
        return

    total_original = len(lines)
    logger.print(f"[cyan]Найдено исходных конфигов: {total_original:,}[/]")

    # 2. Уникальные UUID
    all_uuids = set()
    for line in lines:
        uuid = extract_uuid(line)
        if uuid:
            all_uuids.add(uuid)
    unique_uuids = list(all_uuids)
    logger.print(f"[cyan]Уникальных UUID: {len(unique_uuids):,}[/]")

    # 3. Проверка открытых портов
    logger.print("\n[cyan]Проверка открытых портов серверов...[/]")
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    tasks = [check_vless_port_open(vless, sem, timeout=3.0) for vless in lines]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    working_original = []
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            continue
        if res is True:
            working_original.append(lines[i])

    working_count = len(working_original)
    logger.print(f"[green]Серверов с открытым портом: {working_count:,} из {total_original:,}[/]")

    if not working_original:
        logger.print("[bold red]Не найдено ни одного сервера с открытым портом. Выход.[/]")
        return

    # 4. Генерация новых конфигов
    logger.print("\n[cyan]Генерация новых конфигов...[/]")
    new_configs = []
    for original in working_original:
        tail = extract_tail(original)
        if not tail:
            continue
        orig_uuid = extract_uuid(original)
        for new_uuid in unique_uuids:
            if new_uuid == orig_uuid:
                continue
            new_vless = f"vless://{new_uuid}@{tail}"
            new_configs.append(new_vless)

    total_generated = len(new_configs)
    logger.print(f"[yellow]Сгенерировано новых конфигов: {total_generated:,}[/]")

    if total_generated == 0:
        logger.print("[bold red]Не удалось сгенерировать новые конфиги.[/]")
        return

    # 5. Тестирование через xray
    TEMP_DIR = tempfile.mkdtemp()
    CORE_PATH = shutil.which("xray") or shutil.which("xray.exe")
    if not CORE_PATH:
        for c in ["xray", "xray.exe", "./xray", "./xray.exe"]:
            if os.path.exists(c):
                CORE_PATH = os.path.abspath(c)
                break
    if not CORE_PATH:
        logger.print("[bold red]xray не найден! Положите рядом с этим скриптом.[/]")
        shutil.rmtree(TEMP_DIR, ignore_errors=True)
        return

    logger.print(f"[green]Ядро: {CORE_PATH}[/]")
    logger.print(f"[cyan]Тестируем {total_generated:,} конфигов в {TEST_THREADS} потоках[/]")

    chunks = [new_configs[i:i + PROXIES_PER_BATCH] for i in range(0, len(new_configs), PROXIES_PER_BATCH)]

    live_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Тестирование конфигов...", total=total_generated)

        def test_batch(chunk, start_port):
            cfg_path, mapping = create_batch_config_file(chunk, start_port, TEMP_DIR)
            if not mapping:
                for _ in chunk:
                    progress.advance(task)
                return []

            proc = run_core(CORE_PATH, cfg_path)
            if not proc:
                for _ in chunk:
                    progress.advance(task)
                return []

            started = False
            for _ in range(int(CORE_STARTUP_TIMEOUT * 20)):
                if is_port_in_use(mapping[0][1]):
                    started = True
                    break
                time.sleep(0.05)

            if not started:
                kill_core(proc)
                for _ in chunk:
                    progress.advance(task)
                return []

            time.sleep(0.4)

            batch_live = []
            for url, port, parsed in mapping:
                lat, err = check_connection(port)
                addr = f"{parsed['address']}:{parsed['port']}"
                tag = parsed['tag'][:50]

                if lat:
                    logger.print(f"[green]LIVE[/] {addr:<22} | {lat:>4} ms | {tag}")
                    batch_live.append((url, lat))
                else:
                    logger.print(f"[red]DEAD[/] {addr:<22} | {'':>8} | {tag} → {err or 'unknown error'}")

                progress.advance(task)

            kill_core(proc)
            time.sleep(CORE_KILL_DELAY)

            try:
                os.remove(cfg_path)
            except:
                pass

            return batch_live

        with ThreadPoolExecutor(max_workers=TEST_THREADS) as executor:
            futures = []
            port_offset = LOCAL_PORT_START
            for chunk in chunks:
                futures.append(executor.submit(test_batch, chunk, port_offset))
                port_offset += len(chunk) + 20

            for future in as_completed(futures):
                live_results.extend(future.result())

    # 6. Дедупликация и сортировка
    logger.print("\n[yellow]Удаление дубликатов в стиле v2rayN (игнорируя host)...[/]")
    live_dedup, removed = deduplicate_proxies(live_results)
    live_dedup.sort(key=lambda x: x[1])  # по пингу

    logger.print(f"[yellow]Удалено дубликатов: {removed}[/]")
    logger.print(f"[bold green]Рабочих конфигов после теста и дедупликации: {len(live_dedup):,}[/]")

    # 7. Сохранение
    if live_dedup:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for url, _ in live_dedup:
                f.write(url + '\n')
        logger.print(f"[bold green]Рабочие конфиги сохранены в {OUTPUT_FILE}[/]")

        # Таблица топ-20
        table = Table(title=f"Топ-{min(20, len(live_dedup))} лучших по пингу")
        table.add_column("Пинг", style="green", justify="right")
        table.add_column("Сервер", style="cyan")
        table.add_column("Тег", style="magenta")
        for url, ping in live_dedup[:20]:
            parsed = parse_vless(url)
            addr = f"{parsed['address']}:{parsed['port']}"
            tag = parsed['tag'][:60]
            table.add_row(f"{ping} ms", addr, tag)
        console.print(table)
    else:
        logger.print("[bold red]Не найдено ни одного рабочего конфига после теста.[/]")

    # Уборка
    try:
        shutil.rmtree(TEMP_DIR)
    except:
        pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.print("\n[red]Остановлено пользователем.[/]")
    except Exception as e:
        logger.print(f"[bold red]Критическая ошибка: {e}[/]")
        import traceback
        traceback.print_exc()
