import tempfile
import sys
import os
import shutil
import time
import socket
import subprocess
import platform
import requests
import psutil
import re
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------- НАСТРОЙКИ -------------------------------
INPUT_FILE = "sidr_vless.txt"
OUTPUT_FILE = "sidr_vless_work.txt"
TEST_DOMAIN = "https://www.google.com/generate_204"
TIMEOUT = 30
THREADS = 200
PROXIES_PER_BATCH = 50
LOCAL_PORT_START = 10000
CORE_STARTUP_TIMEOUT = 12.0
CORE_KILL_DELAY = 0.1
SINGLE_PORT_OFFSET = 200     # смещение для одиночных проверок, чтобы не пересекаться

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

# ------------------------------- ВСПОМОГАТЕЛЬНЫЕ -------------------------------
def clean_url(url):
    return url.strip().replace('\ufeff', '').replace('\u200b', '').replace('\n', '').replace('\r', '')

# Регулярки для Reality
REALITY_PBK_RE = re.compile(r"^[A-Za-z0-9_-]{43,44}$")
REALITY_SID_RE = re.compile(r"^[0-9a-fA-F]{0,32}$")
FLOW_ALLOWED = {"", "xtls-rprx-vision", "xtls-rprx-direct", "xtls-rprx-splice"}

# ------------------------------- ПАРСЕР VLESS -------------------------------
def parse_vless(url):
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
        if parsed_url.scheme != "vless":
            return None

        uuid = urllib.parse.unquote(parsed_url.username or "")
        address = parsed_url.hostname or ""
        port = parsed_url.port or 443

        if not uuid or not address:
            return None

        query_params = urllib.parse.parse_qs(parsed_url.query)

        def get_p(key, default=""):
            vals = query_params.get(key, [default])
            return vals[0].strip()

        encryption = get_p("encryption", "none").lower()
        net_type = get_p("type", "tcp").lower()

        if net_type in ["ws", "websocket"]:
            net_type = "ws"
        elif net_type in ["grpc", "gun"]:
            net_type = "grpc"
        elif net_type in ["http", "h2", "httpupgrade"]:
            net_type = "http"
        else:
            net_type = "tcp"

        flow = get_p("flow", "").lower()
        if flow not in FLOW_ALLOWED:
            flow = ""

        stream_security = get_p("security", "none").lower()
        if stream_security not in ["tls", "reality", "none"]:
            stream_security = "none"

        pbk = get_p("pbk", "")
        if pbk and REALITY_PBK_RE.match(pbk):
            if stream_security != "reality":
                stream_security = "reality"
        else:
            pbk = ""

        sid = get_p("sid", "")
        sid = re.sub(r"[^a-fA-F0-9]", "", sid)
        if len(sid) > 32 or len(sid) % 2 != 0:
            sid = ""
        if sid and not REALITY_SID_RE.match(sid):
            sid = ""

        sni = get_p("sni", "")
        fp = get_p("fp", "chrome")
        alpn_str = get_p("alpn", "")
        alpn = [x.strip() for x in alpn_str.split(",")] if alpn_str else []

        return {
            "protocol": "vless",
            "uuid": uuid,
            "address": address,
            "port": port,
            "flow": flow,
            "security": stream_security,
            "encryption": encryption,
            "pbk": pbk,
            "sid": sid,
            "sni": sni or address,
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


def get_proxy_info(parsed):
    if not parsed:
        return "unknown", "parse-error"
    addr = f"{parsed['address']}:{parsed['port']}"
    tag = (parsed['tag'] or "no-remark")[:48]
    return addr, tag


# ------------------------------- ГЕНЕРАЦИЯ OUTBOUND -------------------------------
def make_outbound(parsed, tag):
    if not parsed:
        return None

    user = {"id": parsed["uuid"], "encryption": "none"}
    if parsed["flow"]:
        user["flow"] = parsed["flow"]

    vnext = [{"address": parsed["address"], "port": parsed["port"], "users": [user]}]

    stream = {"network": parsed["type"], "security": parsed["security"]}

    tls_settings = {
        "serverName": parsed["sni"],
        "allowInsecure": True
    }
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
        stream["wsSettings"] = {
            "path": parsed["path"] or "/",
            "headers": {"Host": host} if host else {}
        }
    elif parsed["type"] == "grpc":
        stream["grpcSettings"] = {
            "serviceName": parsed["serviceName"],
            "multiMode": False
        }
    elif parsed["type"] == "http":
        host = parsed["host"] or parsed["sni"]
        stream["httpSettings"] = {
            "path": parsed["path"] or "/",
            "host": [host] if host else []
        }
    elif parsed["type"] == "tcp" and parsed["headerType"] != "none":
        stream["tcpSettings"] = {
            "header": {"type": parsed["headerType"]}
        }

    return {
        "protocol": "vless",
        "tag": tag,
        "settings": {"vnext": vnext},
        "streamSettings": stream
    }


# ------------------------------- СОЗДАНИЕ КОНФИГА -------------------------------
def create_batch_config_file(proxy_list, start_port, work_dir):
    inbounds = []
    outbounds = []
    rules = []
    valid_proxies = []

    for i, url in enumerate(proxy_list):
        port = start_port + i
        in_tag = f"in_{port}"
        out_tag = f"out_{port}"

        inbounds.append({
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "tag": in_tag,
            "settings": {"udp": False}
        })

        parsed = parse_vless(url)
        outbound = make_outbound(parsed, out_tag)
        if not outbound:
            continue

        outbounds.append(outbound)
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})
        valid_proxies.append((url, port, parsed))

    if not valid_proxies:
        return None, None

    config = {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules
        }
    }

    path = os.path.join(work_dir, f"cfg_{start_port}.json")
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    return path, valid_proxies


# ------------------------------- УТИЛИТЫ ПРОЦЕССОВ -------------------------------
def is_port_in_use(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.08)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except:
        return False


def run_core(core_path, config_path):
    cmd = [core_path, "run", "-c", config_path]
    startupinfo = None
    if platform.system() == "Windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    try:
        return subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo
        )
    except Exception as e:
        logger.print(f"[bold red]Не удалось запустить xray: {e}[/]")
        return None


def kill_core(proc):
    if not proc:
        return
    try:
        proc.kill()
        if psutil.pid_exists(proc.pid):
            parent = psutil.Process(proc.pid)
            for child in parent.children(recursive=True):
                child.kill()
            parent.kill()
    except:
        pass


def check_connection(port):
    proxies = {
        'http': f'socks5h://127.0.0.1:{port}',
        'https': f'socks5h://127.0.0.1:{port}'
    }
    try:
        start = time.time()
        r = requests.get(TEST_DOMAIN, proxies=proxies, timeout=TIMEOUT, verify=False)
        latency = round((time.time() - start) * 1000)
        if r.status_code == 204:
            return latency, None
        return None, f"HTTP {r.status_code}"
    except requests.exceptions.ConnectTimeout:
        return None, "ConnectTimeout"
    except requests.exceptions.ReadTimeout:
        return None, "ReadTimeout"
    except Exception as e:
        return None, str(e)[:40]


# ------------------------------- ДЕДУПЛИКАЦИЯ -------------------------------
def _are_equal(a, b):
    return (a == b) or (not a and not b)


def _alpn_equal(a, b):
    return (a or []) == (b or [])


def compare_parsed(a, b):
    if not a or not b:
        return False
    return (
        _are_equal(a.get("protocol"), b.get("protocol")) and
        _are_equal(a.get("address"), b.get("address")) and
        a.get("port") == b.get("port") and
        _are_equal(a.get("uuid"), b.get("uuid")) and
        _are_equal(a.get("encryption"), b.get("encryption")) and
        _are_equal(a.get("type"), b.get("type")) and
        _are_equal(a.get("headerType"), b.get("headerType")) and
        _are_equal(a.get("path"), b.get("path")) and
        _are_equal(a.get("security"), b.get("security")) and
        _are_equal(a.get("flow"), b.get("flow")) and
        _are_equal(a.get("sni"), b.get("sni")) and
        _alpn_equal(a.get("alpn"), b.get("alpn")) and
        _are_equal(a.get("fp"), b.get("fp")) and
        _are_equal(a.get("pbk"), b.get("pbk")) and
        _are_equal(a.get("sid"), b.get("sid"))
    )


def deduplicate_proxies(proxies_with_latency):
    keep = []
    removed = 0
    seen = {}

    for url, lat in sorted(proxies_with_latency, key=lambda x: x[1]):
        parsed = parse_vless(url)
        if not parsed:
            keep.append((url, lat))
            continue

        key = (
            parsed["address"], parsed["port"], parsed["uuid"],
            parsed["type"], parsed["security"], parsed["sni"],
            parsed["flow"], parsed["path"], parsed["host"] or "",
            tuple(parsed["alpn"] or []), parsed["fp"], parsed["pbk"], parsed["sid"]
        )

        if key in seen:
            removed += 1
            continue

        seen[key] = True
        keep.append((url, lat))

    return keep, removed


# ------------------------------- ПРОВЕРКА ОДНОГО ПРОКСИ -------------------------------
def check_single_proxy(url, base_port, progress_task):
    parsed = parse_vless(url)
    if not parsed:
        addr, tag = get_proxy_info(parsed)
        logger.print(f"[grey50]INVALID   {addr:<22} | {tag}[/]")
        progress_task.advance(1)
        return []

    port = base_port
    cfg_path, mapping = create_batch_config_file([url], port, TEMP_DIR)
    if not mapping:
        progress_task.advance(1)
        return []

    proc = run_core(CORE_PATH, cfg_path)
    if not proc:
        progress_task.advance(1)
        return []

    started = False
    for _ in range(int(CORE_STARTUP_TIMEOUT * 25)):
        if is_port_in_use(port):
            started = True
            break
        time.sleep(0.04)

    if not started:
        logger.print(f"[bold red]ОДИНОЧНЫЙ НЕ СТАРТОВАЛ  {port} → {get_proxy_info(parsed)[0]}[/]")
        kill_core(proc)
        time.sleep(CORE_KILL_DELAY)
        try:
            os.remove(cfg_path)
        except:
            pass
        progress_task.advance(1)
        return []

    time.sleep(1.2)

    lat, err = check_connection(port)
    addr, tag = get_proxy_info(parsed)

    if lat is not None:
        logger.print(f"[green bold]LIVE (одиночный)[/] {addr:<22} | {lat:>4} ms | {tag}")
        result = [(url, lat)]
    else:
        logger.print(f"[red]DEAD (одиночный)[/]  {addr:<22} | {'':>8} | {tag} → {err}")
        result = []

    kill_core(proc)
    time.sleep(CORE_KILL_DELAY)
    try:
        os.remove(cfg_path)
    except:
        pass

    progress_task.advance(1)
    return result


# ------------------------------- ПРОВЕРКА БАТЧА -------------------------------
def check_batch(chunk, start_port, progress_task):
    if len(chunk) <= 1:
        if chunk:
            return check_single_proxy(chunk[0], start_port, progress_task)
        return []

    cfg_path, mapping = create_batch_config_file(chunk, start_port, TEMP_DIR)
    if not mapping:
        for _ in chunk:
            progress_task.advance(1)
        return []

    proc = run_core(CORE_PATH, cfg_path)
    if not proc:
        for _ in chunk:
            progress_task.advance(1)
        return []

    first_port = mapping[0][1] if mapping else None
    started = False

    for _ in range(int(CORE_STARTUP_TIMEOUT * 25)):
        if first_port and is_port_in_use(first_port):
            started = True
            break
        time.sleep(0.04)

    if not started:
        logger.print(f"[bold yellow]БАТЧ НЕ СТАРТОВАЛ ({start_port}..{start_port+len(chunk)-1}) → разбиваем на одиночные[/]")
        kill_core(proc)
        time.sleep(CORE_KILL_DELAY)
        try:
            os.remove(cfg_path)
        except:
            pass

        batch_live = []
        single_base = start_port + SINGLE_PORT_OFFSET
        for idx, url in enumerate(chunk):
            res = check_single_proxy(url, single_base + idx * 2, progress_task)
            batch_live.extend(res)
        return batch_live

    # батч запустился нормально
    time.sleep(2.0)

    batch_live = []
    for url, port, parsed in mapping:
        lat, err = check_connection(port)
        addr, tag = get_proxy_info(parsed)
        if lat is not None:
            logger.print(f"[green]LIVE[/]          {addr:<22} | {lat:>4} ms | {tag}")
            batch_live.append((url, lat))
        else:
            logger.print(f"[red]DEAD[/]           {addr:<22} | {'':>8} | {tag} → {err}")
        progress_task.advance(1)

    kill_core(proc)
    time.sleep(CORE_KILL_DELAY)
    try:
        os.remove(cfg_path)
    except:
        pass

    return batch_live


# ------------------------------- MAIN -------------------------------
def main():
    global CORE_PATH, TEMP_DIR

    TEMP_DIR = tempfile.mkdtemp(prefix="xray_checker_")
    CORE_PATH = shutil.which("xray") or shutil.which("xray.exe")

    if not CORE_PATH:
        for candidate in ["xray", "xray.exe", "./xray", "./xray.exe"]:
            if os.path.isfile(candidate):
                CORE_PATH = os.path.abspath(candidate)
                break

    if not CORE_PATH or not os.path.isfile(CORE_PATH):
        logger.print("[bold red]xray / xray.exe не найден в PATH и не найден рядом[/]")
        sys.exit(1)

    logger.print(f"[bright_green]Ядро → {CORE_PATH}[/]")

    if not os.path.isfile(INPUT_FILE):
        logger.print(f"[bold red]Файл {INPUT_FILE} не найден[/]")
        sys.exit(1)

    with open(INPUT_FILE, encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    proxies = [clean_url(line) for line in lines if line.strip().startswith("vless://")]

    if not proxies:
        logger.print("[bold red]В файле нет ни одной vless-ссылки[/]")
        sys.exit(1)

    logger.print(f"[cyan]Найдено {len(proxies)} vless-ссылок  |  батчи по {PROXIES_PER_BATCH}  |  потоков: {THREADS}[/]")

    chunks = [proxies[i:i + PROXIES_PER_BATCH] for i in range(0, len(proxies), PROXIES_PER_BATCH)]

    live = []

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Проверка прокси...", total=len(proxies))

        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = []
            port_counter = LOCAL_PORT_START

            for chunk in chunks:
                futures.append(
                    executor.submit(check_batch, chunk, port_counter, progress)
                )
                port_counter += len(chunk) + 30   # запас

            for future in as_completed(futures):
                try:
                    live.extend(future.result())
                except Exception as e:
                    logger.print(f"[bold red]Ошибка в потоке: {e}[/]")

    # дедупликация
    live, removed = deduplicate_proxies(live)
    logger.print(f"[yellow]Удалено дубликатов: {removed}[/]")

    live.sort(key=lambda x: x[1])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for url, _ in live:
            f.write(url + "\n")

    table = Table(title=f"Результат  |  Живых: {len(live)} из {len(proxies)}")
    table.add_column("Пинг", style="green", justify="right")
    table.add_column("Адрес", style="white")
    table.add_column("Тег", style="cyan")

    for url, ping in live[:15]:
        parsed = parse_vless(url)
        addr, tag = get_proxy_info(parsed)
        table.add_row(f"{ping} ms", addr, tag)

    console.print(table)
    logger.print(f"\n[bold bright_green]Рабочие ссылки сохранены → {OUTPUT_FILE}[/]")

    try:
        shutil.rmtree(TEMP_DIR, ignore_errors=True)
    except:
        pass


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.print("\n[red bold]Остановлено пользователем[/]")
    except Exception as e:
        logger.print(f"[bold red]Критическая ошибка:[/] {e}")
        import traceback
        traceback.print_exc()
