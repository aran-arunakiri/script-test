"""
provision_pi11.py — batch-flash a tray of factory AccuSavers from Tasmota to the
modern (ESP-IDF) firmware, leaving every unit UNPROVISIONED and ready to ship.

pi11 = pi9 (2026-09-10) with the timing work: own AP join (no rescan, no
separate contact check), ARP-based discovery of the tray's MACs instead of a
254-host HTTP sweep, NetworkManager autoconnect disabled for plug APs, BLE
scanned immediately, shorter silence windows. Same decisions as pi9.

Relationship to provision_pi8.py
--------------------------------
pi8 is the last confirmed-working Tasmota -> Tasmota flow and is NOT copied
here — it is imported, so every primitive (AP scanning, WiFi handling, Phase A, the LAN
sweep, Upgrade with retries) is literally the same code. pi11 only:

  * points OtaUrl at accusaver.bin instead of the Tasmota bin
  * drops the steps that cannot survive the migration
  * replaces HTTP verification with a BLE scan

Why the flow gets SHORTER, not longer
-------------------------------------
After a Tasmota -> modern flash the NVS namespace differs, so the WiFi
credentials are gone. The unit does not come back on the LAN; it boots into BLE
provisioning advertising as ACCU_<last 6 hex of MAC>. That means:

  - the Berry script fetch is meaningless (modern firmware has no Berry)
  - waiting for ScriptVersion over HTTP can never succeed
  - Reset 4 has nothing to talk to
  - the closing Reset 1 is redundant: the flash already left the unit blank,
    which is exactly the state we want to ship

So Phase B collapses to "Upgrade 1, then confirm the unit left the LAN", and
the real proof of success is Phase C: one BLE scan that sees every flashed unit
advertising its ACCU_ name at once. One scan covers the whole tray, so we keep
the throughput of pi8's parallel Phase B without needing a serial per-device
step.

Usage
-----
  python3 provision_pi11.py                 # full run: Phase A + B + C
  python3 provision_pi11.py --lan-only      # skip Phase A (units already on WiFi)
  python3 provision_pi11.py --lan-only --ips 192.168.0.61
  python3 provision_pi11.py --ble-only      # just report which ACCU_ units advertise
  python3 provision_pi11.py --dry-run       # everything except the actual Upgrade
"""

import argparse
import asyncio
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

import requests

import provision_pi8 as p8

# Progress lines must reach a `tee`d log file as they happen, not in one burst
# at exit: over ssh the whole run is otherwise invisible until it is over.
sys.stdout.reconfigure(line_buffering=True)


class _Stamped:
    """
    Prefix every line with a wall-clock time, and copy everything to a log
    file when one is open — so a run can be followed with `tail -f` from
    elsewhere no matter how it was started.
    """

    def __init__(self, raw):
        self._raw = raw
        self._at_line_start = True
        self._log = None

    def open_log(self, path: str) -> None:
        self.close_log()
        try:
            self._log = open(path, "a", buffering=1)
        except Exception:
            self._log = None

    def close_log(self) -> None:
        if self._log:
            try:
                self._log.close()
            except Exception:
                pass
        self._log = None

    def write(self, text):
        out = []
        for chunk in text.splitlines(keepends=True):
            if self._at_line_start and chunk.strip():
                out.append(time.strftime("%H:%M:%S ") + chunk)
            else:
                out.append(chunk)
            self._at_line_start = chunk.endswith("\n")
        joined = "".join(out)
        self._raw.write(joined)
        if self._log:
            try:
                self._log.write(joined)
            except Exception:
                pass

    def flush(self):
        self._raw.flush()
        if self._log:
            try:
                self._log.flush()
            except Exception:
                pass

    def __getattr__(self, name):
        return getattr(self._raw, name)


sys.stdout = _Stamped(sys.stdout)

VERBOSE = False
_pi8_print = print


def _pi8_filtered_print(*a, **k):
    """pi8 narrates every scan and poll; keep only its errors unless --verbose."""
    text = " ".join(str(x) for x in a)
    if VERBOSE or any(w in text.lower() for w in ("error", "✗", "failed", "traceback")):
        _pi8_print("      " + text.strip(), **k)


def say(msg: str) -> None:
    print(msg)


def banner(lines: List[str]) -> None:
    """A box the operator cannot miss."""
    width = max(len(l) for l in lines) + 6
    print("")
    print("#" * width)
    for l in lines:
        print("#  " + l.ljust(width - 6) + "  #")
    print("#" * width)
    print("")


def ask_tray_size(default: Optional[int]) -> int:
    """Operator prompt, Dutch, Enter keeps the default."""
    while True:
        hint = f" [{default}]" if default else ""
        try:
            raw = input(f"Hoeveel stekkers liggen er op de tray?{hint}: ").strip()
        except EOFError:
            return default or EXPECTED_TRAY_SIZE
        if not raw and default:
            return default
        if raw.isdigit() and int(raw) > 0:
            return int(raw)
        print("  Typ een getal, bijvoorbeeld 6.")


def ask_next_tray() -> bool:
    """Returns False when the operator wants to stop."""
    try:
        raw = input("Volgende tray klaar?  Druk op Enter om te starten, of typ  q  om te stoppen: ").strip().lower()
    except EOFError:
        return False
    return not raw.startswith("q")


def phase(name: str, detail: str = "") -> None:
    global _phase_t0
    _phase_t0 = time.time()
    print("")
    print(f"{name:<11} {detail}".rstrip())


def plug_line(name: str, what: str, extra: str = "") -> None:
    print(f"    {name:<13} {what:<32} {extra}".rstrip())


_ip_names: Dict[str, str] = {}   # ip -> BLE name, for flash progress lines
_last_status: Dict[str, str] = {}
_phase_t0 = time.time()


def _clock() -> str:
    m, s_ = divmod(int(time.time() - _phase_t0), 60)
    return f"{m}:{s_:02d}"


def bar(done: int, total: int, label: str = "", width: int = 20) -> str:
    if total <= 0:
        return ""
    done = min(done, total)
    full = int(round(width * done / total))
    return "[" + "█" * full + "░" * (width - full) + f"] {done}/{total}" + (f" {label}" if label else "")


def tally(letter: str, *parts: str, progress: Optional[Tuple] = None) -> None:
    """One line that states the whole tray's position; repeated after every event."""
    lead = f"    ── {letter}  " + (bar(*progress) + "  " if progress else "")
    print(lead + "  ·  ".join(parts) + f"  ·  {_clock()} in phase")


def _flash_tally() -> None:
    st = list(_last_status.values())
    sent = sum(1 for x in st if x != "setting OtaUrl")
    done = sum(1 for x in st if x.startswith("✓"))
    bad = sum(1 for x in st if x.startswith("✗"))
    busy = max(0, sent - done - bad)
    tally("B", f"flashing {busy}", f"off the LAN {done}/{len(_ip_names)}",
          f"mislukt {bad}", progress=(done, len(_ip_names), "off the LAN"))


def _status_line(ip: str, status: str) -> None:
    """Replaces pi8's full-table progress print: one line per meaningful change."""
    if _last_status.get(ip) == status or status.startswith("⏳"):
        return
    _last_status[ip] = status
    if status in ("setting OtaUrl", "flashing, waiting for it to leave the LAN"):
        return  # intermediate
    if status != "upgrade sent":  # per-plug lines for off-the-LAN and failures only
        plug_line(_ip_names.get(ip, ip), status, ip if ip in _ip_names else "")
    if _ip_names:
        _flash_tally()


_pi8_run_cmd = p8.run_cmd


def _run_cmd_with_assoc_timeout(cmd):
    if len(cmd) >= 4 and cmd[0] == "nmcli" and cmd[1:4] == ["device", "wifi", "connect"]:
        cmd = ["nmcli", "-w", str(ASSOCIATION_TIMEOUT_S)] + list(cmd[1:])
    return _pi8_run_cmd(cmd)


p8.print = _pi8_filtered_print
p8.update_status = _status_line
p8.run_cmd = _run_cmd_with_assoc_timeout


def disable_ap_autoconnect() -> None:
    """
    NetworkManager keeps a profile per SSID it has joined and, by default,
    reconnects to it on its own. With every plug advertising "accusaver" that
    meant wlan0 wandering onto whichever plug it liked between our steps, and
    our explicit join to a specific BSSID then timing out. Once, persistent.
    """
    import subprocess
    out = subprocess.run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        name, _, typ = line.partition(":")
        if "wireless" not in typ:
            continue
        ssid = subprocess.run(["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", name],
                              capture_output=True, text=True).stdout.strip()
        auto = subprocess.run(["nmcli", "-g", "connection.autoconnect", "connection", "show", name],
                              capture_output=True, text=True).stdout.strip()
        if ssid.lower().startswith("accusaver") and auto != "no":
            subprocess.run(["nmcli", "connection", "modify", name, "connection.autoconnect", "no"],
                           capture_output=True)

# -------- Configurable constants --------

# The modern bin, served by nginx on this Pi (see setup_firmware_server.sh).
# Overridable with --firmware-url: this address has changed with every
# script generation (pi6: 192.168.2.59, pi8: 192.168.50.170); pass a port if
# the bin is served by python -m http.server instead of nginx.
MODERN_FIRMWARE_URL = "http://192.168.0.88/accusaver.bin"  # fallback only


def default_firmware_url() -> str:
    """The bin served by this Pi's own nginx, addressed by the Pi's LAN IP."""
    try:
        import subprocess
        out = subprocess.run(["ip", "-4", "addr", "show", "eth0"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return f"http://{line.split()[1].split('/')[0]}/accusaver.bin"
    except Exception:
        pass
    return MODERN_FIRMWARE_URL


def log_dir() -> str:
    """~/pi9-logs of the person who ran sudo, so `tail -f` works from their account."""
    import os
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
    home = f"/home/{user}" if user and user != "root" else os.path.expanduser("~")
    d = os.path.join(home, "pi9-logs")
    try:
        os.makedirs(d, exist_ok=True)
        if os.environ.get("SUDO_UID"):
            os.chown(d, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"])))
    except Exception:
        pass
    return d

# What we expect that bin to be. Checked once up front against version.txt
# sitting next to it, because once a unit is flashed it is off the network and
# its version can no longer be read over HTTP.
EXPECTED_MODERN_VERSION = "1.0.8"

BLE_SCAN_SECONDS = 15

# Phase A stops after this many consecutive scans without an unvisited AP.
PHASE_A_EMPTY_SCANS = 2

# The whole run keeps converging on the tray for at most this long: a fixed
# part plus one minute per plug (Phase A alone costs ~30 s per plug, and a
# plug that misses its first WiFi join typically retries successfully within
# a few minutes). --max-minutes overrides.
MAX_RUN_MINUTES_BASE = 10
MAX_RUN_MINUTES_PER_PLUG = 1.0

# After provisioning, wait this long before the first sweep; later sweeps
# follow anyway until every plug is on the LAN, so this only sets the
# earliest moment a fast joiner can be picked up.
JOIN_WAIT_SECONDS = 5

# While waiting for provisioned plugs to appear on the LAN, look again this often.
JOIN_POLL_SECONDS = 5

# Reserve this much of the time box for flashing + verification; the rest is
# for getting every plug onto the LAN.
FLASH_AND_VERIFY_MINUTES = 3

# How long the Pi's ping sweep waits per host when locating tray plugs by MAC.
PING_TIMEOUT_S = 1

# How long the Pi tries to associate with a plug's access point. A plug that
# already holds credentials is mid-way onto the office WiFi and never lets us
# in; NetworkManager would otherwise wait ~28 s per such plug. It turns up on
# the LAN by itself, so give up early — but not too early: on 2026-09-10 a
# 12 s cap made two perfectly fresh plugs miss their first association
# (normal is 2–4 s, outliers need more) and cost a retry round.
ASSOCIATION_TIMEOUT_S = 10

# On later attempts at the same plug (its AP came back after a missed WiFi
# join) be patient: a plug in AP-fallback mode has needed >10 s to accept an
# association, and giving up again just burns another round.
ASSOCIATION_TIMEOUT_RETRY_S = 25

# LAN sweep parallelism. 254 hosts at a 3 s probe timeout take ~64 s with
# pi8's 16 workers and ~16 s with 64; the probes themselves are unchanged.
SWEEP_WORKERS = 64

# A plug whose flash was sent but that keeps answering as Tasmota gets one
# immediate retry (from safeboot, OtaUrl + Upgrade again does work).
MAX_FLASH_ATTEMPTS = 2

# A production tray. The run refuses to start unless it can account for exactly
# this many plugs, and refuses to report success unless exactly this many are
# ready to ship — the factory must never be left guessing which ones failed.
EXPECTED_TRAY_SIZE = 30

# How long a unit may take to download, flash and reboot before we call it lost.
FLASH_TIMEOUT_SECONDS = 180

# Phase A sends this as OtaUrl. Overriding the module global is the whole
# "point it at the modern bin" change.
p8.FIRMWARE_URL = MODERN_FIRMWARE_URL


# -------- Helpers --------

# The firmware host's WAF blocks the default python-requests User-Agent
# outright ("Request forbidden by administrative rules"), on HEAD and GET
# alike. Identify ourselves honestly instead. Only the pre-flight talks to
# that host; pi8's own calls go to the Pi and are left untouched.
_http = requests.Session()
_http.headers["User-Agent"] = "AccuSaver-provision/pi11"



def ble_name_for_mac(mac: str) -> Optional[str]:
    """
    Modern firmware advertises as ACCU_<last 6 hex of MAC>, uppercased — the
    same derivation the app uses (MacAddressHelper.bleNameForMac).
    """
    hexchars = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(hexchars) != 12:
        return None
    return f"ACCU_{hexchars[-6:].upper()}"


def ap_bssid_for_mac(mac: str) -> str:
    """ESP32 derives its soft-AP BSSID from the station MAC by adding one."""
    n = int(mac.replace(":", "").replace("-", ""), 16) + 1
    h = f"{n:012X}"
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def sta_mac_for_bssid(bssid: str) -> str:
    """Inverse of ap_bssid_for_mac: the station MAC is the AP BSSID minus one."""
    n = int(bssid.replace(":", "").replace("-", ""), 16) - 1
    h = f"{n:012X}"
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def join_ap(ssid: str, bssid: str, timeout_s: int = ASSOCIATION_TIMEOUT_S) -> Tuple[bool, str]:
    """
    Join one specific plug access point. Unlike pi8's connect this does not
    rescan first (the caller just listed the APs) and does not run a separate
    HTTP contact check (the credentials command is the contact). Returns
    (joined, reason).
    """
    import subprocess
    p8.disconnect_wifi()
    subprocess.run(["ip", "addr", "flush", "dev", p8.WIFI_INTERFACE], capture_output=True)
    cmd = ["nmcli", "-w", str(timeout_s), "device", "wifi", "connect", ssid,
           "bssid", bssid, "ifname", p8.WIFI_INTERFACE]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 and "No network with SSID" in (r.stderr + r.stdout):
        # NetworkManager's cache lost the AP; one fresh scan, one more try.
        subprocess.run(["nmcli", "device", "wifi", "list", "ifname", p8.WIFI_INTERFACE,
                        "--rescan", "yes"], capture_output=True)
        r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip().splitlines()[-1:] and (r.stderr or r.stdout).strip().splitlines()[-1] or "nmcli failed"
    deadline = time.time() + 15
    while time.time() < deadline:
        ip = p8.get_current_ip(p8.WIFI_INTERFACE)
        if ip and ip.startswith("192.168.4."):
            return True, ip
        time.sleep(0.5)
    return False, "joined but got no 192.168.4.x address"


def scan_tray_aps(fresh: bool) -> List[Dict[str, str]]:
    """
    AccuSaver APs as pi8 sees them, optionally from NetworkManager's cache.
    pi8's connect_wifi_to_ap does its own fresh rescan right before joining,
    so the pass loop only needs a cheap look to pick a target; a fresh scan
    costs several seconds with a tray's worth of APs in the air.
    """
    result = p8.run_cmd([
        "nmcli", "-f", "SSID,BSSID,CHAN,SIGNAL", "device", "wifi", "list",
        "ifname", p8.WIFI_INTERFACE, "--rescan", "yes" if fresh else "auto",
    ])
    seen: Set[str] = set()
    aps: List[Dict[str, str]] = []
    for ap in p8.parse_wifi_scan(result.stdout):
        if ap["bssid"] not in seen:
            seen.add(ap["bssid"])
            aps.append(ap)
    aps.sort(key=lambda a: int(a["signal"]), reverse=True)
    return aps


def bin_downloads_since(t0: float, url: str) -> Dict[str, int]:
    """
    ip -> bytes served for the modern bin since t0, from the Pi's own nginx
    access log. Evidence that a plug fetched the whole image even when it was
    pulled before the BLE check. Empty when the log is not readable or the bin
    is served by something else.
    """
    path = url.rsplit("/", 1)[-1]
    out: Dict[str, int] = {}
    try:
        with open("/var/log/nginx/access.log") as f:
            lines = f.readlines()[-5000:]
    except Exception:
        return out
    import datetime
    for line in lines:
        if f"GET /{path} " not in line or '" 200 ' not in line:
            continue
        try:
            ip = line.split(" ", 1)[0]
            stamp = line.split("[", 1)[1].split("]", 1)[0]
            when = datetime.datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z").timestamp()
            size = int(line.split('" 200 ', 1)[1].split(" ", 1)[0])
        except Exception:
            continue
        if when >= t0 - 5:
            out[ip] = max(out.get(ip, 0), size)
    return out


def check_firmware_served(url: str) -> bool:
    """
    Confirm the bin is reachable and is the version we think it is. A whole tray
    flashed with the wrong image is expensive to discover afterwards.
    """
    # HEAD first; some hosts refuse HEAD (or refuse it for this User-Agent)
    # while happily serving GET, so fall back to a streamed GET that reads the
    # headers only and never downloads the bin.
    try:
        resp = _http.head(url, timeout=10, allow_redirects=True)
        if resp.status_code != 200:
            resp = _http.get(url, timeout=10, stream=True)
            resp.close()
    except Exception as e:
        say(f"  ✗ cannot reach {url}: {e}")
        return False
    if resp.status_code != 200:
        print(f"✗ {url} -> HTTP {resp.status_code}")
        return False
    size = resp.headers.get("content-length", "?")
    say(f"  firmware   {url}  ({size} bytes)")

    version_url = url.rsplit("/", 1)[0] + "/version.txt"
    try:
        resp = _http.get(version_url, timeout=10)
        if resp.status_code == 200:
            served = resp.text.strip().splitlines()[0].strip()
            if served == EXPECTED_MODERN_VERSION:
                say(f"  version    {served} (version.txt next to the bin)")
            else:
                print(
                    f"✗ version.txt says {served}, expected {EXPECTED_MODERN_VERSION}"
                )
                return False
        else:
            print(
                f"⚠️  No version.txt next to the bin (HTTP {resp.status_code}) — "
                f"cannot confirm this is {EXPECTED_MODERN_VERSION}"
            )
    except Exception as e:
        print(f"⚠️  version.txt check failed: {e}")
    return True


def get_device_mac(ip: str, timeout_s: float = 6.0, attempts: int = 3) -> Optional[str]:
    """
    Read a Tasmota unit's MAC via Status 5, so we know its future BLE name.

    Stock Tasmota on a freshly reset unit answers erratically: three replies in
    0.1 s, then one that takes 4 s or never comes (measured in the factory on
    2026-09-10). One 3 s try missed a unit that was demonstrably up, so give it
    a few generous tries before declaring it absent.
    """
    for attempt in range(1, attempts + 1):
        try:
            resp = requests.get(
                f"http://{ip}/cm", params={"cmnd": "Status 5"}, timeout=timeout_s
            )
            if resp.status_code == 200:
                mac = resp.json().get("StatusNET", {}).get("Mac")
                if mac:
                    return mac
        except Exception:
            pass
        if attempt < attempts:
            time.sleep(2)
    return None


def set_ota_url(ip: str, url: str, max_retries: int = 3) -> bool:
    """Point the unit's OtaUrl at the modern bin and read it back to be sure."""
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(
                f"http://{ip}/cm", params={"cmnd": f"OtaUrl {url}"}, timeout=8
            )
            if resp.status_code == 200 and resp.json().get("OtaUrl") == url:
                return True
        except Exception:
            pass
        if attempt < max_retries:
            time.sleep(3)
    return False


def wait_for_tasmota_gone(
    ip: str, timeout_s: int = FLASH_TIMEOUT_SECONDS, poll_s: float = 3.0
) -> bool:
    """
    A successful migration takes the unit OFF the LAN: the modern firmware boots
    with an empty WiFi config. So the Tasmota endpoint going quiet — and staying
    quiet — is our LAN-side signal. Confirmation comes from the BLE scan.

    Requires three consecutive silent polls (~15 s of silence), because a stock
    Tasmota unit drops or delays individual requests even when healthy — two
    silent polls in a row happen without any flash at all.
    """
    deadline = time.time() + timeout_s
    silent = 0
    while time.time() < deadline:
        try:
            resp = requests.get(
                f"http://{ip}/cm", params={"cmnd": "Status 5"}, timeout=3
            )
            silent = 0 if resp.status_code == 200 else silent + 1
        except Exception:
            silent += 1
        if silent >= 3:
            return True
        time.sleep(poll_s)
    return False


async def _scan_ble(seconds: int) -> Set[str]:
    from bleak import BleakScanner

    found: Set[str] = set()
    devices = await BleakScanner.discover(timeout=seconds)
    for d in devices:
        name = (d.name or "").strip().upper()
        if name.startswith("ACCU_"):
            found.add(name)
    return found


def scan_ble_accusavers(seconds: int = BLE_SCAN_SECONDS) -> Set[str]:
    """
    One scan sees the whole tray. An advertising ACCU_ name means that unit is
    running modern firmware AND is unprovisioned — which is exactly the state we
    ship in, so this single check covers both things we care about.
    """
    try:
        found = asyncio.run(_scan_ble(seconds))
    except Exception as e:
        say(f"    ✗ BLE scan failed: {e}")
        return set()
    say(f"    BLE scan {seconds} s: {len(found)} AccuSaver(s) advertising"
        + (f" — {', '.join(sorted(found))}" if found else ""))
    return found


# -------- Phase B per-device worker (LAN) --------


def flash_device_to_modern(
    ip: str, stagger_delay: float = 0.0, dry_run: bool = False
) -> Tuple[str, bool, float]:
    start = time.time()

    if stagger_delay > 0:
        p8.update_status(ip, f"⏳ Waiting {stagger_delay:.0f}s...")
        time.sleep(stagger_delay)

    if dry_run:
        p8.update_status(ip, "dry run, no Upgrade sent")
        return ip, True, time.time() - start

    # Phase A sets OtaUrl on the AP side, but a unit that was already on the
    # LAN (--lan-only, or a plug that kept its WiFi creds from an earlier run)
    # still carries whatever OtaUrl it had — typically the Tasmota bin from a
    # pi8 run. Upgrade 1 flashes whatever OtaUrl says, so set it here every
    # time; it is one cheap idempotent command.
    p8.update_status(ip, "setting OtaUrl")
    if not set_ota_url(ip, p8.FIRMWARE_URL):
        p8.update_status(ip, "✗ could not set OtaUrl")
        return ip, False, time.time() - start

    p8.update_status(ip, "upgrade sent")
    if not p8.send_upgrade(ip):
        p8.update_status(ip, "✗ upgrade command failed")
        return ip, False, time.time() - start

    p8.update_status(ip, "flashing, waiting for it to leave the LAN")
    if not wait_for_tasmota_gone(ip):
        p8.update_status(ip, "✗ flash did not take, still Tasmota")
        return ip, False, time.time() - start

    elapsed = time.time() - start
    p8.update_status(ip, f"✓ off the LAN after {elapsed:.0f} s")
    return ip, True, elapsed


# -------- Phases --------


def flash_batch(devices: Dict[str, str], dry_run: bool) -> Dict[str, bool]:
    """Flash every ip in devices in parallel; returns ip -> ok."""
    results: Dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=len(devices)) as executor:
        futures = {
            executor.submit(
                flash_device_to_modern, ip, i * p8.STAGGER_DELAY, dry_run
            ): ip
            for i, ip in enumerate(sorted(devices))
        }
        for future in as_completed(futures):
            ip, ok, _ = future.result()
            results[ip] = ok
    return results


def run_phase_a_pass(
    tray_bssids: Set[str], skip_bssids: Set[str],
    tray: Optional[Dict[str, str]] = None, on_lan_count: int = 0,
    provisioned_before: int = 0, swept: bool = True,
    attempts: Optional[Dict[str, int]] = None,
) -> List[str]:
    """
    One pass: push WiFi + OtaUrl into every currently visible AP that belongs
    to the tray and is not in skip_bssids. Returns the BSSIDs it provisioned.

    Why a pass rather than a one-shot phase (learned on the 2026-09-10 trays):

    * A plug keeps its AP up for a while after joining WiFi, so pi8's
      "strongest first, no memory" provisioned one plug ten times. Every BSSID
      is visited at most once per pass.
    * About a quarter of freshly provisioned plugs miss their first WiFi join
      and fall back to AP mode, then succeed minutes later. The convergence
      loop in main() calls this again on later passes for exactly those.
    * Only tray members are touched: an AccuSaver AP that was not in the
      pre-flight list belongs to someone else.
    """
    config = p8.load_config()
    router_ssid = config["ssid"]
    router_password = config["password"]

    p8.AP_EXCLUSION_ENABLED = True
    p8.STRICT_SSID_MATCH = False  # one plug advertised plain "accusaver"

    provisioned: List[str] = []
    visited: Set[str] = set(skip_bssids)
    empty_scans = 0

    while True:
        visible = scan_tray_aps(fresh=False)
        candidates = [
            ap for ap in visible
            if ap["bssid"].upper() in tray_bssids and ap["bssid"].upper() not in visited
        ]
        if not candidates:
            empty_scans += 1
            if empty_scans >= PHASE_A_EMPTY_SCANS:
                break
            time.sleep(2)
            continue
        empty_scans = 0

        target = max(candidates, key=lambda a: int(a["signal"]))
        name = ble_name_for_mac(sta_mac_for_bssid(target["bssid"])) or target["bssid"]
        t_plug = time.time()

        key = target["bssid"].upper()
        if attempts is not None:
            attempts[key] = attempts.get(key, 0) + 1
        patient = attempts is not None and attempts[key] > 1
        t_join = time.time()
        joined, why = join_ap(target["ssid"], target["bssid"],
                              ASSOCIATION_TIMEOUT_RETRY_S if patient else ASSOCIATION_TIMEOUT_S)
        t_join = time.time() - t_join
        connected_bssid = target["bssid"] if joined else None
        if connected_bssid is None:
            # Count it as visited for this pass so one flaky AP cannot stall
            # the pass; a later pass gets another go at it.
            visited.add(target["bssid"].upper())
            plug_line(name, "✗ could not join its access point", f"after {t_join:.0f} s: {why}; retry later")
            if tray:
                tally("A", f"provisioned {provisioned_before + len(provisioned)}",
                      f"on the LAN {on_lan_count}/{len(tray)}" + ("" if swept else " (not swept yet)"),
                      f"{len(candidates) - 1} AP(s) still visible",
                      progress=((on_lan_count, len(tray), "on the LAN") if swept else (provisioned_before + len(provisioned), len(tray), "provisioned")))
            continue
        visited.add(connected_bssid.upper())

        t_cmd = time.time()
        if not p8.send_phase1_commands(router_ssid, router_password):
            plug_line(name, "✗ credentials not accepted", "retry later")
            p8.disconnect_wifi()
            continue
        t_cmd = time.time() - t_cmd

        p8.disconnect_wifi()
        provisioned.append(connected_bssid.upper())
        plug_line(name, "provisioned",
                  f"{time.time() - t_plug:.0f} s  (join {t_join:.0f} · cmd {t_cmd:.0f})")
        if tray:
            tally("A", f"provisioned {provisioned_before + len(provisioned)}",
                  f"on the LAN {on_lan_count}/{len(tray)}" + ("" if swept else " (not swept yet)"),
                      f"{len(candidates) - 1} AP(s) still visible",
                  progress=((on_lan_count, len(tray), "on the LAN") if swept else (provisioned_before + len(provisioned), len(tray), "provisioned")))

    return provisioned


def arp_discover(prefix: str, wanted_macs: Set[str]) -> Dict[str, str]:
    """
    ip -> mac for the wanted station MACs, found by pinging the /24 and
    reading the Pi's neighbour table. ~5 s for 254 hosts, and it does not
    depend on the plug's erratic HTTP server. Identity comes from ARP, which
    is authoritative for a MAC.
    """
    import subprocess

    def ping(h: int) -> None:
        subprocess.run(["ping", "-c", "1", "-W", str(PING_TIMEOUT_S), f"{prefix}{h}"],
                       capture_output=True)

    with ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(ping, range(p8.SCAN_START_HOST, p8.SCAN_END_HOST + 1)))
    out = subprocess.run(["ip", "neigh", "show", "dev", p8.LAN_INTERFACE],
                         capture_output=True, text=True).stdout
    found: Dict[str, str] = {}
    for line in out.splitlines():
        if "lladdr" not in line or "FAILED" in line or "INCOMPLETE" in line:
            continue
        parts = line.split()
        ip, mac = parts[0], parts[parts.index("lladdr") + 1].upper()
        if mac in wanted_macs:
            found[ip] = mac
    return found


def discover_tray_members(prefix: str, missing_bssids: Set[str]) -> Dict[str, str]:
    """ARP first; the slow HTTP sweep only if ARP found nothing at all."""
    wanted = {sta_mac_for_bssid(b) for b in missing_bssids}
    found = arp_discover(prefix, wanted)
    if found:
        # Confirm each is a live Tasmota answering HTTP (retries inside).
        confirmed: Dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=len(found)) as ex:
            for ip, mac in zip(found, ex.map(get_device_mac, found)):
                if mac and mac.upper() == found[ip]:
                    confirmed[ip] = mac
                elif VERBOSE:
                    say(f"    {ip} is in ARP as {found[ip]} but does not answer Status 5 yet")
        return confirmed
    return discover_devices(None, only_bssids=list(missing_bssids))


def discover_devices(
    explicit_ips: Optional[List[str]], only_bssids: Optional[List[str]] = None
) -> Dict[str, str]:
    """
    Returns ip -> mac for every Tasmota AccuSaver we can see on the LAN.

    With only_bssids (the APs Phase A provisioned in this run) anything else
    on the LAN is listed and skipped: a stray Tasmota somewhere in the office
    must not be flashed just because it answered a scan.
    """
    wanted = {b.upper() for b in only_bssids} if only_bssids else None
    if explicit_ips:
        ips = explicit_ips
    else:
        prefix = p8.detect_lan_prefix(p8.LAN_INTERFACE)
        # 3 s per probe instead of pi8's 1 s: see get_device_mac for why.
        found = p8.find_all_devices_by_scan(
            prefix, p8.SCAN_START_HOST, p8.SCAN_END_HOST,
            timeout_seconds=3.0, max_workers=SWEEP_WORKERS,
        )
        ips = sorted(found.keys())

    result: Dict[str, str] = {}
    for ip in ips:
        mac = get_device_mac(ip)
        if mac and wanted is not None and ap_bssid_for_mac(mac) not in wanted:
            if VERBOSE:
                say(f"    {ip}  {mac}  not on this tray, left alone")
        elif mac:
            result[ip] = mac
            if wanted is None:
                say(f"    {ip}  {mac}  -> {ble_name_for_mac(mac)}")
        else:
            if VERBOSE or wanted is None:
                say(f"    {ip}  answered the sweep but gave no MAC")
    return result


# -------- Main --------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lan-only", action="store_true",
                        help="skip Phase A; flash every Tasmota on the LAN (or --ips)")
    parser.add_argument("--ble-only", action="store_true", help="only run the BLE scan")
    parser.add_argument("--dry-run", action="store_true", help="never send Upgrade")
    parser.add_argument("--ips", nargs="*", help="(--lan-only) target these IPs")
    parser.add_argument(
        "--expected", type=int, default=None,
        help="tray size; pre-flight refuses to start unless exactly this many "
             "Tasmota APs are visible, and the run only succeeds with exactly "
             "this many verified over BLE. Asked interactively when omitted "
             f"(default {EXPECTED_TRAY_SIZE} when not interactive)",
    )
    parser.add_argument(
        "--firmware-url", default=None,
        help="where the modern bin is served (default: this Pi's own nginx)",
    )
    parser.add_argument("--ble-seconds", type=int, default=BLE_SCAN_SECONDS)
    parser.add_argument("--verbose", action="store_true",
                        help="also show pi8's scan/poll narration and per-host sweep lines")
    parser.add_argument("--survey", action="store_true",
                        help="also sweep the LAN and scan BLE at pre-flight and print "
                             "what else is around (informational, +40 s)")
    parser.add_argument("--max-minutes", type=int, default=None,
                        help="give up converging on the tray after this long "
                             "(default: 10 + 1 per plug)")
    parser.add_argument("--once", action="store_true",
                        help="run one tray and exit even from a terminal")
    args = parser.parse_args()

    global VERBOSE
    VERBOSE = args.verbose
    p8.STRICT_SSID_MATCH = False
    if args.firmware_url is None:
        args.firmware_url = default_firmware_url()
    disable_ap_autoconnect()
    p8.FIRMWARE_URL = args.firmware_url  # Phase A sends this as OtaUrl
    p8.STAGGER_DELAY = 0.5  # 30 upgrades in 15 s instead of 30; nginx copes fine

    if args.ble_only:
        scan_ble_accusavers(args.ble_seconds)
        return 0

    interactive = sys.stdin.isatty() and not args.once and not args.lan_only
    tray_size = args.expected
    while True:
        if tray_size is None:
            tray_size = ask_tray_size(None) if interactive else EXPECTED_TRAY_SIZE
        elif interactive and args.expected is None:
            tray_size = ask_tray_size(tray_size)
        args.expected = tray_size
        args.max_minutes = int(MAX_RUN_MINUTES_BASE + MAX_RUN_MINUTES_PER_PLUG * tray_size) \
            if "--max-minutes" not in sys.argv else args.max_minutes

        log_path = f"{log_dir()}/tray-{time.strftime('%Y-%m-%d-%H%M%S')}.log"
        sys.stdout.open_log(log_path)
        say("AccuSaver tray migration: Tasmota -> modern firmware")
        say(f"  tray       {args.expected} plug(s) expected")
        say(f"  time box   {args.max_minutes} min")
        say(f"  log        {log_path}")
        if not check_firmware_served(args.firmware_url):
            say("  ✗ firmware not served correctly, not flashing anything")
            rc = 1
        elif args.lan_only:
            rc = run_lan_only(args)
        else:
            rc = run_tray(args)
        sys.stdout.close_log()

        if not interactive:
            return rc
        if not ask_next_tray():
            return rc
        args.expected = None  # ask again, defaulting to the last size

def run_lan_only(args) -> int:
    """Recovery path: flash whatever Tasmota is on the LAN (or the given IPs)."""
    print("\n=== DISCOVERY: finding units on the LAN ===")
    devices = discover_devices(args.ips)
    if not devices:
        print("✗ No devices found on the LAN.")
        return 1
    print(f"\n✓ {len(devices)} device(s) to flash\n")
    print("=== PHASE B: flashing ===")
    results = flash_batch(devices, args.dry_run)
    if args.dry_run:
        print("\n(dry run — skipping BLE verification)")
        return 0
    print("\n=== PHASE C: BLE verification ===")
    time.sleep(15)
    advertising = scan_ble_accusavers(args.ble_seconds)
    verified = 0
    print("\n=== RESULT ===")
    for ip in sorted(devices):
        name = ble_name_for_mac(devices[ip])
        if results.get(ip) and name in advertising:
            print(f"  ✓ {ip}  {name}  modern firmware, unprovisioned")
            verified += 1
        elif results.get(ip):
            print(f"  ✗ {ip}  {name}  left the LAN but is not advertising")
        else:
            print(f"  ✗ {ip}  {name}  flash failed")
    print(f"\n{verified}/{args.expected} unit(s) ready to ship.")
    return 0 if verified == args.expected else 1


def run_tray(args) -> int:
    """
    The production path, as one straight line:

      pre-flight  exactly --expected Tasmota APs visible, or we do not start
      phase A     provision every tray AP; keep provisioning any tray AP that
                  comes back (a plug that missed its first WiFi join) until
                  every tray member is on the LAN or the join time box expires
      phase B     flash everything on the LAN, once (a flash that does not
                  take gets one immediate retry)
      phase C     verify over BLE, once (with one extra scan for late boots)
      report      per tray member; success only at N/N

    Tray membership is by AP BSSID from pre-flight. A plug that already had
    credentials and joined the LAN by itself is a member like any other; a
    Tasmota that was never a tray AP is never touched.
    """
    phase("PRE-FLIGHT")
    # One scan can miss a few of many APs on the same channel; take the
    # union of up to three fresh scans (~10 s) before judging the tray.
    seen: Dict[str, Dict[str, str]] = {}
    for i in range(3):
        for ap in scan_tray_aps(fresh=True):
            seen.setdefault(ap["bssid"].upper(), ap)
        if len(seen) >= args.expected and i >= 1:
            break
        time.sleep(3)
    aps = list(seen.values())
    say(f"    {len(aps)} Tasmota access point(s) visible, {args.expected} expected")
    if args.survey:
        prefix = p8.detect_lan_prefix(p8.LAN_INTERFACE)
        on_lan = p8.find_all_devices_by_scan(
            prefix, p8.SCAN_START_HOST, p8.SCAN_END_HOST,
            timeout_seconds=3.0, max_workers=SWEEP_WORKERS,
        )
        modern_before = scan_ble_accusavers(args.ble_seconds)
        say(f"    Tasmota already on the LAN, not tray members: {sorted(on_lan) or '-'}")
        say(f"    modern units in BLE range, not tray members: {sorted(modern_before) or '-'}")
    if len(aps) != args.expected:
        banner([
            f"NIET GESTART:  {len(aps)} stekkers gezien, {args.expected} verwacht.",
            "Controleer of alle stekkers stroom hebben en probeer opnieuw.",
        ])
        say(f"    ✗ TRAY MISMATCH: {len(aps)} visible, {args.expected} expected. Nothing touched.")
        if args.expected == EXPECTED_TRAY_SIZE:
            say(f"      {EXPECTED_TRAY_SIZE} is the default tray size. For a different tray pass --expected N,")
            say(f"      e.g.  --expected {len(aps)}  if all {len(aps)} plugs of this tray are powered.")
        say("      Otherwise: missing plugs have no power, are out of WiFi range of the Pi, or are not factory-fresh.")
        say("      For a half-done tray use --lan-only --expected N.")
        return 1

    tray: Dict[str, str] = {}  # bssid -> expected BLE name
    for ap in aps:
        b = ap["bssid"].upper()
        tray[b] = ble_name_for_mac(sta_mac_for_bssid(b)) or "?"
    say(f"    ✓ tray OK: " + "  ".join(sorted(tray.values())))

    t0 = time.time()
    join_deadline = t0 + max(60, (args.max_minutes - FLASH_AND_VERIFY_MINUTES) * 60)
    last_seen: Dict[str, str] = {}
    prefix = p8.detect_lan_prefix(p8.LAN_INTERFACE)

    # ---- Phase A: get every tray member onto the LAN ----
    phase("PHASE A", "provisioning over the access points until every plug is on the LAN")
    on_lan: Dict[str, str] = {}  # ip -> mac, tray members only
    provisioned_total = 0
    swept_once = False
    join_attempts: Dict[str, int] = {}
    while True:
        have = {ap_bssid_for_mac(m) for m in on_lan.values()}
        missing = set(tray) - have
        if not missing:
            break
        if time.time() > join_deadline:
            say(f"    ⏱ join time box reached, {len(missing)} plug(s) never reached the LAN")
            break
        provisioned = run_phase_a_pass(missing, skip_bssids=set(), tray=tray,
                                       on_lan_count=len(have), provisioned_before=provisioned_total,
                                       swept=swept_once, attempts=join_attempts)
        provisioned_total += len(provisioned)
        for b in provisioned:
            last_seen[b] = "provisioned, never joined the WiFi"
        if provisioned:
            say(f"    waiting {JOIN_WAIT_SECONDS} s for {len(provisioned)} plug(s) to join the WiFi")
            time.sleep(JOIN_WAIT_SECONDS)
        found = discover_tray_members(prefix, missing)
        swept_once = True
        for ip, mac in found.items():
            on_lan[ip] = mac
            last_seen[ap_bssid_for_mac(mac)] = f"on the LAN at {ip}"
        have = {ap_bssid_for_mac(m) for m in on_lan.values()}
        still = set(tray) - have
        tally("A", f"on the LAN {len(have)}/{len(tray)}",
              ("waiting for " + ", ".join(sorted(tray[b] for b in still))) if still else "all present",
              progress=(len(have), len(tray), "on the LAN"))
        if still and not provisioned:
            time.sleep(JOIN_POLL_SECONDS)

    if not on_lan:
        say("    ✗ nothing reached the LAN, not flashing anything")
        return 1

    # ---- Phase B: flash, once ----
    phase("PHASE B", f"flashing {len(on_lan)} plug(s) in parallel")
    _ip_names.clear()
    _ip_names.update({ip: tray[ap_bssid_for_mac(mac)] for ip, mac in on_lan.items()})
    _last_status.clear()
    results = flash_batch(on_lan, args.dry_run)
    if args.dry_run:
        say("    dry run: no Upgrade sent, stopping here")
        return 0
    retry = {ip: mac for ip, mac in on_lan.items() if not results.get(ip)}
    if retry and MAX_FLASH_ATTEMPTS > 1:
        say(f"    {len(retry)} flash(es) did not take, one immediate retry")
        results.update(flash_batch(retry, False))
    flashed = {ap_bssid_for_mac(mac) for ip, mac in on_lan.items() if results.get(ip)}
    for ip, mac in on_lan.items():
        b = ap_bssid_for_mac(mac)
        last_seen[b] = (f"flashed from {ip}, left the LAN" if results.get(ip)
                        else f"flash from {ip} did not take; still answering as Tasmota")

    # ---- Phase C: verify, once (plus one scan for late boots) ----
    phase("PHASE C", "BLE verification")
    advertising = scan_ble_accusavers(max(args.ble_seconds, 20))
    verified = {b for b in flashed if tray[b] in advertising}
    if flashed - verified:
        say(f"    {len(flashed - verified)} not advertising yet, one more scan in 10 s")
        time.sleep(10)
        advertising |= scan_ble_accusavers(max(args.ble_seconds, 25))
        verified = {b for b in flashed if tray[b] in advertising}
    for b in verified:
        last_seen[b] = "verified over BLE"
    if flashed - verified:
        served = bin_downloads_since(t0, args.firmware_url)
        for ip, mac in on_lan.items():
            b = ap_bssid_for_mac(mac)
            if b in flashed - verified and served.get(ip):
                last_seen[b] = (f"full download logged by the Pi ({served[ip]} B) and left the LAN, "
                                "but not seen over BLE — power it near the Pi and scan")
    tally("C", f"verified {len(verified)}/{len(tray)}",
          ("missing " + ", ".join(sorted(tray[b] for b in set(tray) - verified))) if len(verified) < len(tray) else "all advertising",
          progress=(len(verified), len(tray), "verified"))

    # ---- Report ----
    still_ap = {ap["bssid"].upper() for ap in scan_tray_aps(fresh=True)} if len(verified) < len(tray) else set()
    minutes = (time.time() - t0) / 60
    phase("RESULT", f"{len(verified)}/{len(tray)} ready to ship in {minutes:.1f} min")
    for b in sorted(tray, key=lambda x: tray[x]):
        mark = "✓" if b in verified else "✗"
        state = last_seen.get(b, "never seen")
        if b not in verified and b in still_ap:
            state = "still a Tasmota access point; " + state
        say(f"    {mark} {tray[b]:<13} {state}")
    if len(verified) != len(tray):
        missing = sorted(tray[b] for b in set(tray) - verified)
        banner([
            f"NIET KLAAR:  {len(verified)} van {len(tray)} stekkers gereed.",
            "DEZE TRAY MAG NIET DOOR.",
            "",
            "Niet gelukt: " + ", ".join(missing),
            "",
            "Haal deze stekkers uit de tray, steek ze opnieuw in,",
            f"en start opnieuw met  {len(missing)}  als aantal.",
        ])
        return 1
    banner([
        f"KLAAR:  {len(tray)} van {len(tray)} stekkers gereed in {minutes:.1f} minuten.",
        "DEZE TRAY KAN DOOR.",
    ])
    return 0

if __name__ == "__main__":
    sys.exit(main())
