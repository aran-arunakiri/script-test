"""
provision_pi9.py — batch-flash a tray of factory AccuSavers from Tasmota to the
modern (ESP-IDF) firmware, leaving every unit UNPROVISIONED and ready to ship.

Relationship to provision_pi8.py
--------------------------------
pi8 is the last confirmed-working Tasmota -> Tasmota flow and is NOT copied
here — it is imported, so every primitive (AP scanning, WiFi handling, Phase A, the LAN
sweep, Upgrade with retries) is literally the same code. pi9 only:

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
  python3 provision_pi9.py                 # full run: Phase A + B + C
  python3 provision_pi9.py --lan-only      # skip Phase A (units already on WiFi)
  python3 provision_pi9.py --lan-only --ips 192.168.0.61
  python3 provision_pi9.py --ble-only      # just report which ACCU_ units advertise
  python3 provision_pi9.py --dry-run       # everything except the actual Upgrade
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
    """Prefix every line with a wall-clock time so a log can be timed later."""

    def __init__(self, raw):
        self._raw = raw
        self._at_line_start = True

    def write(self, text):
        out = []
        for chunk in text.splitlines(keepends=True):
            if self._at_line_start and chunk.strip():
                out.append(time.strftime("%H:%M:%S ") + chunk)
            else:
                out.append(chunk)
            self._at_line_start = chunk.endswith("\n")
        self._raw.write("".join(out))

    def flush(self):
        self._raw.flush()

    def __getattr__(self, name):
        return getattr(self._raw, name)


sys.stdout = _Stamped(sys.stdout)

# -------- Configurable constants --------

# The modern bin, served by nginx on this Pi (see setup_firmware_server.sh).
# Overridable with --firmware-url: this address has changed with every
# script generation (pi6: 192.168.2.59, pi8: 192.168.50.170); pass a port if
# the bin is served by python -m http.server instead of nginx.
MODERN_FIRMWARE_URL = "http://192.168.0.88/accusaver.bin"

# What we expect that bin to be. Checked once up front against version.txt
# sitting next to it, because once a unit is flashed it is off the network and
# its version can no longer be read over HTTP.
EXPECTED_MODERN_VERSION = "1.0.8"

BLE_SCAN_SECONDS = 15

# Phase A stops after this many consecutive scans without an unvisited AP.
PHASE_A_EMPTY_SCANS = 3

# The whole run keeps converging on the tray for at most this long: a fixed
# part plus one minute per plug (Phase A alone costs ~30 s per plug, and a
# plug that misses its first WiFi join typically retries successfully within
# a few minutes). --max-minutes overrides.
MAX_RUN_MINUTES_BASE = 10
MAX_RUN_MINUTES_PER_PLUG = 1.0

# Between convergence passes that found nothing new to do.
PASS_IDLE_SECONDS = 20

# LAN sweep parallelism. 254 hosts at a 3 s probe timeout take ~64 s with
# pi8's 16 workers and ~16 s with 64; the probes themselves are unchanged.
SWEEP_WORKERS = 64

# A plug whose flash was sent but that keeps answering as Tasmota is retried
# this many times (from safeboot, OtaUrl + Upgrade again does work).
MAX_FLASH_ATTEMPTS = 3

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
_http.headers["User-Agent"] = "AccuSaver-provision/pi9"



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
        print(f"✗ Cannot reach {url}: {e}")
        return False
    if resp.status_code != 200:
        print(f"✗ {url} -> HTTP {resp.status_code}")
        return False
    size = resp.headers.get("content-length", "?")
    print(f"✓ Firmware reachable ({size} bytes)")

    version_url = url.rsplit("/", 1)[0] + "/version.txt"
    try:
        resp = _http.get(version_url, timeout=10)
        if resp.status_code == 200:
            served = resp.text.strip().splitlines()[0].strip()
            if served == EXPECTED_MODERN_VERSION:
                print(f"✓ version.txt says {served}, as expected")
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

    Requires four consecutive silent polls (~24 s of silence), because a stock
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
        if silent >= 4:
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
    print(f"[BLE] Scanning {seconds}s for ACCU_ advertisements...")
    try:
        found = asyncio.run(_scan_ble(seconds))
    except Exception as e:
        print(f"✗ BLE scan failed: {e}")
        return set()
    print(f"[BLE] Saw {len(found)} AccuSaver(s): {sorted(found) or '-'}")
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
        p8.update_status(ip, "✓ Dry run (no Upgrade sent)")
        return ip, True, time.time() - start

    # Phase A sets OtaUrl on the AP side, but a unit that was already on the
    # LAN (--lan-only, or a plug that kept its WiFi creds from an earlier run)
    # still carries whatever OtaUrl it had — typically the Tasmota bin from a
    # pi8 run. Upgrade 1 flashes whatever OtaUrl says, so set it here every
    # time; it is one cheap idempotent command.
    p8.update_status(ip, "🔗 Setting OtaUrl...")
    if not set_ota_url(ip, p8.FIRMWARE_URL):
        p8.update_status(ip, "✗ Could not set OtaUrl")
        return ip, False, time.time() - start

    p8.update_status(ip, "📦 Sending upgrade...")
    if not p8.send_upgrade(ip):
        p8.update_status(ip, "✗ Upgrade failed")
        return ip, False, time.time() - start

    p8.update_status(ip, "🔄 Flashing (waiting for it to leave the LAN)...")
    if not wait_for_tasmota_gone(ip):
        p8.update_status(ip, "✗ Still answering Tasmota — flash did not take")
        return ip, False, time.time() - start

    elapsed = time.time() - start
    p8.update_status(ip, f"✓ Off LAN ({elapsed:.0f}s) — pending BLE check")
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


def run_phase_a_pass(tray_bssids: Set[str], skip_bssids: Set[str]) -> List[str]:
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
            time.sleep(3)
            continue
        empty_scans = 0

        target = max(candidates, key=lambda a: int(a["signal"]))
        print("\n==============================================")
        print(f" PHASE A: {target['bssid']}  ({len(candidates)} tray AP(s) visible)")
        print("==============================================\n")

        # pi8 connects with a fixed SSID and excludes by BSSID; steer it onto
        # exactly this AP by naming its SSID and excluding every other one.
        p8.TASMOTA_AP_SSID = target["ssid"]
        exclude = [ap["bssid"] for ap in visible if ap["bssid"] != target["bssid"]]
        connected_bssid = p8.connect_wifi_to_ap(exclude_bssids=exclude)
        if connected_bssid is None:
            # Count it as visited for this pass so one flaky AP cannot stall
            # the pass; a later pass gets another go at it.
            visited.add(target["bssid"].upper())
            print("  ✗ could not join this AP now; will retry on a later pass")
            continue
        visited.add(connected_bssid.upper())

        if not p8.ensure_ap_http():
            print("✗ AP unreachable, will retry on a later pass\n")
            p8.disconnect_wifi()
            continue

        if not p8.send_phase1_commands(router_ssid, router_password):
            print("✗ Phase 1 failed, will retry on a later pass\n")
            p8.disconnect_wifi()
            continue

        time.sleep(2)
        p8.disconnect_wifi()
        provisioned.append(connected_bssid.upper())
        print(f"✓ PHASE A: provisioned {connected_bssid}\n")

    return provisioned


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
            print(f"  {ip}  mac={mac}  not on this tray — skipping")
        elif mac:
            result[ip] = mac
            print(f"  {ip}  mac={mac}  -> expects {ble_name_for_mac(mac)}")
        else:
            print(f"  {ip}  ✗ no MAC via Status 5 (not a Tasmota AccuSaver?)")
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
        "--expected", type=int, default=EXPECTED_TRAY_SIZE,
        help="tray size; pre-flight refuses to start unless exactly this many "
             "Tasmota APs are visible, and the run only succeeds with exactly "
             "this many verified over BLE",
    )
    parser.add_argument(
        "--firmware-url", default=MODERN_FIRMWARE_URL,
        help="where the modern bin is served (version.txt is looked up next to it)",
    )
    parser.add_argument("--ble-seconds", type=int, default=BLE_SCAN_SECONDS)
    parser.add_argument("--max-minutes", type=int, default=None,
                        help="give up converging on the tray after this long "
                             "(default: 10 + 1 per plug)")
    args = parser.parse_args()
    if args.max_minutes is None:
        args.max_minutes = int(MAX_RUN_MINUTES_BASE + MAX_RUN_MINUTES_PER_PLUG * args.expected)

    if args.ble_only:
        scan_ble_accusavers(args.ble_seconds)
        return 0

    p8.FIRMWARE_URL = args.firmware_url  # Phase A sends this as OtaUrl
    p8.STRICT_SSID_MATCH = False

    print("=== TASMOTA -> MODERN BATCH MIGRATION ===\n")
    print(f"Firmware : {args.firmware_url}")
    print(f"Expected : {EXPECTED_MODERN_VERSION}")
    print(f"Tray size: {args.expected}")
    print(f"Time box : {args.max_minutes} min\n")

    if not check_firmware_served(args.firmware_url):
        print("\n✗ Pre-flight failed — not flashing anything.")
        return 1

    if args.lan_only:
        return run_lan_only(args)
    return run_tray(args)


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
    The production path. Pre-flight fixes the tray as the set of Tasmota APs
    visible right now (exactly --expected of them, or we do not start). Then
    converge: provision visible tray APs, pick up tray members on the LAN
    however they got there, flash, verify over BLE, repeat until every member
    is verified or the time box runs out. The report is per tray member.
    """
    print("=== PRE-FLIGHT: a clean tray shows exactly one Tasmota AP per plug ===")
    aps = p8.scan_accusaver_aps()
    prefix = p8.detect_lan_prefix(p8.LAN_INTERFACE)
    on_lan = p8.find_all_devices_by_scan(
        prefix, p8.SCAN_START_HOST, p8.SCAN_END_HOST,
        timeout_seconds=3.0, max_workers=SWEEP_WORKERS,
    )
    modern_before = scan_ble_accusavers(args.ble_seconds)
    if on_lan:
        print(f"\n⚠️  Tasmota already on the LAN (not part of this tray): {sorted(on_lan)}")
    if modern_before:
        print(f"⚠️  Modern units in BLE range (not part of this tray): {sorted(modern_before)}")
    if len(aps) != args.expected:
        print(f"\n✗ Tray mismatch: {len(aps)} Tasmota AP(s) visible, expected "
              f"{args.expected}. Not touching anything.")
        print("   Missing plugs: no power, out of WiFi range of the Pi, or not "
              "factory-fresh (see warnings above). For a half-done tray use "
              "--lan-only --expected N.")
        return 1

    # The tray, by AP BSSID. Everything below is keyed on this set.
    tray: Dict[str, str] = {}  # bssid -> expected BLE name
    for ap in aps:
        b = ap["bssid"].upper()
        tray[b] = ble_name_for_mac(sta_mac_for_bssid(b)) or "?"
    print(f"\n✓ Pre-flight: {len(tray)} AccuSaver AP(s), tray is clean")
    print("  " + ", ".join(sorted(tray.values())) + "\n")

    verified: Set[str] = set()          # bssid
    flashed_pending: Set[str] = set()   # flashed + off LAN, awaiting BLE
    attempts: Dict[str, int] = {}       # bssid -> flash attempts
    last_seen: Dict[str, str] = {}      # bssid -> last observed state
    deadline = time.time() + args.max_minutes * 60
    pass_no = 0

    while True:
        remaining = {b for b in tray if b not in verified}
        if not remaining:
            break
        if pass_no >= 1 and time.time() > deadline:
            print(f"\n⏱  Time box of {args.max_minutes} min reached.")
            break
        pass_no += 1
        print(f"\n########## PASS {pass_no}: {len(verified)}/{len(tray)} verified, "
              f"{len(remaining)} to go, {int((deadline - time.time()) / 60)} min left ##########")

        # A) provision tray APs that are visible now and not yet flashed
        to_provision = remaining - flashed_pending
        provisioned = run_phase_a_pass(to_provision, skip_bssids=set())
        for b in provisioned:
            last_seen[b] = "provisioned, waiting for it to join WiFi"
        if provisioned:
            print(f"Pass {pass_no}: provisioned {len(provisioned)}; waiting 20s for WiFi join...")
            time.sleep(20)

        # B) pick up tray members on the LAN, however they got there
        print(f"\n=== DISCOVERY (pass {pass_no}) ===")
        lan_targets = {b for b in remaining - flashed_pending if attempts.get(b, 0) < MAX_FLASH_ATTEMPTS}
        devices = discover_devices(None, only_bssids=list(lan_targets)) if lan_targets else {}
        for ip, mac in devices.items():
            last_seen[ap_bssid_for_mac(mac)] = f"on the LAN at {ip}"

        # C) flash them
        if devices:
            print(f"\n=== PHASE B (pass {pass_no}): flashing {len(devices)} ===")
            results = flash_batch(devices, args.dry_run)
            for ip, ok in results.items():
                b = ap_bssid_for_mac(devices[ip])
                attempts[b] = attempts.get(b, 0) + 1
                if ok:
                    flashed_pending.add(b)
                    last_seen[b] = f"flashed from {ip}, left the LAN, awaiting BLE"
                else:
                    last_seen[b] = f"flash attempt {attempts[b]} from {ip} did not take"
            if args.dry_run:
                print("\n(dry run — stopping after one pass)")
                return 0

        # D) verify over BLE
        if flashed_pending:
            print(f"\n=== PHASE C (pass {pass_no}): BLE verification ===")
            time.sleep(15 if devices else 0)
            advertising = scan_ble_accusavers(args.ble_seconds)
            for b in list(flashed_pending):
                if tray[b] in advertising:
                    verified.add(b)
                    flashed_pending.discard(b)
                    last_seen[b] = "verified over BLE"

        did_something = bool(provisioned or devices)
        if not did_something and (set(tray) - verified):
            print(f"Pass {pass_no}: nothing new yet; polling again in {PASS_IDLE_SECONDS}s")
            time.sleep(PASS_IDLE_SECONDS)

    # Final state for the report: one last look at what is still out there.
    still_ap = {ap["bssid"].upper() for ap in scan_tray_aps(fresh=True)}
    final_ble = scan_ble_accusavers(max(args.ble_seconds, 25)) if (set(tray) - verified) else set()
    for b in set(tray) - verified:
        if tray[b] in final_ble:
            verified.add(b)
            last_seen[b] = "verified over BLE (final scan)"
        elif b in still_ap:
            last_seen[b] = "still a Tasmota access point: " + last_seen.get(b, "never provisioned")

    print("\n=== RESULT ===")
    for b in sorted(tray, key=lambda x: tray[x]):
        mark = "✓" if b in verified else "✗"
        print(f"  {mark} {tray[b]}  (AP {b})  {last_seen.get(b, 'never seen on the LAN')}")
    print(f"\n{len(verified)}/{len(tray)} unit(s) ready to ship "
          f"after {pass_no} pass(es).")
    if len(verified) != len(tray):
        missing = sorted(tray[b] for b in set(tray) - verified)
        print(f"\n✗ NOT COMPLETE. Not verified: {missing}. Nothing on this tray is "
              f"ready until this says {len(tray)}/{len(tray)}. Power-cycle the "
              "listed plugs and run again with --expected "
              f"{len(missing)} (or --lan-only if they sit on the LAN).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
