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
    ip: str, timeout_s: int = FLASH_TIMEOUT_SECONDS, poll_s: float = 5.0
) -> bool:
    """
    A successful migration takes the unit OFF the LAN: the modern firmware boots
    with an empty WiFi config. So the Tasmota endpoint going quiet — and staying
    quiet — is our LAN-side signal. Confirmation comes from the BLE scan.

    Requires four consecutive silent polls (~35 s of silence), because a stock
    Tasmota unit drops or delays individual requests even when healthy — two
    silent polls in a row happen without any flash at all.
    """
    deadline = time.time() + timeout_s
    silent = 0
    while time.time() < deadline:
        try:
            resp = requests.get(
                f"http://{ip}/cm", params={"cmnd": "Status 5"}, timeout=4
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


def run_phase_a(expected_devices: int) -> int:
    """
    Unchanged from pi6 apart from the bin it points at: a factory unit is still
    Tasmota, still has an AP, and we still need it on WiFi to reach it.
    """
    config = p8.load_config()
    router_ssid = config["ssid"]
    router_password = config["password"]

    provisioned = 0
    provisioned_bssids: List[str] = []

    while provisioned < expected_devices:
        print("\n==============================================")
        print(f" PHASE A: device #{provisioned + 1} of {expected_devices}")
        print("==============================================\n")

        connected_bssid = None
        while connected_bssid is None:
            connected_bssid = p8.connect_wifi_to_ap(exclude_bssids=provisioned_bssids)
            if connected_bssid is None:
                print("✗ Could not connect to AP, retrying in 3 seconds...")
                time.sleep(3)

        if not p8.ensure_ap_http():
            print("✗ AP unreachable, skipping this device...\n")
            continue

        if not p8.send_phase1_commands(router_ssid, router_password):
            print("✗ Phase 1 failed, skipping this device...\n")
            continue

        ip = p8.get_current_ip(p8.WIFI_INTERFACE)
        if ip and ip.startswith("192.168.4."):
            provisioned_bssids.append(connected_bssid)

        time.sleep(2)
        p8.disconnect_wifi()
        provisioned += 1
        print(f"✓ PHASE A: {provisioned}/{expected_devices} AP-provisioned\n")

    return provisioned


def discover_devices(explicit_ips: Optional[List[str]]) -> Dict[str, str]:
    """Returns ip -> mac for every Tasmota AccuSaver we can see on the LAN."""
    if explicit_ips:
        ips = explicit_ips
    else:
        prefix = p8.detect_lan_prefix(p8.LAN_INTERFACE)
        # 3 s per probe instead of pi8's 1 s: see get_device_mac for why.
        found = p8.find_all_devices_by_scan(
            prefix, p8.SCAN_START_HOST, p8.SCAN_END_HOST, timeout_seconds=3.0
        )
        ips = sorted(found.keys())

    result: Dict[str, str] = {}
    for ip in ips:
        mac = get_device_mac(ip)
        if mac:
            result[ip] = mac
            print(f"  {ip}  mac={mac}  -> expects {ble_name_for_mac(mac)}")
        else:
            print(f"  {ip}  ✗ no MAC via Status 5 (not a Tasmota AccuSaver?)")
    return result


# -------- Main --------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lan-only", action="store_true", help="skip Phase A")
    parser.add_argument("--ble-only", action="store_true", help="only run the BLE scan")
    parser.add_argument("--dry-run", action="store_true", help="never send Upgrade")
    parser.add_argument("--ips", nargs="*", help="target these IPs instead of scanning")
    # pi8 ships EXPECTED_DEVICES = 3, which is a test-batch value; a production
    # tray is 18. Keep the real number as the default rather than inheriting it.
    parser.add_argument("--expected", type=int, default=18, help="tray size")
    parser.add_argument(
        "--firmware-url", default=MODERN_FIRMWARE_URL,
        help="where the modern bin is served (version.txt is looked up next to it)",
    )
    parser.add_argument("--ble-seconds", type=int, default=BLE_SCAN_SECONDS)
    args = parser.parse_args()

    if args.ble_only:
        scan_ble_accusavers(args.ble_seconds)
        return 0

    firmware_url = args.firmware_url
    p8.FIRMWARE_URL = firmware_url  # Phase A sends this as OtaUrl

    print("=== TASMOTA -> MODERN BATCH MIGRATION ===\n")
    print(f"Firmware : {firmware_url}")
    print(f"Expected : {EXPECTED_MODERN_VERSION}")
    print(f"Tray size: {args.expected}\n")

    if not check_firmware_served(firmware_url):
        print("\n✗ Pre-flight failed — not flashing anything.")
        return 1

    if not args.lan_only:
        detected = p8.scan_accusaver_aps()
        if len(detected) != args.expected:
            print(f"\n✗ AP count mismatch: saw {len(detected)}, expected {args.expected}")
            return 1
        print(f"\n✓ Pre-flight: {len(detected)} AccuSaver AP(s) detected\n")
        run_phase_a(args.expected)
        print("Waiting 20s for devices to join WiFi...")
        time.sleep(20)

    print("\n=== DISCOVERY: finding units on the LAN ===")
    devices = discover_devices(args.ips)
    if not devices:
        print("✗ No devices found on the LAN.")
        return 1
    print(f"\n✓ {len(devices)} device(s) to flash\n")

    print("=== PHASE B: flashing ===")
    results: Dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=len(devices)) as executor:
        futures = {
            executor.submit(
                flash_device_to_modern, ip, i * p8.STAGGER_DELAY, args.dry_run
            ): ip
            for i, ip in enumerate(sorted(devices))
        }
        for future in as_completed(futures):
            ip, ok, _ = future.result()
            results[ip] = ok

    if args.dry_run:
        print("\n(dry run — skipping BLE verification)")
        return 0

    print("\n=== PHASE C: BLE verification ===")
    print("Giving the units 15s to boot into provisioning mode...")
    time.sleep(15)
    advertising = scan_ble_accusavers(args.ble_seconds)

    print("\n=== RESULT ===")
    ok_count = 0
    for ip in sorted(devices):
        expected_name = ble_name_for_mac(devices[ip])
        if not results.get(ip):
            print(f"  ✗ {ip}  {expected_name}  flash failed")
        elif expected_name in advertising:
            print(f"  ✓ {ip}  {expected_name}  modern firmware, unprovisioned")
            ok_count += 1
        else:
            print(f"  ✗ {ip}  {expected_name}  left the LAN but is not advertising")

    unexpected = advertising - {
        ble_name_for_mac(m) for m in devices.values() if ble_name_for_mac(m)
    }
    if unexpected:
        print(f"\n  note: {len(unexpected)} other AccuSaver(s) in BLE range: "
              f"{sorted(unexpected)}")

    print(f"\n{ok_count}/{len(devices)} unit(s) ready to ship.")
    return 0 if ok_count == len(devices) else 1


if __name__ == "__main__":
    sys.exit(main())
