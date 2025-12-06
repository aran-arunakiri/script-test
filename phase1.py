#!/usr/bin/env python3
"""
Phase 1 provisioner for Tasmota AccuSaver devices.

Flow:
  1. Preflight: single scan of the air, collect all matching AccuSaver APs.
  2. For each BSSID seen in that preflight scan:
       - fast-connect to that BSSID using `iw`
       - verify HTTP connectivity to 192.168.4.1
       - send Backlog0 (OtaUrl + SSID1 + Password1)
  3. Summary of successes / failures.

Assumptions:
  - All devices use the same AP SSID (TASMOTA_AP_SSID) and AP IP (TASMOTA_AP_IP).
  - wlan0 gets a static IP in 192.168.4.0/24 (either by this script or externally).
  - Wi-Fi security is open (no WPA). If not, you'll need to involve wpa_supplicant.
"""

import json
import subprocess
import time
from typing import Optional, List, Dict

import requests

# -------- Config --------

FIRMWARE_URL = "http://192.168.2.59/tasmota32c2-withfs.bin"

TASMOTA_AP_SSID = "accusaver-3FCAD739"
TASMOTA_AP_IP = "192.168.4.1"

WIFI_INTERFACE = "wlan0"

# If True  → only SSID exactly equal to TASMOTA_AP_SSID (case-insensitive)
# If False → accept any SSID starting with "accusaver"
STRICT_SSID_MATCH = True

# WiFi creds for customer router are read from .wifi-config.json:
# {
#   "ssid": "your-router-ssid",
#   "password": "your-router-password"
# }
WIFI_CONFIG_FILE = ".wifi-config.json"

# Static IP we want to use for talking to the AP subnet
STATIC_AP_IP = "192.168.4.2/24"

# Max tries per AP for Phase 1 HTTP backlog
PHASE1_MAX_RETRIES = 3


# -------- Shell helpers --------


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def configure_static_ap_ip() -> None:
    """
    Put WIFI_INTERFACE on STATIC_AP_IP, no DHCP.
    This is done once at the start.
    """
    print(f"[Net] Configuring static IP {STATIC_AP_IP} on {WIFI_INTERFACE}...")
    run_cmd(["ip", "link", "set", WIFI_INTERFACE, "down"])
    run_cmd(["ip", "addr", "flush", "dev", WIFI_INTERFACE])
    run_cmd(["ip", "addr", "add", STATIC_AP_IP, "dev", WIFI_INTERFACE])
    run_cmd(["ip", "link", "set", WIFI_INTERFACE, "up"])


def load_wifi_config() -> Dict[str, str]:
    with open(WIFI_CONFIG_FILE, "r") as f:
        cfg = json.load(f)
    return {
        "ssid": cfg["ssid"],
        "password": cfg["password"],
    }


# -------- Scanning via `iw` --------


def scan_accusaver_aps() -> List[Dict[str, str]]:
    """
    Single preflight scan using `iw dev <iface> scan`.
    Returns list of dicts: {ssid, bssid, signal} for APs that match our filter.
    """
    print(f"[Scan] Preflight scan on {WIFI_INTERFACE}...")
    proc = run_cmd(["iw", "dev", WIFI_INTERFACE, "scan"])
    if proc.returncode != 0:
        print(f"[Scan] iw error: {proc.stderr.strip()}")
        return []

    lines = proc.stdout.splitlines()
    aps: List[Dict[str, str]] = []

    current: Dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()

        # Example: "BSS aa:bb:cc:dd:ee:ff(on wlan0)"
        if line.startswith("BSS "):
            # commit previous AP if it had SSID
            if "ssid" in current and "bssid" in current:
                aps.append(current)
            current = {}

            parts = line.split()
            if len(parts) >= 2:
                bssid = parts[1]
                # strip trailing '(on' if present
                if "(" in bssid:
                    bssid = bssid.split("(")[0]
                current["bssid"] = bssid.lower()

        elif line.startswith("SSID:"):
            ssid = line[len("SSID:") :].strip()
            current["ssid"] = ssid

        elif line.startswith("signal:"):
            # example "signal: -42.00 dBm"
            sig_str = line[len("signal:") :].strip().split()[0]
            try:
                current["signal"] = int(float(sig_str))
            except ValueError:
                current["signal"] = -1000  # fallback

    # commit last AP if present
    if "ssid" in current and "bssid" in current:
        aps.append(current)

    # Filter by SSID
    filtered: List[Dict[str, str]] = []
    target_l = TASMOTA_AP_SSID.lower()
    for ap in aps:
        ssid = ap.get("ssid", "")
        if not ssid:
            continue
        ssid_l = ssid.lower()

        include = False
        if STRICT_SSID_MATCH:
            if ssid_l == target_l:
                include = True
        else:
            if ssid_l.startswith("accusaver"):
                include = True

        if include:
            filtered.append(ap)

    # Deduplicate by BSSID
    seen_bssids = set()
    unique_aps: List[Dict[str, str]] = []
    for ap in filtered:
        bssid = ap["bssid"]
        if bssid in seen_bssids:
            continue
        seen_bssids.add(bssid)
        unique_aps.append(ap)

    # Sort strongest signal first (signal is negative dBm -> higher is better)
    unique_aps.sort(key=lambda x: x.get("signal", -1000), reverse=True)

    print(f"[Scan] Found {len(unique_aps)} AP(s) matching filter:")
    for ap in unique_aps:
        sig = ap.get("signal", "N/A")
        print(f"  {ap['ssid']}  {ap['bssid']}  SIG:{sig}")

    return unique_aps


# -------- Connection + Phase 1 --------


def connect_to_bssid_iw(bssid: str) -> bool:
    """
    Fast-connect to a specific BSSID for TASMOTA_AP_SSID using `iw`.
    Assumes open network (no WPA). If you use WPA, wpa_supplicant needs to be involved.
    """
    print(f"[WiFi] Fast connect to SSID {TASMOTA_AP_SSID} on BSSID {bssid}...")
    proc = run_cmd(["iw", "dev", WIFI_INTERFACE, "connect", TASMOTA_AP_SSID, bssid])

    if proc.returncode != 0:
        print(f"  ✗ iw connect error: {proc.stderr.strip()}")
        return False

    # Give association a moment to complete
    time.sleep(0.4)
    return True


def ensure_ap_http(max_attempts: int = 5) -> bool:
    """
    Quick sanity check that http://192.168.4.1 responds.
    Short timeouts to keep total phase time small.
    """
    print("[Phase 1] Checking HTTP connectivity to Tasmota AP...")
    url = f"http://{TASMOTA_AP_IP}"
    for attempt in range(1, max_attempts + 1):
        print(f"  HTTP check {attempt}/{max_attempts}...")
        try:
            resp = requests.get(url, timeout=1.0)
            if resp.status_code == 200:
                print("  ✓ Tasmota AP reachable")
                return True
            else:
                print(f"  HTTP {resp.status_code}")
        except Exception as e:
            print(f"  HTTP error: {e}")
        time.sleep(0.2)

    print("  ✗ Tasmota AP HTTP not reachable after retries")
    return False


def send_phase1_commands(router_ssid: str, router_password: str) -> bool:
    """
    Phase 1 = send:
      Backlog0 OtaUrl <FIRMWARE_URL>; SSID1 <router_ssid>; Password1 <router_password>
    to the AP at 192.168.4.1.
    """
    commands = (
        f"Backlog0 OtaUrl {FIRMWARE_URL}; "
        f"SSID1 {router_ssid}; "
        f"Password1 {router_password}"
    )

    url = f"http://{TASMOTA_AP_IP}/cm"
    print(f"[Phase 1] Sending WiFi + OtaUrl backlog to {url}")

    for attempt in range(1, PHASE1_MAX_RETRIES + 1):
        print(f"  Phase 1 attempt {attempt}/{PHASE1_MAX_RETRIES}...")
        try:
            resp = requests.get(url, params={"cmnd": commands}, timeout=3.0)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = resp.text
                print(f"  ✓ HTTP 200, response: {data}")
                return True
            else:
                print(f"  ✗ HTTP {resp.status_code} in Phase 1")
        except Exception as e:
            print(f"  ✗ Phase 1 HTTP error: {e}")

        if attempt < PHASE1_MAX_RETRIES:
            print("  Retrying Phase 1 shortly...")
            time.sleep(1.0)

    print("  ✗ Phase 1 failed after retries")
    return False


# -------- Main run --------


def main() -> None:
    wifi_cfg = load_wifi_config()
    router_ssid = wifi_cfg["ssid"]
    router_password = wifi_cfg["password"]

    configure_static_ap_ip()

    # Preflight scan defines the batch.
    aps = scan_accusaver_aps()
    if not aps:
        print("[Main] No AccuSaver APs found during preflight – nothing to do.")
        return

    total = len(aps)
    success = 0
    failures = 0

    print(
        f"[Main] Starting Phase 1 for {total} device(s) "
        f"(only those seen during preflight)."
    )

    for idx, ap in enumerate(aps, start=1):
        bssid = ap["bssid"]
        sig = ap.get("signal", "N/A")

        print("\n" + "=" * 60)
        print(f"[Device {idx}/{total}] BSSID {bssid}  SIG:{sig}")
        print("=" * 60)

        if not connect_to_bssid_iw(bssid):
            print(f"[Device {idx}] ✗ WiFi connect failed")
            failures += 1
            continue

        if not ensure_ap_http():
            print(f"[Device {idx}] ✗ AP HTTP not reachable")
            failures += 1
            continue

        if send_phase1_commands(router_ssid, router_password):
            print(f"[Device {idx}] ✓ Phase 1 succeeded")
            success += 1
        else:
            print(f"[Device {idx}] ✗ Phase 1 failed")
            failures += 1

    print("\n[Summary]")
    print(f"  Total APs in preflight batch: {total}")
    print(f"  ✓ Success: {success}")
    print(f"  ✗ Failed:  {failures}")


if __name__ == "__main__":
    main()
