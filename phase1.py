#!/usr/bin/env python3
"""
Phase 1 provisioner for Tasmota AccuSaver devices.

Flow:
  1. Stop NetworkManager / wpa_supplicant so nothing else touches wlan0.
  2. Bring wlan0 up (no static IP; we'll use DHCP per AP).
  3. Preflight: single scan of the air, collect all matching AccuSaver APs.
  4. For each BSSID seen in that preflight scan:
       - disconnect any association
       - connect to that BSSID using `iw`
       - run `dhclient -4 -1 wlan0` to get a 192.168.4.x lease
       - verify HTTP connectivity to 192.168.4.1
       - send Backlog0 (OtaUrl + SSID1 + Password1)
  5. Summary of successes / failures.
"""

import json
import subprocess
import time
from typing import List, Dict

import requests

# -------- Config --------

FIRMWARE_URL = "http://192.168.2.59/tasmota32c2-withfs.bin"

TASMOTA_AP_SSID = "accusaver-3FCAD739"
TASMOTA_AP_IP = "192.168.4.1"

WIFI_INTERFACE = "wlan0"

STRICT_SSID_MATCH = True  # True = exact SSID, False = any ssid.startswith("accusaver")

WIFI_CONFIG_FILE = ".wifi-config.json"  # router SSID + password for Phase 1 backlog

PHASE1_MAX_RETRIES = 3


# -------- Shell helpers --------


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def quiesce_wifi_managers() -> None:
    print("[Init] Stopping NetworkManager / wpa_supplicant if present...")
    for svc in ("NetworkManager", "wpa_supplicant"):
        proc = run_cmd(["systemctl", "stop", svc])
        if proc.returncode == 0:
            print(f"  - stopped {svc}")
        else:
            msg = proc.stderr.strip()
            if msg:
                print(f"  - {svc}: {msg}")


def bringup_wlan() -> None:
    print(f"[Net] Bringing {WIFI_INTERFACE} up (no IP yet)...")
    run_cmd(["ip", "link", "set", WIFI_INTERFACE, "down"])
    run_cmd(["ip", "addr", "flush", "dev", WIFI_INTERFACE])
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
    print(f"[Scan] Preflight scan on {WIFI_INTERFACE} using iw...")
    proc = run_cmd(["iw", "dev", WIFI_INTERFACE, "scan"])
    if proc.returncode != 0:
        print(f"[Scan] iw error: {proc.stderr.strip()}")
        print("       Make sure no other process manages wlan0 and run as root.")
        return []

    lines = proc.stdout.splitlines()
    aps: List[Dict[str, str]] = []
    current: Dict[str, str] = {}

    for raw_line in lines:
        line = raw_line.strip()

        if line.startswith("BSS "):
            if "ssid" in current and "bssid" in current:
                aps.append(current)
            current = {}
            parts = line.split()
            if len(parts) >= 2:
                bssid = parts[1]
                if "(" in bssid:
                    bssid = bssid.split("(")[0]
                current["bssid"] = bssid.lower()

        elif line.startswith("SSID:"):
            current["ssid"] = line[len("SSID:") :].strip()

        elif line.startswith("signal:"):
            sig_str = line[len("signal:") :].strip().split()[0]
            try:
                current["signal"] = int(float(sig_str))
            except ValueError:
                current["signal"] = -1000

    if "ssid" in current and "bssid" in current:
        aps.append(current)

    # Filter + dedupe + sort
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

    seen_bssids = set()
    unique_aps: List[Dict[str, str]] = []
    for ap in filtered:
        bssid = ap["bssid"]
        if bssid in seen_bssids:
            continue
        seen_bssids.add(bssid)
        unique_aps.append(ap)

    unique_aps.sort(key=lambda x: x.get("signal", -1000), reverse=True)

    print(f"[Scan] Found {len(unique_aps)} AP(s) matching filter:")
    for ap in unique_aps:
        sig = ap.get("signal", "N/A")
        print(f"  {ap['ssid']}  {ap['bssid']}  SIG:{sig}")

    return unique_aps


# -------- Connection + DHCP + Phase 1 --------


def connect_to_bssid_iw(bssid: str, max_wait_s: float = 3.0) -> bool:
    # ensure clean state
    run_cmd(["iw", "dev", WIFI_INTERFACE, "disconnect"])

    print(f"[WiFi] Fast connect to SSID {TASMOTA_AP_SSID} on BSSID {bssid}...")
    proc = run_cmd(["iw", "dev", WIFI_INTERFACE, "connect", TASMOTA_AP_SSID, bssid])

    if proc.returncode != 0:
        print(f"  ✗ iw connect error: {proc.stderr.strip()}")
        return False

    # Wait for association to really complete
    deadline = time.time() + max_wait_s
    last_link = ""
    while time.time() < deadline:
        link_proc = run_cmd(["iw", "dev", WIFI_INTERFACE, "link"])
        last_link = link_proc.stdout.strip()
        if "Connected to" in last_link and bssid.lower() in last_link.lower():
            print(f"  ✓ Associated:\n    {last_link.replace(chr(10), chr(10)+'    ')}")
            return True
        time.sleep(0.1)

    print("  ✗ Failed to associate within timeout. iw link says:")
    print("    " + last_link.replace("\n", "\n    "))
    return False


def dhcp_for_ap(max_wait_s: float = 4.0) -> bool:
    """
    Run a one-shot DHCP request on wlan0 to get 192.168.4.x from the AP.
    Requires dhclient installed.
    """
    print("[DHCP] Requesting address on wlan0...")
    # -1 = single attempt in foreground, -4 = IPv4 only
    proc = run_cmd(["dhclient", "-4", "-1", WIFI_INTERFACE])
    if proc.returncode != 0:
        print(f"  ✗ dhclient error: {proc.stderr.strip()}")
        return False

    # quick sanity check that we have some IPv4 now
    addr_proc = run_cmd(["ip", "-4", "addr", "show", WIFI_INTERFACE])
    print("  ip addr:\n    " + addr_proc.stdout.replace("\n", "\n    "))
    return True


def ensure_ap_http(max_attempts: int = 5) -> bool:
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

    quiesce_wifi_managers()
    bringup_wlan()

    aps = scan_accusaver_aps()
    if not aps:
        print("[Main] No AccuSaver APs found during preflight – nothing to do.")
        return

    total = len(aps)
    success = 0
    failures = 0

    print(
        f"[Main] Starting Phase 1 for {total} device(s) (only those seen during preflight)."
    )

    for idx, ap in enumerate(aps, start=1):
        bssid = ap["bssid"]
        sig = ap.get("signal", "N/A")

        print("\n" + "=" * 60)
        print(f"[Device {idx}/{total}] BSSID {bssid}  SIG:{sig}")
        print("=" * 60)

        if not connect_to_bssid_iw(bssid):
            print(f"[Device {idx}] ✗ WiFi connect/associate failed")
            failures += 1
            continue

        if not dhcp_for_ap():
            print(f"[Device {idx}] ✗ DHCP failed")
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
