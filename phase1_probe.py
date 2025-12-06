#!/usr/bin/env python3
import subprocess
import json
import time
from typing import List, Dict

import requests

# -------- Config --------

SSID = "accusaver"
WIFI_IF = "wlan0"

FIRMWARE_URL = "http://192.168.2.59/tasmota32c2-withfs.bin"
WIFI_CONFIG_FILE = ".wifi-config.json"

PHASE1_MAX_RETRIES = 1  # no retries, 1 shot per device
NMCLI_CONNECT_TIMEOUT_S = 5  # max seconds nmcli can spend on a connect
HTTP_TIMEOUT_S = 1.0  # backlog HTTP timeout


# -------- Shell helpers --------


def run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


# -------- WiFi / scan --------


def scan_accusavers() -> List[Dict[str, str]]:
    print("[Scan] nmcli scan for AccuSaver APs...")
    proc = run(
        [
            "nmcli",
            "-f",
            "SSID,BSSID,CHAN,SIGNAL",
            "device",
            "wifi",
            "list",
            "ifname",
            WIFI_IF,
            "--rescan",
            "yes",
        ]
    )
    if proc.returncode != 0:
        print("  ✗ nmcli error:", proc.stderr.strip())
        return []

    aps: List[Dict[str, str]] = []
    lines = proc.stdout.splitlines()
    for line in lines[1:]:  # skip header
        line = line.strip()
        if not line or line.startswith("-"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        signal = parts[-1]
        chan = parts[-2]
        bssid = parts[-3]
        ssid = " ".join(parts[:-3]).strip()
        if ssid.lower() == SSID.lower():
            aps.append(
                {
                    "ssid": ssid,
                    "bssid": bssid,
                    "chan": chan,
                    "signal": int(signal),
                }
            )

    aps.sort(key=lambda x: x["signal"], reverse=True)
    print(f"[Scan] Found {len(aps)} AccuSaver AP(s):")
    for ap in aps:
        print(f"  {ap['ssid']} {ap['bssid']} CH:{ap['chan']} SIG:{ap['signal']}")
    return aps


def connect_to_bssid(bssid: str) -> bool:
    """
    Fast-ish connect:
      - disconnect wlan0 first
      - nmcli with short timeout
      - small post-connect delay
    """
    print(f"\n[WiFi] Connecting to {SSID} @ {bssid}...")
    # Ensure clean state
    run(["nmcli", "dev", "disconnect", WIFI_IF])

    t0 = time.perf_counter()
    proc = run(
        [
            "nmcli",
            "-w",
            str(NMCLI_CONNECT_TIMEOUT_S),
            "dev",
            "wifi",
            "connect",
            SSID,
            "bssid",
            bssid,
            "ifname",
            WIFI_IF,
        ]
    )
    dt = time.perf_counter() - t0
    if proc.returncode != 0:
        print(f"  ✗ nmcli connect error (after {dt:.2f}s): {proc.stderr.strip()}")
        return False

    # DHCP usually lands very quickly; keep this small
    time.sleep(0.3)
    print(f"  ✓ nmcli connect completed in {dt:.2f}s")
    return True


# -------- HTTP helpers --------


def load_wifi_config() -> Dict[str, str]:
    with open(WIFI_CONFIG_FILE, "r") as f:
        cfg = json.load(f)
    return {
        "ssid": cfg["ssid"],
        "password": cfg["password"],
    }


def send_phase1(router_ssid: str, router_password: str) -> bool:
    """
    Phase 1 backlog:
      Backlog0 OtaUrl <FIRMWARE_URL>; SSID1 <router_ssid>; Password1 <router_password>
    Single attempt with short HTTP timeout.
    """
    cmd = (
        f"Backlog0 OtaUrl {FIRMWARE_URL}; "
        f"SSID1 {router_ssid}; "
        f"Password1 {router_password}"
    )

    url = "http://192.168.4.1/cm"
    print(f"  → Sending Phase-1 backlog (timeout {HTTP_TIMEOUT_S}s)...")
    for attempt in range(1, PHASE1_MAX_RETRIES + 1):
        print(f"    attempt {attempt}/{PHASE1_MAX_RETRIES}...")
        try:
            resp = requests.get(url, params={"cmnd": cmd}, timeout=HTTP_TIMEOUT_S)
            if resp.status_code != 200:
                print(f"    ✗ HTTP {resp.status_code}")
            else:
                try:
                    data = resp.json()
                except Exception:
                    data = resp.text
                print(f"    ✓ Response: {data}")
                return True
        except Exception as e:
            print(f"    ✗ Phase1 HTTP error: {e}")

    print("  ✗ Phase1 failed")
    return False


# -------- Main --------


def main():
    script_start = time.perf_counter()

    try:
        wifi_cfg = load_wifi_config()
        router_ssid = wifi_cfg["ssid"]
        router_password = wifi_cfg["password"]
    except Exception as e:
        print(f"[Main] ✗ Failed to load {WIFI_CONFIG_FILE}: {e}")
        return

    aps = scan_accusavers()
    if not aps:
        print("[Main] No APs, nothing to do.")
        return

    total = len(aps)
    success_phase1 = 0
    failures_phase1 = 0
    durations: List[float] = []
    success_durations: List[float] = []

    print(
        f"[Main] Starting Phase 1 for {total} device(s) "
        "(only those seen during this scan)."
    )

    for idx, ap in enumerate(aps, start=1):
        bssid = ap["bssid"]
        sig = ap["signal"]

        print("\n" + "=" * 60)
        print(f"[Device {idx}/{total}] BSSID {bssid} SIG:{sig}")
        print("=" * 60)

        start_t = time.perf_counter()

        if not connect_to_bssid(bssid):
            print(f"[Device {idx}] ✗ WiFi connect failed")
            failures_phase1 += 1
            elapsed = time.perf_counter() - start_t
            durations.append(elapsed)
            print(f"  ⏱ Device duration: {elapsed:.2f}s")
            continue

        ok = send_phase1(router_ssid, router_password)
        if ok:
            success_phase1 += 1
        else:
            failures_phase1 += 1

        elapsed = time.perf_counter() - start_t
        durations.append(elapsed)
        if ok:
            success_durations.append(elapsed)

        avg = sum(durations) / len(durations)
        print(f"  ⏱ Device duration: {elapsed:.2f}s (avg so far: {avg:.2f}s)")

    total_elapsed = time.perf_counter() - script_start

    print("\n[Summary]")
    print(f"  Total devices in scan: {total}")
    print(f"  ✓ Phase1 success:           {success_phase1}")
    print(f"  ✗ Phase1 failed:            {failures_phase1}")
    print(f"  ⏱ Total runtime:            {total_elapsed:.2f}s")

    if durations:
        print(f"  ⏱ Avg per device (all):     {sum(durations)/len(durations):.2f}s")
    if success_durations:
        print(
            f"  ⏱ Avg per device (success): {sum(success_durations)/len(success_durations):.2f}s"
        )


if __name__ == "__main__":
    main()
