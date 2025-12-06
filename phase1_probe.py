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

PHASE1_MAX_RETRIES = 1  # 1 HTTP attempt per connect
NMCLI_CONNECT_TIMEOUT_S = 3  # shorter connect timeout for speed
HTTP_TIMEOUT_S = 1.0  # backlog HTTP timeout

EXPECTED_DEVICES = 4  # set to 18 in production
MAX_ATTEMPTS_PER_DEVICE = 10  # hard cap so we don't loop forever


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
    Single fast-ish connect attempt:
      - disconnect wlan0 first
      - nmcli with short timeout
      - small post-connect delay
    """
    print(f"  [WiFi] Connecting to {SSID} @ {bssid}...")
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
        print(f"    ✗ nmcli connect error (after {dt:.2f}s): {proc.stderr.strip()}")
        return False

    time.sleep(0.3)
    print(f"    ✓ nmcli connect completed in {dt:.2f}s")
    return True


# -------- HTTP helpers --------


def load_wifi_config() -> Dict[str, str]:
    with open(WIFI_CONFIG_FILE, "r") as f:
        cfg = json.load(f)
    return {"ssid": cfg["ssid"], "password": cfg["password"]}


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
    print(f"    → Sending Phase-1 backlog (HTTP timeout {HTTP_TIMEOUT_S}s)...")
    for attempt in range(1, PHASE1_MAX_RETRIES + 1):
        print(f"      HTTP attempt {attempt}/{PHASE1_MAX_RETRIES}...")
        try:
            resp = requests.get(url, params={"cmnd": cmd}, timeout=HTTP_TIMEOUT_S)
            if resp.status_code != 200:
                print(f"      ✗ HTTP {resp.status_code}")
            else:
                try:
                    data = resp.json()
                except Exception:
                    data = resp.text
                print(f"      ✓ Response: {data}")
                return True
        except Exception as e:
            print(f"      ✗ Phase1 HTTP error: {e}")

    print("    ✗ Phase1 failed for this connect")
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
    if len(aps) < EXPECTED_DEVICES:
        print(
            f"[Main] ✗ Preflight: expected {EXPECTED_DEVICES} devices, "
            f"but only saw {len(aps)}. Aborting."
        )
        return

    # only take the first EXPECTED_DEVICES (strongest signals)
    aps = aps[:EXPECTED_DEVICES]
    print(
        f"[Main] Using first {EXPECTED_DEVICES} AP(s) from preflight scan "
        "(strongest signals)."
    )

    success_count = 0
    durations_all: List[float] = []
    durations_success: List[float] = []

    for idx, ap in enumerate(aps, start=1):
        bssid = ap["bssid"]
        sig = ap["signal"]

        print("\n" + "=" * 60)
        print(f"[Device {idx}/{EXPECTED_DEVICES}] BSSID {bssid} SIG:{sig}")
        print("=" * 60)

        device_start = time.perf_counter()
        attempt = 0
        success = False

        while attempt < MAX_ATTEMPTS_PER_DEVICE:
            attempt += 1
            print(f"  [Device {idx}] Attempt {attempt}/{MAX_ATTEMPTS_PER_DEVICE}...")

            t0 = time.perf_counter()
            if not connect_to_bssid(bssid):
                elapsed_attempt = time.perf_counter() - t0
                print(f"    ✗ Connect failed in {elapsed_attempt:.2f}s")
            else:
                if send_phase1(router_ssid, router_password):
                    elapsed_attempt = time.perf_counter() - t0
                    print(
                        f"    ✓ Device {idx} Phase1 OK in this attempt ({elapsed_attempt:.2f}s)"
                    )
                    success = True
                    break
                else:
                    elapsed_attempt = time.perf_counter() - t0
                    print(
                        f"    ✗ Device {idx} Phase1 HTTP failed in {elapsed_attempt:.2f}s"
                    )

            # small backoff before retrying same BSSID
            time.sleep(0.5)

        device_elapsed = time.perf_counter() - device_start
        durations_all.append(device_elapsed)

        if not success:
            print(
                f"[Device {idx}] ✗ FAILED after {MAX_ATTEMPTS_PER_DEVICE} attempts "
                f"(total {device_elapsed:.2f}s)"
            )
            # hard fail: we don't continue to next devices
            break
        else:
            success_count += 1
            durations_success.append(device_elapsed)
            print(
                f"[Device {idx}] ✓ SUCCESS after {attempt} attempt(s), "
                f"device time {device_elapsed:.2f}s"
            )

    total_elapsed = time.perf_counter() - script_start

    print("\n[Summary]")
    print(f"  Expected devices:          {EXPECTED_DEVICES}")
    print(f"  Successfully provisioned:  {success_count}")
    print(f"  ⏱ Total runtime:           {total_elapsed:.2f}s")

    if durations_all:
        print(
            f"  ⏱ Avg per device (all):    {sum(durations_all)/len(durations_all):.2f}s"
        )
    if durations_success:
        print(
            f"  ⏱ Avg per device (OK):     "
            f"{sum(durations_success)/len(durations_success):.2f}s"
        )

    if success_count == EXPECTED_DEVICES:
        print("\n[Main] ✓ All expected devices succeeded.")
    else:
        print("\n[Main] ✗ Did NOT reach expected device count (hard failure).")


if __name__ == "__main__":
    main()
