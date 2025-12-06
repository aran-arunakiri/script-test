#!/usr/bin/env python3
import subprocess
import json
import time
from typing import List, Dict, Set

import requests

# -------- Config --------

SSID = "accusaver"
WIFI_IF = "wlan0"

FIRMWARE_URL = "http://192.168.2.59/tasmota32c2-withfs.bin"
WIFI_CONFIG_FILE = ".wifi-config.json"

# INCREASED TIMEOUT for more reliable nmcli connect
NMCLI_CONNECT_TIMEOUT_S = 5.0
# HTTP retry attempts per successful Wi-Fi connection
HTTP_MAX_RETRIES = 2
HTTP_TIMEOUT_S = 1.0

EXPECTED_DEVICES = 4
MAX_ROUNDS = 10

# -------- Shell helpers --------


def run(cmd: List[str]) -> subprocess.CompletedProcess:
    # Added check=False to suppress error on disconnect
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


# -------- WiFi / scan --------


def scan_accusavers() -> List[Dict[str, str]]:
    """Scan for AccuSaver APs and return a sorted list of APs."""
    print(f"[Scan] nmcli scan for {SSID} APs...")

    # Run nmcli to scan for APs
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
        print("  ✗ nmcli scan error:", proc.stderr.strip())
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

        # Parse output from nmcli
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
    print(f"[Scan] Found {len(aps)} {SSID} AP(s) currently active.")
    return aps


def connect_to_bssid(bssid: str, max_retries: int = 2) -> bool:
    """
    Multiple fast connect attempts:
      - disconnect wlan0 first
      - nmcli with slightly longer timeout
      - small post-connect delay
    """
    print(f"    [WiFi] Connecting to {SSID} @ {bssid} (Max {max_retries} attempts)...")

    # Disconnect wlan0 first to ensure a clean slate
    run(["nmcli", "dev", "disconnect", WIFI_IF])
    time.sleep(0.1)  # small pause

    for attempt in range(1, max_retries + 1):
        print(f"      nmcli connect attempt {attempt}/{max_retries}...")
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
            print(
                f"        ✗ nmcli connect error (after {dt:.2f}s): {proc.stderr.strip()}"
            )
            if attempt < max_retries:
                time.sleep(0.5)  # small delay before retrying
            continue

        # Success
        time.sleep(0.5)  # slightly longer post-connect delay
        print(f"        ✓ nmcli connect completed in {dt:.2f}s")
        return True

    return False


# -------- HTTP helpers --------


def load_wifi_config():
    with open(WIFI_CONFIG_FILE, "r") as f:
        cfg = json.load(f)
    return cfg["ssid"], cfg["password"]


def send_phase1(router_ssid: str, router_password: str) -> bool:
    """
    Phase 1 backlog command with multiple HTTP attempts.
    """
    cmd = (
        f"Backlog0 OtaUrl {FIRMWARE_URL}; "
        f"SSID1 {router_ssid}; "
        f"Password1 {router_password}"
    )

    url = "http://192.168.4.1/cm"
    print(f"      → Sending Phase-1 backlog (HTTP timeout {HTTP_TIMEOUT_S}s)...")

    for attempt in range(1, HTTP_MAX_RETRIES + 1):
        print(f"        HTTP attempt {attempt}/{HTTP_MAX_RETRIES}...")
        try:
            resp = requests.get(url, params={"cmnd": cmd}, timeout=HTTP_TIMEOUT_S)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except json.JSONDecodeError:
                    data = resp.text
                # A successful response is all we need to proceed
                print(f"        ✓ Response: {data}")
                return True
            else:
                print(f"        ✗ HTTP status code error: {resp.status_code}")
        except requests.exceptions.Timeout:
            print("        ✗ Phase1 HTTP error: Request timed out.")
        except Exception as e:
            print(f"        ✗ Phase1 HTTP error: {e}")

    print("      ✗ Phase1 failed after all attempts")
    return False


# -------- Main --------


def main():
    script_start = time.perf_counter()

    try:
        router_ssid, router_password = load_wifi_config()
    except Exception as e:
        print(f"[Main] ✗ Failed to load {WIFI_CONFIG_FILE}: {e}")
        return

    success_bssids: Set[str] = set()
    attempt_durations: List[float] = []
    success_device_durations: List[float] = []
    total_attempts = 0

    for round_idx in range(1, MAX_ROUNDS + 1):
        print("\n" + "#" * 60)
        print(
            f"[Round {round_idx}/{MAX_ROUNDS}] "
            f"Success so far: {len(success_bssids)}/{EXPECTED_DEVICES}"
        )
        print("#" * 60)

        if len(success_bssids) == EXPECTED_DEVICES:
            print("[Main] All devices succeeded, stopping.")
            break

        # 1. Fresh scan at the beginning of each round
        aps = scan_accusavers()

        # Filter for active BSSIDs that have not yet succeeded
        active_unprocessed_bssids = [
            ap["bssid"] for ap in aps if ap["bssid"] not in success_bssids
        ]

        # Create a dictionary for easy signal lookup
        signals = {ap["bssid"]: ap["signal"] for ap in aps}

        if not active_unprocessed_bssids:
            print(f"[Round {round_idx}] No active, unprocessed APs found. Pausing.")
            time.sleep(3.0)  # Longer pause if nothing is found
            continue  # Go to next round

        # 2. Iterate only over active, unprocessed BSSIDs
        for idx, bssid in enumerate(active_unprocessed_bssids, start=1):
            total_attempts += 1
            sig = signals.get(bssid, "N/A")
            print("\n" + "-" * 60)
            print(
                f"[Device idx {idx}] BSSID {bssid} SIG:{sig} "
                f"(round {round_idx}, attempt #{total_attempts})"
            )
            print("-" * 60)

            t_device_attempt_start = time.perf_counter()

            # 3. Use revised connect with retries
            if not connect_to_bssid(bssid, max_retries=2):
                elapsed = time.perf_counter() - t_device_attempt_start
                attempt_durations.append(elapsed)
                print(f"    ⏱ Attempt duration: {elapsed:.2f}s")
                continue

            # 4. Use revised send_phase1 with retries
            ok = send_phase1(router_ssid, router_password)
            elapsed = time.perf_counter() - t_device_attempt_start
            attempt_durations.append(elapsed)

            if ok:
                success_bssids.add(bssid)
                success_device_durations.append(elapsed)
                print(
                    f"    ✓ Phase1 success for {bssid} in {elapsed:.2f}s "
                    f"(total successes: {len(success_bssids)}/{EXPECTED_DEVICES})"
                )
            else:
                print(
                    f"    ✗ Phase1 HTTP failed for {bssid} "
                    f"(attempt took {elapsed:.2f}s)"
                )

            if attempt_durations:
                avg_attempt = sum(attempt_durations) / len(attempt_durations)
                print(
                    f"    ⏱ Attempt duration: {elapsed:.2f}s (avg attempts: {avg_attempt:.2f}s)"
                )

        # 5. Small pause between rounds so devices can reboot / change state
        time.sleep(1.0)

    total_elapsed = time.perf_counter() - script_start

    print("\n[Summary] 📋")
    print(f"  Expected devices:             {EXPECTED_DEVICES}")
    print(f"  Unique BSSIDs succeeded:      {len(success_bssids)}")
    print(f"  Total attempts:               {total_attempts}")
    print(f"  ⏱ Total runtime:              {total_elapsed:.2f}s")

    if attempt_durations:
        print(
            f"  ⏱ Avg per attempt (all):      "
            f"{sum(attempt_durations)/len(attempt_durations):.2f}s"
        )
    if success_device_durations:
        print(
            f"  ⏱ Avg per success attempt:    "
            f"{sum(success_device_durations)/len(success_device_durations):.2f}s"
        )

    if len(success_bssids) == EXPECTED_DEVICES:
        print("\n[Main] ✓ All expected devices succeeded. 🎉")
    else:
        print("\n[Main] ✗ Did NOT reach expected device count (hard failure). 😢")


if __name__ == "__main__":
    main()
