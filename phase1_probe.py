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

PHASE1_MAX_RETRIES = 1          # 1 HTTP attempt per connect
NMCLI_CONNECT_TIMEOUT_S = 3     # single connect attempt timeout
HTTP_TIMEOUT_S = 1.0            # backlog HTTP timeout

EXPECTED_DEVICES = 4            # set to 18 in production
MAX_ROUNDS = 10                 # how many passes over all devices max


# -------- Shell helpers --------

def run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


# -------- WiFi / scan (preflight only) --------

def scan_accusavers() -> List[Dict[str, str]]:
    print("[Scan] nmcli scan for AccuSaver APs (preflight)...")
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
    One fast-ish connect attempt:
      - disconnect wlan0 first
      - nmcli with short timeout
      - small post-connect delay
    """
    print(f"    [WiFi] Connecting to {SSID} @ {bssid}...")
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
        print(f"      ✗ nmcli connect error (after {dt:.2f}s): {proc.stderr.strip()}")
        return False

    time.sleep(0.3)
    print(f"      ✓ nmcli connect completed in {dt:.2f}s")
    return True


# -------- HTTP helpers --------

def load_wifi_config():
    with open(WIFI_CONFIG_FILE, "r") as f:
        cfg = json.load(f)
    return cfg["ssid"], cfg["password"]


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
    print(f"      → Sending Phase-1 backlog (HTTP timeout {HTTP_TIMEOUT_S}s)...")
    for attempt in range(1, PHASE1_MAX_RETRIES + 1):
        print(f"        HTTP attempt {attempt}/{PHASE1_MAX_RETRIES}...")
        try:
            resp = requests.get(url, params={"cmnd": cmd}, timeout=HTTP_TIMEOUT_S)
            if resp.status_code != 200:
                print(f"        ✗ HTTP {resp.status_code}")
            else:
                try:
                    data = resp.json()
                except Exception:
                    data = resp.text
                print(f"        ✓ Response: {data}")
                return True
        except Exception as e:
            print(f"        ✗ Phase1 HTTP error: {e}")

    print("      ✗ Phase1 failed for this attempt")
    return False


# -------- Main --------

def main():
    script_start = time.perf_counter()

    try:
        router_ssid, router_password = load_wifi_config()
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

    aps = aps[:EXPECTED_DEVICES]
    bssids = [ap["bssid"] for ap in aps]
    signals = {ap["bssid"]: ap["signal"] for ap in aps}

    print(
        f"[Main] Using first {EXPECTED_DEVICES} AP(s) from preflight scan "
        "(strongest signals)."
    )

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

        for idx, bssid in enumerate(bssids, start=1):
            if bssid in success_bssids:
                continue  # already done

            total_attempts += 1
            sig = signals[bssid]
            print("\n" + "-" * 60)
            print(
                f"[Device idx {idx}] BSSID {bssid} SIG:{sig} "
                f"(round {round_idx}, attempt #{total_attempts})"
            )
            print("-" * 60)

            t_device_attempt_start = time.perf_counter()

            if not connect_to_bssid(bssid):
                elapsed = time.perf_counter() - t_device_attempt_start
                attempt_durations.append(elapsed)
                print(f"    ⏱ Attempt duration: {elapsed:.2f}s")
                continue

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

            avg_attempt = sum(attempt_durations) / len(attempt_durations)
            print(f"    ⏱ Attempt duration: {elapsed:.2f}s (avg attempts: {avg_attempt:.2f}s)")

        # small pause between rounds so devices can reboot / change state
        time.sleep(1.0)

    total_elapsed = time.perf_counter() - script_start

    print("\n[Summary]")
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
        print("\n[Main] ✓ All expected devices succeeded.")
    else:
        print("\n[Main] ✗ Did NOT reach expected device count (hard failure).")


if __name__ == "__main__":
    main()
