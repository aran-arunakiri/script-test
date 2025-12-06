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

PHASE1_MAX_RETRIES = 1  # one HTTP attempt per connect
NMCLI_CONNECT_TIMEOUT_S = 5  # max seconds nmcli can spend on a connect
HTTP_TIMEOUT_S = 1.0  # backlog HTTP timeout

EXPECTED_DEVICES = 4  # <-- set to 18 in production
MAX_ROUNDS = 30  # safety guard so we don't loop forever
NO_NEW_AP_SLEEP_S = 3.0  # wait between rounds when nothing new is seen


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

    success_bssids: Set[str] = set()
    durations: List[float] = []
    success_durations: List[float] = []
    attempts = 0

    print(
        f"[Main] Target: Phase 1 success on {EXPECTED_DEVICES} device(s). "
        f"Max rounds: {MAX_ROUNDS}"
    )

    for round_idx in range(1, MAX_ROUNDS + 1):
        print("\n" + "#" * 60)
        print(
            f"[Round {round_idx}/{MAX_ROUNDS}] "
            f"Success so far: {len(success_bssids)}/{EXPECTED_DEVICES}"
        )
        print("#" * 60)

        if len(success_bssids) >= EXPECTED_DEVICES:
            print("[Main] Target reached, stopping rounds.")
            break

        aps = scan_accusavers()
        if not aps:
            print("  No APs visible this round.")
        # only attempt devices we haven't already succeeded on
        candidates = [ap for ap in aps if ap["bssid"] not in success_bssids]

        if not candidates:
            print("  No new APs to process this round, sleeping a bit...")
            time.sleep(NO_NEW_AP_SLEEP_S)
            continue

        total_this_round = len(candidates)
        print(f"  Candidates this round (not yet successful): {total_this_round}")

        for idx, ap in enumerate(candidates, start=1):
            if len(success_bssids) >= EXPECTED_DEVICES:
                print("  Target reached mid-round, breaking.")
                break

            bssid = ap["bssid"]
            sig = ap["signal"]
            attempts += 1

            print("\n" + "=" * 60)
            print(
                f"[Device attempt #{attempts}] "
                f"BSSID {bssid} SIG:{sig} "
                f"(round {round_idx}, candidate {idx}/{total_this_round})"
            )
            print("=" * 60)

            start_t = time.perf_counter()

            if not connect_to_bssid(bssid):
                print("  ✗ WiFi connect failed for this attempt")
                elapsed = time.perf_counter() - start_t
                durations.append(elapsed)
                print(f"  ⏱ Attempt duration: {elapsed:.2f}s")
                continue

            ok = send_phase1(router_ssid, router_password)
            elapsed = time.perf_counter() - start_t
            durations.append(elapsed)

            if ok:
                success_bssids.add(bssid)
                success_durations.append(elapsed)
                print(
                    f"  ✓ Phase1 success for {bssid} in {elapsed:.2f}s "
                    f"(total successes: {len(success_bssids)}/{EXPECTED_DEVICES})"
                )
            else:
                print(
                    f"  ✗ Phase1 failed for {bssid} (this attempt, will retry in later rounds)"
                )

            avg = sum(durations) / len(durations)
            print(
                f"  ⏱ Attempt duration: {elapsed:.2f}s (avg over attempts: {avg:.2f}s)"
            )

        # small pause between rounds to let devices reboot / leave AP mode
        time.sleep(1.0)

    total_elapsed = time.perf_counter() - script_start

    print("\n[Summary]")
    print(f"  Target devices:                {EXPECTED_DEVICES}")
    print(f"  Unique BSSIDs successful:      {len(success_bssids)}")
    print(f"  Total attempts:                {attempts}")
    print(f"  ⏱ Total runtime:               {total_elapsed:.2f}s")

    if durations:
        print(f"  ⏱ Avg per attempt (all):       {sum(durations)/len(durations):.2f}s")
    if success_durations:
        print(
            f"  ⏱ Avg per success attempt:     {sum(success_durations)/len(success_durations):.2f}s"
        )

    if len(success_bssids) < EXPECTED_DEVICES:
        print("\n[Main] ⚠ Did NOT reach expected device count.")
    else:
        print("\n[Main] ✓ Reached expected device count.")


if __name__ == "__main__":
    main()
