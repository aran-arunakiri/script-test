#!/usr/bin/env python3
import subprocess
import json
import time

SSID = "accusaver"
WIFI_IF = "wlan0"


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def scan_accusavers():
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

    aps = []
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
    print(f"\n[WiFi] Connecting to {SSID} @ {bssid}...")
    proc = run(
        [
            "nmcli",
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
    if proc.returncode != 0:
        print("  ✗ nmcli connect error:", proc.stderr.strip())
        return False
    time.sleep(1.0)  # short wait for DHCP
    return True


def status_0():
    import requests

    try:
        resp = requests.get(
            "http://192.168.4.1/cm", params={"cmnd": "Status 0"}, timeout=3
        )
        if resp.status_code != 200:
            print(f"  ✗ HTTP {resp.status_code}")
            return
        data = resp.json()
        status = data.get("Status", {})
        prm = data.get("StatusPRM", {})
        net = data.get("StatusNET", {})
        name = status.get("DeviceName", "")
        topic = status.get("Topic", "")
        ip = net.get("IPAddress", "")
        print(f"  ✓ Status 0: name={name!r}, topic={topic!r}, ip={ip!r}")
    except Exception as e:
        print("  ✗ Status 0 error:", e)


def main():
    aps = scan_accusavers()
    if not aps:
        print("[Main] No APs, nothing to do.")
        return

    for idx, ap in enumerate(aps, start=1):
        print("\n" + "=" * 60)
        print(f"[Device {idx}/{len(aps)}] BSSID {ap['bssid']} SIG:{ap['signal']}")
        print("=" * 60)

        if not connect_to_bssid(ap["bssid"]):
            continue
        status_0()


if __name__ == "__main__":
    main()
