#!/usr/bin/env python3
import subprocess
import requests
from typing import List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

LAN_INTERFACE = "eth0"
START_HOST = 1
END_HOST = 254
MAX_WORKERS = 32
REQUEST_TIMEOUT = 0.3  # seconds


# ------------------------------------------------
# Detect LAN prefix automatically (e.g. 192.168.1.)
# ------------------------------------------------
def detect_lan_prefix(interface: str = LAN_INTERFACE) -> str:
    result = subprocess.run(
        ["ip", "-4", "addr", "show", interface],
        capture_output=True,
        text=True,
    )
    out = result.stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            ip = line.split()[1].split("/")[0]
            parts = ip.split(".")
            prefix = ".".join(parts[:3]) + "."
            print(f"[LAN] Detected LAN prefix: {prefix}")
            return prefix
    raise RuntimeError("Could not detect LAN prefix")


# ------------------------------------------------
# Probe a single IP using Status 5
# ------------------------------------------------
def probe_ip_for_accusaver(
    ip: str, timeout: float = REQUEST_TIMEOUT
) -> Optional[Tuple[str, str]]:
    """
    Returns (ip, hostname) if this IP is an AccuSaver, otherwise None.
    """
    url = f"http://{ip}/cm"
    try:
        resp = requests.get(url, params={"cmnd": "Status 5"}, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            statusnet = data.get("StatusNET", {})
            hostname = str(statusnet.get("Hostname", "")).strip()
            ip_reported = str(statusnet.get("IPAddress", "")).strip()

            if hostname.lower().startswith("accusaver"):
                print(f"  ✓ AccuSaver hit: {ip}  Hostname={hostname}  IP={ip_reported}")
                return (ip_reported or ip, hostname)
    except Exception:
        pass
    return None


# ------------------------------------------------
# Full subnet scan for *all* AccuSaver devices
# ------------------------------------------------
def scan_subnet_for_all_accusavers(
    prefix: str,
    start: int = START_HOST,
    end: int = END_HOST,
    workers: int = MAX_WORKERS,
) -> List[Tuple[str, str]]:
    print(f"[Scan] Scanning {prefix}{start}-{end} for AccuSaver devices...")

    devices: List[Tuple[str, str]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(probe_ip_for_accusaver, f"{prefix}{i}"): i
            for i in range(start, end + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)

    # Sort by IP for nicer output
    devices.sort(key=lambda t: t[0])
    return devices


# ------------------------------------------------
# Send Reset 1 to a single device
# ------------------------------------------------
def send_reset1(ip: str, timeout: float = 5.0) -> bool:
    try:
        resp = requests.get(
            f"http://{ip}/cm",
            params={"cmnd": "Reset 1"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            print(f"  ✓ Reset 1 sent to {ip}")
            return True
        else:
            print(f"  ✗ Reset 1 to {ip} failed: HTTP {resp.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ Reset 1 to {ip} failed: {e}")
        return False


# ------------------------------------------------
# Main
# ------------------------------------------------
if __name__ == "__main__":
    try:
        prefix = detect_lan_prefix(LAN_INTERFACE)
    except RuntimeError as e:
        print(f"✗ {e}")
        raise SystemExit(1)

    devices = scan_subnet_for_all_accusavers(prefix)

    if not devices:
        print("\n[Result] No AccuSaver devices found on this LAN.")
        raise SystemExit(0)

    print("\n[Result] AccuSaver devices discovered:")
    for ip, hostname in devices:
        print(f"  - {ip} ({hostname})")

    print("\n[Action] Sending Reset 1 to all AccuSaver devices...\n")

    success = 0
    fail = 0
    for ip, hostname in devices:
        print(f"[Device] {ip} ({hostname})")
        if send_reset1(ip):
            success += 1
        else:
            fail += 1

    print("\n=== SUMMARY ===")
    print(f"Total AccuSaver devices found: {len(devices)}")
    print(f"  ✓ Reset success: {success}")
    print(f"  ✗ Reset failed: {fail}")
