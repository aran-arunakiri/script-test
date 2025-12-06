#!/usr/bin/env python3
import subprocess
import requests
import time
from typing import List, Tuple, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------------------------------------------
# Config
# ------------------------------------------------
LAN_INTERFACE = "eth0"  # change to "wlan0" if needed
START_HOST = 1
END_HOST = 254
MAX_WORKERS = 32

REQUEST_TIMEOUT = 1.0  # seconds per HTTP request
PROBE_RETRIES = 2  # retries per IP (inside probe)
MAX_SCAN_ATTEMPTS = 3  # full subnet scan attempts
SCAN_RETRY_DELAY = 5  # seconds between full subnet scans


# ------------------------------------------------
# Detect LAN prefix automatically (e.g. 192.168.1.)
# ------------------------------------------------
def detect_lan_prefix(interface: str = LAN_INTERFACE) -> str:
    """
    Detects the /24 prefix for the given interface, e.g. '192.168.1.'.
    """
    result = subprocess.run(
        ["ip", "-4", "addr", "show", interface],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Could not get IP info for interface '{interface}': {result.stderr}"
        )

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            ip = line.split()[1].split("/")[0]
            parts = ip.split(".")
            if len(parts) != 4:
                break
            prefix = ".".join(parts[:3]) + "."
            print(f"[LAN] Detected LAN prefix on {interface}: {prefix}")
            return prefix

    raise RuntimeError(f"Could not detect IPv4 address on interface '{interface}'")


# ------------------------------------------------
# Probe a single IP using Status 5, with retries
# ------------------------------------------------
def probe_ip_for_accusaver(
    ip: str,
    timeout: float = REQUEST_TIMEOUT,
    retries: int = PROBE_RETRIES,
) -> Optional[Tuple[str, str]]:
    """
    Returns (ip, hostname) if this IP is an AccuSaver, otherwise None.
    Uses multiple retries with a small delay between attempts.
    """
    url = f"http://{ip}/cm"

    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, params={"cmnd": "Status 5"}, timeout=timeout)
            if resp.status_code != 200:
                # Non-200, try again if retries left
                if attempt == retries:
                    return None
                time.sleep(0.05)
                continue

            data = resp.json()
            statusnet = data.get("StatusNET", {})
            hostname = str(statusnet.get("Hostname", "")).strip()
            ip_reported = str(statusnet.get("IPAddress", "")).strip()

            if hostname.lower().startswith("accusaver"):
                print(
                    f"  ✓ AccuSaver hit: {ip}  "
                    f"Hostname={hostname}  IP={ip_reported}"
                )
                return (ip_reported or ip, hostname)

            # Not an AccuSaver -> no need to retry further
            return None

        except Exception:
            if attempt == retries:
                return None
            time.sleep(0.05)

    return None


# ------------------------------------------------
# One full subnet scan for all AccuSaver devices
# ------------------------------------------------
def scan_subnet_for_all_accusavers(
    prefix: str,
    start: int = START_HOST,
    end: int = END_HOST,
    workers: int = MAX_WORKERS,
    timeout: float = REQUEST_TIMEOUT,
    retries: int = PROBE_RETRIES,
) -> List[Tuple[str, str]]:
    """
    Scans prefix.X where X in [start, end] in parallel.
    Returns list of (ip, hostname) tuples for AccuSaver devices.
    """
    print(f"[Scan] Scanning {prefix}{start}-{end} for AccuSaver devices...")

    devices: List[Tuple[str, str]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                probe_ip_for_accusaver,
                f"{prefix}{i}",
                timeout,
                retries,
            ): i
            for i in range(start, end + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)

    # Deduplicate by reported IP (index 0 in tuple)
    unique_by_ip: Dict[str, Tuple[str, str]] = {}
    for ip_reported, hostname in devices:
        unique_by_ip[ip_reported] = (ip_reported, hostname)

    devices = list(unique_by_ip.values())
    # Sort by IP for nicer output
    devices.sort(key=lambda t: t[0])

    print(f"[Scan] Found {len(devices)} AccuSaver device(s) in this run.")
    return devices


# ------------------------------------------------
# Robust discovery with multiple scan attempts
# ------------------------------------------------
def discover_accusavers_with_retry(
    interface: str = LAN_INTERFACE,
    max_attempts: int = MAX_SCAN_ATTEMPTS,
    delay_seconds: int = SCAN_RETRY_DELAY,
    start: int = START_HOST,
    end: int = END_HOST,
    workers: int = MAX_WORKERS,
    timeout: float = REQUEST_TIMEOUT,
    retries: int = PROBE_RETRIES,
) -> List[Tuple[str, str]]:
    """
    Runs one or more subnet scan attempts with a delay between them.
    Returns list of AccuSaver devices discovered in the first successful attempt.
    """
    prefix = detect_lan_prefix(interface)
    last_found: List[Tuple[str, str]] = []

    for attempt in range(1, max_attempts + 1):
        print(f"\n[Attempt {attempt}/{max_attempts}] Starting scan...")
        found = scan_subnet_for_all_accusavers(
            prefix=prefix,
            start=start,
            end=end,
            workers=workers,
            timeout=timeout,
            retries=retries,
        )

        if found:
            print("\n[Result] AccuSaver devices discovered:")
            for ip, hostname in found:
                print(f"  - {ip} ({hostname})")
            return found

        last_found = found
        if attempt < max_attempts:
            print(f"[Retry] No AccuSavers found. Waiting {delay_seconds} seconds...\n")
            time.sleep(delay_seconds)

    print("[Result] No AccuSaver devices could be found after retries.")
    return last_found


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
        devices = discover_accusavers_with_retry(interface=LAN_INTERFACE)
    except RuntimeError as e:
        print(f"✗ {e}")
        raise SystemExit(1)

    if not devices:
        print("\n[Result] No AccuSaver devices found on this LAN.")
        raise SystemExit(0)

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
