import subprocess
import requests
import time
from typing import Optional, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed


def detect_lan_prefix(interface: str = "eth0") -> str:
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


def probe_ip(
    ip: str,
    timeout: float = 1.0,
    retries: int = 2,
    path: str = "/cm",
) -> Optional[Dict[str, str]]:
    """
    Probes a single IP by HTTP GET http://<ip>/<path>?cmnd=Status 5.
    Returns a dict with info if it looks like a valid AccuSaver device, else None.
    """
    url = f"http://{ip}{path}"

    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, params={"cmnd": "Status 5"}, timeout=timeout)
            if resp.status_code != 200:
                continue

            data = resp.json()
            statusnet = data.get("StatusNET", {})

            hostname = statusnet.get("Hostname", "") or ""
            ip_reported = statusnet.get("IPAddress", "") or ""

            print(f"  ✓ Hit: {ip}  Hostname={hostname}  IP={ip_reported}")
            return {
                "ip": ip,
                "reported_ip": ip_reported or ip,
                "hostname": hostname,
            }
        except Exception:
            # Network/timeout/JSON errors -> try again if retries left
            if attempt == retries:
                return None
            # small delay between retries to avoid hammering
            time.sleep(0.05)

    return None


def scan_subnet(
    prefix: str,
    start: int = 1,
    end: int = 254,
    workers: int = 32,
    timeout: float = 1.0,
    retries: int = 2,
) -> List[Dict[str, str]]:
    """
    Scans prefix.X where X in [start, end] in parallel.
    Returns list of devices (dicts) that responded.
    """
    print(f"[Scan] Scanning {prefix}{start}-{end} ...")

    found_devices: List[Dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                probe_ip,
                f"{prefix}{i}",
                timeout=timeout,
                retries=retries,
            ): i
            for i in range(start, end + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                found_devices.append(result)

    print(f"[Scan] Found {len(found_devices)} device(s) in this run.")
    return found_devices


def discover_devices_with_retry(
    interface: str = "eth0",
    max_attempts: int = 3,
    delay_seconds: int = 5,
    start: int = 1,
    end: int = 254,
    workers: int = 32,
    timeout: float = 1.0,
    retries: int = 2,
) -> List[Dict[str, str]]:
    """
    Runs one or more scan attempts with a delay between them.
    Returns a list of all devices discovered in the last attempt that found any.
    """
    prefix = detect_lan_prefix(interface)
    last_found: List[Dict[str, str]] = []

    for attempt in range(1, max_attempts + 1):
        print(f"\n[Attempt {attempt}/{max_attempts}] Starting scan...")
        found = scan_subnet(
            prefix=prefix,
            start=start,
            end=end,
            workers=workers,
            timeout=timeout,
            retries=retries,
        )

        if found:
            # Optionally deduplicate by reported_ip or hostname
            unique_by_ip: Dict[str, Dict[str, str]] = {}
            for dev in found:
                unique_by_ip[dev["reported_ip"]] = dev

            devices = list(unique_by_ip.values())
            print("\n✓ Devices discovered:")
            for dev in devices:
                print(
                    f"  - {dev['ip']} (reported: {dev['reported_ip']}, hostname: {dev['hostname']})"
                )
            return devices

        last_found = found
        print(f"[Retry] Not found. Waiting {delay_seconds} seconds...\n")
        time.sleep(delay_seconds)

    print("✗ No devices could be found after retries.")
    return last_found


if __name__ == "__main__":
    # Change interface="wlan0" if your Pi + devices are on WiFi
    discover_devices_with_retry(interface="eth0")
