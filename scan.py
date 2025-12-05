import subprocess
import requests
import time
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


def detect_lan_prefix(interface: str = "eth0") -> str:
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


def probe_ip(ip: str, timeout=0.3) -> Optional[str]:
    url = f"http://{ip}/cm"
    try:
        resp = requests.get(url, params={"cmnd": "Status 5"}, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            statusnet = data.get("StatusNET", {})
            hostname = statusnet.get("Hostname", "")
            ip_reported = statusnet.get("IPAddress", "")
            print(f"  ✓ Hit: {ip}  Hostname={hostname}  IP={ip_reported}")
            return ip_reported or ip
    except Exception:
        pass
    return None


def scan_subnet(prefix: str, start=1, end=254, workers=32) -> Optional[str]:
    print(f"[Scan] Scanning {prefix}{start}-{end} ...")

    found_ips = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(probe_ip, f"{prefix}{i}"): i for i in range(start, end + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                found_ips.append(result)

    print(f"[Scan] Found {len(found_ips)} device(s) in this run.")

    # Preserve old behavior: return first found IP or None
    return found_ips[0] if found_ips else None


def discover_device_with_retry(
    interface="eth0",
    max_attempts=3,
    delay_seconds=5,
) -> Optional[str]:

    prefix = detect_lan_prefix(interface)

    for attempt in range(1, max_attempts + 1):
        print(f"\n[Attempt {attempt}/{max_attempts}] Starting scan...")
        ip = scan_subnet(prefix)

        if ip:
            print(f"\n✓ Device discovered at: {ip}")
            return ip

        print(f"[Retry] Not found. Waiting {delay_seconds} seconds...\n")
        time.sleep(delay_seconds)

    print("✗ Device could not be found after retries.")
    return None


if __name__ == "__main__":
    discover_device_with_retry(interface="eth0")
