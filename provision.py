import json
import subprocess
import time
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import requests

# -------- Configurable constants --------

# FIRMWARE_URL = "https://github.com/aran-arunakiri/script-test/raw/refs/heads/main/tasmota32c2-withfs.bin"
FIRMWARE_URL = "https://github.com/aran-arunakiri/script-test/raw/refs/heads/main/tasmota32c2-withfs_old.bin"
# BERRY_SCRIPT_URL = "https://raw.githubusercontent.com/aran-arunakiri/script-test/refs/heads/main/autoexec.be"
BERRY_SCRIPT_URL = "https://raw.githubusercontent.com/aran-arunakiri/script-test/refs/heads/main/old/autoexec.be"

TASMOTA_AP_SSID = "accusaver-3FCAD739"
TASMOTA_AP_IP = "192.168.4.1"
TASMOTA_HOSTNAME = "accusaver-3FCAD739"  # Hostname once on LAN

EXPECTED_FIRMWARE_DATE = "2025-11-16T15:13:02"
EXPECTED_SCRIPT_VERSION = "1.0.0"

WIFI_INTERFACE = "wlan0"  # Pi Wi-Fi interface
LAN_SUBNET_PREFIX = "192.168.0."  # <-- adjust to your router subnet
SCAN_START_HOST = 1
SCAN_END_HOST = 254

IP_DISCOVERY_ORDER: List[str] = ["scan", "mdns"]


# -------- Helpers --------


def load_config():
    """
    .wifi-config.json:
    {
      "ssid": "YourRouterSSID",
      "password": "YourRouterPassword"
    }
    """
    with open(".wifi-config.json", "r") as f:
        return json.load(f)


def run_cmd(cmd) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )


def get_current_ip(interface: str) -> Optional[str]:
    result = run_cmd(["ip", "-4", "addr", "show", interface])
    out = result.stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            # inet 192.168.4.2/24 brd ...
            ip = line.split()[1].split("/")[0]
            return ip
    return None


# -------- Wi-Fi / AP handling (Pi / Linux) --------


def disconnect_wifi():
    print(f"[WiFi] Disconnecting {WIFI_INTERFACE}...")
    run_cmd(["nmcli", "device", "disconnect", WIFI_INTERFACE])


def connect_wifi_to_ap(max_wait_seconds: int = 20) -> bool:
    """
    Use nmcli to connect wlan0 to the AccuSaver AP (open network).
    """
    disconnect_wifi()

    print(f"[WiFi] Connecting {WIFI_INTERFACE} to SSID {TASMOTA_AP_SSID}...")
    proc = run_cmd(
        [
            "nmcli",
            "device",
            "wifi",
            "connect",
            TASMOTA_AP_SSID,
            "ifname",
            WIFI_INTERFACE,
        ]
    )
    if proc.returncode != 0:
        print(f"  ✗ nmcli connect error: {proc.stderr.strip()}")
        return False

    # Wait for 192.168.4.x
    print(f"[WiFi] Waiting for 192.168.4.x on {WIFI_INTERFACE}...")
    for i in range(max_wait_seconds):
        time.sleep(1)
        ip = get_current_ip(WIFI_INTERFACE)
        print(f"  AP IP check {i + 1}/{max_wait_seconds}: {ip}")
        if ip and ip.startswith("192.168.4."):
            print(f"  ✓ On AP subnet: {ip}")
            return True

    print("  ✗ Failed to get 192.168.4.x on Wi-Fi")
    return False


def ensure_ap_http(max_attempts: int = 5) -> bool:
    """
    Confirm that we can talk HTTP to 192.168.4.1 once we're on 192.168.4.x.
    """
    print("[Phase 1] Verifying HTTP connectivity to Tasmota AP...")
    for attempt in range(1, max_attempts + 1):
        print(f"  AP HTTP check {attempt}/{max_attempts}...")
        try:
            resp = requests.get(f"http://{TASMOTA_AP_IP}", timeout=5)
            print(f"    HTTP status from AP: {resp.status_code}")
            if resp.status_code == 200:
                print("  ✓ Tasmota AP reachable")
                return True
        except Exception as e:
            print(f"    AP HTTP error: {e}")
        time.sleep(1)

    print("  ✗ Tasmota AP HTTP not reachable after retries")
    return False


# -------- Phase 1: AP-side provisioning --------


def send_phase1_commands(router_ssid: str, router_password: str, max_retries=3) -> bool:
    """
    Phase 1 (AP): send WiFi credentials + OtaUrl (no UrlFetch/Upgrade yet).
    Mirrors _sendPhase1Commands() in Flutter.
    """
    commands = (
        f"Backlog0 OtaUrl {FIRMWARE_URL}; "
        f"SSID1 {router_ssid}; "
        f"Password1 {router_password}"
    )
    url = f"http://{TASMOTA_AP_IP}/cm"
    print(f"[Phase 1] Sending WiFi + OtaUrl to {url}")

    for attempt in range(1, max_retries + 1):
        print(f"  Phase 1 attempt {attempt}/{max_retries}...")
        try:
            resp = requests.get(url, params={"cmnd": commands}, timeout=10)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = resp.text
                print(f"  ✓ Phase 1 HTTP 200, response: {data}")
                return True
            else:
                print(f"  ✗ HTTP {resp.status_code} during Phase 1")
        except Exception as e:
            print(f"  ✗ Phase 1 request failed: {e}")

        if attempt < max_retries:
            print("  Retrying Phase 1 in 3 seconds...")
            time.sleep(3)

    return False


# -------- IP discovery strategies (LAN side) --------


def find_device_ip_by_hostname(
    hostname: str,
    max_attempts: int = 10,
    delay_seconds: int = 4,
) -> Optional[str]:
    """
    Strategy: "mdns"
    Try to resolve device IP via mDNS:
      http://<hostname>.local/cm?cmnd=Status 5
    and read StatusNET.IPAddress.
    """
    print("[IP discovery: mdns] Using hostname.local + Status 5")
    for attempt in range(1, max_attempts + 1):
        print(f"  mDNS attempt {attempt}/{max_attempts}...")
        url = f"http://{hostname}.local/cm"
        try:
            resp = requests.get(url, params={"cmnd": "Status 5"}, timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                ip = str(data.get("StatusNET", {}).get("IPAddress", "")).strip()
                if ip:
                    print(f"  ✓ Resolved {hostname}.local to {ip}")
                    return ip
                else:
                    print("  Status 5 did not contain IPAddress")
            else:
                print(f"  HTTP {resp.status_code} resolving {hostname}.local")
        except Exception as e:
            print(f"  Error resolving {hostname}.local: {e}")

        time.sleep(delay_seconds)

    print("  ✗ mDNS IP discovery failed")
    return None


def find_device_ip_by_scan(
    subnet_prefix: str,
    start_host: int = 1,
    end_host: int = 254,
    timeout_seconds: float = 0.3,
    max_workers: int = 32,
) -> Optional[str]:
    """
    Strategy: "scan"
    Parallel scan subnet_prefix.X using Status 5 on each IP.
    """

    print(
        f"[IP discovery: scan] Scanning {subnet_prefix}{start_host}-{end_host} via Status 5 (parallel)"
    )

    def probe(host: int) -> Optional[str]:
        ip = f"{subnet_prefix}{host}"
        url = f"http://{ip}/cm"
        try:
            resp = requests.get(
                url, params={"cmnd": "Status 5"}, timeout=timeout_seconds
            )
            if resp.status_code == 200:
                data = resp.json()
                hostname = str(data.get("StatusNET", {}).get("Hostname", "")).lower()
                ip_reported = str(
                    data.get("StatusNET", {}).get("IPAddress", "")
                ).strip()
                if hostname.startswith("accusaver") or hostname.startswith("tasmota"):
                    print(
                        f"  ✓ Found candidate at {ip} (Hostname={hostname}, IP={ip_reported})"
                    )
                    return ip_reported or ip
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(probe, host): host
            for host in range(start_host, end_host + 1)
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                # We found our device; cancel the rest
                print("[scan] Device found, cancelling remaining probes")
                for f in futures:
                    f.cancel()
                return result

    print("  ✗ scan-based IP discovery failed")
    return None


def resolve_device_ip(order: List[str]) -> Optional[str]:
    """
    Try IP discovery strategies in the given order.
    order elements: "scan", "mdns"
    """
    for method in order:
        if method == "scan":
            ip = find_device_ip_by_scan(
                LAN_SUBNET_PREFIX, SCAN_START_HOST, SCAN_END_HOST
            )
        elif method == "mdns":
            ip = find_device_ip_by_hostname(TASMOTA_HOSTNAME)
        else:
            print(f"[IP discovery] Unknown method: {method}")
            ip = None

        if ip:
            print(f"[IP discovery] Resolved device IP via {method}: {ip}")
            return ip

    print("[IP discovery] All strategies failed")
    return None


# -------- Phase 2: LAN-side update (UrlFetch + Upgrade 1) --------


def send_phase2_commands(device_ip: str, max_retries=3) -> bool:
    """
    Phase 2 (LAN): send UrlFetch + Upgrade 1 to the device IP.
    Mirrors _sendPhase2Commands in Flutter.
    """
    commands = f"Backlog0 UrlFetch {BERRY_SCRIPT_URL}; Upgrade 1"
    url = f"http://{device_ip}/cm"

    print(f"[Phase 2] Sending UrlFetch + Upgrade 1 to {url}")

    for attempt in range(1, max_retries + 1):
        print(f"  Phase 2 attempt {attempt}/{max_retries}...")
        try:
            resp = requests.get(url, params={"cmnd": commands}, timeout=15)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = resp.text
                print(f"  ✓ Phase 2 HTTP 200, response: {data}")
                return True
            else:
                print(f"  ✗ HTTP {resp.status_code} during Phase 2")
        except Exception as e:
            print(f"  ✗ Phase 2 request failed: {e}")

        if attempt < max_retries:
            print("  Retrying Phase 2 in 3 seconds...")
            time.sleep(3)

    return False


def wait_for_script_after_safeboot(
    ip: str,
    expected_version: str,
    max_attempts: int = 30,
    delay_seconds: int = 5,
) -> bool:
    """
    Poll ScriptVersion until safeboot has completed and the Berry script is installed.
    """
    print("[Safeboot] Waiting for safeboot to complete...")

    for attempt in range(1, max_attempts + 1):
        print(f"  ScriptVersion check {attempt}/{max_attempts}...")
        try:
            resp = requests.get(
                f"http://{ip}/cm",
                params={"cmnd": "ScriptVersion"},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                version = str(data.get("ScriptVersion", "")).strip()
                if version:
                    print(
                        f"    ScriptVersion: {version} (expected: {expected_version})"
                    )
                    if version == expected_version:
                        print("  ✓ ScriptVersion matches, safeboot complete!")
                        return True
            else:
                print(f"    HTTP {resp.status_code} from ScriptVersion")
        except Exception as e:
            print(f"    ScriptVersion request error: {e}")

        time.sleep(delay_seconds)

    print("  ✗ Timeout waiting for ScriptVersion")
    return False


# -------- Resets and online wait --------


def send_reset4(ip: str) -> bool:
    print("[Reset 4] Sending Reset 4 (activate firmware, keep WiFi)")
    try:
        requests.get(f"http://{ip}/cm", params={"cmnd": "Reset 4"}, timeout=5)
        print("  ✓ Reset 4 sent")
        return True
    except Exception as e:
        print(f"  ✗ Failed to send Reset 4: {e}")
        return False


def send_reset1(ip: str) -> bool:
    print("[Reset 1] Sending Reset 1 (factory reset)")
    try:
        requests.get(f"http://{ip}/cm", params={"cmnd": "Reset 1"}, timeout=5)
        print("  ✓ Reset 1 sent")
        return True
    except Exception as e:
        print(f"  ✗ Failed to send Reset 1: {e}")
        return False


def wait_for_device_online(
    ip: str, max_attempts: int = 20, delay_seconds: int = 3
) -> bool:
    print("[Online check] Waiting for device to come back online...")
    for attempt in range(1, max_attempts + 1):
        print(f"  Status 0 check {attempt}/{max_attempts}...")
        try:
            resp = requests.get(
                f"http://{ip}/cm",
                params={"cmnd": "Status 0"},
                timeout=5,
            )
            if resp.status_code == 200:
                print("  ✓ Device is back online")
                return True
        except Exception:
            pass
        time.sleep(delay_seconds)

    print("  ✗ Timeout waiting for device")
    return False


# -------- Verification --------


def verify_firmware(ip: str) -> bool:
    print("[Verify] Verifying firmware...")
    try:
        resp = requests.get(
            f"http://{ip}/cm",
            params={"cmnd": "Status 2"},
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"  ✗ Status 2 HTTP {resp.status_code}")
            return False

        data = resp.json()
        build_date = str(data.get("StatusFWR", {}).get("BuildDateTime", "")).strip()
        ok = build_date == EXPECTED_FIRMWARE_DATE
        print(f"  Firmware BuildDateTime: {build_date} {'✓' if ok else '✗'}")
        return ok
    except Exception as e:
        print(f"  ✗ Firmware verification failed: {e}")
        return False


def verify_script(ip: str) -> bool:
    print("[Verify] Verifying Berry script...")
    try:
        resp = requests.get(
            f"http://{ip}/cm",
            params={"cmnd": "ScriptVersion"},
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"  ✗ ScriptVersion HTTP {resp.status_code}")
            return False

        data = resp.json()
        version = str(data.get("ScriptVersion", "")).strip()
        ok = version == EXPECTED_SCRIPT_VERSION
        print(f"  Script version: {version} {'✓' if ok else '✗'}")
        return ok
    except Exception as e:
        print(f"  ✗ Script verification failed: {e}")
        return False


# -------- Orchestration (one-device flow) --------

if __name__ == "__main__":
    config = load_config()
    router_ssid = config["ssid"]
    router_password = config["password"]

    print(f"Target router SSID: {router_ssid}")
    print(f"IP discovery order: {IP_DISCOVERY_ORDER}")
    print("Assumption: LAN (eth0) has access to the router subnet.\n")

    # STEP 1: Connect to AP
    print("=== STEP 1: Connect WiFi to AccuSaver AP ===")
    if not connect_wifi_to_ap():
        print("✗ Could not connect WiFi to Tasmota AP")
        raise SystemExit(1)

    if not ensure_ap_http():
        print("✗ Tasmota AP HTTP not reachable, aborting")
        raise SystemExit(1)

    # STEP 2: Phase 1 - WiFi + OtaUrl
    print("\n=== STEP 2: Phase 1 - Send WiFi credentials + OtaUrl ===")
    if not send_phase1_commands(router_ssid, router_password):
        print("✗ Phase 1 failed")
        raise SystemExit(1)

    # STEP 3: Wait for device to join home WiFi
    print("\n=== STEP 3: Wait for device to join home WiFi ===")
    print("Waiting 20 seconds before LAN discovery...")
    time.sleep(20)

    # OPTIONAL: free wlan0 again (keeps things clean)
    disconnect_wifi()

    # STEP 4: Discover device IP using chosen strategies (LAN side)
    print("\n=== STEP 4: Discover device IP (LAN) ===")
    device_ip = resolve_device_ip(IP_DISCOVERY_ORDER)
    if not device_ip:
        print("✗ Could not find device IP on home network")
        raise SystemExit(1)

    # STEP 5: Phase 2 - UrlFetch + Upgrade 1 (safeboot)
    print("\n=== STEP 5: Phase 2 - UrlFetch + Upgrade 1 ===")
    if not send_phase2_commands(device_ip):
        print("✗ Phase 2 failed")
        raise SystemExit(1)

    # STEP 6: Wait for safeboot to complete (ScriptVersion)
    print("\n=== STEP 6: Wait for safeboot / ScriptVersion ===")
    time.sleep(10)
    if not wait_for_script_after_safeboot(device_ip, EXPECTED_SCRIPT_VERSION):
        print("✗ Safeboot / Berry script installation failed")
        raise SystemExit(1)

    # STEP 7: Reset 4 and wait online
    print("\n=== STEP 7: Reset 4 and wait for device online ===")
    if not send_reset4(device_ip):
        print("✗ Reset 4 failed")
        raise SystemExit(1)

    time.sleep(5)
    if not wait_for_device_online(device_ip):
        print("✗ Device offline after Reset 4")
        raise SystemExit(1)

    # STEP 8: Verification
    print("\n=== STEP 8: Verify firmware and script ===")
    fw_ok = verify_firmware(device_ip)
    script_ok = verify_script(device_ip)
    if not (fw_ok and script_ok):
        print("✗ Verification failed")
        raise SystemExit(1)

    print("✓ Verification complete!")

    # STEP 9: Reset 1 (factory reset)
    print("\n=== STEP 9: Factory reset (Reset 1) ===")
    send_reset1(device_ip)

    print("\n════════════════════════════════════════")
    print(f"✓ SUCCESS: {TASMOTA_HOSTNAME} ({device_ip}) fully provisioned")
    print("════════════════════════════════════════")
