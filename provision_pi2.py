import json
import subprocess
import time
from typing import Optional, List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# -------- Configurable constants --------
FIRMWARE_URL = "https://github.com/aran-arunakiri/script-test/raw/refs/heads/main/tasmota32c2-withfs.bin"
BERRY_SCRIPT_URL = "https://raw.githubusercontent.com/aran-arunakiri/script-test/refs/heads/main/autoexec.be"

TASMOTA_AP_SSID = "accusaver-3FCAD739"
TASMOTA_AP_IP = "192.168.4.1"
TASMOTA_HOSTNAME = (
    "accusaver-3FCAD739"  # (AP hostname, LAN hostname will be 'accusaver' on new fw)
)

EXPECTED_FIRMWARE_DATE = "2025-12-04T13:37:42"
EXPECTED_SCRIPT_VERSION = "1.0.0"

WIFI_INTERFACE = "wlan0"  # Pi Wi-Fi interface (AP side)
LAN_INTERFACE = "eth0"  # interface used to reach your router/LAN

SCAN_START_HOST = 1
SCAN_END_HOST = 254

# LAN discovery: "scan" or "mdns" or both
IP_DISCOVERY_ORDER: List[str] = ["scan"]

# For testing batch of 4 – later you can bump this to 18
MAX_DEVICES = 5

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


def detect_lan_prefix(interface: str) -> str:
    """
    Detect the LAN subnet prefix for the given interface.
    Example: if IP is 192.168.2.23 => returns '192.168.2.'
    """
    print(f"[LAN] Detecting LAN prefix on interface {interface}...")
    result = run_cmd(["ip", "-4", "addr", "show", interface])
    out = result.stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            ip = line.split()[1].split("/")[0]
            parts = ip.split(".")
            prefix = ".".join(parts[:3]) + "."
            print(f"[LAN] Detected LAN prefix: {prefix}")
            return prefix
    raise RuntimeError(f"Could not detect LAN prefix on {interface}")


# -------- Wi-Fi / AP handling (Pi / Linux) --------


def disconnect_wifi():
    print(f"[WiFi] Disconnecting {WIFI_INTERFACE}...")
    run_cmd(["nmcli", "device", "disconnect", WIFI_INTERFACE])


def connect_wifi_to_ap(max_wait_seconds: int = 20) -> bool:
    """
    Use nmcli to connect wlan0 to the AccuSaver AP (open network).
    Performs a WiFi rescan first to refresh AP visibility.
    """
    disconnect_wifi()

    print(f"[WiFi] Scanning for {TASMOTA_AP_SSID}...")
    run_cmd(["nmcli", "device", "wifi", "rescan"])
    time.sleep(2)  # give the scan a moment

    # List networks
    scan_list = run_cmd(["nmcli", "-f", "SSID,CHAN,SIGNAL", "device", "wifi"])
    lines = scan_list.stdout.splitlines()

    # Filter SSIDs starting with "accusaver-"
    accusavers = [
        line for line in lines if line.strip().lower().startswith("accusaver")
    ]

    print("  Available networks:")
    if accusavers:
        for line in accusavers:
            print(" ", line)
    else:
        print("  (no accusavers found)")

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


# -------- Phase 1: AP-side provisioning (WiFi creds + OtaUrl) --------


def send_phase1_commands(router_ssid: str, router_password: str, max_retries=3) -> bool:
    """
    Phase 1 (AP): send WiFi credentials + OtaUrl (no UrlFetch/Upgrade yet).
    Mirrors _sendPhase1Commands() from Flutter.
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


def find_all_devices_by_scan(
    subnet_prefix: str,
    start_host: int = 1,
    end_host: int = 254,
    timeout_seconds: float = 0.3,
    max_workers: int = 32,
) -> Dict[str, str]:
    """
    Scan subnet_prefix.X using Status 5 on each IP.
    Return dict ip -> hostname for all AccuSaver/Tasmota-like devices.
    """
    print(
        f"[IP discovery: scan] Scanning {subnet_prefix}{start_host}-{end_host} via Status 5 (parallel)"
    )

    found: Dict[str, str] = {}

    def probe(host: int) -> Optional[Tuple[str, str]]:
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
                    real_ip = ip_reported or ip
                    return (real_ip, hostname)
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
                ip, hostname = result
                found[ip] = hostname

    if found:
        print(f"[scan] Found {len(found)} AccuSaver/Tasmota device(s) on LAN")
        for ip, hostname in found.items():
            print(f"  - {ip} ({hostname})")
    else:
        print("  ✗ scan-based IP discovery found no devices")

    return found


# -------- Phase 2: LAN-side script fetch + upgrade --------


def send_script_fetch(device_ip: str, max_retries=3) -> bool:
    """
    Phase 2a (LAN): UrlFetch <BERRY_SCRIPT_URL> only.

    We only treat this as success if the device replies with:
        {"UrlFetch": "Done"}

    Any other result (including "Failed", missing field, bad JSON, or
    network errors) will be retried up to max_retries, then we abort.
    """
    if not BERRY_SCRIPT_URL:
        print("[Phase 2a] No BERRY_SCRIPT_URL set, skipping UrlFetch")
        return True

    url = f"http://{device_ip}/cm"
    commands = f"UrlFetch {BERRY_SCRIPT_URL}"
    print(f"[Phase 2a] ({device_ip}) Sending UrlFetch")

    for attempt in range(1, max_retries + 1):
        print(f"  ({device_ip}) UrlFetch attempt {attempt}/{max_retries}...")
        try:
            resp = requests.get(url, params={"cmnd": commands}, timeout=15)
        except Exception as e:
            print(f"  ✗ ({device_ip}) UrlFetch request failed: {e}")
            if attempt < max_retries:
                print(f"  ({device_ip}) Retrying UrlFetch in 3 seconds...")
                time.sleep(3)
            continue

        if resp.status_code != 200:
            print(
                f"  ✗ ({device_ip}) HTTP {resp.status_code} during UrlFetch, body={resp.text!r}"
            )
            if attempt < max_retries:
                print(f"  ({device_ip}) Retrying UrlFetch in 3 seconds...")
                time.sleep(3)
            continue

        # HTTP 200 – parse JSON and inspect UrlFetch result
        try:
            data = resp.json()
        except Exception:
            print(f"  ✗ ({device_ip}) UrlFetch: invalid JSON response: {resp.text!r}")
            if attempt < max_retries:
                print(f"  ({device_ip}) Retrying UrlFetch in 3 seconds...")
                time.sleep(3)
            continue

        result = data.get("UrlFetch")
        print(f"  ✓ ({device_ip}) UrlFetch HTTP 200, response: {data}")

        if result == "Done":
            # Only here do we consider UrlFetch successful.
            return True
        else:
            print(f"  ✗ ({device_ip}) UrlFetch result {result!r}, " f"expected 'Done'.")
            if attempt < max_retries:
                print(f"  ({device_ip}) Retrying UrlFetch in 3 seconds...")
                time.sleep(3)
            # else fall through and fail.

    print(
        f"✗ ({device_ip}) UrlFetch failed after {max_retries} attempts, aborting this device."
    )
    return False


def send_upgrade(device_ip: str, max_retries=3) -> bool:
    """
    Phase 2b (LAN): Upgrade 1 only.
    Relies on OtaUrl set during Phase 1.
    """
    url = f"http://{device_ip}/cm"
    commands = "Upgrade 1"
    print(f"[Phase 2b] ({device_ip}) Sending Upgrade 1")
    for attempt in range(1, max_retries + 1):
        print(f"  ({device_ip}) Upgrade attempt {attempt}/{max_retries}...")
        try:
            resp = requests.get(url, params={"cmnd": commands}, timeout=15)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = resp.text
                print(f"  ✓ ({device_ip}) Upgrade HTTP 200, response: {data}")
                return True
            else:
                print(f"  ✗ ({device_ip}) HTTP {resp.status_code} during Upgrade 1")
        except Exception as e:
            print(f"  ✗ ({device_ip}) Upgrade request failed: {e}")
        if attempt < max_retries:
            print(f"  ({device_ip}) Retrying Upgrade in 5 seconds...")
            time.sleep(5)
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
    print(f"[Safeboot] ({ip}) Waiting for safeboot to complete...")

    for attempt in range(1, max_attempts + 1):
        print(f"  ({ip}) ScriptVersion check {attempt}/{max_attempts}...")
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
                        f"    ({ip}) ScriptVersion: {version} (expected: {expected_version})"
                    )
                    if version == expected_version:
                        print(f"  ✓ ({ip}) ScriptVersion matches, safeboot complete!")
                        return True
            else:
                print(f"    ({ip}) HTTP {resp.status_code} from ScriptVersion")
        except Exception as e:
            print(f"    ({ip}) ScriptVersion request error: {e}")

        time.sleep(delay_seconds)

    print(f"  ✗ ({ip}) Timeout waiting for ScriptVersion")
    return False


# -------- Resets and online wait --------


def send_reset4(ip: str) -> bool:
    print(f"[Reset 4] ({ip}) Sending Reset 4 (activate firmware, keep WiFi)")
    try:
        requests.get(f"http://{ip}/cm", params={"cmnd": "Reset 4"}, timeout=5)
        print(f"  ✓ ({ip}) Reset 4 sent")
        return True
    except Exception as e:
        print(f"  ✗ ({ip}) Failed to send Reset 4: {e}")
        return False


def send_reset1(ip: str) -> bool:
    print(f"[Reset 1] ({ip}) Sending Reset 1 (factory reset)")
    try:
        requests.get(f"http://{ip}/cm", params={"cmnd": "Reset 1"}, timeout=5)
        print(f"  ✓ ({ip}) Reset 1 sent")
        return True
    except Exception as e:
        print(f"  ✗ ({ip}) Failed to send Reset 1: {e}")
        return False


def wait_for_device_online(
    ip: str, max_attempts: int = 20, delay_seconds: int = 3
) -> bool:
    print(f"[Online check] ({ip}) Waiting for device to come back online...")
    for attempt in range(1, max_attempts + 1):
        print(f"  ({ip}) Status 0 check {attempt}/{max_attempts}...")
        try:
            resp = requests.get(
                f"http://{ip}/cm",
                params={"cmnd": "Status 0"},
                timeout=5,
            )
            if resp.status_code == 200:
                print(f"  ✓ ({ip}) Device is back online")
                return True
        except Exception:
            pass
        time.sleep(delay_seconds)

    print(f"  ✗ ({ip}) Timeout waiting for device")
    return False


# -------- Verification --------


def verify_firmware(ip: str) -> bool:
    print(f"[Verify] ({ip}) Verifying firmware...")
    try:
        resp = requests.get(
            f"http://{ip}/cm",
            params={"cmnd": "Status 2"},
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"  ✗ ({ip}) Status 2 HTTP {resp.status_code}")
            return False

        data = resp.json()
        build_date = str(data.get("StatusFWR", {}).get("BuildDateTime", "")).strip()
        ok = build_date == EXPECTED_FIRMWARE_DATE
        print(f"  ({ip}) Firmware BuildDateTime: {build_date} {'✓' if ok else '✗'}")
        return ok
    except Exception as e:
        print(f"  ✗ ({ip}) Firmware verification failed: {e}")
        return False


def verify_script(ip: str) -> bool:
    print(f"[Verify] ({ip}) Verifying Berry script...")
    try:
        resp = requests.get(
            f"http://{ip}/cm",
            params={"cmnd": "ScriptVersion"},
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"  ✗ ({ip}) ScriptVersion HTTP {resp.status_code}")
            return False

        data = resp.json()
        version = str(data.get("ScriptVersion", "")).strip()
        ok = version == EXPECTED_SCRIPT_VERSION
        print(f"  ({ip}) Script version: {version} {'✓' if ok else '✗'}")
        return ok
    except Exception as e:
        print(f"  ✗ ({ip}) Script verification failed: {e}")
        return False


# -------- Phase B per-device worker (LAN) --------


def provision_device_on_lan(ip: str) -> Tuple[str, bool, float]:
    """
    Full LAN-side flow for a single device, run in a thread.
    Returns (ip, success, elapsed_seconds).
    """
    start = time.time()
    success = False
    try:
        # STEP B1: UrlFetch script
        print(f"\n[LAN worker] ({ip}) Starting LAN provisioning...")
        if not send_script_fetch(ip):
            print(f"[LAN worker] ({ip}) UrlFetch failed, aborting this device")
            return ip, False, time.time() - start

        # STEP B2: Upgrade 1 (firmware OTA)
        if not send_upgrade(ip):
            print(f"[LAN worker] ({ip}) Upgrade failed, aborting this device")
            return ip, False, time.time() - start

        # STEP B3: Wait for safeboot / ScriptVersion
        time.sleep(10)  # initial grace period
        if not wait_for_script_after_safeboot(ip, EXPECTED_SCRIPT_VERSION):
            print(f"[LAN worker] ({ip}) Safeboot / script install failed")
            return ip, False, time.time() - start

        # STEP B4: Reset 4 and wait online
        if not send_reset4(ip):
            print(f"[LAN worker] ({ip}) Reset 4 failed")
            return ip, False, time.time() - start

        time.sleep(5)
        if not wait_for_device_online(ip):
            print(f"[LAN worker] ({ip}) Device did not come back after Reset 4")
            return ip, False, time.time() - start

        # STEP B5: Verification
        fw_ok = verify_firmware(ip)
        script_ok = verify_script(ip)
        if not (fw_ok and script_ok):
            print(f"[LAN worker] ({ip}) Verification failed")
            return ip, False, time.time() - start

        # STEP B6: Factory reset
        send_reset1(ip)
        success = True
        return ip, True, time.time() - start

    finally:
        elapsed = time.time() - start
        print(
            f"[LAN worker] ({ip}) Finished with success={success}, elapsed={elapsed:.1f}s"
        )


# -------- Main --------

if __name__ == "__main__":
    config = load_config()
    router_ssid = config["ssid"]
    router_password = config["password"]

    script_start = time.time()

    print("=== MULTI-DEVICE MODE (HORIZONTAL) ===\n")
    print(f"Target router SSID: {router_ssid}")
    print(f"IP discovery order: {IP_DISCOVERY_ORDER}")
    print(f"Batch size: {MAX_DEVICES}\n")

    # ---------- PHASE A: AP provisioning for N devices ----------

    ap_start = time.time()
    ap_provisioned = 0
    ap_durations: List[float] = []

    while ap_provisioned < MAX_DEVICES:
        device_number = ap_provisioned + 1
        print("\n==============================================")
        print(f" PHASE A: Ready for device #{device_number} of {MAX_DEVICES}")
        print(" Power on the next AccuSaver device now.")
        print("==============================================\n")

        device_ap_start = time.time()

        # Connect to AP
        print("=== AP STEP: Connect WiFi to AccuSaver AP ===")
        while not connect_wifi_to_ap():
            print("✗ Could not connect to AP, retrying in 3 seconds...")
            time.sleep(3)

        if not ensure_ap_http():
            print("✗ AP unreachable, skipping this device...\n")
            continue

        # Send WiFi creds + OtaUrl
        print("\n=== AP STEP: Send WiFi credentials + OtaUrl ===")
        if not send_phase1_commands(router_ssid, router_password):
            print("✗ Phase 1 failed, skipping this device...\n")
            continue

        # Small grace period so the device can process, then disconnect
        print("\n=== AP STEP: Disconnect and move to next device ===")
        time.sleep(2)
        disconnect_wifi()

        device_ap_elapsed = time.time() - device_ap_start
        ap_durations.append(device_ap_elapsed)
        ap_provisioned += 1

        print("\n==============================================================")
        print(f"✓ PHASE A SUCCESS: Device #{device_number} AP-provisioned")
        print(
            f"  AP provisioning time for this device: {device_ap_elapsed:.1f} seconds"
        )
        print(f"  AP-provisioned devices: {ap_provisioned}/{MAX_DEVICES}")
        print("==============================================================\n")

    total_ap_time = time.time() - ap_start
    print("=== PHASE A COMPLETE ===")
    print(f"Total AP provisioning time: {total_ap_time:.1f} seconds")
    if ap_durations:
        avg_ap = sum(ap_durations) / len(ap_durations)
        print(f"Average AP time per device: {avg_ap:.1f} seconds\n")

    # ---------- PHASE B: LAN batch upgrade & verify ----------

    print("\n=== PHASE B: Discover devices on LAN and upgrade in parallel ===\n")

    try:
        lan_prefix = detect_lan_prefix(LAN_INTERFACE)
    except RuntimeError as e:
        print(f"✗ {e}, cannot proceed with PHASE B.")
        exit(1)

    # Discover up to MAX_DEVICES devices whose hostname starts with 'accusaver'
    lan_discovery_start = time.time()
    devices_found: Dict[str, str] = {}
    max_discovery_rounds = 12  # e.g. 12 * 5s = 60 seconds total
    for round_idx in range(1, max_discovery_rounds + 1):
        print(f"\n[LAN discovery] Round {round_idx}/{max_discovery_rounds}...")
        scan_results = find_all_devices_by_scan(
            lan_prefix, SCAN_START_HOST, SCAN_END_HOST
        )
        # Filter hostnames starting with 'accusaver'
        for ip, hostname in scan_results.items():
            if hostname.startswith("accusaver"):
                devices_found[ip] = hostname

        print(
            f"[LAN discovery] AccuSaver devices found so far: {len(devices_found)}/{MAX_DEVICES}"
        )
        for ip, hostname in devices_found.items():
            print(f"  - {ip} ({hostname})")

        if len(devices_found) >= MAX_DEVICES:
            print("[LAN discovery] Found required number of devices on LAN.")
            break

        time.sleep(5)

    lan_discovery_elapsed = time.time() - lan_discovery_start

    if len(devices_found) == 0:
        print("✗ No AccuSaver devices found on LAN. Cannot continue.")
        exit(1)

    if len(devices_found) < MAX_DEVICES:
        print(
            f"⚠ WARNING: Only {len(devices_found)} AccuSaver device(s) discovered on LAN,"
        )
        print(
            f"  but batch expects {MAX_DEVICES}. Proceeding with discovered devices only.\n"
        )

    print(
        f"\n=== PHASE B: LAN discovery complete in {lan_discovery_elapsed:.1f} seconds ==="
    )
    print("Devices to process:")
    for ip, hostname in devices_found.items():
        print(f"  - {ip} ({hostname})")
    print()

    lan_batch_start = time.time()
    lan_results: List[Tuple[str, bool, float]] = []

    # Use a thread pool to process devices in parallel (horizontalization)
    with ThreadPoolExecutor(max_workers=min(len(devices_found), 8)) as executor:
        future_map = {
            executor.submit(provision_device_on_lan, ip): ip
            for ip in devices_found.keys()
        }

        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                ip_result, success, elapsed = future.result()
                lan_results.append((ip_result, success, elapsed))
            except Exception as e:
                print(f"[LAN worker] ({ip}) raised unexpected exception: {e}")
                lan_results.append((ip, False, 0.0))

    lan_batch_elapsed = time.time() - lan_batch_start

    # ---------- Stats & summary ----------

    total_success = sum(1 for _, ok, _ in lan_results if ok)
    total_fail = len(lan_results) - total_success

    print("\n=== BATCH SUMMARY ===")
    print(f"Batch size (expected): {MAX_DEVICES}")
    print(f"Devices discovered on LAN: {len(devices_found)}")
    print(f"LAN workers executed: {len(lan_results)}")
    print(f"  ✓ Success: {total_success}")
    print(f"  ✗ Failed: {total_fail}\n")

    for ip, success, elapsed in lan_results:
        print(f"  Device {ip}: success={success}, LAN phase time={elapsed:.1f} seconds")

    total_script_time = time.time() - script_start
    print("\n=== TIMING SUMMARY ===")
    print(f"Total script runtime (AP + LAN): {total_script_time:.1f} seconds")
    if total_success > 0:
        avg_total_per_device = total_script_time / total_success
        print(
            f"Average total time per successful device: {avg_total_per_device:.1f} seconds"
        )

    if ap_durations:
        avg_ap = sum(ap_durations) / len(ap_durations)
        print(f"Average AP-only time per device: {avg_ap:.1f} seconds")

    if lan_results and total_success > 0:
        avg_lan = sum(elapsed for _, ok, elapsed in lan_results if ok) / total_success
        print(f"Average LAN-only time per successful device: {avg_lan:.1f} seconds")

    print("\nDone.")
