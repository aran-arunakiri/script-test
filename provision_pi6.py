import json
import subprocess
import time
import threading
from typing import Optional, List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.exceptions import ReadTimeout, ConnectionError, Timeout
import sys


# -------- Configurable constants --------
FIRMWARE_URL = "http://192.168.2.59/tasmota32c2-withfs.bin"
BERRY_SCRIPT_URL = "http://192.168.2.59/autoexec.be"

TASMOTA_AP_SSID = "accusaver-3FCAD739"
TASMOTA_AP_IP = "192.168.4.1"
TASMOTA_HOSTNAME = "accusaver-3FCAD739"

EXPECTED_FIRMWARE_DATE = "2025-12-04T13:37:42"
EXPECTED_SCRIPT_VERSION = "1.0.0"

WIFI_INTERFACE = "wlan0"
LAN_INTERFACE = "eth0"

SCAN_START_HOST = 1
SCAN_END_HOST = 254

IP_DISCOVERY_ORDER: List[str] = ["scan"]

EXPECTED_DEVICES = 18

# Stagger delay between each device starting LAN provisioning (seconds)
STAGGER_DELAY = 1.0

# Toggle: whether to exclude already-provisioned BSSIDs when picking the next AP
# True  = old behaviour (skip provisioned BSSIDs)
# False = allow reusing APs even if their BSSID is in provisioned_bssids
AP_EXCLUSION_ENABLED = False

# -------- Progress tracking --------
progress_lock = threading.Lock()
device_status: Dict[str, str] = {}  # ip -> status string

_last_progress_len = 0
_last_progress_time = 0.0


def update_status(ip: str, status: str):
    """Update device status and refresh progress bar (single line)."""
    global device_status
    with progress_lock:
        # Skip redundant updates
        if device_status.get(ip) == status:
            return
        device_status[ip] = status
        print_progress_locked()


def print_progress_locked():
    """Print a single-line progress bar. Caller must hold progress_lock."""
    global _last_progress_len, _last_progress_time

    now = time.time()
    # throttle updates to avoid excessive flicker (max ~5 per second)
    if now - _last_progress_time < 0.2:
        return
    _last_progress_time = now

    total = len(device_status)
    complete = sum(1 for s in device_status.values() if s.startswith("✓"))
    failed = sum(1 for s in device_status.values() if s.startswith("✗"))
    in_progress = total - complete - failed

    bar_width = 30
    done = complete + failed
    frac = (done / total) if total > 0 else 0.0
    done_chars = int(bar_width * frac)
    bar = "#" * done_chars + "-" * (bar_width - done_chars)

    line = f"[{bar}] ✓ {complete}/{total} complete | ✗ {failed} failed | ⋯ {in_progress} in progress"

    # overwrite same line; pad with spaces to fully clear previous content
    padded = line.ljust(_last_progress_len)
    sys.stdout.write("\r" + padded)
    sys.stdout.flush()
    _last_progress_len = len(padded)


# Backwards-compatible wrapper if you still call print_progress() elsewhere
def print_progress():
    with progress_lock:
        print_progress_locked()


# -------- Helpers --------


def load_config():
    with open(".wifi-config.json", "r") as f:
        return json.load(f)


def run_cmd(cmd) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def get_current_ip(interface: str) -> Optional[str]:
    result = run_cmd(["ip", "-4", "addr", "show", interface])
    out = result.stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            ip = line.split()[1].split("/")[0]
            return ip
    return None


def detect_lan_prefix(interface: str) -> str:
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


def parse_wifi_scan(scan_output: str) -> List[Dict[str, str]]:
    """Parse nmcli wifi scan output into list of dicts with SSID, BSSID, CHAN, SIGNAL."""
    results = []
    lines = scan_output.strip().splitlines()
    if not lines:
        return results

    # Skip header line
    for line in lines[1:]:
        # Format: "SSID                BSSID              CHAN  SIGNAL"
        # Fields are separated by whitespace, but SSID might have spaces
        parts = line.split()
        if len(parts) >= 4:
            # Last 3 parts are BSSID, CHAN, SIGNAL
            # Everything before is SSID
            signal = parts[-1]
            chan = parts[-2]
            bssid = parts[-3]
            ssid = " ".join(parts[:-3])

            if ssid.lower().startswith("accusaver"):
                results.append(
                    {
                        "ssid": ssid,
                        "bssid": bssid,
                        "chan": chan,
                        "signal": signal,
                    }
                )

    return results


def scan_accusaver_aps() -> List[Dict[str, str]]:
    """
    Scan for AccuSaver APs and return list of unique APs (by BSSID).
    Used for initial sanity check before Phase A.
    """
    print(f"[WiFi] Scanning for AccuSaver APs (fresh scan)...")

    scan_result = run_cmd(
        [
            "nmcli",
            "-f",
            "SSID,BSSID,CHAN,SIGNAL",
            "device",
            "wifi",
            "list",
            "ifname",
            WIFI_INTERFACE,
            "--rescan",
            "yes",
        ]
    )

    all_aps = parse_wifi_scan(scan_result.stdout)

    # Deduplicate by BSSID (same AP can appear multiple times in scan)
    seen_bssids = set()
    unique_aps = []
    for ap in all_aps:
        if ap["bssid"] not in seen_bssids:
            seen_bssids.add(ap["bssid"])
            unique_aps.append(ap)

    # Sort by signal strength (strongest first)
    unique_aps.sort(key=lambda x: int(x["signal"]), reverse=True)

    print(f"  Found {len(unique_aps)} unique AccuSaver AP(s):")
    for ap in unique_aps:
        print(f"    {ap['bssid']}  CH:{ap['chan']}  SIG:{ap['signal']}")

    return unique_aps


def connect_wifi_to_ap(
    exclude_bssids: List[str] = None, max_wait_seconds: int = 20
) -> Optional[str]:
    """
    Connect to an AccuSaver AP, optionally excluding any BSSIDs in the exclude list.
    Returns the BSSID we connected to, or None on failure.
    """
    if exclude_bssids is None:
        exclude_bssids = []

    disconnect_wifi()
    run_cmd(["ip", "addr", "flush", "dev", WIFI_INTERFACE])

    print(f"[WiFi] Scanning for {TASMOTA_AP_SSID} (fresh scan)...")

    # Use --rescan yes for fresh results
    scan_result = run_cmd(
        [
            "nmcli",
            "-f",
            "SSID,BSSID,CHAN,SIGNAL",
            "device",
            "wifi",
            "list",
            "ifname",
            WIFI_INTERFACE,
            "--rescan",
            "yes",
        ]
    )

    # Parse scan results
    available_aps = parse_wifi_scan(scan_result.stdout)

    print("  Available AccuSaver networks:")
    if available_aps:
        for ap in available_aps:
            is_excluded = ap["bssid"] in exclude_bssids
            suffix = "(EXCLUDED)" if is_excluded else ""
            print(
                f"    {ap['ssid']}  {ap['bssid']}  CH:{ap['chan']}  SIG:{ap['signal']}  {suffix}"
            )
    else:
        print("    (no accusavers found)")
        return None

    # Filter out already-provisioned BSSIDs if exclusion is enabled
    if AP_EXCLUSION_ENABLED:
        candidate_aps = [
            ap for ap in available_aps if ap["bssid"] not in exclude_bssids
        ]
    else:
        # No exclusion: every visible AccuSaver AP is a candidate
        candidate_aps = list(available_aps)

    if not candidate_aps:
        print("  ✗ All visible AccuSaver APs have already been provisioned")
        return None

    # Pick the strongest signal from candidates
    target_ap = max(candidate_aps, key=lambda x: int(x["signal"]))
    target_bssid = target_ap["bssid"]

    print(
        f"[WiFi] Connecting to BSSID {target_bssid} (signal: {target_ap['signal']})..."
    )

    proc = run_cmd(
        [
            "nmcli",
            "device",
            "wifi",
            "connect",
            TASMOTA_AP_SSID,
            "bssid",
            target_bssid,
            "ifname",
            WIFI_INTERFACE,
        ]
    )

    if proc.returncode != 0:
        print(f"  ✗ nmcli connect error: {proc.stderr.strip()}")
        return None

    print(f"[WiFi] Waiting for 192.168.4.x on {WIFI_INTERFACE}...")
    for i in range(max_wait_seconds):
        time.sleep(1)
        ip = get_current_ip(WIFI_INTERFACE)
        print(f"  AP IP check {i + 1}/{max_wait_seconds}: {ip}")
        if ip and ip.startswith("192.168.4."):
            print(f"  ✓ On AP subnet: {ip} (BSSID: {target_bssid})")
            return target_bssid

    print("  ✗ Failed to get 192.168.4.x on Wi-Fi")
    return None


def ensure_ap_http(max_attempts: int = 5) -> bool:
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
    timeout_seconds: float = 1.0,  # was 0.3
    max_workers: int = 16,
) -> Dict[str, str]:
    """
    Scans subnet for AccuSaver/Tasmota devices using HTTP Status 5
    with retries matching scan.py behaviour.
    Returns IP->hostname mapping.
    """
    print(
        f"[IP discovery: scan] Scanning {subnet_prefix}{start_host}-{end_host} via Status 5 (parallel)"
    )

    found: Dict[str, str] = {}

    def probe_ip(ip: str) -> Optional[Tuple[str, str]]:
        url = f"http://{ip}/cm"

        # mimic scan.py retry behaviour
        for attempt in range(1, 3):
            try:
                resp = requests.get(
                    url, params={"cmnd": "Status 5"}, timeout=timeout_seconds
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                statusnet = data.get("StatusNET", {})

                hostname = (statusnet.get("Hostname", "") or "").lower()
                ip_reported = statusnet.get("IPAddress", "") or ip

                if hostname.startswith("accusaver") or hostname.startswith("tasmota"):
                    return (ip_reported, hostname)

            except Exception:
                if attempt == 2:
                    return None
                time.sleep(0.05)
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(probe_ip, f"{subnet_prefix}{h}"): h
            for h in range(start_host, end_host + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                reported_ip, hostname = result
                found[reported_ip] = hostname

    return found


# -------- Phase 2a: Script fetch (wait for "Done") --------


def send_script_fetch(
    device_ip: str, max_retries: int = 3, verbose: bool = True
) -> bool:
    if not BERRY_SCRIPT_URL:
        return True

    url = f"http://{device_ip}/cm"
    commands = f"UrlFetch {BERRY_SCRIPT_URL}"

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, params={"cmnd": commands}, timeout=30)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = {}

                url_fetch_result = str(data.get("UrlFetch", "")).strip()

                if url_fetch_result == "Done":
                    return True

        except Timeout:
            pass
        except Exception:
            pass

        if attempt < max_retries:
            time.sleep(3)

    return False


# -------- Phase 2b: Firmware upgrade --------


def send_upgrade(device_ip: str, max_retries=3) -> bool:
    url = f"http://{device_ip}/cm"
    commands = "Upgrade 1"

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, params={"cmnd": commands}, timeout=15)
            if resp.status_code == 200:
                return True
        except Exception:
            pass
        if attempt < max_retries:
            time.sleep(5)
    return False


def wait_for_script_after_safeboot(
    ip: str,
    expected_version: str,
    max_attempts: int = 30,
    delay_seconds: int = 5,
) -> bool:
    """Wait for device to come back after safeboot with correct script version."""
    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.get(
                f"http://{ip}/cm",
                params={"cmnd": "ScriptVersion"},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                version = str(data.get("ScriptVersion", "")).strip()
                if version == expected_version:
                    return True
        except Exception:
            pass
        time.sleep(delay_seconds)

    return False


# -------- Resets and online wait --------


def send_reset4(ip: str) -> bool:
    try:
        requests.get(f"http://{ip}/cm", params={"cmnd": "Reset 4"}, timeout=5)
        return True
    except Exception:
        return False


def send_reset1(ip: str, max_retries: int = 3, timeout_s: float = 5.0) -> bool:
    """
    Fire factory reset (Reset 1) with retries.
    We don't expect the device to come back online after this (it's going to the customer),
    so:
      * HTTP 200 = success
      * Timeout / connection drop = very likely success (reboot in progress)
      * Only repeated unexpected errors count as failure
    """
    url = f"http://{ip}/cm"
    params = {"cmnd": "Reset 1"}

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, params=params, timeout=timeout_s)
            if resp.status_code == 200:
                return True
        except Timeout:
            # device probably rebooting mid-response -> treat as success
            return True
        except ConnectionError:
            # connection dropped, also consistent with immediate reboot
            return True
        except Exception as e:
            print(f"  ✗ Reset 1 error on {ip} (attempt {attempt}/{max_retries}): {e}")

        if attempt < max_retries:
            time.sleep(1.0)

    return False


def wait_for_device_online(
    ip: str, max_attempts: int = 20, delay_seconds: int = 3
) -> bool:
    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.get(
                f"http://{ip}/cm",
                params={"cmnd": "Status 0"},
                timeout=5,
            )
            if resp.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(delay_seconds)
    return False


# -------- Verification --------


def verify_firmware(ip: str) -> bool:
    try:
        resp = requests.get(
            f"http://{ip}/cm",
            params={"cmnd": "Status 2"},
            timeout=10,
        )
        if resp.status_code != 200:
            return False

        data = resp.json()
        build_date = str(data.get("StatusFWR", {}).get("BuildDateTime", "")).strip()
        return build_date == EXPECTED_FIRMWARE_DATE
    except Exception:
        return False


def verify_script(ip: str) -> bool:
    try:
        resp = requests.get(
            f"http://{ip}/cm",
            params={"cmnd": "ScriptVersion"},
            timeout=10,
        )
        if resp.status_code != 200:
            return False

        data = resp.json()
        version = str(data.get("ScriptVersion", "")).strip()
        return version == EXPECTED_SCRIPT_VERSION
    except Exception:
        return False


# -------- Phase B per-device worker (LAN) --------


def provision_device_on_lan(
    ip: str, stagger_delay: float = 0.0
) -> Tuple[str, bool, float]:
    """
    Full LAN-side flow for a single device, run in a thread.
    Returns (ip, success, elapsed_seconds).
    """
    start = time.time()

    # Stagger start to avoid network congestion during firmware download
    if stagger_delay > 0:
        update_status(ip, f"⏳ Waiting {stagger_delay:.0f}s...")
        time.sleep(stagger_delay)

    # STEP B1: UrlFetch script
    update_status(ip, "📥 Fetching script...")
    if not send_script_fetch(ip):
        update_status(ip, "✗ Script fetch failed")
        return ip, False, time.time() - start

    # STEP B2: Upgrade 1 (firmware OTA)
    update_status(ip, "📦 Sending upgrade...")
    if not send_upgrade(ip):
        update_status(ip, "✗ Upgrade failed")
        return ip, False, time.time() - start

    # STEP B3: Wait for safeboot / ScriptVersion
    update_status(ip, "🔄 Safeboot (firmware download)...")
    time.sleep(10)
    if not wait_for_script_after_safeboot(ip, EXPECTED_SCRIPT_VERSION):
        update_status(ip, "✗ Safeboot timeout")
        return ip, False, time.time() - start

    # STEP B4: Reset 4 and wait online
    update_status(ip, "🔁 Rebooting...")
    if not send_reset4(ip):
        update_status(ip, "✗ Reset 4 failed")
        return ip, False, time.time() - start

    time.sleep(5)
    if not wait_for_device_online(ip):
        update_status(ip, "✗ Device offline after Reset 4")
        return ip, False, time.time() - start

    # STEP B5: Verification
    update_status(ip, "🔍 Verifying...")
    fw_ok = verify_firmware(ip)
    script_ok = verify_script(ip)
    if not (fw_ok and script_ok):
        update_status(ip, "✗ Verification failed")
        return ip, False, time.time() - start

    # STEP B6: Factory reset (final Reset 1, device not expected to come back)
    update_status(ip, "🧽 Factory reset (Reset 1)...")
    reset_ok = send_reset1(ip)

    elapsed = time.time() - start
    if reset_ok:
        update_status(ip, f"✓ Complete ({elapsed:.0f}s)")
    else:
        # still treat device as provisioned, but make it visible in the status text
        update_status(ip, f"✓ Complete (reset not confirmed, {elapsed:.0f}s)")

    return ip, True, elapsed


# -------- Main --------

if __name__ == "__main__":
    config = load_config()
    router_ssid = config["ssid"]
    router_password = config["password"]

    script_start = time.time()

    print("=== MULTI-DEVICE MODE (HORIZONTAL) ===\n")
    print(f"Target router SSID: {router_ssid}")
    print(f"IP discovery order: {IP_DISCOVERY_ORDER}")
    print(f"Expected devices: {EXPECTED_DEVICES}")
    print(f"Stagger delay: {STAGGER_DELAY}s\n")
    print(f"AP exclusion enabled: {AP_EXCLUSION_ENABLED}\n")

    # ---------- SANITY CHECK: Verify expected number of APs ----------

    print("=== PRE-FLIGHT CHECK: Scanning for AccuSaver APs ===\n")
    detected_aps = scan_accusaver_aps()
    detected_count = len(detected_aps)

    if detected_count != EXPECTED_DEVICES:
        print(f"\n✗ AP count mismatch!")
        print(f"  Detected: {detected_count} device(s)")
        print(f"  Expected: {EXPECTED_DEVICES} device(s)")
        if detected_count < EXPECTED_DEVICES:
            print(
                f"  → Power on {EXPECTED_DEVICES - detected_count} more device(s), or reduce EXPECTED_DEVICES"
            )
        else:
            print(
                f"  → {detected_count - EXPECTED_DEVICES} extra device(s) in range. Remove them or increase EXPECTED_DEVICES"
            )
        exit(1)

    print(f"\n✓ Pre-flight check passed: {detected_count} AccuSaver AP(s) detected\n")

    # ---------- PHASE A: AP provisioning for N devices ----------

    ap_start = time.time()
    ap_provisioned = 0
    ap_durations: List[float] = []
    provisioned_bssids: List[str] = []  # Track BSSIDs we've already provisioned

    while ap_provisioned < EXPECTED_DEVICES:
        device_number = ap_provisioned + 1
        print("\n==============================================")
        print(f" PHASE A: Ready for device #{device_number} of {EXPECTED_DEVICES}")
        print(" Power on the next AccuSaver device now.")
        print("==============================================\n")

        device_ap_start = time.time()

        # Connect to AP (excluding already-provisioned BSSIDs)
        print("=== AP STEP: Connect WiFi to AccuSaver AP ===")
        connected_bssid = None
        while connected_bssid is None:
            connected_bssid = connect_wifi_to_ap(exclude_bssids=provisioned_bssids)
            if connected_bssid is None:
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

        # Track only if AP connection actually succeeded
        ip = get_current_ip(WIFI_INTERFACE)
        if ip and ip.startswith("192.168.4."):
            provisioned_bssids.append(connected_bssid)
            print(f"✓ Marked {connected_bssid} as provisioned")
        else:
            print(f"⚠️ Not excluding {connected_bssid} — AP connection incomplete")

        # Small grace period so the device can process, then disconnect
        print("\n=== AP STEP: Disconnect and move to next device ===")
        time.sleep(2)
        disconnect_wifi()

        device_ap_elapsed = time.time() - device_ap_start
        ap_durations.append(device_ap_elapsed)
        ap_provisioned += 1

        print("\n==============================================================")
        print(f"✓ PHASE A SUCCESS: Device #{device_number} AP-provisioned")
        print(f"  BSSID: {connected_bssid}")
        print(
            f"  AP provisioning time for this device: {device_ap_elapsed:.1f} seconds"
        )
        print(f"  AP-provisioned devices: {ap_provisioned}/{EXPECTED_DEVICES}")
        print(f"  Provisioned BSSIDs: {provisioned_bssids}")
        print("==============================================================\n")

    total_ap_time = time.time() - ap_start
    print("=== PHASE A COMPLETE ===")
    print(f"Total AP provisioning time: {total_ap_time:.1f} seconds")
    if ap_durations:
        avg_ap = sum(ap_durations) / len(ap_durations)
        print(f"Average AP time per device: {avg_ap:.1f} seconds")
    print(f"Provisioned BSSIDs ({len(provisioned_bssids)}):")
    for bssid in provisioned_bssids:
        print(f"  - {bssid}")
    print()

    # ---------- PHASE B: LAN batch upgrade & verify ----------

    print("\n=== PHASE B: Discover devices on LAN and upgrade in parallel ===\n")

    try:
        lan_prefix = detect_lan_prefix(LAN_INTERFACE)
    except RuntimeError as e:
        print(f"✗ {e}, cannot proceed with PHASE B.")
        exit(1)

    # Discover up to EXPECTED_DEVICES devices whose hostname starts with 'accusaver'
    lan_discovery_start = time.time()
    devices_found: Dict[str, str] = {}
    max_discovery_rounds = 12
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
            f"[LAN discovery] AccuSaver devices found so far: {len(devices_found)}/{EXPECTED_DEVICES}"
        )
        for ip, hostname in devices_found.items():
            print(f"  - {ip} ({hostname})")

        if len(devices_found) >= EXPECTED_DEVICES:
            print("[LAN discovery] Found required number of devices on LAN.")
            break

        time.sleep(5)

    lan_discovery_elapsed = time.time() - lan_discovery_start

    if len(devices_found) == 0:
        print("✗ No AccuSaver devices found on LAN. Cannot continue.")
        exit(1)

    if len(devices_found) < EXPECTED_DEVICES:
        print(
            f"✗ ERROR: Only {len(devices_found)}/{EXPECTED_DEVICES} AccuSaver device(s) discovered on LAN."
        )
        print("  Aborting. Make sure all devices are powered on and connected to WiFi.")
        exit(1)
    print(
        f"\n=== PHASE B: LAN discovery complete in {lan_discovery_elapsed:.1f} seconds ==="
    )
    print("Devices to process:")
    for ip, hostname in devices_found.items():
        print(f"  - {ip} ({hostname})")
    print()

    lan_batch_start = time.time()
    lan_results: List[Tuple[str, bool, float]] = []

    # Initialize progress tracking
    device_status.clear()
    for ip in devices_found.keys():
        device_status[ip] = "⏳ Queued"

    print("\n=== PHASE B: Starting parallel upgrades ===")
    # initial progress bar draw
    print_progress()

    # Use a thread pool to process devices in parallel with staggered starts
    with ThreadPoolExecutor(max_workers=min(len(devices_found), 16)) as executor:
        future_map = {}
        for idx, ip in enumerate(devices_found.keys()):
            stagger = idx * STAGGER_DELAY
            future = executor.submit(provision_device_on_lan, ip, stagger)
            future_map[future] = ip

        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                ip_result, success, elapsed = future.result()
                lan_results.append((ip_result, success, elapsed))
            except Exception as e:
                update_status(ip, f"✗ Exception: {e}")
                lan_results.append((ip, False, 0.0))

    lan_batch_elapsed = time.time() - lan_batch_start

    # Move to a new line after the live progress bar
    print()

    # ---------- Final Summary ----------

    total_success = sum(1 for _, ok, _ in lan_results if ok)
    total_fail = len(lan_results) - total_success

    print("\n" + "=" * 60)
    print("=== FINAL RESULTS ===")
    print("=" * 60)

    # Show final status of each device
    for ip, success, elapsed in sorted(lan_results, key=lambda x: x[0]):
        status = "✓" if success else "✗"
        print(f"  {status} {ip}: {elapsed:.1f}s")

    print()
    print(f"  Total: {total_success}/{len(lan_results)} succeeded, {total_fail} failed")

    total_script_time = time.time() - script_start
    print(f"\n=== TIMING ===")
    print(
        f"  Phase A (AP provisioning): {total_ap_time:.1f}s ({len(ap_durations)} devices)"
    )
    print(f"  Phase B (LAN upgrades):    {lan_batch_elapsed:.1f}s")
    print(f"  Total runtime:             {total_script_time:.1f}s")

    if total_success > 0:
        avg_total = total_script_time / total_success
        print(f"  Average per device:        {avg_total:.1f}s")

    print("\nDone.")
