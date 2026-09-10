import time
import json
import subprocess
from typing import Optional, List, Dict
import requests

# -------- Configuraties --------
TASMOTA_AP_SSID = "accusaver-3FCAD739"
TASMOTA_AP_IP = "192.168.4.1"

WIFI_INTERFACE = "wlan0"
LAN_INTERFACE = "eth0"

SCAN_START_HOST = 1
SCAN_END_HOST = 254

STRICT_SSID_MATCH = True

# -------- Helper Functies --------

def load_config():
    with open(".wifi-config.json", "r") as f:
        return json.load(f)

def run_cmd(cmd) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)

def get_current_ip(interface: str) -> Optional[str]:
    result = run_cmd(["ip", "-4", "addr", "show", interface])
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            return line.split()[1].split("/")[0]
    return None

def detect_lan_prefix(interface: str) -> str:
    result = run_cmd(["ip", "-4", "addr", "show", interface])
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            ip = line.split()[1].split("/")[0]
            parts = ip.split(".")
            return ".".join(parts[:3]) + "."
    raise RuntimeError(f"Kan geen LAN-prefix detecteren op {interface}")

def disconnect_wifi():
    run_cmd(["nmcli", "device", "disconnect", WIFI_INTERFACE])

def parse_wifi_scan(scan_output: str) -> List[Dict[str, str]]:
    results = []
    lines = scan_output.strip().splitlines()
    if not lines:
        return results

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        signal = parts[-1]
        chan = parts[-2]
        bssid = parts[-3]
        ssid = " ".join(parts[:-3]).strip()

        if not ssid:
            continue

        ssid_l = ssid.lower()
        target_l = TASMOTA_AP_SSID.lower()

        include = False
        if STRICT_SSID_MATCH:
            if ssid_l == target_l:
                include = True
        else:
            if ssid_l.startswith("accusaver"):
                include = True

        if include:
            results.append({"ssid": ssid, "bssid": bssid, "chan": chan, "signal": signal})

    return results

def connect_wifi_to_ap(max_wait_seconds: int = 20) -> Optional[str]:
    disconnect_wifi()
    run_cmd(["ip", "addr", "flush", "dev", WIFI_INTERFACE])

    scan_result = run_cmd([
        "nmcli", "-f", "SSID,BSSID,CHAN,SIGNAL", "device", "wifi",
        "list", "ifname", WIFI_INTERFACE, "--rescan", "yes"
    ])

    available_aps = parse_wifi_scan(scan_result.stdout)
    if not available_aps:
        return None

    target_ap = max(available_aps, key=lambda x: int(x["signal"]))
    target_bssid = target_ap["bssid"]

    print(f"[WiFi] Verbinden met {target_ap['ssid']} ({target_bssid})...")
    proc = run_cmd([
        "nmcli", "device", "wifi", "connect", TASMOTA_AP_SSID,
        "bssid", target_bssid, "ifname", WIFI_INTERFACE
    ])

    if proc.returncode != 0:
        return None

    for _ in range(max_wait_seconds):
        time.sleep(1)
        ip = get_current_ip(WIFI_INTERFACE)
        if ip and ip.startswith("192.168.4."):
            return target_bssid

    return None

def send_phase1_commands(router_ssid: str, router_password: str, max_retries=3) -> bool:
    commands = f"Backlog0 SSID1 {router_ssid}; Password1 {router_password}"
    url = f"http://{TASMOTA_AP_IP}/cm"

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, params={"cmnd": commands}, timeout=10)
            if resp.status_code == 200:
                return True
        except Exception:
            pass
        if attempt < max_retries:
            time.sleep(3)
    return False

def find_device_ip_by_scan(subnet_prefix: str, max_attempts: int = 10) -> Optional[str]:
    for attempt in range(1, max_attempts + 1):
        print(f"[LAN] Zoeken naar IP-adres van stekker (Poging {attempt}/{max_attempts})...")
        for h in range(SCAN_START_HOST, SCAN_END_HOST + 1):
            ip = f"{subnet_prefix}{h}"
            try:
                resp = requests.get(f"http://{ip}/cm", params={"cmnd": "Status 5"}, timeout=0.3)
                if resp.status_code == 200:
                    data = resp.json()
                    statusnet = data.get("StatusNET", {})
                    hostname = (statusnet.get("Hostname", "") or "").lower()
                    if hostname.startswith("accusaver") or hostname.startswith("tasmota"):
                        return ip
            except Exception:
                pass
        time.sleep(3)
    return None

# -------- Hoofdproces per stekker --------

def process_single_plug(router_ssid: str, router_password: str, lan_prefix: str) -> bool:
    print("\n--- Zoeken naar een nieuwe AccuSaver stekker ---")
    bssid = connect_wifi_to_ap()
    
    if not bssid:
        return False  # Geen stekker gevonden

    print(f"✓ Verbonden met AP ({bssid})")

    print("Wi-Fi gegevens instellen...")
    if not send_phase1_commands(router_ssid, router_password):
        print("✗ Wi-Fi gegevens instellen mislukt.")
        disconnect_wifi()
        return False

    print("✓ Wi-Fi ingesteld. Disconnecten van AP...")
    disconnect_wifi()
    time.sleep(5)  # Tijd geven om te verbinden met het netwerk

    device_ip = find_device_ip_by_scan(lan_prefix)
    if device_ip:
        print(f"\n==================================================")
        print(f"🎉 MELDING: Stekker succesvol verbonden!")
        print(f"✓ IP-adres: {device_ip}")
        print(f"==================================================\n")
        return True
    else:
        print("✗ IP-adres niet kunnen vinden op het LAN-netwerk.")
        return False

# -------- Main Loop --------

if __name__ == "__main__":
    config = load_config()
    router_ssid = config["ssid"]
    router_password = config["password"]

    try:
        lan_prefix = detect_lan_prefix(LAN_INTERFACE)
    except RuntimeError as e:
        print(f"Fout: {e}")
        exit(1)

    print("=== ACCUSAVER NETWERK KOPPELING SCRIPT GESTART ===")

    no_device_notified = False

    while True:
        success = process_single_plug(router_ssid, router_password, lan_prefix)
        
        if success:
            no_device_notified = False
            time.sleep(2)  # Direct door naar het zoeken van de volgende stekker
        else:
            if not no_device_notified:
                print("\n⚠️  MELDING: Geen stekkers gevonden.")
                print("⚠️  Steek een stekker in het stopcontact. Script blijft zoeken...\n")
                no_device_notified = True
            
            time.sleep(5)  # Wacht 5 seconden voor de volgende poging
