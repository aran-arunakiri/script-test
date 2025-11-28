import json
import subprocess
import time
import requests

FIRMWARE_URL = "https://github.com/aran-arunakiri/script-test/raw/refs/heads/main/tasmota32c2-withfs.bin"
BERRY_SCRIPT_URL = "https://raw.githubusercontent.com/aran-arunakiri/script-test/refs/heads/main/autoexec.be"
TASMOTA_IP = "192.168.4.1"


def load_config():
    with open(".wifi-config.json", "r") as f:
        return json.load(f)


TASMOTA_AP_SSID = "accusaver-3FCAD739"
WIFI_INTERFACE = "en0"


def connect_to_tasmota_ap():
    """Attempt to connect to a Tasmota AP. Returns True if successful."""
    result = subprocess.run(
        ["networksetup", "-setairportnetwork", WIFI_INTERFACE, TASMOTA_AP_SSID],
        capture_output=True,
        text=True,
    )

    # Give it a moment to connect
    time.sleep(2)

    # Check if we're connected by trying to reach the device
    try:
        response = subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--connect-timeout",
                "3",
                "http://192.168.4.1",
            ],
            capture_output=True,
            text=True,
        )
        return response.stdout.strip() == "200"
    except:
        return False


def provision_device(wifi_ssid, wifi_password):
    """Send provisioning commands to Tasmota device. Returns True if successful."""
    
    # Build the backlog command - all in one
    commands = f"Backlog SSID1 {wifi_ssid}; Password1 {wifi_password}; OtaUrl {FIRMWARE_URL}; UrlFetch {BERRY_SCRIPT_URL}; Upgrade 1"
    
    try:
        response = requests.get(
            f"http://{TASMOTA_IP}/cm",
            params={"cmnd": commands},
            timeout=10
        )
        
        if response.status_code == 200:
            print(f"  ✓ Provisioning command sent")
            return True
        else:
            print(f"  ✗ HTTP {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"  ✗ Request failed: {e}")
        return False


if __name__ == "__main__":
    config = load_config()
    print(f"Target network: {config['ssid']}")

    print(f"\nAttempting to connect to {TASMOTA_AP_SSID}...")
    if connect_to_tasmota_ap():
        print("✓ Connected and Tasmota reachable!")

        print("\nSending provisioning commands...")
        if provision_device(config["ssid"], config["password"]):
            print("✓ Device provisioned!")
        else:
            print("✗ Provisioning failed")
    else:
        print("✗ Could not connect or reach Tasmota")
