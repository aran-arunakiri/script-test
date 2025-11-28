import json
import subprocess
import time


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


if __name__ == "__main__":
    config = load_config()
    print(f"Target network: {config['ssid']}")

    print(f"\nAttempting to connect to {TASMOTA_AP_SSID}...")
    if connect_to_tasmota_ap():
        print("✓ Connected and Tasmota reachable!")
    else:
        print("✗ Could not connect or reach Tasmota")
