import json
import subprocess
import time
from typing import Optional, List

import requests

# -------- Configurable constants --------

FIRMWARE_URL = "https://github.com/aran-arunakiri/script-test/raw/refs/heads/main/tasmota32c2-withfs.bin"
BERRY_SCRIPT_URL = "https://raw.githubusercontent.com/aran-arunakiri/script-test/refs/heads/main/autoexec.be"

TASMOTA_AP_SSID = "accusaver-3FCAD739"
TASMOTA_AP_IP = "192.168.4.1"
TASMOTA_HOSTNAME = "accusaver-3FCAD739"  # Hostname once on LAN

EXPECTED_FIRMWARE_DATE = "2025-11-16T15:13:02"
EXPECTED_SCRIPT_VERSION = "1.0.0"

WIFI_INTERFACE = "wlan0"          # Pi Wi-Fi interface
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