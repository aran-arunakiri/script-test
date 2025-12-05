import subprocess

WIFI_INTERFACE = "wlan0"


def run_cmd(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def scan_accusavers():
    print(f"[WiFi] Scanning {WIFI_INTERFACE} (fresh)...")

    scan_list = run_cmd(
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
            "yes",  # Blocks until scan completes, returns fresh results
        ]
    )

    lines = scan_list.stdout.splitlines()

    if lines:
        print(lines[0])
        print("-" * 60)

    accusavers = [
        line for line in lines[1:] if line.strip().lower().startswith("accusaver")
    ]

    if accusavers:
        for l in accusavers:
            print(l)
        print("-" * 60)
        print(f"\n✓ Found {len(accusavers)} AccuSaver AP(s)")
    else:
        print("(no AccuSaver networks found)")

    return accusavers


if __name__ == "__main__":
    scan_accusavers()
