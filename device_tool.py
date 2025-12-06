#!/usr/bin/env python3
import argparse
import sys
from urllib.parse import urljoin
import requests
from requests.exceptions import Timeout, ConnectionError

# -------- Shared constants (same as batch script) --------
FIRMWARE_URL = "http://192.168.2.59/tasmota32c2-withfs.bin"
BERRY_SCRIPT_URL = "http://192.168.2.59/autoexec.be"

EXPECTED_FIRMWARE_DATE = "2025-12-04T13:37:42"
EXPECTED_SCRIPT_VERSION = "1.0.0"

DEFAULT_TIMEOUT = 10.0


def cm_url(base: str) -> str:
    """Build the /cm URL from a base like http://ip or http://host/."""
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    if not base.endswith("/"):
        base += "/"
    return urljoin(base, "cm")


def do_get(url: str, params: dict, timeout: float = DEFAULT_TIMEOUT):
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        return resp
    except (Timeout, ConnectionError) as e:
        print(f"✗ Request error: {e}")
        return None


# -------- Commands --------


def cmd_status(base_url: str, which: str) -> int:
    url = cm_url(base_url)
    cmnd = f"Status {which}"
    print(f"→ GET {url}?cmnd={cmnd}")
    resp = do_get(url, {"cmnd": cmnd})
    if not resp:
        return 1
    print(f"HTTP {resp.status_code}")
    print(resp.text)
    return 0 if resp.ok else 1


def cmd_reset(base_url: str, which: int) -> int:
    url = cm_url(base_url)
    cmnd = f"Reset {which}"
    print(f"→ GET {url}?cmnd={cmnd}")
    # For reset we accept timeout / early disconnect as "likely success"
    try:
        resp = requests.get(url, params={"cmnd": cmnd}, timeout=5.0)
        print(f"HTTP {resp.status_code}")
        print(resp.text)
        return 0 if resp.ok else 1
    except (Timeout, ConnectionError) as e:
        print(
            f"⚠ Connection dropped/timeout during reset ({e}). "
            f"Device may already be rebooting."
        )
        return 0


def cmd_upgrade(base_url: str) -> int:
    url = cm_url(base_url)
    # Use OtaUrl already set on the device; Upgrade 1 triggers OTA
    cmnd = "Upgrade 1"
    print(f"→ GET {url}?cmnd={cmnd}")
    resp = do_get(url, {"cmnd": cmnd}, timeout=15.0)
    if not resp:
        return 1
    print(f"HTTP {resp.status_code}")
    print(resp.text)
    return 0 if resp.ok else 1


def cmd_urlfetch(base_url: str) -> int:
    url = cm_url(base_url)
    cmnd = f"UrlFetch {BERRY_SCRIPT_URL}"
    print(f"→ GET {url}?cmnd={cmnd}")
    resp = do_get(url, {"cmnd": cmnd}, timeout=30.0)
    if not resp:
        return 1
    print(f"HTTP {resp.status_code}")

    try:
        data = resp.json()
        print(data)
        result = str(data.get("UrlFetch", "")).strip()
        if result == "Done":
            print("✓ UrlFetch reported: Done")
            return 0
        else:
            print(f"✗ UrlFetch result: {result!r}")
            return 1
    except Exception:
        print(resp.text)
        print("✗ Could not parse UrlFetch JSON response")
        return 1


def cmd_verify_script(base_url: str) -> int:
    url = cm_url(base_url)
    cmnd = "ScriptVersion"
    print(f"→ GET {url}?cmnd={cmnd}")
    resp = do_get(url, {"cmnd": cmnd})
    if not resp:
        return 1
    print(f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        print(resp.text)
        print("✗ Could not parse ScriptVersion JSON response")
        return 1

    version = str(data.get("ScriptVersion", "")).strip()
    print(f"Reported ScriptVersion: {version!r}")
    if version == EXPECTED_SCRIPT_VERSION:
        print(f"✓ Script version matches expected: {EXPECTED_SCRIPT_VERSION}")
        return 0
    else:
        print(f"✗ Script version mismatch! Expected {EXPECTED_SCRIPT_VERSION}")
        return 1


def cmd_verify_fw(base_url: str) -> int:
    url = cm_url(base_url)
    cmnd = "Status 2"
    print(f"→ GET {url}?cmnd={cmnd}")
    resp = do_get(url, {"cmnd": cmnd})
    if not resp:
        return 1
    print(f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        print(resp.text)
        print("✗ Could not parse Status 2 JSON response")
        return 1

    build_date = str(data.get("StatusFWR", {}).get("BuildDateTime", "")).strip()
    print(f"Reported BuildDateTime: {build_date!r}")
    if build_date == EXPECTED_FIRMWARE_DATE:
        print(f"✓ Firmware build date matches expected: {EXPECTED_FIRMWARE_DATE}")
        return 0
    else:
        print(f"✗ Firmware build date mismatch! Expected {EXPECTED_FIRMWARE_DATE}")
        return 1


def print_help():
    print(
        """device_tool.py – single-device helper for AccuSaver/Tasmota

Usage:
  python device_tool.py <ip-or-url> <command> [arg]

Examples:
  python device_tool.py 192.168.2.120 status 0
  python device_tool.py 192.168.2.120 reset4
  python device_tool.py 192.168.2.120 reset1
  python device_tool.py 192.168.2.120 upgrade
  python device_tool.py 192.168.2.120 urlfetch
  python device_tool.py 192.168.2.120 verify-script
  python device_tool.py 192.168.2.120 verify-fw

Commands:
  status X        → run Status X (e.g. status 0, status 2, status 5)
  reset1          → send Reset 1 (factory reset, device may not come back)
  reset4          → send Reset 4 (normal reboot)
  upgrade         → Upgrade 1 (uses OtaUrl set on device; firmware URL is:
                    {fw})
  urlfetch        → UrlFetch using Berry script URL:
                    {berry}
  verify-script   → checks ScriptVersion == {script_ver}
  verify-fw       → checks Status 2 BuildDateTime == {fw_date}

Shortcut:
  python device_tool.py help
    prints this message.
""".format(
            fw=FIRMWARE_URL,
            berry=BERRY_SCRIPT_URL,
            script_ver=EXPECTED_SCRIPT_VERSION,
            fw_date=EXPECTED_FIRMWARE_DATE,
        )
    )


# -------- CLI wiring --------


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # Custom simple help if user types `device_tool.py help` or no args
    if not argv or argv[0].lower() in ("help", "-h", "--help"):
        print_help()
        return 0

    parser = argparse.ArgumentParser(add_help=False)  # we handle help ourselves
    parser.add_argument("base_url")
    parser.add_argument(
        "command",
        help=(
            "One of: reset1, reset4, status, upgrade, urlfetch, "
            "verify-script, verify-fw"
        ),
    )
    parser.add_argument(
        "arg",
        nargs="?",
        help="Extra argument for some commands (e.g. status 2)",
    )

    args = parser.parse_args(argv)

    # Allow ip like "192.168.2.120" without scheme
    base = args.base_url.strip()
    cmd = args.command.lower()

    if cmd == "help":
        print_help()
        return 0

    if cmd == "reset1":
        return cmd_reset(base, 1)
    elif cmd == "reset4":
        return cmd_reset(base, 4)
    elif cmd == "status":
        which = args.arg or "0"
        return cmd_status(base, which)
    elif cmd == "upgrade":
        return cmd_upgrade(base)
    elif cmd == "urlfetch":
        return cmd_urlfetch(base)
    elif cmd == "verify-script":
        return cmd_verify_script(base)
    elif cmd == "verify-fw":
        return cmd_verify_fw(base)
    else:
        print(f"Unknown command: {cmd}\n")
        print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
