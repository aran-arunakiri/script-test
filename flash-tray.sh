#!/bin/bash
# AccuSaver: flash een tray. Start met  ./flash-tray.sh  en volg de vragen.
cd "$(dirname "$0")"
exec sudo -n python3 provision_pi11.py "$@"
