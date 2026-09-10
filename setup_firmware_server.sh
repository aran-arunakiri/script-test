#!/usr/bin/env bash
set -euo pipefail

# This script:
#  - Installs nginx
#  - Serves the CURRENT DIRECTORY via http://<host>/...
#  - Sets minimal permissions so nginx can read this directory

FOLDER="$(pwd)"                          # directory to serve
PARENT_DIR="$(dirname "$FOLDER")"
SITE_NAME="firmware"
SITE_FILE="/etc/nginx/sites-available/${SITE_NAME}"

echo "[+] Using folder: $FOLDER"

echo "[+] Installing nginx (if not present)..."
sudo apt update -y
sudo apt install -y nginx

echo "[+] Adjusting permissions so nginx (www-data) can read the folder..."
# Allow traversal into the parent and the folder
sudo chmod o+rx "$PARENT_DIR"
sudo chmod o+rx "$FOLDER"

echo "[+] Writing nginx site config to $SITE_FILE..."
sudo tee "$SITE_FILE" >/dev/null <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name _;

    root $FOLDER;

    # Show directory listing at http://host/
    autoindex on;

    location / {
        try_files \$uri =404;
    }
}
EOF

echo "[+] Enabling site..."
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf "$SITE_FILE" "/etc/nginx/sites-enabled/${SITE_NAME}"

echo "[+] Testing nginx config..."
sudo nginx -t

echo "[+] Reloading nginx..."
sudo systemctl reload nginx

echo ""
echo "[✓] Firmware HTTP server ready."
echo "    Served folder : $FOLDER"
echo "    Example URL   : http://<pi-ip>/tasmota32c2-withfs.bin"
echo "                     or http://<hostname>/tasmota32c2-withfs.bin"
