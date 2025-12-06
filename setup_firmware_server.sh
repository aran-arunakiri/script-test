#!/bin/bash

set -e

FOLDER="/home/aran/script-test"
SITE_FILE="/etc/nginx/sites-available/firmware"

echo "[+] Installing nginx..."
sudo apt update -y
sudo apt install -y nginx

echo "[+] Creating nginx site config..."
sudo bash -c "cat > $SITE_FILE" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name _;

    root $FOLDER;

    autoindex on;

    location / {
        try_files \$uri =404;
    }
}
EOF

echo "[+] Enabling site..."
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf "$SITE_FILE" /etc/nginx/sites-enabled/firmware

echo "[+] Testing nginx config..."
sudo nginx -t

echo "[+] Reloading nginx..."
sudo systemctl reload nginx

echo "[+] Done!"
echo "Test via:  http://<pi-ip>/tasmota32c2-withfs.bin"
