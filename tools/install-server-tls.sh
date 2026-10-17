#!/bin/sh
# Provision/renew a publicly trusted IP certificate for the Linux DW listener.
# Does not restart the backend or change its plaintext-access policy.
set -eu
if [ "$(id -u)" != 0 ] || [ "$#" != 1 ]; then
    echo "Usage: sudo sh tools/install-server-tls.sh PUBLIC_IPV4" >&2
    exit 1
fi
ip=$1
python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$ip"
id replay-dw >/dev/null
test -d /var/lib/replay-dw
if [ ! -x /opt/replay-dw/certbot/bin/certbot ]; then
    if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
        apt-get update
        apt-get install -y --no-install-recommends python3-venv
    fi
    python3 -m venv /opt/replay-dw/certbot
    /opt/replay-dw/certbot/bin/pip install 'certbot>=5.4,<6'
fi
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/replay-dw <<'HOOK'
#!/bin/sh
set -eu
# Only this explicitly selected certificate may replace the DW certificate.
expected=$(cat /etc/replay-dw-tls-ip)
[ "$RENEWED_LINEAGE" = "/etc/letsencrypt/live/$expected" ] || exit 0
root=/var/lib/replay-dw/tls
install -d -o root -g replay-dw -m 0750 "$root"
serial=$(openssl x509 -in "$RENEWED_LINEAGE/fullchain.pem" -noout -serial | cut -d= -f2)
case "$serial" in ''|*[!0-9A-Fa-f]*) exit 1;; esac
bundle="$root/$serial"
install -d -o root -g replay-dw -m 0750 "$bundle"
install -o root -g replay-dw -m 0640 "$RENEWED_LINEAGE/fullchain.pem" "$bundle/fullchain.pem"
install -o root -g replay-dw -m 0640 "$RENEWED_LINEAGE/privkey.pem" "$bundle/privkey.pem"
ln -sfn "$serial" "$root/current.pending"
mv -Tf "$root/current.pending" "$root/current"
# The server loads a changed certificate on the next TLS connection. No restart.
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/replay-dw
printf '%s\n' "$ip" > /etc/replay-dw-tls-ip
chmod 0644 /etc/replay-dw-tls-ip
if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
    ufw allow 80/tcp comment 'ACME certificate renewal'
    ufw allow 8443/tcp comment 'Replay DW HTTPS'
fi
/opt/replay-dw/certbot/bin/certbot certonly --standalone --non-interactive \
    --agree-tos --register-unsafely-without-email --preferred-profile shortlived \
    --ip-address "$ip" --cert-name "$ip" --key-type rsa --rsa-key-size 2048
RENEWED_LINEAGE="/etc/letsencrypt/live/$ip" /etc/letsencrypt/renewal-hooks/deploy/replay-dw
cat > /etc/systemd/system/replay-dw-cert-renew.service <<'SERVICE'
[Unit]
Description=Renew Replay DW HTTPS certificate
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/replay-dw/certbot/bin/certbot renew --quiet
SERVICE
cat > /etc/systemd/system/replay-dw-cert-renew.timer <<'TIMER'
[Unit]
Description=Check Replay DW certificate renewal twice daily

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
TIMER
systemctl daemon-reload
systemctl enable --now replay-dw-cert-renew.timer
openssl x509 -in /var/lib/replay-dw/tls/current/fullchain.pem -noout -subject -issuer -dates
echo 'Certificate prepared. Configure tls.json and deploy the tested TLS server separately.'
