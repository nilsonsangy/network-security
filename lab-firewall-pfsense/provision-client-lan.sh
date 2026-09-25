#!/usr/bin/env bash
# LAN client (10.10.10.0/24) — uses pfSense as the gateway to the DMZ.
# Serves a simple "client-lan" HTTP page on port 80 and installs test tools
# (curl, ping) for the firewall-rule exercises.
#
# Arguments (passed by the Vagrantfile):
#   $1 = GATEWAY  -> pfSense LAN interface IP (e.g. 10.10.10.1)
#   $2 = DMZ_TARGET -> client-dmz IP (e.g. 10.10.20.50), used in the tests
#
# NOTE: the route to the DMZ only works once pfSense is active as the gateway
# (LAN interface at $GATEWAY) and the exercise rules have been created.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

GATEWAY="${1:-10.10.10.1}"
DMZ_TARGET="${2:-10.10.20.50}"

# DMZ network derived from the target IP (assumes /24): used for the static route.
DMZ_NET="$(echo "$DMZ_TARGET" | awk -F. '{print $1"."$2"."$3".0/24"}')"

# --- Connectivity check (provisioning downloads packages through the NAT) ---
if ! curl -fsS --max-time 10 -o /dev/null http://archive.ubuntu.com/ 2>/dev/null; then
  echo "ERROR: no internet access from the VM (NAT)." >&2
  echo "       Check the VMware NAT network (eth0) and try again." >&2
  exit 1
fi

apt-get update -qq
apt-get install -y -qq curl iputils-ping python3

# --- Detect the segment interface (eth1 = LAN host-only network) ------------
# eth0 is Vagrant''s NAT; the second interface is the lab one.
LAB_IFACE="$(ip -o -4 addr show | awk '$2 != "lo" {print $2}' | grep -v -E 'eth0|ens.*0$' | head -n1)"
[ -z "$LAB_IFACE" ] && LAB_IFACE="eth1"

# --- Route to the DMZ via pfSense (idempotent) ------------------------------
# Specific route to the DMZ, without touching the default route (which exits via NAT).
# Only takes effect once pfSense is active at $GATEWAY.
if ! ip route show | grep -q "^${DMZ_NET%/*}/24 "; then
  ip route replace "$DMZ_NET" via "$GATEWAY" dev "$LAB_IFACE" || \
    echo "WARNING: could not install the route now (pfSense may be inactive)."
else
  ip route replace "$DMZ_NET" via "$GATEWAY" dev "$LAB_IFACE" || true
fi

# --- Simple "client-lan" HTTP server on port 80 via systemd (idempotent) ----
install -d -m 0755 /var/www/lab
cat > /var/www/lab/index.html <<'HTML'
<!doctype html><html lang="en"><meta charset="utf-8">
<title>client-lan</title>
<h1>client-lan</h1>
<p>Page served by the LAN VM (port 80) to test firewall rules.</p>
</html>
HTML

cat > /etc/systemd/system/lab-http.service <<'UNIT'
[Unit]
Description=Simple lab HTTP server (client-lan) on port 80
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/var/www/lab
ExecStart=/usr/bin/python3 -m http.server 80 --bind 0.0.0.0
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now lab-http.service
systemctl restart lab-http.service

# --- Summary for verification -----------------------------------------------
LAB_IP="$(ip -o -4 addr show dev "$LAB_IFACE" | awk '{print $4}' | cut -d/ -f1)"
echo "-------------------------------------------------------------"
echo "OK  client-lan"
echo "    lab interface  : $LAB_IFACE"
echo "    LAN IP         : ${LAB_IP:-unknown}"
echo "    gateway (pfSense): $GATEWAY"
echo "    route to DMZ   : $DMZ_NET via $GATEWAY"
echo "    DMZ target     : $DMZ_TARGET"
echo "    local HTTP     : http://${LAB_IP:-127.0.0.1}/  (client-lan page)"
echo "    NOTE: LAN->DMZ routing only works with pfSense active and the rules created."
echo "-------------------------------------------------------------"