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

# --- Persistent route to the DMZ via pfSense --------------------------------
# The traffic between segments MUST cross the pfSense, never the NAT (eth0).
# A specific /24 route beats the default route, so LAN->DMZ always goes via the
# pfSense LAN interface ($GATEWAY). We install it as a systemd oneshot unit so it
# is (re)applied on every boot, even if pfSense was not up yet at provision time.
cat > /usr/local/sbin/lab-route.sh <<ROUTE
#!/usr/bin/env bash
# Force DMZ traffic through the pfSense LAN interface (not the NAT).
# The route is a directly-connected next hop, so it can be installed even before
# the pfSense answers. We (re)install it and then wait for the gateway to come up,
# retrying for a while so a reboot before pfSense is ready still ends up correct.
GW="${GATEWAY}"
NET="${DMZ_NET}"
DEV="${LAB_IFACE}"
for i in \$(seq 1 60); do
  ip route replace "\$NET" via "\$GW" dev "\$DEV" 2>/dev/null || true
  if ping -c1 -W1 "\$GW" >/dev/null 2>&1; then
    ip route replace "\$NET" via "\$GW" dev "\$DEV" 2>/dev/null || true
    exit 0
  fi
  sleep 5
done
ip route replace "\$NET" via "\$GW" dev "\$DEV" 2>/dev/null || true
exit 0
ROUTE
chmod +x /usr/local/sbin/lab-route.sh

cat > /etc/systemd/system/lab-route.service <<'UNIT'
[Unit]
Description=Lab static route (segment traffic via pfSense, not the NAT)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lab-route.sh
RemainAfterExit=yes
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable lab-route.service || true
systemctl start lab-route.service || true
ip route replace "$DMZ_NET" via "$GATEWAY" dev "$LAB_IFACE" 2>/dev/null || \
  echo "NOTE: route staged; lab-route.service keeps (re)applying it until the gateway is up."

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