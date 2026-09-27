#!/usr/bin/env bash
# Wazuh all-in-one (server + indexer + dashboard) on a single Ubuntu VM.
# Installs the stack via the official Wazuh quickstart assistant, tunes the
# kernel for the indexer (OpenSearch) and prints the generated admin password.
#
# Arguments (passed by the Vagrantfile):
#   $1 = WAZUH_IP -> lab IP of this VM; used only for the summary/dashboard URL
#
# NOTE: the assistant downloads several hundred MB and can take many minutes.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

WAZUH_IP="${1:-10.10.10.77}"

# Pin to a specific Wazuh version for the all-in-one installer. The old
# /4.x/ alias for wazuh-install.sh was retired and now returns HTTP 403, so
# the URL must carry an explicit version (e.g. 4.14). Bump WAZUH_VERSION to move.
WAZUH_VERSION="4.14"
WAZUH_INSTALL_URL="https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"

# --- Connectivity check (provisioning needs to download packages) ---
if ! curl -fsS --max-time 10 -o /dev/null http://archive.ubuntu.com/ 2>/dev/null; then
  echo "ERROR: the VM has no internet access to download packages." >&2
  exit 1
fi

apt-get update -qq
apt-get install -y -qq curl tar

# --- Kernel tuning for the Wazuh indexer (OpenSearch) -----------------------
# OpenSearch mmaps a lot of files and refuses to start unless vm.max_map_count
# is high enough. Set it now and persist it so it survives reboots. Do this
# BEFORE the install so the indexer boots on the first try.
if [ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -lt 262144 ]; then
  sysctl -w vm.max_map_count=262144
fi
if ! grep -q '^vm.max_map_count' /etc/sysctl.conf 2>/dev/null; then
  echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
else
  sed -i 's/^vm.max_map_count.*/vm.max_map_count=262144/' /etc/sysctl.conf
fi

# --- Install the Wazuh all-in-one stack -------------------------------------
# -a = all-in-one deployment (server + indexer + dashboard on this host)
# -i = ignore hardware/system checks so it runs in the lab VM
# Idempotency: the assistant refuses to run over an existing install, so we
# only run it when the dashboard package is not present yet.
cd /root
if ! dpkg -l wazuh-dashboard >/dev/null 2>&1; then
  echo "Downloading and running the Wazuh all-in-one assistant (this takes a while)..."
  curl -fsSL -o /root/wazuh-install.sh "$WAZUH_INSTALL_URL"
  bash /root/wazuh-install.sh -a -i
else
  echo "Wazuh already installed; skipping the assistant."
fi

# --- Recover the generated admin password -----------------------------------
# The assistant stores credentials in wazuh-install-files.tar. We read the
# admin password from wazuh-passwords.txt inside that tarball. The password is
# GENERATED (never hardcoded here).
ADMIN_PASS="(read it manually — see below)"
if [ -f /root/wazuh-install-files.tar ]; then
  ADMIN_PASS="$(tar -O -xf /root/wazuh-install-files.tar \
      wazuh-install-files/wazuh-passwords.txt 2>/dev/null \
      | grep -A1 "username: 'admin'" \
      | grep 'password:' \
      | sed "s/.*password: '\(.*\)'.*/\1/" || true)"
  [ -z "$ADMIN_PASS" ] && ADMIN_PASS="(see /root/wazuh-install-files.tar -> wazuh-passwords.txt)"
fi

# --- Summary for verification -----------------------------------------------
echo "-------------------------------------------------------------"
echo "OK  wazuh all-in-one"
echo "    dashboard URL : https://${WAZUH_IP}   (port 443, self-signed cert)"
echo "    admin user    : admin"
echo "    admin pass    : ${ADMIN_PASS}"
echo "    read pass any time (on this VM):"
echo "      sudo tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt"
echo "      # or: sudo /usr/share/wazuh-indexer/bin/wazuh-passwords-tool --user admin"
echo "    lab IP        : ${WAZUH_IP}"
echo "-------------------------------------------------------------"
