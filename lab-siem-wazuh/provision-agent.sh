#!/usr/bin/env bash
# Wazuh agent VM. Installs the wazuh-agent from the official APT repo, points it
# at the manager (WAZUH_IP) and registers it. Also installs the small helpers used
# by the lab exercises (SSH server for E2, a FIM-monitored dir for E3/E5).
#
# Arguments (passed by the Vagrantfile):
#   $1 = WAZUH_MANAGER -> manager IP (= WAZUH_IP), where the agent registers
#   $2 = AGENT_IP      -> lab IP of this VM (used only for the summary)
#
# NOTE: the manager must be up first. The Vagrantfile defines the "wazuh" VM
# before "agent", so ordering is handled. Once registered, this agent shows up in
# the dashboard under Agents / Endpoints.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

WAZUH_MANAGER="${1:-10.10.10.77}"
AGENT_IP="${2:-10.10.10.99}"
AGENT_NAME="agent-$(hostname)"

# --- Connectivity check (provisioning needs to download packages) ---
if ! curl -fsS --max-time 10 -o /dev/null http://archive.ubuntu.com/ 2>/dev/null; then
  echo "ERROR: the VM has no internet access to download packages." >&2
  exit 1
fi

apt-get update -qq
apt-get install -y -qq curl gnupg apt-transport-https lsb-release

# --- Helpers used by the exercises ------------------------------------------
# E2: an SSH server so we can generate authentication failures against it.
# E3/E5: a directory that will be monitored by FIM (created early so it exists
# when the agent starts). Keep this minimal.
apt-get install -y -qq openssh-server
systemctl enable --now ssh || systemctl enable --now sshd || true
install -d -m 0755 /root/fim-test

# --- Wazuh APT repo (pinned to the 4.x line) --------------------------------
# Import the GPG key and add the repo, then install the agent with the manager
# baked into the install via the WAZUH_MANAGER env var (so ossec.conf points at
# the manager on first start). Idempotent: skip the repo setup if already present.
if ! dpkg -l wazuh-agent >/dev/null 2>&1; then
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
  chmod 644 /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \
    apt-get install -y -qq wazuh-agent
else
  echo "wazuh-agent already installed; skipping repo + install."
fi

# Make sure the manager address is set even on a re-provision.
if [ -f /var/ossec/etc/ossec.conf ]; then
  sed -i "s|<address>[^<]*</address>|<address>${WAZUH_MANAGER}</address>|" \
    /var/ossec/etc/ossec.conf || true
fi

# --- Enable and start the agent ---------------------------------------------
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

# --- Summary for verification -----------------------------------------------
echo "-------------------------------------------------------------"
echo "OK  wazuh-agent"
echo "    manager IP    : ${WAZUH_MANAGER}"
echo "    agent IP      : ${AGENT_IP}"
echo "    agent name    : ${AGENT_NAME}"
echo "    confirm reg.  : sudo systemctl status wazuh-agent"
echo "                    sudo /var/ossec/bin/agent_control -l   # on the wazuh VM"
echo "    the agent appears in the dashboard under Agents / Endpoints (Active)."
echo "    FIM test dir  : /root/fim-test  (used by E3 and E5)"
echo "-------------------------------------------------------------"
