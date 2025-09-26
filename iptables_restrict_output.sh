#!/bin/bash
# Restrict OUTPUT rules to allow only web browsing
# This script assumes you already executed the "iptables_basic_rules.sh" script before.
# It modifies OUTPUT rules only:
#  - Default policy for OUTPUT → DROP (block all by default)
#  - Allow loopback traffic
#  - Allow established/related connections
#  - Allow DNS queries (UDP and TCP port 53)
#  - Allow HTTP (TCP port 80)
#  - Allow HTTPS (TCP port 443)

# -------------------------------------------------------
# 1) Change default OUTPUT policy to DROP
# -------------------------------------------------------
iptables -P OUTPUT DROP
# -P OUTPUT DROP : set OUTPUT chain default policy to DROP
# This blocks all outgoing packets unless explicitly allowed below.

# -------------------------------------------------------
# 2) Allow loopback interface for OUTPUT
# -------------------------------------------------------
iptables -A OUTPUT -o lo -j ACCEPT
# -A OUTPUT : append to OUTPUT chain
# -o lo     : match packets going out via loopback interface (127.0.0.1)
# -j ACCEPT : accept the packet
# Required for local processes that talk to each other via loopback.

# -------------------------------------------------------
# 3) Allow established/related OUTPUT
# -------------------------------------------------------
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# -m conntrack : use the connection tracking module
# --ctstate ESTABLISHED,RELATED :
#   ESTABLISHED → packets part of an existing connection
#   RELATED     → packets related to an existing connection
# -j ACCEPT : accept the packet
# Ensures that replies from connections initiated by the host are allowed.

# -------------------------------------------------------
# 4) Allow DNS (UDP port 53)
# -------------------------------------------------------
iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
# -p udp        : match UDP protocol
# --dport 53    : destination port 53 (DNS service)
# --ctstate NEW : only allow NEW connection attempts
# -j ACCEPT     : accept the packet
# Required for hostname resolution.

# -------------------------------------------------------
# 5) Allow DNS (TCP port 53)
# -------------------------------------------------------
iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
# -p tcp        : match TCP protocol
# --dport 53    : DNS over TCP (used for large queries and DNSSEC)
# --ctstate NEW : only allow new outbound connections
# -j ACCEPT     : accept the packet
# Ensures DNS always works, even when TCP fallback is required.

# -------------------------------------------------------
# 6) Allow ICMP (ping)
# -------------------------------------------------------
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
# -p icmp                : match ICMP protocol
# --icmp-type echo-request : allow outgoing ping requests
# -j ACCEPT              : accept the packet
# This allows the host to send ping requests.

iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
# -p icmp                : match ICMP protocol
# --icmp-type echo-reply : allow incoming ping replies
# -j ACCEPT              : accept the packet
# Required so that replies to our pings are received.

# -------------------------------------------------------
# 7) Allow HTTP (port 80)
# -------------------------------------------------------
iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
# -p tcp        : match TCP protocol
# --dport 80    : destination port 80 (HTTP)
# --ctstate NEW : only new outbound connections
# -j ACCEPT     : accept the packet
# Enables browsing of unencrypted websites.

# -------------------------------------------------------
# 8) Allow HTTPS (port 443)
# -------------------------------------------------------
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
# -p tcp        : match TCP protocol
# --dport 443   : destination port 443 (HTTPS)
# --ctstate NEW : only new outbound connections
# -j ACCEPT     : accept the packet
# Enables browsing of secure websites (encrypted).

# -------------------------------------------------------
# 9) Show active rules after configuration
# -------------------------------------------------------
iptables -L -n -v --line-numbers
# -L : list rules
# -n : numeric output (no DNS resolution)
# -v : verbose (shows packet and byte counters)
# --line-numbers : display rule numbers for easier management
