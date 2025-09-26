#!/bin/bash
# Basic iptables firewall for Ubuntu
# - Blocks all incoming traffic by default
# - Allows all outgoing traffic by default
# - Only allows incoming SSH (port 22)
# - Allows traffic for established/related connections
# - Allows loopback traffic (localhost)

# -------------------------------------------------------
# 1) Flush (clean) all existing rules and chains
# -------------------------------------------------------
iptables -F                # -F: flush all rules from the default chains
iptables -X                # -X: delete all user-defined chains
iptables -t nat -F         # flush rules in the NAT table
iptables -t mangle -F      # flush rules in the Mangle table
iptables -t raw -F         # flush rules in the Raw table

# -------------------------------------------------------
# 2) Set default policies
# -------------------------------------------------------
iptables -P INPUT DROP     # -P: set default policy → DROP: drop all incoming traffic
iptables -P FORWARD DROP   # drop all forwarded traffic (not acting as a router)
iptables -P OUTPUT ACCEPT  # allow all outgoing traffic

# -------------------------------------------------------
# 3) Allow loopback interface traffic
# -------------------------------------------------------
iptables -A INPUT -i lo -j ACCEPT
# -A INPUT: append rule to INPUT chain
# -i lo: match traffic on the "lo" (loopback) interface
# -j ACCEPT: accept the packet
# Required for local applications to communicate via 127.0.0.1

# -------------------------------------------------------
# 4) Allow established and related incoming traffic
# -------------------------------------------------------
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# -m conntrack: use the connection tracking module
# --ctstate:
#   ESTABLISHED → packets that are part of an existing connection
#   RELATED → packets related to an existing connection (e.g., FTP passive mode)
# -j ACCEPT: accept the packet
# This ensures responses to outgoing connections are allowed back in

# -------------------------------------------------------
# 5) Allow new incoming SSH connections (port 22)
# -------------------------------------------------------
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
# -p tcp: match TCP protocol
# --dport 22: match destination port 22 (SSH)
# -m conntrack --ctstate NEW: only allow NEW connection attempts
# -j ACCEPT: accept the packet
# This allows remote SSH access

# -------------------------------------------------------
# (Optional) 6) Log dropped packets for debugging
# -------------------------------------------------------
# iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "DROP INPUT: " --log-level 4
# -m limit --limit 5/min: rate limit log messages to avoid flooding logs
# --log-prefix: prefix text for log entries
# --log-level 4: log level WARNING
# Useful for troubleshooting blocked traffic (but can fill logs if left open)

# -------------------------------------------------------
# 7) Show active rules
# -------------------------------------------------------
iptables -L -n -v --line-numbers
# -L: list rules
# -n: show IPs/ports in numeric form (don’t resolve hostnames)
# -v: verbose output (shows packet/byte counters)
# --line-numbers: display rule numbers (useful for deleting/editing rules)
