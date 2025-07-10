#!/bin/bash

# Check if CIDR block was provided
if [ -z "$1" ]; then
  echo "Usage: $0 <CIDR>"
  echo "Example: $0 199.36.154.0/23"
  exit 1
fi

cidr="$1"
output="results.csv"

# Write CSV header
echo "IP,PTR" > "$output"

echo "[*] Generating IP list from CIDR: $cidr"

# Generate list of IPs using nmap -sL and parse
# Note: requires nmap installed
ip_list=$(nmap -n -sL "$cidr" | awk '/Nmap scan report/{print $NF}')

# Loop through IPs
for ip in $ip_list; do
    # Perform reverse DNS lookup using Google's DNS (8.8.8.8)
    ptr=$(dig -x "$ip" @8.8.8.8 +short)

    # Check if there is a PTR record
    if [ -n "$ptr" ]; then
        # Remove trailing dot
        ptr_clean=${ptr%.}
        echo "$ip,$ptr_clean" >> "$output"
        echo "[+] $ip -> $ptr_clean"
    fi
done

echo "Done! Results saved to $output"