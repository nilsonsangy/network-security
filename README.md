<div align="center">

# 🕵️‍♂️ Network Security Toolkit

**Useful scripts for security auditing, hardening, and network intelligence**

[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)](#)

*Automate common security tasks and generate actionable reports*

</div>

---

## 📋 Table of Contents

- [🧰 Tools Overview](#-tools-overview)
- [🚀 Quick Start](#-quick-start)
- [ Usage](#-usage)
  - [IP WHOIS/RDAP Report (PDF)](#ip-whoisrdap-report-pdf)
- [🧪 Firewall Lab (pfSense)](#-firewall-lab-pfsense)
- [⚙️ Requirements](#️-requirements)
- [⚠️ Disclaimer](#-disclaimer)
- [💝 Donations](#-donations)

---

## 🧰 Tools Overview

| Tool / Script | Description | Platform |
| --- | --- | --- |
| `ip_whois_report.py` | Query WHOIS/RDAP for IPs and generate a grouped PDF report | Windows / Linux / WSL |
| `AD_security_audit.ps1` | Active Directory security audit checks and reporting | Windows |
| `enumerate_ptr.sh` | Enumerate reverse DNS (PTR) records for a range/subnet | Linux |
| `iptables_basic_rules.sh` | Baseline iptables rules | Linux |
| `iptables_restrict_output.sh` | Restrict outbound traffic to web-only (HTTP/HTTPS/DNS) | Linux |
| `Just_Enough_Administration.ps1` | JEA (RBAC) with PowerShell Remoting | Windows |
| `Information_Security_Policy/` | Templates and docs for security policies | Any |
| `lab-firewall-pfsense/` | Hands-on perimeter-security lab: pfSense firewall/gateway between LAN and DMZ | Linux / VMware |

---

## 🚀 Quick Start

```powershell
# Clone the repository
git clone https://github.com/nilsonsangy/network-security.git
cd network-security

# Create and activate a local Python environment (.venv)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# (Optional) allow venv activation if blocked
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Install dependencies
pip install -r requirements.txt
```

Linux / WSL:

```bash
git clone https://github.com/nilsonsangy/network-security.git
cd network-security
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Deactivate the environment when done:

```bash
deactivate
```

---

## 📖 Usage

### IP WHOIS/RDAP Report (PDF)

Generate a PDF report grouped by the responsible organization/person.

```powershell
# Single IP
python ip_whois_report.py 8.8.8.8

# Comma-separated list
python ip_whois_report.py 8.8.8.8,1.1.1.1

# File with one IP per line
python ip_whois_report.py ips.txt

# Override output path (-o accepts a folder or a final PDF file path)
python ip_whois_report.py 8.8.8.8 -o $env:USERPROFILE\Downloads\my_report.pdf
```

Output location (auto):
- Windows: user `Downloads` folder
- Linux/WSL: user `HOME` folder
- Unknown OS: current directory

The PDF includes:
- RDAP summary (CIDR, name, handle, country, range, etc.)
- Contacts/entities when available
- WHOIS snippet (if the `whois` command exists on your system)
- Grouping by responsible (organization/person)

---

## 🧪 Firewall Lab (pfSense)

A hands-on **perimeter-security** lab that uses **pfSense** as the firewall/gateway between a LAN segment and a DMZ segment. The automation brings up two Ubuntu client VMs with Vagrant on VMware; pfSense is installed manually and routes traffic between the segments.

### Topology

```
   [ client-lan ]                          [ client-dmz ]
   LAN 10.10.10.0/24                        DMZ 10.10.20.0/24
          \                                       /
           \                                     /
            \-------------[ pfSense ]-----------/
                    LAN 10.10.10.1  |  DMZ 10.10.20.1
                 (firewall/gateway between the segments)

   Each VM: eth0 = NAT (internet/SSH)  |  eth1 = host-only lab segment
```

### Files (`lab-firewall-pfsense/`)

- `Vagrantfile` — defines two Ubuntu VMs on VMware: `client-lan` on the LAN (10.10.10.0/24) and `client-dmz` on the DMZ (10.10.20.0/24).
- `provision-client-lan.sh` — provisions the LAN client (test tools and a simple HTTP page on port 80).
- `provision-client-dmz.sh` — provisions the DMZ client (test tools and a simple HTTP page on port 80).

### Getting started

From inside the `lab-firewall-pfsense/` directory:

```bash
vagrant up --provider=vmware_desktop
```

> pfSense is not managed by Vagrant: install it manually from the ISO, with the LAN interface at `10.10.10.1` and the DMZ interface at `10.10.20.1`. Routing between LAN and DMZ only works once pfSense is active and the rules are configured.

---

## ⚙️ Requirements

- Python 3.8+
- Virtual environment: `.venv` in the repo root (recommended)
- Install: `pip install -r requirements.txt`
- Optional: `whois` CLI on the OS (for WHOIS snippet fallback)

---

## ⚠️ Disclaimer

This project is intended for educational and defensive security purposes only. Always ensure you have authorization before running any security tooling in environments you do not own.

---

## 💝 Donations

If you find this project helpful and would like to support its development, consider making a donation. Your contribution helps keep this toolkit updated and motivates further improvements!

| ☕ Support this project (EN) | ☕ Apoie este projeto (PT-BR) |
|-----------------------------|------------------------------|
| If this project helps you or you think it's cool, consider supporting:<br>💳 [PayPal](https://www.paypal.com/donate/?business=7CC3CMJVYYHAC&no_recurring=0&currency_code=BRL)<br>![PayPal QR code](https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=https://www.paypal.com/donate/?business=7CC3CMJVYYHAC&no_recurring=0&currency_code=BRL) | Se este projeto te ajuda ou você acha legal, considere apoiar:<br>🇧🇷 Pix: `df92ab3c-11e2-4437-a66b-39308f794173`<br>![Pix QR code](https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=df92ab3c-11e2-4437-a66b-39308f794173) |
