# network-security

A collection of scripts, tools, and reference material for network security — from an information security policy to hands-on firewall labs.

## Contents

| Item | Type | Description |
|------|------|-------------|
| [`Information_Security_Policy/`](Information_Security_Policy) | Document | Information Security Policy (ISP) template, in English and Portuguese. |
| [`JEA-secure-privileged-access.ps1`](JEA-secure-privileged-access.ps1) | PowerShell script | Restricted privileged access with Just Enough Administration (JEA). |
| [`ping-sweep.ps1`](ping-sweep.ps1) | PowerShell script | Sweep a subnet to find active hosts via ping. |
| [`lab-firewall-pfsense/`](lab-firewall-pfsense) | Lab | Hands-on perimeter-security lab with pfSense between LAN and DMZ. |

---

## Information_Security_Policy

An Information Security Policy (ISP) template — a document that defines the rules, guidelines, and best practices for protecting an organization's information assets.

- **`/`** — English version (`README.md`).
- **`pt-br/`** — Brazilian Portuguese version (`README.md`).

## JEA-secure-privileged-access.ps1

A script that implements the **Just Enough Administration (JEA)** principle — role-based access control (RBAC) — through PowerShell Remoting, granting only the privileges needed for each administrative task.

## ping-sweep.ps1

A network-sweep script that iterates over the addresses in a subnet and reports which hosts respond to ping, running the checks in parallel to speed up the result.

## lab-firewall-pfsense

A hands-on **perimeter-security** lab that uses **pfSense** as the firewall/gateway between a LAN segment and a DMZ segment. The automation brings up the two client VMs with Vagrant on VMware; pfSense is installed manually and routes traffic between the segments.

### Topology

```
   [ cliente-lan ]                         [ cliente-dmz ]
   LAN 10.10.10.0/24                        DMZ 10.10.20.0/24
          \                                       /
           \                                     /
            \-------------[ pfSense ]-----------/
                    LAN 10.10.10.1  |  DMZ 10.10.20.1
                 (firewall/gateway between the segments)

   Each VM: eth0 = NAT (internet/SSH)  |  eth1 = host-only lab segment
```

### Files

- `Vagrantfile` — defines two Ubuntu VMs on VMware: a client on the LAN (10.10.10.0/24) and a client on the DMZ (10.10.20.0/24).
- `provision-cliente-lan.sh` — provisions the LAN client (test tools and a simple HTTP page on port 80).
- `provision-cliente-dmz.sh` — provisions the DMZ client (test tools and a simple HTTP page on port 80).

### Getting started

From inside the `lab-firewall-pfsense/` directory:

```
vagrant up --provider=vmware_desktop
```

> pfSense is not managed by Vagrant: install it manually from the ISO, with the LAN interface at `10.10.10.1` and the DMZ interface at `10.10.20.1`. Routing between LAN and DMZ only works once pfSense is active and the rules are configured.
