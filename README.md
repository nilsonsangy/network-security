# network-security

Useful scripts and tools for network security.

## Information_Security_Policy folder

This folder contains templates and documentation for information security policies. These resources provide guidelines, best practices, and policy examples to help organizations define, implement, and maintain effective information security standards. The materials can be adapted to fit specific organizational needs and compliance requirements.

## AD_security_audit.ps1

This script performs an Active Directory (AD) security audit. It checks for common misconfigurations, weak permissions, and other vulnerabilities in an AD environment. The script generates a detailed report that can be used to improve the security posture of the AD infrastructure.

## enumerate_ptr.sh

This script enumerates PTR (Pointer) records in DNS for a given IP range or subnet. PTR records are used for reverse DNS lookups, mapping IP addresses to hostnames. The script helps identify devices and possible misconfigurations in the network by listing all PTR records found.

## Just_Enough_Administration.ps1

This script implements Just Enough Administration (JEA) - a Role-Based Access Control (RBAC) principle through PowerShell Remoting. It allows administrators to delegate specific administrative tasks without granting full administrative privileges, reducing the risk of accidental or malicious changes to the system.