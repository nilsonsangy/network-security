#!/usr/bin/env python3
"""
IP WHOIS/RDAP report generator

Usage examples:
    python ip_whois_report.py 8.8.8.8
    python ip_whois_report.py 8.8.8.8,1.1.1.1
    python ip_whois_report.py ips.txt

Output location (auto):
- Windows: %USERPROFILE%/Downloads
- Linux/WSL: $HOME
- Fallback: current directory

Optional flags:
    -o <file|folder>    Override output path (PDF file or target folder)
    -t <threads>        Number of parallel threads (default: 5, max: 20)
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import platform
import shutil
import subprocess
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import redirect_stderr
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests  # noqa: F401 (requests may be useful for future HTTP fallbacks)
from ipwhois import IPWhois
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Preformatted,
)


@dataclass
class IPReport:
    ip: str
    country: str
    responsible: str  # organization/person responsible (owner)
    owner_id: str  # CPF/CNPJ for grouping
    role: str
    address: str
    email: str
    phone: str


def detect_output_directory() -> Path:
    system = platform.system().lower()
    # Windows -> Downloads
    if system == "windows":
        base = Path(os.environ.get("USERPROFILE", Path.home()))
        return (base / "Downloads").resolve()
    # Linux (including WSL) -> HOME
    if system == "linux":
        return Path.home().resolve()
    # Fallback -> CWD
    return Path.cwd().resolve()


def is_file(path_like: str) -> bool:
    try:
        return Path(path_like).is_file()
    except Exception:
        return False


def parse_input(input_str: str) -> List[str]:
    ips: List[str] = []

    if is_file(input_str):
        for line in Path(input_str).read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            if validate_ip(line):
                ips.append(line)
            else:
                print(f"Warning: invalid IP ignored: {line}")
        return ips

    if "," in input_str:
        parts = [p.strip() for p in input_str.split(",")]
        for part in parts:
            if validate_ip(part):
                ips.append(part)
            else:
                print(f"Warning: invalid IP ignored: {part}")
        return ips

    # Single value
    if validate_ip(input_str):
        return [input_str]

    raise ValueError(f"Invalid input: {input_str}. Provide an IP, comma-separated list or a file path.")


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def run_system_whois(ip: str, timeout: int = 20) -> Optional[str]:
    """Run system whois command to get raw WHOIS data."""
    exe = shutil.which("whois")
    if not exe:
        return None
    try:
        proc = subprocess.run([exe, ip], capture_output=True, text=True, timeout=timeout)
        text = proc.stdout or proc.stderr
        return text.strip() if text else None
    except Exception:
        return None


def parse_whois_text(whois_text: str) -> dict:
    """Parse raw WHOIS text to extract Brazilian fields (owner, ownerid)."""
    import re
    
    result = {
        "owner": None,
        "ownerid": None,
        "responsible": None,
        "country": None
    }
    
    if not whois_text:
        return result
    
    # Extract ownerid (CPF/CNPJ format: XX.XXX.XXX/XXXX-XX)
    ownerid_match = re.search(r'ownerid:\s*(.+)', whois_text, re.IGNORECASE)
    if ownerid_match:
        result["ownerid"] = ownerid_match.group(1).strip()
    
    # Extract owner (organization name)
    owner_match = re.search(r'^owner:\s*(.+)', whois_text, re.IGNORECASE | re.MULTILINE)
    if owner_match:
        result["owner"] = owner_match.group(1).strip()
    
    # Extract responsible person
    resp_match = re.search(r'responsible:\s*(.+)', whois_text, re.IGNORECASE)
    if resp_match:
        result["responsible"] = resp_match.group(1).strip()
    
    # Extract country
    country_match = re.search(r'^country:\s*(.+)', whois_text, re.IGNORECASE | re.MULTILINE)
    if country_match:
        result["country"] = country_match.group(1).strip()
    
    return result


def extract_entity_details(objects: Dict) -> Dict[str, Dict[str, str]]:
    """Extract detailed contact information from RDAP objects by role."""
    entities = {}
    if not isinstance(objects, dict):
        return entities

    for handle, obj in objects.items():  # type: ignore[assignment]
        if not isinstance(obj, dict):
            continue
            
        contact = obj.get("contact", {})
        if not isinstance(contact, dict):
            contact = {}
            
        roles_raw = obj.get("roles", [])
        
        # Extract roles safely
        if isinstance(roles_raw, list):
            roles = [str(r) for r in roles_raw if r]
        else:
            roles = [str(roles_raw)] if roles_raw else []
        
        # Extract contact details safely
        name = ""
        if isinstance(contact.get("name"), str):
            name = contact["name"]
        elif obj.get("handle"):
            name = str(obj["handle"])
        
        email = ""
        if isinstance(contact.get("email"), str):
            email = contact["email"]
        elif isinstance(contact.get("email"), list) and contact["email"]:
            # Handle list of email objects
            first_email = contact["email"][0]
            if isinstance(first_email, dict) and "value" in first_email:
                email = str(first_email["value"])
            else:
                email = str(first_email)
        elif isinstance(contact.get("email"), dict) and "value" in contact["email"]:
            email = str(contact["email"]["value"])
        
        phone = ""
        if isinstance(contact.get("phone"), str):
            phone = contact["phone"]
        elif isinstance(contact.get("phone"), list) and contact["phone"]:
            # Handle list of phone objects
            first_phone = contact["phone"][0]
            if isinstance(first_phone, dict) and "value" in first_phone:
                phone_val = str(first_phone["value"])
                # Remove tel: prefix if present
                phone = phone_val.replace("tel:", "").strip()
            else:
                phone = str(first_phone)
        elif isinstance(contact.get("phone"), dict) and "value" in contact["phone"]:
            phone_val = str(contact["phone"]["value"])
            phone = phone_val.replace("tel:", "").strip()
        
        # Extract address safely
        address_parts = []
        addr = contact.get("address")
        if addr:
            if isinstance(addr, str):
                address_parts.append(addr)
            elif isinstance(addr, list):
                for item in addr:
                    if isinstance(item, str):
                        address_parts.append(item)
                    elif isinstance(item, dict) and item.get("value"):
                        address_parts.append(str(item["value"]))
            elif isinstance(addr, dict) and addr.get("value"):
                address_parts.append(str(addr["value"]))
        
        address = ", ".join(filter(None, address_parts)) if address_parts else ""
        
        for role in roles:
            if role not in entities:
                entities[role] = {
                    "name": str(name),
                    "email": str(email),
                    "phone": str(phone),
                    "address": str(address)
                }
    
    return entities


def _determine_responsible(res: Dict) -> tuple[str, str]:
    """Determine responsible party and owner ID from RDAP.
    
    Returns: (owner_name, owner_id)
    owner_id should be CPF/CNPJ only, not name fallback.
    """
    try:
        network = res.get("network", {}) if isinstance(res, dict) else {}
        
        # Try to get owner and ownerid first (Brazilian RDAP standard)
        owner_id = str(network.get("ownerid", "")).strip()
        owner = str(network.get("owner", "")).strip()
        
        # If we have ownerid (CPF/CNPJ), use it
        if owner_id:
            return (owner or owner_id, owner_id)
        
        # If we only have owner name but no ownerid, use N/A for owner_id
        if owner:
            return (owner, "N/A")
        
        # Fallback to objects/entities
        objects = res.get("objects", {}) if isinstance(res, dict) else {}
        priorities = ["registrant", "org", "administrative"]
        
        for role in priorities:
            for _, obj in (objects or {}).items():
                roles = obj.get("roles", []) if isinstance(obj, dict) else []
                if role in roles:
                    contact = obj.get("contact", {}) if isinstance(obj, dict) else {}
                    name = contact.get("name") or obj.get("handle")
                    if name:
                        name_str = str(name)
                        return (name_str, "N/A")
        
        # Last resort: network name
        name = network.get("name") or network.get("handle")
        if name:
            name_str = str(name)
            return (name_str, "N/A")
            
    except Exception:
        pass
    
    return ("Unknown", "N/A")


def query_rdap(ip: str) -> IPReport:
    """Query RDAP first, then complement missing fields with WHOIS.
    This ensures we get ownerid (CPF/CNPJ) even if RDAP doesn't provide it."""
    
    # Step 1: Try RDAP first
    rdap_data = {
        "country": "N/A",
        "responsible": "Unknown",
        "owner_id": "N/A",
        "role": "N/A",
        "address": "N/A",
        "email": "N/A",
        "phone": "N/A"
    }
    
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1, rate_limit_timeout=10)
        
        network = res.get("network", {}) if isinstance(res, dict) else {}
        rdap_data["country"] = str(network.get("country", "N/A"))
        
        # Get owner and owner_id from RDAP
        responsible, owner_id = _determine_responsible(res)
        rdap_data["responsible"] = responsible
        rdap_data["owner_id"] = owner_id
        
        # Extract entity details by role
        entities = extract_entity_details(res.get("objects", {}))
        
        # Priority roles for contact information
        for role in ["registrant", "administrative", "technical", "abuse"]:
            if role in entities:
                entity = entities[role]
                if rdap_data["email"] == "N/A" and entity.get("email"):
                    rdap_data["email"] = entity["email"]
                if rdap_data["phone"] == "N/A" and entity.get("phone"):
                    rdap_data["phone"] = entity["phone"]
                if rdap_data["address"] == "N/A" and entity.get("address"):
                    rdap_data["address"] = entity["address"]
                if rdap_data["role"] == "N/A":
                    rdap_data["role"] = role
    except Exception as e:
        print(f"  RDAP failed for {ip}: {str(e)[:50]}")
    
    # Step 2: If critical fields are missing, try WHOIS to complement
    needs_whois = (
        rdap_data["owner_id"] == "N/A" or 
        rdap_data["responsible"] == "Unknown"
    )
    
    if needs_whois:
        print(f"  Complementing {ip} with WHOIS (missing ownerid or responsible)...")
        
        # First, try system whois command for Brazilian fields
        raw_whois = run_system_whois(ip)
        if raw_whois:
            parsed_whois = parse_whois_text(raw_whois)
            
            # Fill ownerid from system whois
            if parsed_whois["ownerid"] and rdap_data["owner_id"] == "N/A":
                rdap_data["owner_id"] = parsed_whois["ownerid"]
                print(f"    Found ownerid in system WHOIS: {parsed_whois['ownerid']}")
            
            # Fill owner name from system whois
            if parsed_whois["owner"] and rdap_data["responsible"] == "Unknown":
                rdap_data["responsible"] = parsed_whois["owner"]
            
            # Fill country if missing
            if parsed_whois["country"] and rdap_data["country"] == "N/A":
                rdap_data["country"] = parsed_whois["country"]
        
        # Then, try ipwhois library for additional fields
        try:
            obj = IPWhois(ip)
            res = obj.lookup_whois(get_referral=True, retry_count=2)
            
            nets = res.get("nets", [])
            if nets:
                net = nets[0] if isinstance(nets, list) else nets
                
                # Fill missing fields from ipwhois
                if rdap_data["responsible"] == "Unknown":
                    whois_desc = str(net.get("description", "")).strip()
                    if whois_desc:
                        rdap_data["responsible"] = whois_desc
                
                # Fill other missing fields
                if rdap_data["email"] == "N/A":
                    emails = net.get("emails", [])
                    rdap_data["email"] = emails[0] if isinstance(emails, list) and emails else str(emails) if emails else "N/A"
                
                if rdap_data["address"] == "N/A":
                    address_parts = []
                    for field in ["address", "city", "state", "postal_code"]:
                        val = net.get(field)
                        if val and str(val).strip():
                            address_parts.append(str(val).strip())
                    if address_parts:
                        rdap_data["address"] = ", ".join(address_parts)
                
                if rdap_data["phone"] == "N/A":
                    rdap_data["phone"] = str(net.get("phone", "N/A")).strip() or "N/A"
                
                if rdap_data["role"] == "N/A":
                    rdap_data["role"] = "registrant"
                    
        except Exception as e:
            print(f"  WHOIS also failed for {ip}: {str(e)[:50]}")
    
    return IPReport(
        ip=ip,
        country=rdap_data["country"],
        responsible=rdap_data["responsible"],
        owner_id=rdap_data["owner_id"],
        role=rdap_data["role"],
        address=rdap_data["address"],
        email=rdap_data["email"],
        phone=rdap_data["phone"]
    )


def build_pdf(report_path: Path, groups: Dict[str, List[IPReport]]) -> None:
    """Generate PDF in landscape A4 format with table layout similar to reference."""
    report_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(report_path),
        pagesize=landscape(A4),  # Landscape orientation
        leftMargin=10 * mm,
        rightMargin=10 * mm,
        topMargin=10 * mm,
        bottomMargin=10 * mm,
        title="WHOIS/RDAP Report",
    )

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    normal = ParagraphStyle("Normal", parent=styles["BodyText"], fontSize=8, leading=10)
    header_style = ParagraphStyle("Header", parent=styles["Heading3"], fontSize=9, leading=11, textColor=colors.whitesmoke)

    story: List = []

    total_ips = sum(len(v) for v in groups.values())
    story.append(Paragraph("WHOIS/RDAP Report", title_style))
    story.append(Paragraph(datetime.now().strftime("Generated: %Y-%m-%d %H:%M:%S"), normal))
    story.append(Paragraph(f"Total IPs: {total_ips}", normal))
    story.append(Spacer(1, 10))

    # Group by owner_id (CPF/CNPJ) as requested - each group gets its own table
    for idx, group_key in enumerate(sorted(groups.keys(), key=lambda s: (s.lower() == "unknown", s.lower())), 1):
        ips_in_group = groups[group_key]
        
        # Get responsible name from first IP in group
        responsible_name = ips_in_group[0].responsible if ips_in_group else "Unknown"
        
        # Group header with more visual separation
        if idx > 1:
            story.append(Spacer(1, 15))  # Extra space between groups
        
        story.append(Paragraph(f"<b>Responsible:</b> {responsible_name} | <b>CPF/CNPJ:</b> {group_key}", normal))
        story.append(Spacer(1, 6))

        # Build table data for THIS group only
        table_data = [[
            Paragraph("<b>IP Address</b>", header_style),
            Paragraph("<b>Country</b>", header_style),
            Paragraph("<b>Responsible</b>", header_style),
            Paragraph("<b>CPF/CNPJ</b>", header_style),
            Paragraph("<b>Role</b>", header_style),
            Paragraph("<b>Address</b>", header_style),
            Paragraph("<b>E-mail</b>", header_style),
            Paragraph("<b>Phone</b>", header_style),
        ]]

        # Add ONLY the IPs for this specific group
        for report in ips_in_group:
            table_data.append([
                Paragraph(report.ip, normal),
                Paragraph(report.country, normal),
                Paragraph(report.responsible, normal),
                Paragraph(report.owner_id, normal),
                Paragraph(report.role, normal),
                Paragraph(report.address or "-", normal),
                Paragraph(report.email or "-", normal),
                Paragraph(report.phone or "-", normal),
            ])

        # Column widths adjusted for landscape A4 (297mm width - margins)
        col_widths = [25*mm, 15*mm, 35*mm, 25*mm, 20*mm, 45*mm, 40*mm, 30*mm]
        
        table = Table(table_data, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            # Header row styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            
            # Data rows styling
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 1), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
            
            # Grid
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('LINEBELOW', (0, 0), (-1, 0), 1.5, colors.HexColor('#2c3e50')),
            
            # Alternating row colors
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))

        story.append(table)
        
        # Add visual separation between groups
        if idx < len(groups):
            story.append(Spacer(1, 20))  # Space between group tables
            # Add page break if current group was large
            if len(ips_in_group) > 15:
                story.append(PageBreak())
        story.append(Spacer(1, 15))

    doc.build(story)


def query_single_ip(ip: str) -> IPReport:
    """Query a single IP and return IPReport with progress indication.
    Suppresses stderr to avoid HTTPResponse cleanup warnings."""
    print(f"Querying: {ip}")
    
    # Suppress stderr during query to hide HTTPResponse finalization errors
    stderr_buffer = StringIO()
    with redirect_stderr(stderr_buffer):
        result = query_rdap(ip)
    
    return result


def main() -> None:
    # Suppress ResourceWarning from ipwhois library (Python 3.14+ HTTPResponse cleanup)
    warnings.filterwarnings("ignore", category=ResourceWarning)
    
    parser = argparse.ArgumentParser(description="Query WHOIS/RDAP and generate a grouped PDF report")
    parser.add_argument("input", help="IP, comma-separated list of IPs, or path to a file with one IP per line")
    parser.add_argument("-o", dest="out", default=None, help="Output path override (PDF file or folder)")
    parser.add_argument("-t", "--threads", dest="threads", type=int, default=5, 
                        help="Number of parallel threads (default: 5, max: 20)")
    args = parser.parse_args()

    try:
        ip_list = parse_input(args.input)
    except Exception as e:
        print(f"Error: {e}")
        raise SystemExit(2)

    # Validate and cap thread count
    thread_count = max(1, min(args.threads, 20))
    if thread_count != args.threads:
        print(f"Thread count adjusted to {thread_count} (valid range: 1-20)")

    out_dir = detect_output_directory()

    # Resolve output path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"whois_report_{timestamp}.pdf"

    if args.out:
        out_path = Path(args.out)
        if out_path.is_dir() or str(args.out).endswith(os.sep):
            pdf_path = (out_path / default_name).resolve()
        elif out_path.suffix.lower() == ".pdf":
            pdf_path = out_path.resolve()
        else:
            # Treat as directory path that may not exist yet
            pdf_path = (out_path / default_name).resolve()
    else:
        pdf_path = (out_dir / default_name).resolve()

    reports: List[IPReport] = []

    # Process IPs in parallel
    print(f"Processing {len(ip_list)} IPs with {thread_count} threads...")
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        future_to_ip = {executor.submit(query_single_ip, ip): ip for ip in ip_list}
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                report = future.result()
                reports.append(report)
                print(f"✓ Completed: {ip} ({len(reports)}/{len(ip_list)})")
            except Exception as e:
                print(f"✗ Failed: {ip} - {e}")
                # Add a placeholder report for failed IPs
                reports.append(IPReport(
                    ip=ip,
                    country="N/A",
                    responsible="Unknown",
                    owner_id="N/A",
                    role="N/A",
                    address=f"Error: {str(e)}",
                    email="N/A",
                    phone="N/A"
                ))

    try:
        # Group by owner_id (CPF/CNPJ) when available, otherwise by responsible name
        # This prevents grouping all IPs without CPF/CNPJ under a single "N/A" group
        groups: Dict[str, List[IPReport]] = defaultdict(list)
        for r in reports:
            # Use CPF/CNPJ if available, otherwise use responsible name as grouping key
            group_key = r.owner_id if r.owner_id != "N/A" else r.responsible
            groups[group_key].append(r)

        build_pdf(pdf_path, groups)
        print(f"Report generated: {pdf_path}")
    except Exception as e:
        print(f"Failed to generate PDF: {e}")
        # Fallback: save minimal text report
        txt_fallback = pdf_path.with_suffix(".txt")
        with open(txt_fallback, "w", encoding="utf-8") as f:
            for r in reports:
                f.write(f"IP: {r.ip}\n")
                f.write(f"  Country: {r.country}\n")
                f.write(f"  Responsible: {r.responsible}\n")
                f.write(f"  CPF/CNPJ: {r.owner_id}\n")
                f.write(f"  Role: {r.role}\n")
                f.write(f"  Address: {r.address}\n")
                f.write(f"  E-mail: {r.email}\n")
                f.write(f"  Phone: {r.phone}\n")
                f.write("\n")
        print(f"Fallback saved as text: {txt_fallback}")


if __name__ == "__main__":
    main()
