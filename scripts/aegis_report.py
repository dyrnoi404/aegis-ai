#!/usr/bin/env python3
"""
AEGIS AI - Executive Reporting & CVSS v3.1 Calculator Engine
Calculates standard CVSS v3.1 Base Scores, maps findings to MITRE ATT&CK & CWE,
and renders publication-grade NIST SP 800-61 security audit reports in Markdown and JSON.
"""

import sys
import math
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

# ==============================================================================
# 1. CVSS v3.1 BASE SCORE CALCULATOR (FIRST PRINCIPLES)
# ==============================================================================

AV_METRICS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_METRICS = {"L": 0.77, "H": 0.44}
PR_METRICS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_METRICS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_METRICS = {"N": 0.85, "R": 0.62}
CIA_METRICS = {"N": 0.0, "L": 0.22, "H": 0.56}


def roundup(val: float) -> float:
    return math.ceil(val * 10) / 10


def calculate_cvss_v31(vector_str: str) -> Tuple[float, str]:
    """
    Parses a CVSS v3.1 vector string and calculates the official Base Score.
    Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    parts = {}
    tokens = vector_str.replace("CVSS:3.1/", "").split("/")
    for t in tokens:
        if ":" in t:
            k, v = t.split(":", 1)
            parts[k] = v

    av = AV_METRICS.get(parts.get("AV", "N"), 0.85)
    ac = AC_METRICS.get(parts.get("AC", "L"), 0.77)
    scope_changed = (parts.get("S", "U") == "C")

    if scope_changed:
        pr = PR_METRICS_CHANGED.get(parts.get("PR", "N"), 0.85)
    else:
        pr = PR_METRICS_UNCHANGED.get(parts.get("PR", "N"), 0.85)

    ui = UI_METRICS.get(parts.get("UI", "N"), 0.85)
    c = CIA_METRICS.get(parts.get("C", "H"), 0.56)
    i = CIA_METRICS.get(parts.get("I", "H"), 0.56)
    a = CIA_METRICS.get(parts.get("A", "H"), 0.56)

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if iss <= 0:
        return 0.0, "None"

    if not scope_changed:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif not scope_changed:
        base_score = roundup(min(impact + exploitability, 10.0))
    else:
        base_score = roundup(min(1.08 * (impact + exploitability), 10.0))

    if base_score == 0.0:
        rating = "None"
    elif base_score <= 3.9:
        rating = "Low"
    elif base_score <= 6.9:
        rating = "Medium"
    elif base_score <= 8.9:
        rating = "High"
    else:
        rating = "Critical"

    return base_score, rating


# Pre-mapped standard vectors for common AEGIS findings
CWE_CVSS_MAP = {
    "CWE-78": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",   # OS Command Injection -> 10.0 Critical
    "CWE-89": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # SQL Injection -> 9.8 Critical
    "CWE-502": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Deserialization -> 9.8 Critical
    "CWE-798": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # Leaked Credential -> 7.5 High
    "CWE-312": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # Cleartext Storage -> 6.2 Medium
    "CWE-22": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",   # Path Traversal -> 7.5 High
    "CWE-327": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",  # Broken Crypto -> 3.7 Low
}


# ==============================================================================
# 2. REPORT GENERATOR (NIST SP 800-61 COMPLIANT)
# ==============================================================================

def generate_markdown_report(scan_res: Optional[Dict], audit_res: Optional[Dict], triage_res: Optional[Dict]) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []

    lines.append("# AEGIS AI: Executive Cybersecurity Audit & Incident Report")
    lines.append(f"**Generated:** {now_str} | **Framework Standards:** NIST SP 800-61 Rev. 2, MITRE ATT&CK, CIS, CVSS v3.1\n")
    lines.append("---")

    # 1. Executive Summary
    lines.append("## 1. Executive Summary")
    host = audit_res.get("hostname", "Local Host") if audit_res else "Target System"
    cis_score = audit_res.get("score", "N/A") if audit_res else "N/A"
    cis_grade = audit_res.get("grade", "N/A") if audit_res else "N/A"

    lines.append(f"* **Target Infrastructure:** `{host}`")
    lines.append(f"* **CIS Host Hardening Score:** **{cis_score}/100 (Grade: {cis_grade})**")

    findings_count = len(scan_res.get("findings", [])) if scan_res else 0
    incidents_count = len(triage_res.get("correlated_incidents", [])) if triage_res else 0
    lines.append(f"* **Static Code Flaws & Leaked Secrets:** **{findings_count}** detected")
    lines.append(f"* **Active Correlated Incident Chains:** **{incidents_count}** confirmed\n")

    # 2. Host Hardening & Posture Breakdown
    if audit_res:
        lines.append("## 2. Host Posture & Binary Protections (CIS & Checksec)")
        lines.append("| Domain | Status | Severity | Check | Details |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for c in audit_res.get("checks", []):
            lines.append(f"| {c['domain']} | `{c['status']}` | **{c['severity']}** | {c['check']} | {c['detail']} |")
        lines.append("")

    # 3. Static Application Security Testing (SAST) & Credentials
    if scan_res and scan_res.get("findings"):
        lines.append("## 3. SAST & Leaked Credential Findings (OWASP & CWE)")
        lines.append("| ID | CWE | Severity | CVSS v3.1 | Rule Name | Location | Remediation |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in scan_res["findings"]:
            cwe = f.get("cwe", "CWE-798")
            vector = CWE_CVSS_MAP.get(cwe, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
            score, rating = calculate_cvss_v31(vector)
            loc = f"`{Path(f['file']).name}:{f['line']}`"
            lines.append(f"| `{f['id']}` | **{cwe}** | `{f['severity']}` | **{score} ({rating})** | {f['rule']} | {loc} | {f.get('remediation', '')} |")
        lines.append("")

    # 4. Incident Forensics & SIEM Correlation
    if triage_res and (triage_res.get("correlated_incidents") or triage_res.get("sudo_violations")):
        lines.append("## 4. Threat Forensics & Active Incident Analysis (NIST SP 800-61)")
        for inc in triage_res.get("correlated_incidents", []):
            lines.append(f"### [INCIDENT] {inc['summary']}")
            lines.append(f"* **Attacker Origin:** `{inc['ip']}`")
            lines.append(f"* **MITRE ATT&CK:** `{inc['mitre']['technique_id']}` ({inc['mitre']['technique_name']})")
            lines.append(f"* **Targeted Personas:** `{', '.join(inc['targeted_users'])}`")
            lines.append(f"* **Timeline Window:** `{inc['first_seen']}` -> `{inc['last_seen']}`\n")

        if triage_res.get("containment_firewall_rules"):
            lines.append("#### Automated Containment Playbook (Immediate Action):")
            lines.append("```bash")
            for r in triage_res["containment_firewall_rules"]:
                lines.append(r)
            lines.append("```\n")

    # 5. Strategic Defense Roadmap
    lines.append("## 5. Strategic Remediation Roadmap")
    lines.append("1. **Immediate Containment (0-24 Hours)**:")
    lines.append("   * Apply generated iptables/nftables firewall drop rules for identified rogue IPs.")
    lines.append("   * Revoke and rotate all exposed API credentials and private keys.")
    lines.append("2. **Tactical Hardening (1-7 Days)**:")
    lines.append("   * Patch AST vulnerability sinks: eliminate `shell=True` and parameterize all database queries.")
    lines.append("   * Restrict kernel pointers: `sysctl -w kernel.kptr_restrict=2`.")
    lines.append("   * Audit and prune exploitable GTFOBins SUID binaries (`chmod u-s <binary>`).")
    lines.append("3. **Strategic Assurance (Ongoing)**:")
    lines.append("   * Integrate AEGIS SAST scanning into CI/CD pull request gates.")
    lines.append("   * Deploy automated fail2ban jails mapped to MITRE T1110 brute-force behaviors.")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="AEGIS AI - Executive Reporting & CVSS Calculator")
    parser.add_argument("--scan-json", help="Path to aegis_scan JSON output")
    parser.add_argument("--audit-json", help="Path to aegis_audit JSON output")
    parser.add_argument("--triage-json", help="Path to aegis_triage JSON output")
    parser.add_argument("--out", "-o", help="Output markdown report file path", default="aegis_security_report.md")

    args = parser.parse_args()

    scan_data = None
    audit_data = None
    triage_data = None

    if args.scan_json and Path(args.scan_json).exists():
        with open(args.scan_json, "r") as f:
            scan_data = json.load(f)

    if args.audit_json and Path(args.audit_json).exists():
        with open(args.audit_json, "r") as f:
            audit_data = json.load(f)

    if args.triage_json and Path(args.triage_json).exists():
        with open(args.triage_json, "r") as f:
            triage_data = json.load(f)

    report_md = generate_markdown_report(scan_data, audit_data, triage_data)

    out_path = Path(args.out)
    out_path.write_text(report_md, encoding="utf-8")
    print(f"\n[✓] AEGIS Executive Report generated successfully: {out_path.resolve()}\n")


if __name__ == "__main__":
    main()
