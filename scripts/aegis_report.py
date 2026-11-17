#!/usr/bin/env python3
"""
CVSS v3.1 calculation and audit report generation engine.
"""

import math
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

AV_METRICS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_METRICS = {"L": 0.77, "H": 0.44}
PR_METRICS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_METRICS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_METRICS = {"N": 0.85, "R": 0.62}
CIA_METRICS = {"N": 0.0, "L": 0.22, "H": 0.56}

CWE_CVSS_MAP = {
    "CWE-78": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "CWE-89": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-502": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-798": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-312": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-22": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-327": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
}


def roundup(val: float) -> float:
    return math.ceil(val * 10) / 10


def calculate_cvss_v31(vector_str: str) -> Tuple[float, str]:
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


def generate_markdown_report(scan_res: Optional[Dict], audit_res: Optional[Dict], triage_res: Optional[Dict]) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []

    lines.append("# AEGIS Security Audit and Incident Report")
    lines.append(f"Generated: {now_str}\n")
    lines.append("---")

    lines.append("## 1. Executive Summary")
    host = audit_res.get("hostname", "Local Host") if audit_res else "Target System"
    cis_score = audit_res.get("score", "N/A") if audit_res else "N/A"
    cis_grade = audit_res.get("grade", "N/A") if audit_res else "N/A"

    lines.append(f"- Target Host: `{host}`")
    lines.append(f"- CIS Hardening Score: **{cis_score}/100 (Grade: {cis_grade})**")

    findings_count = len(scan_res.get("findings", [])) if scan_res else 0
    incidents_count = len(triage_res.get("correlated_incidents", [])) if triage_res else 0
    lines.append(f"- Static Code Flaws and Credentials: **{findings_count}** detected")
    lines.append(f"- Correlated Incidents: **{incidents_count}** confirmed\n")

    if audit_res:
        lines.append("## 2. Host Posture and Mitigations")
        lines.append("| Domain | Status | Severity | Check | Details |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for c in audit_res.get("checks", []):
            lines.append(f"| {c['domain']} | `{c['status']}` | **{c['severity']}** | {c['check']} | {c['detail']} |")
        lines.append("")

    if scan_res and scan_res.get("findings"):
        lines.append("## 3. SAST and Leaked Credentials")
        lines.append("| ID | CWE | Severity | CVSS v3.1 | Rule Name | Location | Remediation |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in scan_res["findings"]:
            cwe = f.get("cwe", "CWE-798")
            vector = CWE_CVSS_MAP.get(cwe, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
            score, rating = calculate_cvss_v31(vector)
            loc = f"`{Path(f['file']).name}:{f['line']}`"
            lines.append(f"| `{f['id']}` | **{cwe}** | `{f['severity']}` | **{score} ({rating})** | {f['rule']} | {loc} | {f.get('remediation', '')} |")
        lines.append("")

    if triage_res and (triage_res.get("correlated_incidents") or triage_res.get("sudo_violations")):
        lines.append("## 4. Threat Forensics and Active Incidents")
        for inc in triage_res.get("correlated_incidents", []):
            lines.append(f"### [INCIDENT] {inc['summary']}")
            lines.append(f"- Attacker Origin: `{inc['ip']}`")
            lines.append(f"- MITRE ATT&CK: `{inc['mitre']['technique_id']}` ({inc['mitre']['technique_name']})")
            lines.append(f"- Targeted Personas: `{', '.join(inc['targeted_users'])}`")
            lines.append(f"- Timeline Window: `{inc['first_seen']}` -> `{inc['last_seen']}`\n")

        if triage_res.get("containment_firewall_rules"):
            lines.append("#### Containment Playbook:")
            lines.append("```bash")
            for r in triage_res["containment_firewall_rules"]:
                lines.append(r)
            lines.append("```\n")

    lines.append("## 5. Remediation Roadmap")
    lines.append("1. **Containment (Immediate)**:")
    lines.append("   - Apply firewall rules for rogue origin IPs.")
    lines.append("   - Revoke and rotate exposed credentials and private keys.")
    lines.append("2. **Eradication and Hardening**:")
    lines.append("   - Parameterize database queries and remove `shell=True` invocations.")
    lines.append("   - Enforce `kernel.kptr_restrict=2`.")
    lines.append("   - Prune unneeded SUID binaries (`chmod u-s`).")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="AEGIS Executive Reporting and CVSS Calculator")
    parser.add_argument("--scan-json", help="Path to aegis_scan JSON output")
    parser.add_argument("--audit-json", help="Path to aegis_audit JSON output")
    parser.add_argument("--triage-json", help="Path to aegis_triage JSON output")
    parser.add_argument("--out", "-o", help="Output markdown report path", default="aegis_security_report.md")

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
    print(f"[OK] Report written: {out_path.resolve()}")


if __name__ == "__main__":
    main()
