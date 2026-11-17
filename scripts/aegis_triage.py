#!/usr/bin/env python3
"""
AEGIS AI - Log & Incident Triage Analyzer
Parses Linux authentication (auth.log/secure) and Web server access logs
to identify brute-force attacks, scanner probes, privilege escalation, and web exploit attempts.
"""

import sys
import re
import json
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Dict, Any, List

# Regex patterns for SSH / Auth logs
RE_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2")
RE_SSH_ACCEPT = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2")
RE_SUDO_NOT_IN_SUDOERS = re.compile(r"sudo:\s+(\S+) : user NOT in sudoers ; .* COMMAND=(.*)")
RE_SUDO_CMD = re.compile(r"sudo:\s+(\S+) : .* COMMAND=(.*)")

# Regex patterns for Web access logs
RE_WEB_LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^ "]+) HTTP/[0-9.]+" (\d{3}) \d+ "([^"]*)" "([^"]*)"')

SCANNER_SIGNATURES = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster",
    "nuclei", "zgrab", "wpscan", "acunetix", "nessus", "openvas"
]

SUSPICIOUS_WEB_TARGETS = [
    r"\.\./", r"/etc/passwd", r"\.env", r"wp-config\.php",
    r"phpinfo\.php", r"/actuator/env", r"/\.git/", r"shell\.php"
]


def triage_auth_log(lines: List[str]) -> Dict[str, Any]:
    failed_logins = defaultdict(int)  # (ip, user) -> count
    failed_by_ip = defaultdict(int)   # ip -> count
    accepted_logins = []
    sudo_violations = []

    for line in lines:
        m_fail = RE_SSH_FAIL.search(line)
        if m_fail:
            user, ip = m_fail.groups()
            failed_logins[(ip, user)] += 1
            failed_by_ip[ip] += 1
            continue

        m_acc = RE_SSH_ACCEPT.search(line)
        if m_acc:
            user, ip = m_acc.groups()
            accepted_logins.append({"user": user, "ip": ip, "raw": line.strip()[:100]})
            continue

        m_sudo_fail = RE_SUDO_NOT_IN_SUDOERS.search(line)
        if m_sudo_fail:
            user, cmd = m_sudo_fail.groups()
            sudo_violations.append({"user": user, "command": cmd.strip()})

    # Filter brute-force offenders (> 5 failed attempts)
    brute_force_ips = {ip: count for ip, count in failed_by_ip.items() if count >= 5}

    return {
        "log_type": "auth",
        "total_failed_ssh": sum(failed_by_ip.values()),
        "unique_attacker_ips": len(failed_by_ip),
        "brute_force_detected": len(brute_force_ips) > 0,
        "brute_force_offenders": brute_force_ips,
        "successful_logins": accepted_logins[-10:],
        "sudo_violations": sudo_violations,
    }


def triage_web_log(lines: List[str]) -> Dict[str, Any]:
    scanner_hits = defaultdict(int)
    exploit_attempts = []
    ip_bursts = defaultdict(int)
    status_codes = defaultdict(int)

    re_suspicious = re.compile("|".join(SUSPICIOUS_WEB_TARGETS), re.IGNORECASE)

    for line in lines:
        m = RE_WEB_LINE.match(line)
        if not m:
            continue
        ip, date, method, path, status, referer, user_agent = m.groups()
        ip_bursts[ip] += 1
        status_codes[status] += 1

        ua_lower = user_agent.lower()
        for scanner in SCANNER_SIGNATURES:
            if scanner in ua_lower:
                scanner_hits[scanner] += 1
                break

        if re_suspicious.search(path):
            exploit_attempts.append({
                "ip": ip,
                "method": method,
                "path": path[:80],
                "status": status
            })

    return {
        "log_type": "web",
        "total_requests": sum(ip_bursts.values()),
        "unique_ips": len(ip_bursts),
        "scanner_activity": dict(scanner_hits),
        "exploit_attempts_count": len(exploit_attempts),
        "exploit_samples": exploit_attempts[:10],
        "top_requesting_ips": dict(sorted(ip_bursts.items(), key=lambda x: x[1], reverse=True)[:5])
    }


def analyze_log_file(filepath: Path) -> Dict[str, Any]:
    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        sample = [f.readline() for _ in range(50)]
        f.seek(0)
        lines = f.readlines()

    sample_text = "".join(sample)
    # Detect log format
    if "Failed password" in sample_text or "sshd[" in sample_text or "sudo:" in sample_text:
        return triage_auth_log(lines)
    elif 'HTTP/' in sample_text or 'GET ' in sample_text:
        return triage_web_log(lines)
    else:
        # Fallback to auth triage
        auth_res = triage_auth_log(lines)
        if auth_res["total_failed_ssh"] > 0:
            return auth_res
        return triage_web_log(lines)


def main():
    parser = argparse.ArgumentParser(description="AEGIS AI - Incident & Log Triage Analyzer")
    parser.add_argument("logfile", help="Path to log file (auth.log, access.log, etc.)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()
    log_path = Path(args.logfile)

    try:
        results = analyze_log_file(log_path)
    except Exception as e:
        print(f"[-] Triage error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    print(f"\n[+] AEGIS Incident Triage - File: {log_path.name}")
    print("=" * 60)

    if results["log_type"] == "auth":
        print(f" Total Failed SSH Attempts: {results['total_failed_ssh']}")
        print(f" Unique Suspicious IPs:     {results['unique_attacker_ips']}")
        print(f" Brute-force Status:        {'CRITICAL (Active Brute-Force)' if results['brute_force_detected'] else 'NORMAL'}")
        
        if results["brute_force_offenders"]:
            print("\n[!] Top Brute-Force Attackers:")
            for ip, count in results["brute_force_offenders"].items():
                print(f"    - IP {ip:<18} ({count} failed attempts)")

        if results["sudo_violations"]:
            print(f"\n[!] Unauthorized Sudo Violations: {len(results['sudo_violations'])}")
            for v in results["sudo_violations"]:
                print(f"    - User '{v['user']}' attempted unauthorized command: {v['command']}")

        if results["successful_logins"]:
            print(f"\n[i] Recent Successful Logins: {len(results['successful_logins'])}")
            for s in results["successful_logins"]:
                print(f"    - User: {s['user']} from IP: {s['ip']}")

    elif results["log_type"] == "web":
        print(f" Total Requests Analyzed:    {results['total_requests']}")
        print(f" Unique Client IPs:          {results['unique_ips']}")
        print(f" Automated Scanner Hits:     {sum(results['scanner_activity'].values())}")
        print(f" Exploit Probes Detected:    {results['exploit_attempts_count']}")

        if results["scanner_activity"]:
            print("\n[!] Detected Security Scanners:")
            for sc, count in results["scanner_activity"].items():
                print(f"    - {sc}: {count} hits")

        if results["exploit_samples"]:
            print("\n[!] Sample Malicious Requests:")
            for ex in results["exploit_samples"]:
                print(f"    - [{ex['ip']}] {ex['method']} {ex['path']} (HTTP {ex['status']})")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()
