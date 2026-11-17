#!/usr/bin/env python3
"""
Incident forensics and SIEM event correlation engine.
"""

import sys
import re
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, Any, List

MITRE_TECHNIQUES = {
    "SSH_BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing"
    },
    "ACCOUNT_TAKEOVER": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts"
    },
    "UNAUTHORIZED_SUDO": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
    },
    "WEB_EXPLOIT_PROBE": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application"
    },
    "ACTIVE_SCANNING": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595.002",
        "technique_name": "Active Scanning: Vulnerability Scanning"
    }
}

RE_AUTH_TIMESTAMP = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")
RE_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2")
RE_SSH_ACCEPT = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2")
RE_SUDO_NOT_IN_SUDOERS = re.compile(r"sudo:\s+(\S+) : user NOT in sudoers ; .* COMMAND=(.*)")
RE_SUDO_EXEC = re.compile(r"sudo:\s+(\S+) : TTY=\S+ ; PWD=\S+ ; USER=\S+ ; COMMAND=(.*)")

RE_WEB_LINE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^ "]+) HTTP/[0-9.]+" (\d{3}) \d+ "([^"]*)" "([^"]*)"'
)

SCANNER_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster",
    "nuclei", "zgrab", "wpscan", "acunetix", "nessus", "openvas"
]

SUSPICIOUS_PATHS = [
    (re.compile(r"\.\./"), "CWE-22", "Path Traversal"),
    (re.compile(r"/etc/passwd"), "CWE-22", "Passwd Disclosure Attempt"),
    (re.compile(r"\.env"), "CWE-200", "Environment Secret Probe"),
    (re.compile(r"wp-config\.php"), "CWE-200", "CMS Credential Probe"),
    (re.compile(r"/\.git/"), "CWE-200", "Git Repository Exposure Probe"),
    (re.compile(r"(?:UNION\s+SELECT|'\s*OR\s*1=1|benchmark\(|sleep\()", re.IGNORECASE), "CWE-89", "SQL Injection Payload"),
    (re.compile(r"(?:<script|javascript:|onerror=)", re.IGNORECASE), "CWE-79", "Cross-Site Scripting (XSS) Probe")
]


class TimestampedEvent:
    def __init__(self, raw_ts: str, event_type: str, ip: str, user: str, details: Dict[str, Any]):
        self.raw_ts = raw_ts
        self.event_type = event_type
        self.ip = ip
        self.user = user
        self.details = details
        self.timestamp = self._parse_timestamp(raw_ts)

    def _parse_timestamp(self, ts_str: str) -> datetime:
        current_year = datetime.now().year
        try:
            return datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
        except Exception:
            return datetime.now()


def correlate_auth_events(events: List[TimestampedEvent]) -> List[Dict[str, Any]]:
    correlated_incidents = []
    events_by_ip = defaultdict(list)

    for ev in events:
        if ev.ip:
            events_by_ip[ev.ip].append(ev)

    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda x: x.timestamp)
        failed_attempts = [e for e in ip_events if e.event_type == "SSH_FAIL"]
        accepted_attempts = [e for e in ip_events if e.event_type == "SSH_ACCEPT"]

        if len(failed_attempts) >= 5:
            incident = {
                "id": f"INC-BF-{ip.replace('.', '-')}",
                "severity": "HIGH",
                "ip": ip,
                "mitre": MITRE_TECHNIQUES["SSH_BRUTE_FORCE"],
                "summary": f"SSH brute-force activity ({len(failed_attempts)} failed attempts)",
                "targeted_users": list(set(e.user for e in failed_attempts)),
                "first_seen": failed_attempts[0].raw_ts,
                "last_seen": failed_attempts[-1].raw_ts,
                "chain_detected": False
            }

            for acc in accepted_attempts:
                if acc.timestamp >= failed_attempts[0].timestamp:
                    time_diff = (acc.timestamp - failed_attempts[-1].timestamp).total_seconds()
                    if 0 <= time_diff <= 600:
                        incident["severity"] = "CRITICAL"
                        incident["chain_detected"] = True
                        incident["compromised_user"] = acc.user
                        incident["summary"] = f"Account takeover chain detected: brute-force succeeded for user '{acc.user}'"
                        incident["mitre_chain"] = [
                            MITRE_TECHNIQUES["SSH_BRUTE_FORCE"],
                            MITRE_TECHNIQUES["ACCOUNT_TAKEOVER"]
                        ]
                        break

            correlated_incidents.append(incident)

    return correlated_incidents


def triage_auth_log(lines: List[str]) -> Dict[str, Any]:
    events: List[TimestampedEvent] = []
    sudo_violations = []

    for line in lines:
        ts_match = RE_AUTH_TIMESTAMP.match(line)
        raw_ts = ts_match.group(1) if ts_match else "Nov 17 00:00:00"

        m_fail = RE_SSH_FAIL.search(line)
        if m_fail:
            user, ip = m_fail.groups()
            events.append(TimestampedEvent(raw_ts, "SSH_FAIL", ip, user, {"raw": line.strip()}))
            continue

        m_acc = RE_SSH_ACCEPT.search(line)
        if m_acc:
            user, ip = m_acc.groups()
            events.append(TimestampedEvent(raw_ts, "SSH_ACCEPT", ip, user, {"raw": line.strip()}))
            continue

        m_sudo_fail = RE_SUDO_NOT_IN_SUDOERS.search(line)
        if m_sudo_fail:
            user, cmd = m_sudo_fail.groups()
            sudo_violations.append({
                "timestamp": raw_ts,
                "user": user,
                "command": cmd.strip(),
                "mitre": MITRE_TECHNIQUES["UNAUTHORIZED_SUDO"],
                "severity": "HIGH"
            })

    incidents = correlate_auth_events(events)

    return {
        "log_type": "auth",
        "total_events_parsed": len(lines),
        "correlated_incidents": incidents,
        "sudo_violations": sudo_violations,
        "unique_attacker_ips": list(set(e.ip for e in events if e.event_type == "SSH_FAIL"))
    }


def triage_web_log(lines: List[str]) -> Dict[str, Any]:
    scanner_hits = defaultdict(int)
    probes = []
    ip_activity = defaultdict(int)

    for line in lines:
        m = RE_WEB_LINE.match(line)
        if not m:
            continue
        ip, date, method, path, status, referer, user_agent = m.groups()
        ip_activity[ip] += 1
        ua_lower = user_agent.lower()

        for sc in SCANNER_USER_AGENTS:
            if sc in ua_lower:
                scanner_hits[sc] += 1
                break

        for pattern, cwe, attack_name in SUSPICIOUS_PATHS:
            if pattern.search(path):
                probes.append({
                    "ip": ip,
                    "cwe": cwe,
                    "attack": attack_name,
                    "method": method,
                    "path": path[:90],
                    "status": status,
                    "mitre": MITRE_TECHNIQUES["WEB_EXPLOIT_PROBE"]
                })
                break

    return {
        "log_type": "web",
        "total_requests": len(lines),
        "scanner_activity": dict(scanner_hits),
        "exploit_probes_count": len(probes),
        "exploit_samples": probes[:15],
        "top_ips": dict(sorted(ip_activity.items(), key=lambda x: x[1], reverse=True)[:5])
    }


def parse_and_triage(filepath: Path) -> Dict[str, Any]:
    if not filepath.exists():
        raise FileNotFoundError(f"Log artifact does not exist: {filepath}")

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        sample = "".join(f.readline() for _ in range(50))
        f.seek(0)
        lines = f.readlines()

    if "Failed password" in sample or "sshd[" in sample or "sudo:" in sample:
        res = triage_auth_log(lines)
    elif "HTTP/" in sample or 'GET ' in sample or 'POST ' in sample:
        res = triage_web_log(lines)
    else:
        res = triage_auth_log(lines)
        if not res["correlated_incidents"] and not res["sudo_violations"]:
            res = triage_web_log(lines)

    containment_rules = []
    if res.get("log_type") == "auth":
        for inc in res.get("correlated_incidents", []):
            ip = inc["ip"]
            containment_rules.append(f"iptables -A INPUT -s {ip} -j DROP")
    elif res.get("log_type") == "web":
        flagged_ips = list(set(p["ip"] for p in res.get("exploit_samples", [])))
        for ip in flagged_ips[:10]:
            containment_rules.append(f"iptables -A INPUT -s {ip} -j DROP")

    res["containment_firewall_rules"] = containment_rules
    return res


def main():
    parser = argparse.ArgumentParser(description="AEGIS Incident Forensics and SIEM Engine")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    try:
        results = parse_and_triage(Path(args.logfile))
    except Exception as err:
        print(f"[-] Triage analysis error: {err}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    print(f"\nTarget File:    {Path(args.logfile).name}")
    print(f"Log Subsystem:  {results.get('log_type', 'unknown').upper()}")

    if results["log_type"] == "auth":
        incidents = results.get("correlated_incidents", [])
        print(f"Total Incidents: {len(incidents)}")
        print(f"Sudo Violations: {len(results.get('sudo_violations', []))}\n")

        for inc in incidents:
            color = "\033[91m" if inc["severity"] == "CRITICAL" else "\033[93m"
            reset = "\033[0m"
            print(f"[{color}{inc['severity']}{reset}] {inc['summary']}")
            print(f"  Attacker IP:   {inc['ip']}")
            print(f"  MITRE ATT&CK:  {inc['mitre']['technique_id']} - {inc['mitre']['technique_name']}")
            print(f"  Target Users:  {', '.join(inc['targeted_users'])}")
            print(f"  Time Window:   {inc['first_seen']} -> {inc['last_seen']}")
            print("-" * 75)

        if results["sudo_violations"]:
            print("\nUnauthorized Sudo Escalation Attempts:")
            for s in results["sudo_violations"]:
                print(f"  - [{s['timestamp']}] User: {s['user']} | Command: {s['command']} | ({s['mitre']['technique_id']})")

    elif results["log_type"] == "web":
        print(f"Total Requests:  {results['total_requests']}")
        print(f"Exploit Probes:  {results['exploit_probes_count']}")
        print(f"Scanners:        {sum(results['scanner_activity'].values())}\n")

        if results["scanner_activity"]:
            print("Scanner Fingerprints:")
            for sc, count in results["scanner_activity"].items():
                print(f"  - {sc}: {count} probes")
            print("-" * 75)

        if results["exploit_samples"]:
            print("\nHigh-Risk Exploit Probes:")
            for p in results["exploit_samples"][:8]:
                print(f"  - [{p['ip']}] {p['attack']} ({p['cwe']}): {p['method']} {p['path']} -> HTTP {p['status']}")

    if results.get("containment_firewall_rules"):
        print("\nContainment Rules:")
        for rule in results["containment_firewall_rules"][:5]:
            print(f"  \033[36m{rule}\033[0m")

    print("\n")


if __name__ == "__main__":
    main()
