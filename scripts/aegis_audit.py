#!/usr/bin/env python3
"""
AEGIS AI - Linux Host Hardening & Posture Auditor
Non-destructive system audit for misconfigurations, risky SUIDs,
insecure permissions, open ports, and kernel hardening parameters.
"""

import os
import sys
import json
import socket
import subprocess
import argparse
from pathlib import Path
from typing import List, Dict, Any

RISKY_SUID_BINARIES = {
    "bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby",
    "lua", "vim", "vi", "nano", "find", "tar", "zip", "gzip", "nmap",
    "tcpdump", "awk", "sed", "gdb", "strace", "curl", "wget", "nc",
    "netcat", "socat", "cp", "mv", "chmod", "chown", "env", "sudo"
}


def check_aslr() -> Dict[str, Any]:
    path = Path("/proc/sys/kernel/randomize_va_space")
    if not path.exists():
        return {"check": "ASLR", "status": "UNKNOWN", "severity": "INFO", "score": 0, "detail": "Procfs not accessible"}
    try:
        val = path.read_text().strip()
        if val == "2":
            return {"check": "ASLR", "status": "PASS", "severity": "LOW", "score": 10, "detail": "ASLR is fully enabled (value=2)"}
        elif val == "1":
            return {"check": "ASLR", "status": "WARN", "severity": "MEDIUM", "score": 5, "detail": "ASLR is partially enabled (value=1)"}
        else:
            return {"check": "ASLR", "status": "FAIL", "severity": "HIGH", "score": 0, "detail": f"ASLR is disabled (value={val})"}
    except Exception as e:
        return {"check": "ASLR", "status": "ERROR", "severity": "INFO", "score": 0, "detail": str(e)}


def check_critical_file_perms() -> List[Dict[str, Any]]:
    checks = []
    # /etc/passwd should not be world-writable
    p = Path("/etc/passwd")
    if p.exists():
        mode = p.stat().st_mode
        if mode & 0o002:
            checks.append({"check": "File Perm: /etc/passwd", "status": "FAIL", "severity": "CRITICAL", "score": 0, "detail": "/etc/passwd is world-writable!"})
        else:
            checks.append({"check": "File Perm: /etc/passwd", "status": "PASS", "severity": "LOW", "score": 10, "detail": "/etc/passwd permissions are restricted"})

    # /etc/shadow should not be readable by others
    s = Path("/etc/shadow")
    if s.exists():
        try:
            with open(s, "r"):
                checks.append({"check": "File Perm: /etc/shadow", "status": "FAIL", "severity": "CRITICAL", "score": 0, "detail": "/etc/shadow is readable by current unprivileged user!"})
        except PermissionError:
            checks.append({"check": "File Perm: /etc/shadow", "status": "PASS", "severity": "LOW", "score": 10, "detail": "/etc/shadow is protected against unprivileged reads"})
        except Exception:
            pass

    # ~/.ssh/ permissions check
    ssh_dir = Path.home() / ".ssh"
    if ssh_dir.exists():
        mode = ssh_dir.stat().st_mode
        if mode & 0o077 != 0:
            checks.append({"check": "SSH Dir Perms", "status": "WARN", "severity": "MEDIUM", "score": 5, "detail": f"~/.ssh has loose permissions: {oct(mode & 0o777)}"})
        else:
            checks.append({"check": "SSH Dir Perms", "status": "PASS", "severity": "LOW", "score": 10, "detail": "~/.ssh has strict 700 permissions"})

        for key_file in ssh_dir.glob("id_*"):
            if not key_file.name.endswith(".pub"):
                k_mode = key_file.stat().st_mode
                if k_mode & 0o077 != 0:
                    checks.append({"check": f"Private Key Perm: {key_file.name}", "status": "WARN", "severity": "HIGH", "score": 0, "detail": f"{key_file.name} is accessible by group/others: {oct(k_mode & 0o777)}"})
    return checks


def check_suid_binaries() -> List[Dict[str, Any]]:
    findings = []
    # Scan standard binary directories
    bin_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"]
    detected_risky = []
    
    for b_dir in bin_dirs:
        p = Path(b_dir)
        if not p.is_dir():
            continue
        try:
            for item in p.iterdir():
                if item.is_file() and not item.is_symlink():
                    try:
                        st = item.stat()
                        if st.st_mode & 0o4000:  # SUID bit
                            if item.name.lower() in RISKY_SUID_BINARIES:
                                detected_risky.append(f"{item} (GTFOBins target)")
                    except (PermissionError, FileNotFoundError):
                        continue
        except Exception:
            continue

    if detected_risky:
        findings.append({
            "check": "SUID Binaries",
            "status": "WARN",
            "severity": "HIGH",
            "score": 5,
            "detail": f"Detected potentially exploitable SUID binaries: {', '.join(detected_risky[:5])}"
        })
    else:
        findings.append({
            "check": "SUID Binaries",
            "status": "PASS",
            "severity": "LOW",
            "score": 10,
            "detail": "No anomalous or high-risk GTFOBins SUID binaries detected in standard paths"
        })
    return findings


def check_listening_ports() -> List[Dict[str, Any]]:
    checks = []
    open_public = []
    
    # Run ss -tulpn or parse /proc/net/tcp
    try:
        res = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            lines = res.stdout.strip().split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[4]
                    if local_addr.startswith("0.0.0.0:") or local_addr.startswith("[::]:") or local_addr.startswith("*:") :
                        open_public.append(local_addr)
    except Exception:
        pass

    if open_public:
        checks.append({
            "check": "Public Listening Services",
            "status": "WARN",
            "severity": "MEDIUM",
            "score": 5,
            "detail": f"Services listening on all network interfaces (0.0.0.0/*): {', '.join(open_public[:6])}"
        })
    else:
        checks.append({
            "check": "Public Listening Services",
            "status": "PASS",
            "severity": "LOW",
            "score": 10,
            "detail": "No unbound public listening sockets detected or ports strictly bound to localhost"
        })
    return checks


def check_sshd_config() -> List[Dict[str, Any]]:
    checks = []
    p = Path("/etc/ssh/sshd_config")
    if not p.exists():
        return checks

    try:
        content = p.read_text(errors="ignore")
        root_login = None
        pass_auth = None
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if line.lower().startswith("permitrootlogin"):
                root_login = line.split()[-1]
            if line.lower().startswith("passwordauthentication"):
                pass_auth = line.split()[-1]

        if root_login and root_login.lower() in ("yes", "prohibit-password"):
            checks.append({
                "check": "SSH Root Login",
                "status": "WARN" if root_login.lower() == "prohibit-password" else "FAIL",
                "severity": "HIGH" if root_login.lower() == "yes" else "MEDIUM",
                "score": 5 if root_login.lower() == "prohibit-password" else 0,
                "detail": f"PermitRootLogin is set to '{root_login}' (recommended: 'no')"
            })
        else:
            checks.append({
                "check": "SSH Root Login",
                "status": "PASS",
                "severity": "LOW",
                "score": 10,
                "detail": "SSH root login is disabled or default restricted"
            })
    except Exception:
        pass
    return checks


def run_audit() -> Dict[str, Any]:
    all_checks = []
    all_checks.append(check_aslr())
    all_checks.extend(check_critical_file_perms())
    all_checks.extend(check_suid_binaries())
    all_checks.extend(check_listening_ports())
    all_checks.extend(check_sshd_config())

    # Calculate overall security score (0 - 100)
    total_score = sum(c.get("score", 0) for c in all_checks)
    max_score = len(all_checks) * 10
    final_percentage = round((total_score / max_score) * 100) if max_score > 0 else 0

    if final_percentage >= 85:
        grade = "A"
    elif final_percentage >= 70:
        grade = "B"
    elif final_percentage >= 50:
        grade = "C"
    else:
        grade = "D"

    return {
        "hostname": socket.gethostname(),
        "score": final_percentage,
        "grade": grade,
        "checks_count": len(all_checks),
        "checks": all_checks
    }


def main():
    parser = argparse.ArgumentParser(description="AEGIS AI - Host Hardening & Posture Auditor")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    results = run_audit()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n╔═══════════════════════════════════════════════════════════╗")
        print(f"║             AEGIS AI - Host Security Posture              ║")
        print(f"╚═══════════════════════════════════════════════════════════╝")
        print(f" Target Host:    {results['hostname']}")
        print(f" Security Grade: {results['grade']} ({results['score']}/100)")
        print(f" Total Audits:   {results['checks_count']}\n")
        print(f"{'STATUS':<8} {'SEVERITY':<10} {'CHECK':<28} {'DETAILS'}")
        print("-" * 75)

        for c in results["checks"]:
            st = c["status"]
            sev = c["severity"]
            if st == "PASS":
                st_str = "\033[92mPASS\033[0m"
            elif st == "WARN":
                st_str = "\033[93mWARN\033[0m"
            else:
                st_str = "\033[91mFAIL\033[0m"

            print(f"{st_str:<17} {sev:<10} {c['check']:<28} {c['detail']}")
        print("\n")


if __name__ == "__main__":
    main()
