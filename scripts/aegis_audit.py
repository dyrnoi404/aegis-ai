#!/usr/bin/env python3
"""
Host security posture, binary mitigations (Checksec), and kernel parameter auditor.
"""

import os
import sys
import json
import struct
import socket
import subprocess
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x00000008
DF_1_NOW = 0x00000001

GTFOBINS_TARGETS = {
    "bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby",
    "lua", "vim", "vi", "nano", "find", "tar", "zip", "gzip", "nmap",
    "tcpdump", "awk", "sed", "gdb", "strace", "curl", "wget", "nc",
    "netcat", "socat", "cp", "mv", "chmod", "chown", "env", "pkexec"
}


def analyze_elf_binary(filepath: Path) -> Optional[Dict[str, Any]]:
    if not filepath.is_file() or filepath.is_symlink():
        return None

    try:
        with open(filepath, "rb") as f:
            header = f.read(64)
            if len(header) < 52 or header[:4] != b"\x7fELF":
                return None

            ei_class = header[4]
            e_type = struct.unpack("<H", header[16:18])[0]
            is_64 = (ei_class == 2)

            if is_64:
                e_phoff = struct.unpack("<Q", header[32:40])[0]
                e_phentsize = struct.unpack("<H", header[54:56])[0]
                e_phnum = struct.unpack("<H", header[56:58])[0]
            else:
                e_phoff = struct.unpack("<I", header[28:32])[0]
                e_phentsize = struct.unpack("<H", header[42:44])[0]
                e_phnum = struct.unpack("<H", header[44:46])[0]

            f.seek(e_phoff)
            ph_data = f.read(e_phentsize * e_phnum)

            nx_enabled = True
            has_relro = False

            for i in range(e_phnum):
                offset = i * e_phentsize
                ph = ph_data[offset: offset + e_phentsize]
                if not ph:
                    break

                if is_64:
                    p_type = struct.unpack("<I", ph[0:4])[0]
                    p_flags = struct.unpack("<I", ph[4:8])[0]
                else:
                    p_type = struct.unpack("<I", ph[0:4])[0]
                    p_flags = struct.unpack("<I", ph[24:28])[0]

                if p_type == PT_GNU_STACK:
                    if p_flags & 0x1:
                        nx_enabled = False
                elif p_type == PT_GNU_RELRO:
                    has_relro = True

            f.seek(0)
            raw_content = f.read(2 * 1024 * 1024)
            has_canary = b"__stack_chk_fail" in raw_content or b"__stack_chk_guard" in raw_content

            relro_status = "Full RELRO" if (has_relro and b"BIND_NOW" in raw_content) else ("Partial RELRO" if has_relro else "No RELRO")

            return {
                "binary": filepath.name,
                "path": str(filepath),
                "nx": nx_enabled,
                "canary": has_canary,
                "pie": e_type == 3,
                "relro": relro_status,
                "secure": nx_enabled and has_canary and (e_type == 3)
            }
    except Exception:
        return None


def audit_critical_binaries() -> List[Dict[str, Any]]:
    checks = []
    sample_binaries = [
        "/bin/bash", "/usr/bin/sudo", "/usr/sbin/sshd",
        "/usr/bin/python3", "/bin/login", "/usr/bin/passwd"
    ]
    for b_str in sample_binaries:
        p = Path(b_str)
        if p.exists() and p.is_file():
            res = analyze_elf_binary(p)
            if res:
                status = "PASS" if res["secure"] else "WARN"
                detail = f"NX={res['nx']}, Canary={res['canary']}, PIE={res['pie']}, RELRO={res['relro']}"
                checks.append({
                    "domain": "Binary Hardening",
                    "check": f"Checksec: {p.name}",
                    "status": status,
                    "severity": "LOW" if status == "PASS" else "MEDIUM",
                    "score": 10 if status == "PASS" else 5,
                    "detail": detail
                })
    return checks


def audit_kernel_parameters() -> List[Dict[str, Any]]:
    checks = []

    p_aslr = Path("/proc/sys/kernel/randomize_va_space")
    if p_aslr.exists():
        try:
            val = p_aslr.read_text().strip()
            if val == "2":
                checks.append({
                    "domain": "Kernel Protections",
                    "check": "Kernel ASLR Posture",
                    "status": "PASS",
                    "severity": "LOW",
                    "score": 10,
                    "detail": "Full ASLR active (randomize_va_space=2)."
                })
            else:
                checks.append({
                    "domain": "Kernel Protections",
                    "check": "Kernel ASLR Posture",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "score": 0,
                    "detail": f"ASLR compromised or disabled (value={val}). Execute: sysctl -w kernel.randomize_va_space=2"
                })
        except Exception:
            pass

    p_dump = Path("/proc/sys/fs/suid_dumpable")
    if p_dump.exists():
        try:
            val = p_dump.read_text().strip()
            if val == "0":
                checks.append({
                    "domain": "Kernel Protections",
                    "check": "SUID Core Dump Restriction",
                    "status": "PASS",
                    "severity": "LOW",
                    "score": 10,
                    "detail": "SUID core dumping disabled (fs.suid_dumpable=0)."
                })
            else:
                checks.append({
                    "domain": "Kernel Protections",
                    "check": "SUID Core Dump Restriction",
                    "status": "WARN",
                    "severity": "MEDIUM",
                    "score": 4,
                    "detail": f"SUID process dumps permitted (value={val}). Execute: sysctl -w fs.suid_dumpable=0"
                })
        except Exception:
            pass

    p_kptr = Path("/proc/sys/kernel/kptr_restrict")
    if p_kptr.exists():
        try:
            val = p_kptr.read_text().strip()
            if val in ("1", "2"):
                checks.append({
                    "domain": "Kernel Protections",
                    "check": "Kernel Pointer Protection (kptr_restrict)",
                    "status": "PASS",
                    "severity": "LOW",
                    "score": 10,
                    "detail": f"Kernel pointers hidden (value={val})."
                })
            else:
                checks.append({
                    "domain": "Kernel Protections",
                    "check": "Kernel Pointer Protection (kptr_restrict)",
                    "status": "WARN",
                    "severity": "MEDIUM",
                    "score": 5,
                    "detail": f"Kernel address leakage risk (value={val}). Recommended: sysctl -w kernel.kptr_restrict=2"
                })
        except Exception:
            pass

    p_dmesg = Path("/proc/sys/kernel/dmesg_restrict")
    if p_dmesg.exists():
        try:
            val = p_dmesg.read_text().strip()
            if val == "1":
                checks.append({
                    "domain": "Kernel Protections",
                    "check": "Dmesg Unprivileged Access",
                    "status": "PASS",
                    "severity": "LOW",
                    "score": 10,
                    "detail": "Kernel syslog/dmesg restricted to privileged callers."
                })
            else:
                checks.append({
                    "domain": "Kernel Protections",
                    "check": "Dmesg Unprivileged Access",
                    "status": "WARN",
                    "severity": "LOW",
                    "score": 7,
                    "detail": "Kernel log buffer readable by standard users. Recommended: sysctl -w kernel.dmesg_restrict=1"
                })
        except Exception:
            pass

    return checks


def audit_privilege_surfaces() -> List[Dict[str, Any]]:
    checks = []

    bin_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"]
    flagged_suids = []
    for b_dir in bin_dirs:
        p = Path(b_dir)
        if not p.is_dir():
            continue
        try:
            for item in p.iterdir():
                if item.is_file() and not item.is_symlink():
                    try:
                        st = item.stat()
                        if st.st_mode & 0o4000:
                            if item.name.lower() in GTFOBINS_TARGETS:
                                flagged_suids.append(f"{item.name} ({item})")
                    except (PermissionError, FileNotFoundError):
                        continue
        except Exception:
            continue

    if flagged_suids:
        checks.append({
            "domain": "Privilege Surfaces",
            "check": "SUID Binary Exploitability (GTFOBins)",
            "status": "WARN",
            "severity": "HIGH",
            "score": 5,
            "detail": f"SUID binaries with known bypass vectors detected: {', '.join(flagged_suids[:4])}"
        })
    else:
        checks.append({
            "domain": "Privilege Surfaces",
            "check": "SUID Binary Exploitability (GTFOBins)",
            "status": "PASS",
            "severity": "LOW",
            "score": 10,
            "detail": "No abnormal or high-risk SUID binaries found in standard search paths."
        })

    try:
        proc = subprocess.run(["getcap", "-r", "/usr/bin", "/bin"], capture_output=True, text=True, timeout=3)
        if proc.returncode == 0 and proc.stdout.strip():
            caps = proc.stdout.strip().splitlines()
            risky_caps = [c for c in caps if "cap_setuid" in c or "cap_sys_admin" in c]
            if risky_caps:
                checks.append({
                    "domain": "Privilege Surfaces",
                    "check": "Linux Capabilities Elevation",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "score": 0,
                    "detail": f"Elevated file capabilities detected: {', '.join(risky_caps[:2])}"
                })
            else:
                checks.append({
                    "domain": "Privilege Surfaces",
                    "check": "Linux Capabilities Elevation",
                    "status": "PASS",
                    "severity": "LOW",
                    "score": 10,
                    "detail": "Standard bounded capabilities detected."
                })
    except Exception:
        pass

    p_shadow = Path("/etc/shadow")
    if p_shadow.exists():
        try:
            with open(p_shadow, "r"):
                checks.append({
                    "domain": "Privilege Surfaces",
                    "check": "Shadow File Access Controls",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "score": 0,
                    "detail": "/etc/shadow is readable by unprivileged processes."
                })
        except PermissionError:
            checks.append({
                "domain": "Privilege Surfaces",
                "check": "Shadow File Access Controls",
                "status": "PASS",
                "severity": "LOW",
                "score": 10,
                "detail": "/etc/shadow access is restricted strictly to root/shadow."
            })

    return checks


def audit_network_surface() -> List[Dict[str, Any]]:
    checks = []
    unrestricted_ports = []

    try:
        res = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            lines = res.stdout.strip().split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    addr = parts[4]
                    if addr.startswith("0.0.0.0:") or addr.startswith("[::]:") or addr.startswith("*:"):
                        port = addr.split(":")[-1]
                        unrestricted_ports.append(port)
    except Exception:
        pass

    if unrestricted_ports:
        checks.append({
            "domain": "Network Perimeter",
            "check": "Public Socket Ingress Exposure",
            "status": "WARN",
            "severity": "MEDIUM",
            "score": 6,
            "detail": f"Active listeners on 0.0.0.0/*: ports {', '.join(unrestricted_ports[:5])}."
        })
    else:
        checks.append({
            "domain": "Network Perimeter",
            "check": "Public Socket Ingress Exposure",
            "status": "PASS",
            "severity": "LOW",
            "score": 10,
            "detail": "All active TCP listeners are strictly bound to localhost loopback interfaces."
        })

    sshd_conf = Path("/etc/ssh/sshd_config")
    if sshd_conf.exists():
        try:
            content = sshd_conf.read_text(errors="ignore")
            root_login = "prohibit-password"
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if line.lower().startswith("permitrootlogin"):
                    root_login = line.split()[-1]
            if root_login.lower() == "yes":
                checks.append({
                    "domain": "Network Perimeter",
                    "check": "SSHD Root Authentication",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "score": 0,
                    "detail": "PermitRootLogin is configured to 'yes'."
                })
            else:
                checks.append({
                    "domain": "Network Perimeter",
                    "check": "SSHD Root Authentication",
                    "status": "PASS",
                    "severity": "LOW",
                    "score": 10,
                    "detail": f"SSHD root login restricted ({root_login})."
                })
        except Exception:
            pass

    return checks


def execute_host_audit() -> Dict[str, Any]:
    all_checks = []
    all_checks.extend(audit_kernel_parameters())
    all_checks.extend(audit_critical_binaries())
    all_checks.extend(audit_privilege_surfaces())
    all_checks.extend(audit_network_surface())

    total_score = sum(c.get("score", 0) for c in all_checks)
    max_possible = len(all_checks) * 10
    final_score = round((total_score / max_possible) * 100) if max_possible > 0 else 0

    if final_score >= 85:
        grade = "A"
    elif final_score >= 70:
        grade = "B"
    elif final_score >= 50:
        grade = "C"
    else:
        grade = "D"

    return {
        "hostname": socket.gethostname(),
        "score": final_score,
        "grade": grade,
        "checks_total": len(all_checks),
        "checks": all_checks
    }


def main():
    parser = argparse.ArgumentParser(description="AEGIS Host Hardening and Binary Posture Auditor")
    parser.add_argument("--json", action="store_true", help="Output full results in JSON format")
    args = parser.parse_args()

    results = execute_host_audit()

    if args.json:
        print(json.dumps(results, indent=2))
        return

    print(f"\nTarget Hostname:     {results['hostname']}")
    print(f"Hardening Score:     {results['score']}/100 (Grade: {results['grade']})")
    print(f"Total Audits Run:    {results['checks_total']}\n")

    print(f"{'DOMAIN':<20} {'STATUS':<8} {'SEVERITY':<10} {'CHECK':<30} {'DETAILS'}")
    print("-" * 100)

    for c in results["checks"]:
        st = c["status"]
        if st == "PASS":
            st_color = "\033[92mPASS\033[0m"
        elif st == "WARN":
            st_color = "\033[93mWARN\033[0m"
        else:
            st_color = "\033[91mFAIL\033[0m"

        print(f"{c['domain']:<20} {st_color:<17} {c['severity']:<10} {c['check']:<30} {c['detail']}")
    print("\n")


if __name__ == "__main__":
    main()
