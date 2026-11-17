---
name: aegis-security
description: Autonomous cybersecurity analysis, Linux host hardening, incident triage, and secret-scanning skill. Use when the user requests a security review, source code vulnerability audit (SAST), leaked credential scan, Linux system posture check, suspicious log analysis, or defensive hardening advice.
---

# AEGIS Security Intelligence Skill

AEGIS is an autonomous defensive cybersecurity analyst for AI agents. It provides a structured methodology and automated tooling for posture auditing, incident log triage, code security assessments, and credential leak detection.

---

## Capabilities & Tooling

AEGIS is backed by automated scripts in `scripts/`:

| Capability | Script | Purpose |
| :--- | :--- | :--- |
| **Credential Scanner** | `scripts/aegis_scan.py` | Scans directories for exposed tokens, private keys, and API secrets |
| **Host Hardening** | `scripts/aegis_audit.py` | Audits Linux ASLR, SUID binaries, critical file perms, ports, and SSH |
| **Incident Triage** | `scripts/aegis_triage.py` | Parses `auth.log` and web logs for brute-force, scanners, and exploit attempts |
| **CLI Runner** | `cli/aegis` | Unified CLI interface: `aegis scan`, `aegis audit`, `aegis triage` |

---

## Security Audit Workflows

When activated by a user request, execute the appropriate workflow:

### 1. Linux Host Hardening & Posture Check
Triggered when the user asks: *"Проверь безопасность системы"*, *"Audit Linux posture"*, *"Are there risky permissions?"*.

1. Execute the non-destructive posture auditor:
   ```bash
   python3 scripts/aegis_audit.py
   ```
2. Interpret the results:
   * **SUID Binaries**: Flag any binary that belongs to GTFOBins (e.g. `nmap`, `vim`, `find`, `python` with SUID).
   * **Open Ports**: Differentiate between `127.0.0.1` (local) and `0.0.0.0` (world-accessible). Warn on unauthenticated databases or debug ports.
   * **File Permissions**: Verify `/etc/passwd` is not world-writable and `/etc/shadow` is unreadable by standard users.
   * **ASLR & Kernel**: Ensure `randomize_va_space == 2`.
3. Provide concrete remediation commands for any warnings (e.g., `chmod 600 ~/.ssh/id_*`, `chmod u-s <binary>`).

---

### 2. Leaked Credentials & Secret Scanning
Triggered when the user asks: *"Check repository for leaked keys"*, *"Найди секреты в проекте"*, *"Scan code before push"*.

1. Run the high-fidelity secret scanner:
   ```bash
   python3 scripts/aegis_scan.py <target_directory>
   ```
2. For each detected credential:
   * Classify risk level: **CRITICAL** (private keys, database URLs, GitHub PATs), **HIGH** (cloud tokens, bot tokens), **MEDIUM** (hardcoded test secrets).
   * Advise immediate token revocation and replacement with environment variables (`.env` added to `.gitignore`).
   * Never output the full unmasked credential in chat.

---

### 3. Log Forensics & Incident Triage
Triggered when the user asks: *"Проанализируй auth.log"*, *"Кто ломится на сервер?"*, *"Triage web access logs"*.

1. Execute the incident triage analyzer:
   ```bash
   python3 scripts/aegis_triage.py <path_to_log>
   ```
2. Identify attack vectors:
   * **SSH Brute-force**: Group failed attempts by IP. If an IP exceeds 10 attempts, generate immediate defensive firewall rules:
     ```bash
     sudo iptables -A INPUT -s <OFFENDER_IP> -j DROP
     ```
   * **Web Exploit Probes**: Identify path traversal (`../etc/passwd`), `.env` access, or SQL injection queries.
   * **Scanner Fingerprinting**: Identify tools such as `sqlmap`, `nikto`, `nuclei`, or `gobuster`.

---

### 4. Source Code Security Audit (SAST)
Triggered when reviewing code for vulnerabilities:

1. **Injection Flaws (CWE-89, CWE-78)**:
   * Check for unsanitized inputs in SQL queries, shell commands (`subprocess.Popen(..., shell=True)`), and system calls.
2. **Broken Access Control (CWE-284, CWE-862)**:
   * Ensure user identity is verified on every state-changing route (IDOR).
3. **Cryptographic Failures (CWE-327, CWE-798)**:
   * Detect deprecated algorithms (MD5, SHA1 for passwords) and lack of salting/bcrypt.
4. **Input Validation & Sanitization (CWE-79)**:
   * Inspect HTML template rendering for XSS vulnerabilities.

---

## Tone & Professional Guidelines

* **Defensive Focus**: Focus exclusively on defensive posture, vulnerability remediation, hardening, and forensics.
* **No Speculation**: Report verified findings with exact file paths, line numbers, and actionable fixes.
* **Severity Scoring**: Map critical issues to standard CVSS/CWE terminology so reports look credible and audit-ready.
