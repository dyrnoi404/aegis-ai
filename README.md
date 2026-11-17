<p align="center">
  <img src="assets/banner.svg" alt="AEGIS AI Banner" width="100%" />
</p>

<p align="center">
  <a href="#english">🇬🇧 English</a> · <a href="README.ru.md">🇷🇺 Русский</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/Agent_Skill-v2.0_Ready-3FB950.svg?style=flat-square&logo=githubactions&logoColor=white" alt="Agent Skill Ready" />
  <img src="https://img.shields.io/badge/Standards-NIST_|_MITRE_|_CIS_|_OWASP-161B22.svg?style=flat-square&logo=linux&logoColor=58A6FF" alt="Standards Compliant" />
</p>

---

## ⚡ Overview

**AEGIS AI v2.0** is an enterprise-grade autonomous cybersecurity architecture, host hardening, and threat intelligence toolkit engineered for **AI coding agents** (Antigravity, Claude Code, Cursor, Codex) and DevSecOps terminal workflows.

Built on foundational principles from academic and practical information security literature, AEGIS integrates:
* **NIST SP 800-61 Rev. 2** (Computer Security Incident Handling Guide)
* **MITRE ATT&CK® v14+** (Tactic & Technique Event Correlation)
* **CIS Linux Benchmarks** (Operating System & Kernel Hardening)
* **OWASP Top 10:2021 & CWE Top 25** (Structural Static Application Security Testing)
* **CVSS v3.1** (Deterministic Vulnerability Base Scoring)

> [!IMPORTANT]
> **Zero External Dependencies**: AEGIS is engineered entirely on the Python 3 standard library (`struct`, `ast`, `math`, `re`, `socket`, `subprocess`). No third-party wheels, no network exfiltration, 100% private, auditable, and local.

---

## 🏛️ Architectural Framework

```
                                 ┌────────────────────────────────────────────────────────┐
                                 │                 AEGIS Security Engine                  │
                                 └───────────────────────────┬────────────────────────────┘
                                                             │
            ┌────────────────────────────────┼───────────────┴────────────────┼────────────────────────────────┐
            ▼                                ▼                                ▼                                ▼
  [ SAST & Secret Guard ]         [ Deep Host Posture ]             [ Incident Forensics ]            [ Reporting & Scoring ]
  • Shannon Entropy analysis      • Binary hardening (checksec)     • Sliding-window correlation      • CVSS v3.1 calculator
  • AST parser (AST injection)    • Kernel & memory parameters      • MITRE ATT&CK tagging            • NIST SP 800-61 timeline
  • CWE & OWASP Top 10            • Linux Capabilities & SUID       • IoC extraction & FW rules       • Executive MD / JSON
```

---

## 🛡️ Core Capabilities

### 1. 🔍 SAST & Secret Guard Engine (`scripts/aegis_scan.py`)
* **Shannon Entropy Analysis**: Detects obfuscated, high-entropy secrets and raw keys ($H \ge 4.5$) regardless of variable naming conventions.
* **AST Code Inspector**: Scans Python codebases for structural vulnerabilities (CWE-78 Command Injection, CWE-89 SQL Injection, CWE-502 Insecure Deserialization via `pickle`, CWE-327 Broken Crypto).
* **Cryptographic Token Matrix**: High-precision detection for private keys (RSA/OpenSSH/PGP/EC), GitHub PATs, AWS Access Keys, Telegram tokens, OpenAI/Gemini keys, and database connection strings.
* **Zero-Leakage Masking**: Automatically redacts all detected secrets in logs and terminals.

### 2. 🛡️ Deep Host Posture & Binary Hardener (`scripts/aegis_audit.py`)
* **Native ELF Checksec (Erickson Model)**: Direct binary header parsing (`struct`) verifying compiler protections on critical binaries:
  * **NX / DEP**: Stack execution mitigation (`PT_GNU_STACK`).
  * **Stack Canaries**: Stack buffer overflow protections (`__stack_chk_fail`).
  * **PIE (Position Independent Executables)**: Full address space randomization.
  * **Full RELRO**: GOT/PLT read-only protection (`PT_GNU_RELRO` & `BIND_NOW`).
* **Kernel Protections**: Validates ASLR (`randomize_va_space=2`), SUID core dump restrictions (`fs.suid_dumpable=0`), pointer hiding (`kernel.kptr_restrict=2`), and dmesg protection.
* **Privilege Surfaces & Capabilities**: Audits SUID binaries against GTFOBins, discovers dangerous Linux file capabilities (`cap_setuid`), and audits file permissions.
* **CIS Hardening Score**: Computes a deterministic 0-100 posture score and letter grade.

### 3. 📑 Incident Forensics & SIEM Correlation (`scripts/aegis_triage.py`)
* **Sliding Time-Window Correlation**: Aggregates log events within a 10-minute window to identify multi-stage attack chains:
  * *Brute-Force (T1110.001) → Account Takeover (T1078) → Privilege Escalation (T1548.003)*.
* **Web Exploit Analysis**: Flags Path Traversal (`CWE-22`), SQLi probes (`CWE-89`), sensitive file sweeps (`.env`, `wp-config.php`), and automated scanners (`sqlmap`, `nikto`, `nuclei`).
* **Automated Containment Playbook**: Generates immediate `iptables`/`nftables` drop rules for rogue attacker IPs.

### 4. 📊 Reporting & CVSS v3.1 Engine (`scripts/aegis_report.py`)
* **Deterministic CVSS v3.1 Calculator**: Programmatically computes Base Scores from metric vector strings.
* **Publication-Grade Reports**: Generates NIST SP 800-61 compliant Markdown audit reports with executive summaries, threat matrices, and prioritized remediation roadmaps.

---

## 🚀 Quickstart

### Option A: Use as an Agent Skill (Recommended)

Clone AEGIS directly into your AI coding assistant's skill repository:

```bash
# For Google Antigravity / Agentic Coding Assistants:
git clone https://github.com/dyrnoi404/aegis-ai.git ~/.gemini/config/skills/aegis-security
```

Once installed, your AI agent automatically activates the `aegis-security` skill with operational protocols:
* **Protocol ALPHA**: Threat Hunting & SIEM Log Forensics
* **Protocol BRAVO**: Binary Checksec & Linux Host Hardening
* **Protocol CHARLIE**: SAST Code Review & Secret Guard
* **Protocol DELTA**: Incident Mitigation, CVSS Scoring & Reporting

---

### Option B: Standalone Terminal CLI

Run AEGIS directly from the terminal without installing any third-party dependencies:

```bash
# 1. Audit Linux host security posture & binary mitigations
./cli/aegis audit

# 2. Run SAST vulnerability & secret scan on repository
./cli/aegis scan /path/to/project --fail-on-findings

# 3. Triage authentication or web access logs
./cli/aegis triage /var/log/auth.log

# 4. Generate comprehensive NIST SP 800-61 audit report
./cli/aegis report --scan-path . --log-file /var/log/auth.log --out security_report.md
```

---

## 📁 Repository Structure

```
aegis-ai/
├── SKILL.md                  # Autonomous Agent Skill instructions (Protocols ALPHA-DELTA)
├── README.md                 # English architecture & usage guide
├── README.ru.md              # Russian architecture & usage guide
├── LICENSE                   # MIT License
├── cli/
│   └── aegis                 # Unified enterprise CLI orchestrator
├── scripts/
│   ├── aegis_scan.py         # SAST, Shannon entropy & secret guard
│   ├── aegis_audit.py        # ELF checksec, kernel & host hardening
│   ├── aegis_triage.py       # SIEM event correlator & log forensics
│   └── aegis_report.py       # CVSS v3.1 calculator & NIST report generator
├── references/
│   ├── hardening_checklist.md # CIS & binary mitigation baseline
│   └── cwe_mitre_matrix.md   # CWE to MITRE ATT&CK correlation matrix
└── docs/
    ├── architecture.md       # Detailed technical design
    └── roadmap.md            # Enterprise engineering roadmap
```

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

Maintained by [@dyrnoi404](https://github.com/dyrnoi404) · [Telegram](https://t.me/not_mudota)
