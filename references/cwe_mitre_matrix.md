# AEGIS Framework: CWE & MITRE ATT&CK® Correlation Matrix

This reference documents the formal mapping between software weaknesses (CWE), attack techniques (MITRE ATT&CK), and default CVSS v3.1 vector baselines used by AEGIS engines.

---

## 1. Application Vulnerabilities (SAST & OWASP)

| CWE ID | Weakness Description | MITRE ATT&CK TTP | Default CVSS v3.1 Vector | Base Score |
| :--- | :--- | :--- | :--- | :--- |
| **CWE-78** | OS Command Injection (`subprocess(shell=True)`) | `T1059.004` (Unix Shell) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | **10.0 (Critical)** |
| **CWE-89** | SQL Injection (Query Concatenation) | `T1190` (Exploit Public App) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 (Critical)** |
| **CWE-502** | Insecure Deserialization (`pickle.loads`) | `T1059` (Command Execution) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 (Critical)** |
| **CWE-798** | Hardcoded Credentials / High-Entropy Secrets | `T1552.001` (Credentials in Files) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5 (High)** |
| **CWE-22** | Path Traversal (`../etc/passwd`) | `T1083` (File & Dir Discovery) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5 (High)** |
| **CWE-312** | Cleartext Storage of Sensitive Info (Keys/JWT) | `T1552` (Unsecured Credentials) | `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **6.2 (Medium)** |
| **CWE-327** | Broken / Deprecated Crypto (MD5/SHA1) | `T1588.002` (Vulnerabilities) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | **3.7 (Low)** |

---

## 2. Infrastructure & Host Hardening (CIS & Checksec)

| Domain | Control Target | Adversary Technique Addressed | Defense Mechanism |
| :--- | :--- | :--- | :--- |
| **Binary** | NX / DEP | `T1055` (Process Injection / Shellcode) | Non-executable memory segment (`PT_GNU_STACK`) |
| **Binary** | Stack Canary | `T1203` (Exploitation for Client Execution) | `__stack_chk_fail` stack cookie verification |
| **Binary** | Position Independent Executable (PIE) | `T1068` (Exploitation for Privilege Escalation) | Full code section randomization via ASLR |
| **Binary** | Full RELRO | `T1055` (GOT/PLT Overwrite) | Read-only GOT/PLT reallocation on startup |
| **Kernel** | ASLR (`randomize_va_space=2`) | `T1068` (Memory Corruption) | Randomization of stack, heap, VDSO, libraries |
| **Kernel** | SUID Core Dump Restriction | `T1003` (OS Credential Dumping) | Setting `fs.suid_dumpable = 0` |
| **Host** | Linux Capabilities Sanitization | `T1548.001` (Setuid and Setgid) | Elimination of unneeded `cap_setuid`/`cap_net_raw` |
