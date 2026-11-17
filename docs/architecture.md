# AEGIS AI Architecture

AEGIS is designed with a dual-execution architecture:
1. **Agent Skill Layer (`SKILL.md`)**: Context-aware instructions, heuristics, and reasoning pipelines for AI agents (Antigravity, Claude Code, Cursor, Codex).
2. **Autonomous Tooling Layer (`scripts/` & `cli/`)**: Standalone, dependency-free Python 3 engines that can be invoked either by an AI agent or directly from the terminal by an engineer.

```
       +--------------------------------------------------+
       |                  User / Agent                    |
       +--------------------------------------------------+
                                |
             +------------------+------------------+
             |                                     |
             v                                     v
   [ Agent Skill Mode ]                   [ Standalone CLI ]
      (SKILL.md)                           (./cli/aegis)
             |                                     |
             +------------------+------------------+
                                |
                                v
               +----------------------------------+
               |        AEGIS Core Engines        |
               +----------------------------------+
               |  • aegis_scan: Secret Scanner    |
               |  • aegis_audit: Host Hardener    |
               |  • aegis_triage: Log Forensics   |
               +----------------------------------+
                                |
                                v
               +----------------------------------+
               |    Findings & Structured JSON    |
               +----------------------------------+
```

## Core Modules

### 1. Secret Scanner (`scripts/aegis_scan.py`)
Multi-rule regex engine targeting private keys, high-entropy tokens, cloud provider keys, and database connection strings. Ignores binary artifacts and masked output prevents secret leakage.

### 2. Host Posture Auditor (`scripts/aegis_audit.py`)
Non-destructive local security auditor. Validates memory layout protection (ASLR), file permission bounds, dangerous SUID binaries, network socket exposure, and SSH daemon configuration.

### 3. Log Forensics (`scripts/aegis_triage.py`)
Dual-format triage engine parsing system authentication logs (`auth.log`/`secure`) and web server access logs (Nginx/Apache). Identifies brute-force IP clusters, unauthorized privilege escalations, and automated security scanners.
