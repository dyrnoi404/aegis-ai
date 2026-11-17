# AEGIS AI Roadmap

## Phase 1 - Core Foundations (Completed)
- [x] Autonomous Agent Skill definition (`SKILL.md`) for AI coding agents.
- [x] Zero-dependency Secret & Credential scanner (`scripts/aegis_scan.py`).
- [x] Linux host posture & hardening auditor (`scripts/aegis_audit.py`).
- [x] Incident forensics & auth/web log triage engine (`scripts/aegis_triage.py`).
- [x] Unified standalone command-line interface (`cli/aegis`).

## Phase 2 - Advanced Detection & Integrations (In Progress)
- [ ] Container posture auditor (Docker socket inspection, unconfined capabilities).
- [ ] Automated remediation generator (fail2ban jail generation, iptables rules).
- [ ] Expanded SAST AST-based rule engine for Python and Node.js.

## Phase 3 - Ecosystem & Automation (Planned)
- [ ] Reusable GitHub Action (`aegis-scan-action`) for PR security gates.
- [ ] Standalone desktop report generator (clean HTML / PDF executive reports).
