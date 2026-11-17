#!/usr/bin/env python3
"""
AEGIS AI - Secret & Credential Scanner
High-performance, dependency-free scanner for sensitive credentials,
private keys, and exposed API tokens in repositories and filesystems.
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Generator

# High-fidelity regex rules with verified patterns
RULES = [
    {
        "id": "SEC-001",
        "name": "Private Key",
        "severity": "CRITICAL",
        "pattern": re.compile(r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE KEY-----", re.MULTILINE),
    },
    {
        "id": "SEC-002",
        "name": "GitHub Personal Access Token (Classic)",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"),
    },
    {
        "id": "SEC-003",
        "name": "GitHub Fine-Grained Personal Access Token",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}\b"),
    },
    {
        "id": "SEC-004",
        "name": "AWS Access Key ID",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    },
    {
        "id": "SEC-005",
        "name": "Telegram Bot Token",
        "severity": "HIGH",
        "pattern": re.compile(r"\b\d{8,11}:[A-Za-z0-9_-]{35}\b"),
    },
    {
        "id": "SEC-006",
        "name": "Slack Token",
        "severity": "HIGH",
        "pattern": re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b"),
    },
    {
        "id": "SEC-007",
        "name": "Google / Gemini API Key",
        "severity": "HIGH",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    },
    {
        "id": "SEC-008",
        "name": "OpenAI / Anthropic API Key",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{32,120})\b"),
    },
    {
        "id": "SEC-009",
        "name": "Database Connection String with Credentials",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:\s]+:[^@\s]+@[^\s]+\b", re.IGNORECASE),
    },
    {
        "id": "SEC-010",
        "name": "Generic High-Entropy Password / Secret Assignment",
        "severity": "MEDIUM",
        "pattern": re.compile(r"""(?:password|passwd|api_secret|client_secret|auth_token)\s*[:=]\s*["']([^"'\s]{8,})["']""", re.IGNORECASE),
    },
]

IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", ".tox", "dist", "build", ".next",
    ".cache", "vendor"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".zip", ".tar",
    ".gz", ".bz2", ".7z", ".pdf", ".lock", ".min.js", ".min.css",
    ".exe", ".bin", ".iso", ".deb", ".rpm", ".so", ".dylib", ".dll"
}

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def is_binary(filepath: Path) -> bool:
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except Exception:
        return True


def scan_file(filepath: Path) -> List[Dict[str, Any]]:
    findings = []
    try:
        if filepath.stat().st_size > MAX_FILE_SIZE_BYTES or is_binary(filepath):
            return findings

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        content = "".join(lines)
        for rule in RULES:
            for match in rule["pattern"].finditer(content):
                start_pos = match.start()
                # Determine line number
                line_no = content[:start_pos].count("\n") + 1
                matched_text = match.group(0)
                
                # Context line
                context_line = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""

                findings.append({
                    "id": rule["id"],
                    "rule": rule["name"],
                    "severity": rule["severity"],
                    "file": str(filepath),
                    "line": line_no,
                    "preview": mask_secret(matched_text),
                    "context": context_line[:120],
                })
    except Exception as e:
        pass
    return findings


def walk_files(target: Path) -> Generator[Path, None, None]:
    if target.is_file():
        yield target
        return

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for f in files:
            p = Path(root) / f
            if p.suffix.lower() not in IGNORE_EXTENSIONS:
                yield p


def scan_path(target_path: str) -> List[Dict[str, Any]]:
    target = Path(target_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target_path}")

    all_findings = []
    for file_path in walk_files(target):
        findings = scan_file(file_path)
        if findings:
            all_findings.extend(findings)
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="AEGIS AI - Credential & Secret Scanner")
    parser.add_argument("target", nargs="?", default=".", help="Directory or file to scan (default: current dir)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit with code 1 if secrets found")

    args = parser.parse_args()

    try:
        findings = scan_path(args.target)
    except Exception as err:
        print(f"[-] Scan error: {err}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
    else:
        print(f"\n[+] AEGIS Secret Scanner - Target: {args.target}")
        print(f"[+] Total findings: {len(findings)}\n")
        if not findings:
            print("[✓] No exposed credentials or secrets detected.")
        else:
            for f in findings:
                sev_color = "\033[91m" if f["severity"] == "CRITICAL" else ("\033[93m" if f["severity"] == "HIGH" else "\033[94m")
                reset = "\033[0m"
                print(f"[{sev_color}{f['severity']}{reset}] {f['rule']} ({f['id']})")
                print(f"  Location: {f['file']}:{f['line']}")
                print(f"  Match:    {f['preview']}")
                print(f"  Context:  {f['context']}")
                print("-" * 60)

    if args.fail_on_findings and findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
