#!/usr/bin/env python3
"""
Static Application Security Testing (SAST) and credential scanner.
"""

import os
import sys
import ast
import math
import re
import json
import argparse
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any, Generator

TOKEN_RULES = [
    {
        "id": "AEGIS-SEC-001",
        "cwe": "CWE-312",
        "name": "Asymmetric Private Key (RSA/OpenSSH/PGP/EC)",
        "severity": "CRITICAL",
        "pattern": re.compile(r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE KEY-----", re.MULTILINE),
    },
    {
        "id": "AEGIS-SEC-002",
        "cwe": "CWE-798",
        "name": "GitHub Personal Access Token (Classic)",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"),
    },
    {
        "id": "AEGIS-SEC-003",
        "cwe": "CWE-798",
        "name": "GitHub Fine-Grained Personal Access Token",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}\b"),
    },
    {
        "id": "AEGIS-SEC-004",
        "cwe": "CWE-798",
        "name": "AWS Access Key Identifier",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    },
    {
        "id": "AEGIS-SEC-005",
        "cwe": "CWE-798",
        "name": "Telegram Bot API Authentication Token",
        "severity": "HIGH",
        "pattern": re.compile(r"\b\d{8,11}:[A-Za-z0-9_-]{35}\b"),
    },
    {
        "id": "AEGIS-SEC-006",
        "cwe": "CWE-798",
        "name": "Slack Webhook / Bot Token",
        "severity": "HIGH",
        "pattern": re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b"),
    },
    {
        "id": "AEGIS-SEC-007",
        "cwe": "CWE-798",
        "name": "Google Cloud / Gemini API Key",
        "severity": "HIGH",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    },
    {
        "id": "AEGIS-SEC-008",
        "cwe": "CWE-798",
        "name": "OpenAI / Anthropic Secret API Key",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{32,120})\b"),
    },
    {
        "id": "AEGIS-SEC-009",
        "cwe": "CWE-259",
        "name": "Database Connection String With Embedded Credentials",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:\s]+:[^@\s]+@[^\s]+\b", re.IGNORECASE),
    },
    {
        "id": "AEGIS-SEC-010",
        "cwe": "CWE-312",
        "name": "JSON Web Token (JWT) Literal",
        "severity": "MEDIUM",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b"),
    },
]

IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", ".tox", "dist", "build", ".next",
    ".cache", "vendor", ".idea", ".vscode"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".zip", ".tar",
    ".gz", ".bz2", ".7z", ".pdf", ".lock", ".min.js", ".min.css",
    ".exe", ".bin", ".iso", ".deb", ".rpm", ".so", ".dylib", ".dll",
    ".pyc", ".o", ".a"
}

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy_token(token: str) -> bool:
    if len(token) < 20 or len(token) > 120:
        return False
    if " " in token or "/" in token or "\\" in token or token.startswith("http"):
        return False
    return shannon_entropy(token) >= 4.5


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "********"
    return f"{value[:4]}...{value[-4:]}"


def is_binary(filepath: Path) -> bool:
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except Exception:
        return True


class PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str, lines: List[str]):
        self.filepath = filepath
        self.lines = lines
        self.findings: List[Dict[str, Any]] = []

    def _get_context(self, line_no: int) -> str:
        if 1 <= line_no <= len(self.lines):
            return self.lines[line_no - 1].strip()[:140]
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("system", "popen"):
            self.findings.append({
                "id": "AEGIS-SAST-001",
                "cwe": "CWE-78",
                "rule": "OS Command Injection via os.system / os.popen",
                "severity": "HIGH",
                "file": self.filepath,
                "line": node.lineno,
                "preview": f"Call to os.{func_name}()",
                "context": self._get_context(node.lineno),
                "remediation": "Replace with subprocess.run() using a strict argument list and shell=False."
            })
        elif func_name in ("Popen", "call", "check_call", "check_output", "run"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append({
                        "id": "AEGIS-SAST-002",
                        "cwe": "CWE-78",
                        "rule": "Dangerous Subprocess Execution with shell=True",
                        "severity": "CRITICAL",
                        "file": self.filepath,
                        "line": node.lineno,
                        "preview": "subprocess(..., shell=True)",
                        "context": self._get_context(node.lineno),
                        "remediation": "Set shell=False and pass arguments as an immutable sequence/list."
                    })

        if func_name in ("eval", "exec"):
            self.findings.append({
                "id": "AEGIS-SAST-003",
                "cwe": "CWE-95",
                "rule": "Arbitrary Code Execution via eval()/exec()",
                "severity": "CRITICAL",
                "file": self.filepath,
                "line": node.lineno,
                "preview": f"Call to {func_name}()",
                "context": self._get_context(node.lineno),
                "remediation": "Eliminate dynamic code execution. Use ast.literal_eval() for safe data parsing."
            })

        if func_name in ("loads", "load"):
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                if module_name == "pickle":
                    self.findings.append({
                        "id": "AEGIS-SAST-004",
                        "cwe": "CWE-502",
                        "rule": "Insecure Deserialization via pickle",
                        "severity": "CRITICAL",
                        "file": self.filepath,
                        "line": node.lineno,
                        "preview": "pickle.loads() call",
                        "context": self._get_context(node.lineno),
                        "remediation": "Do not deserialize untrusted data with pickle. Use HMAC-signed payloads or JSON."
                    })
                elif module_name in ("yaml", "ruamel"):
                    has_safe_loader = any(
                        kw.arg == "Loader" and "SafeLoader" in getattr(kw.value, "id", "")
                        for kw in node.keywords
                    )
                    if not has_safe_loader:
                        self.findings.append({
                            "id": "AEGIS-SAST-005",
                            "cwe": "CWE-502",
                            "rule": "Potentially Insecure YAML Deserialization",
                            "severity": "HIGH",
                            "file": self.filepath,
                            "line": node.lineno,
                            "preview": "yaml.load without SafeLoader",
                            "context": self._get_context(node.lineno),
                            "remediation": "Always use yaml.safe_load() or specify Loader=yaml.SafeLoader."
                        })

        if func_name == "execute" and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.BinOp, ast.JoinedStr)):
                self.findings.append({
                    "id": "AEGIS-SAST-006",
                    "cwe": "CWE-89",
                    "rule": "SQL Query Formatted with String Concatenation / F-string",
                    "severity": "CRITICAL",
                    "file": self.filepath,
                    "line": node.lineno,
                    "preview": "cursor.execute(query_with_formatting)",
                    "context": self._get_context(node.lineno),
                    "remediation": "Use parameterized queries with prepared statements (e.g., execute(sql, (param,)))"
                })

        if func_name in ("md5", "sha1"):
            self.findings.append({
                "id": "AEGIS-SAST-007",
                "cwe": "CWE-327",
                "rule": "Use of Broken Cryptographic Algorithm (MD5/SHA1)",
                "severity": "MEDIUM",
                "file": self.filepath,
                "line": node.lineno,
                "preview": f"hashlib.{func_name}()",
                "context": self._get_context(node.lineno),
                "remediation": "Upgrade to SHA-256 / SHA-3 for hashing, or Argon2id / bcrypt for password storage."
            })

        self.generic_visit(node)


def scan_file_sast(filepath: Path) -> List[Dict[str, Any]]:
    findings = []
    if filepath.suffix != ".py":
        return findings
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        lines = code.splitlines()
        tree = ast.parse(code, filename=str(filepath))
        visitor = PythonSecurityVisitor(str(filepath), lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError:
        pass
    except Exception:
        pass
    return findings


def scan_file_secrets(filepath: Path) -> List[Dict[str, Any]]:
    findings = []
    try:
        if filepath.stat().st_size > MAX_FILE_SIZE_BYTES or is_binary(filepath):
            return findings

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        content = "".join(lines)

        for rule in TOKEN_RULES:
            for match in rule["pattern"].finditer(content):
                start_pos = match.start()
                line_no = content[:start_pos].count("\n") + 1
                matched_text = match.group(0)
                context_line = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""

                findings.append({
                    "id": rule["id"],
                    "cwe": rule["cwe"],
                    "rule": rule["name"],
                    "severity": rule["severity"],
                    "file": str(filepath),
                    "line": line_no,
                    "preview": mask_secret(matched_text),
                    "context": context_line[:120],
                    "remediation": "Revoke token immediately and inject credentials via environment variables."
                })

        for idx, line in enumerate(lines, start=1):
            literals = re.findall(r"""["']([A-Za-z0-9+/=_-]{24,100})["']""", line)
            for lit in literals:
                if is_high_entropy_token(lit):
                    if not any(f["line"] == idx and f["cwe"] == "CWE-798" for f in findings):
                        findings.append({
                            "id": "AEGIS-ENT-001",
                            "cwe": "CWE-798",
                            "rule": f"High-Entropy Secret Literal Detected (Shannon H={shannon_entropy(lit):.2f})",
                            "severity": "HIGH",
                            "file": str(filepath),
                            "line": idx,
                            "preview": mask_secret(lit),
                            "context": line.strip()[:120],
                            "remediation": "Confirm if token is an active secret. Migrate to an encrypted vault or .env."
                        })
    except Exception:
        pass
    return findings


def walk_target(target: Path) -> Generator[Path, None, None]:
    if target.is_file():
        yield target
        return

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for f in files:
            p = Path(root) / f
            if p.suffix.lower() not in IGNORE_EXTENSIONS:
                yield p


def scan_target(target_path: str) -> List[Dict[str, Any]]:
    target = Path(target_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target_path}")

    all_findings = []
    for file_path in walk_target(target):
        all_findings.extend(scan_file_secrets(file_path))
        all_findings.extend(scan_file_sast(file_path))

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="AEGIS SAST and Secret Scanner")
    parser.add_argument("target", nargs="?", default=".", help="Directory or file to scan")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit code 1 if vulnerabilities found")
    parser.add_argument("--strict-cwe", action="store_true", help="Include extensive CWE remediation details")

    args = parser.parse_args()

    try:
        findings = scan_target(args.target)
    except Exception as err:
        print(f"[-] Scan execution error: {err}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps({
            "target": str(Path(args.target).resolve()),
            "findings_count": len(findings),
            "findings": findings
        }, indent=2))
        return

    print(f"\nTarget Path:    {Path(args.target).resolve()}")
    print(f"Total Findings: {len(findings)}\n")

    if not findings:
        print("[OK] Clean audit: no secrets or AST flaws detected.\n")
    else:
        for f in findings:
            sev = f["severity"]
            color = "\033[91m" if sev == "CRITICAL" else ("\033[93m" if sev == "HIGH" else "\033[94m")
            reset = "\033[0m"
            print(f"[{color}{sev:<8}{reset}] {f['rule']} [{f['cwe']}] ({f['id']})")
            print(f"  Location:    {f['file']}:{f['line']}")
            print(f"  Snippet:     {f['preview']}")
            print(f"  Context:     {f['context']}")
            print(f"  Remediation: \033[36m{f['remediation']}\033[0m")
            print("-" * 75)

    if args.fail_on_findings and findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
