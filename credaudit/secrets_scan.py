from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from credaudit.findings import Finding, Severity

MAX_FILE_SIZE = 5 * 1024 * 1024  # skip anything bigger than 5MB
SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".db", ".sqlite", ".sqlite3",
                    ".exe", ".dll", ".so", ".zip", ".woff", ".woff2", ".ttf"}


@dataclass
class SecretPattern:
    name: str
    regex: re.Pattern
    severity: Severity


PATTERNS: list[SecretPattern] = [
    SecretPattern("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL),
    SecretPattern("AWS Secret Access Key (assignment)",
                  re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
                  Severity.CRITICAL),
    SecretPattern("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Severity.HIGH),
    SecretPattern("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    SecretPattern("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), Severity.HIGH),
    SecretPattern("Generic private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), Severity.CRITICAL),
    SecretPattern("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), Severity.MEDIUM),
    SecretPattern("Password-like assignment",
                  re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?(?!\{\{|\$\{|%|CHANGEME|xxxx|<)[^\s'\"]{4,}['\"]?"),
                  Severity.HIGH),
    SecretPattern("Generic API key/token assignment",
                  re.compile(r"(?i)\b(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|"
                             r"client[_-]?secret|secret[_-]?token|secret[_-]?key)"
                             r"\s*[=:]\s*['\"]?(?!\{\{|\$\{|%|CHANGEME|xxxx|<)[A-Za-z0-9_\-./+]{8,}['\"]?"),
                  Severity.HIGH),
    SecretPattern("Connection string with credentials",
                  re.compile(r"(?i)\b\w+://[^\s:/'\"]+:[^\s@/'\"]+@[^\s'\"]+"), Severity.HIGH),
]

# Config file locations commonly used by dev tools that sometimes hold plaintext secrets.
CANDIDATE_RELATIVE_PATHS = [
    ".aws/credentials",
    ".aws/config",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".docker/config.json",
    ".ssh/config",
    ".gitconfig",
    ".env",
    ".bash_history",
    ".zsh_history",
    ".config/gh/hosts.yml",
    ".config/gcloud/credentials.db",
    "AppData/Roaming/Code/User/settings.json",
    "AppData/Roaming/Postman/config.json",
]


def _redact(text: str, match: re.Match) -> str:
    value = match.group(0)
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "…" + value[-2:] + f" ({len(value)} chars)"


def _iter_candidate_files(extra_roots: list[Path] | None = None) -> list[Path]:
    home = Path.home()
    files = []
    for rel in CANDIDATE_RELATIVE_PATHS:
        p = home / rel
        if p.is_file():
            files.append(p)

    for root in extra_roots or []:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")]
            for fname in filenames:
                # Match `.env`, `.env.local`, `.env.production`, `prod.env`, plus common config formats.
                if (
                    fname == ".env"
                    or fname.startswith(".env.")
                    or fname.endswith((".env", ".ini", ".cfg", ".conf", ".json", ".yml", ".yaml"))
                ):
                    files.append(Path(dirpath) / fname)

    return files


def _scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        if path.suffix.lower() in SKIP_EXTENSIONS:
            return findings
        if path.stat().st_size > MAX_FILE_SIZE:
            return findings
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    seen_lines: set[tuple[str, int]] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pattern in PATTERNS:
            match = pattern.regex.search(line)
            if not match:
                continue
            key = (pattern.name, lineno)
            if key in seen_lines:
                continue
            seen_lines.add(key)
            findings.append(
                Finding(
                    category="plaintext_secret",
                    severity=pattern.severity,
                    title=f"Possible {pattern.name} stored in plaintext",
                    detail=f"Line {lineno}: {_redact(line, match)}",
                    location=str(path),
                    recommendation="Move this credential to an OS keychain / secrets manager and rotate it, "
                                   "since it may already be compromised if this file was ever synced or backed up.",
                    metadata={"pattern": pattern.name, "line": lineno},
                )
            )
    return findings


def scan_local_configs(extra_roots: list[Path] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_candidate_files(extra_roots):
        findings.extend(_scan_file(path))
    return findings
