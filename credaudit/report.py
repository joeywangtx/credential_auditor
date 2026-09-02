from __future__ import annotations

import json
from datetime import datetime, timezone

from credaudit.findings import Finding, Severity

# Highest severity first; derived from Severity.rank so there is a single source of truth.
_SEVERITY_ORDER = sorted(Severity, key=lambda s: -s.rank)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: -f.severity.rank)


def summarize(findings: list[Finding]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def to_json(findings: list[Finding]) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2)


def to_console(findings: list[Finding]) -> str:
    lines: list[str] = []
    summary = summarize(findings)
    lines.append("=" * 70)
    lines.append("Credential & Browser Hygiene Audit")
    lines.append("=" * 70)
    lines.append(
        f"Findings: {len(findings)}  "
        f"(CRITICAL={summary['CRITICAL']} HIGH={summary['HIGH']} "
        f"MEDIUM={summary['MEDIUM']} LOW={summary['LOW']})"
    )
    lines.append("")

    if not findings:
        lines.append("No issues found.")
        return "\n".join(lines)

    for sev in _SEVERITY_ORDER:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        lines.append(f"--- {sev.value} ({len(group)}) ---")
        for f in group:
            lines.append(f"[{f.category}] {f.title}")
            lines.append(f"  location: {f.location}")
            lines.append(f"  detail:   {f.detail}")
            lines.append(f"  fix:      {f.recommendation}")
            lines.append("")

    return "\n".join(lines)
