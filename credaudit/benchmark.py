"""Labeled detection benchmark.

Runs the three scanners (secrets, extensions, settings) against the fixed,
hand-labeled corpus in ``data/benchmark/`` and scores their output against
ground truth (``data/benchmark/labels.json``). Produces a per-category and
overall confusion matrix plus precision / recall / F1.

Nothing here touches the machine it runs on: every input is a checked-in
fixture file, and the extension pass is pinned to the built-in blocklist
(``use_cached_feed=False``) so a cached feed on the runner can't move the
numbers.

Entry points:
    run_all()            -> {"secrets": Score, "extensions": Score,
                             "settings": Score, "overall": Score, "gaps": [...]}
    format_scorecard()   -> text table (used by scripts/run_benchmark.py)
    format_markdown()    -> docs/benchmark.md body
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from credaudit.browsers import BrowserProfile
from credaudit.extensions import scan_extensions
from credaudit.secrets_scan import _scan_file
from credaudit.settings import scan_settings

BENCHMARK_ROOT = Path(__file__).resolve().parent.parent / "data" / "benchmark"


@dataclass
class Score:
    name: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    fp_known: int = 0  # false positives already tracked in labels.json (known_false_positive)
    fp_detail: list[str] = field(default_factory=list)
    fn_detail: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def untracked_fp(self) -> int:
        return self.fp - self.fp_known

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def add(self, other: "Score") -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn
        self.tn += other.tn
        self.fp_known += other.fp_known


# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #
def load_labels(root: Path = BENCHMARK_ROOT) -> dict:
    path = root / "labels.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"benchmark labels not found at {path} -- run from a source checkout, "
            "the data/ directory is not shipped in the wheel"
        )
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# secrets
# --------------------------------------------------------------------------- #
def _secret_findings_by_line(path: Path) -> dict[int, list]:
    by_line: dict[int, list] = {}
    for finding in _scan_file(path):
        by_line.setdefault(finding.metadata.get("line", -1), []).append(finding)
    return by_line


def _patterns(hits: list) -> str:
    return ", ".join(sorted({h.metadata.get("pattern", h.title) for h in hits}))


def score_secrets(spec: dict, root: Path = BENCHMARK_ROOT) -> Score:
    s = Score("secrets")
    positives = spec["positives"]
    negatives = spec["negatives"]

    pos_lines: dict[str, set[int]] = {}
    for p in positives:
        pos_lines.setdefault(p["file"], set()).add(p["line"])
    neg_lines: dict[str, set[int]] = {}
    for n in negatives:
        neg_lines.setdefault(n["file"], set()).add(n["line"])
    known_fp = {(n["file"], n["line"]) for n in negatives if n.get("known_false_positive")}

    files = set(pos_lines) | set(neg_lines)
    findings_by_file = {rel: _secret_findings_by_line(root / rel) for rel in files}

    for p in positives:
        if findings_by_file.get(p["file"], {}).get(p["line"]):
            s.tp += 1
        else:
            s.fn += 1
            s.fn_detail.append(f'{p["file"]}:{p["line"]} expected {p["pattern"]}')

    for n in negatives:
        hits = findings_by_file.get(n["file"], {}).get(n["line"])
        if not hits:
            s.tn += 1
            continue
        tag = " [tracked]" if (n["file"], n["line"]) in known_fp else ""
        if tag:
            s.fp_known += 1
        s.fp += 1
        s.fp_detail.append(f'{n["file"]}:{n["line"]} -> {_patterns(hits)}{tag}  ({n["why"]})')

    # A finding on a line that is neither a labeled positive nor a labeled
    # negative is still an unexpected false positive.
    for rel, by_line in findings_by_file.items():
        for line, hits in by_line.items():
            if line in pos_lines.get(rel, set()) or line in neg_lines.get(rel, set()):
                continue
            s.fp += 1
            s.fp_detail.append(f"{rel}:{line} -> {_patterns(hits)}  (unlabeled line)")

    return s


def report_gaps(spec: dict, root: Path = BENCHMARK_ROOT) -> list[tuple]:
    """(file, line, detected_now, why) for each known_gaps entry."""
    out = []
    for g in spec.get("known_gaps", []):
        by_line = _secret_findings_by_line(root / g["file"])
        out.append((g["file"], g["line"], bool(by_line.get(g["line"])), g["why"]))
    return out


# --------------------------------------------------------------------------- #
# extensions / settings
# --------------------------------------------------------------------------- #
def _profile_for(case: dict, root: Path) -> BrowserProfile:
    case_dir = root / case["dir"]
    if case["browser"] == "firefox":
        prof = case_dir / case["profile"]
        ext = prof / "extensions"
    else:
        prof = case_dir / "Default"
        ext = prof / "Extensions"
    return BrowserProfile(
        browser=case["browser"],
        profile_name=prof.name,
        profile_dir=prof,
        extensions_dir=ext if ext.is_dir() else None,
    )


def score_extensions(spec: dict, root: Path = BENCHMARK_ROOT) -> Score:
    s = Score("extensions")
    for case in spec["cases"]:
        findings = scan_extensions([_profile_for(case, root)], use_cached_feed=False)
        if case["detect"]:
            if not findings:
                s.fn += 1
                s.fn_detail.append(f'{case["dir"]}: expected a finding, got none')
                continue
            s.tp += 1
            want_cat = case.get("category")
            if want_cat and want_cat not in {f.category for f in findings}:
                s.notes.append(
                    f'{case["dir"]}: expected {want_cat}, got {sorted({f.category for f in findings})}'
                )
            elif want_cat and case.get("severity"):
                sevs = {f.severity.value for f in findings if f.category == want_cat}
                if case["severity"] not in sevs:
                    s.notes.append(
                        f'{case["dir"]}: expected {want_cat}={case["severity"]}, got {sorted(sevs)}'
                    )
        else:
            if findings:
                s.fp += 1
                s.fp_detail.append(f'{case["dir"]} -> {sorted({f.category for f in findings})}')
            else:
                s.tn += 1
    return s


def score_settings(spec: dict, root: Path = BENCHMARK_ROOT) -> Score:
    s = Score("settings")
    for case in spec["cases"]:
        findings = scan_settings([_profile_for(case, root)])
        n = len(findings)
        if case["detect"]:
            if n == 0:
                s.fn += 1
                s.fn_detail.append(f'{case["dir"]}: expected findings, got none')
                continue
            s.tp += 1
            want = case.get("min_findings", 1)
            if n < want:
                s.notes.append(f'{case["dir"]}: expected >={want} findings, got {n}')
        else:
            if n:
                s.fp += 1
                s.fp_detail.append(f'{case["dir"]} -> {[f.title for f in findings]}')
            else:
                s.tn += 1
    return s


# --------------------------------------------------------------------------- #
# top level
# --------------------------------------------------------------------------- #
def run_all(root: Path = BENCHMARK_ROOT) -> dict:
    labels = load_labels(root)
    secrets = score_secrets(labels["secrets"], root)
    extensions = score_extensions(labels["extensions"], root)
    settings = score_settings(labels["settings"], root)
    overall = Score("overall")
    for sc in (secrets, extensions, settings):
        overall.add(sc)
    return {
        "secrets": secrets,
        "extensions": extensions,
        "settings": settings,
        "overall": overall,
        "gaps": report_gaps(labels["secrets"], root),
    }


def _row(s: Score) -> str:
    return (
        f"{s.name:<12}{s.total:>6}{s.tp:>5}{s.fp:>5}{s.fn:>5}{s.tn:>5}"
        f"{s.precision:>11.3f}{s.recall:>9.3f}{s.f1:>7.3f}"
    )


def format_scorecard(results: dict) -> str:
    lines = [
        "Credential Auditor -- detection benchmark",
        "=" * 66,
        f"{'category':<12}{'cases':>6}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}"
        f"{'precision':>11}{'recall':>9}{'F1':>7}",
        "-" * 66,
        _row(results["secrets"]),
        _row(results["extensions"]),
        _row(results["settings"]),
        "-" * 66,
        _row(results["overall"]),
    ]

    for cat in ("secrets", "extensions", "settings"):
        s = results[cat]
        if s.fn_detail:
            lines += ["", f"{cat} - missed (false negatives):"] + [f"  - {d}" for d in s.fn_detail]
        if s.fp_detail:
            lines += ["", f"{cat} - mis-flagged (false positives):"] + [f"  - {d}" for d in s.fp_detail]
        if s.notes:
            lines += ["", f"{cat} - notes:"] + [f"  - {d}" for d in s.notes]

    gaps = results["gaps"]
    if gaps:
        lines += ["", "known gaps (formats not yet covered; not scored):"]
        for file, line, detected, why in gaps:
            mark = "now DETECTED - promote to positives" if detected else "not detected"
            lines.append(f"  - {file}:{line} [{mark}] {why}")

    return "\n".join(lines)


def format_markdown(results: dict) -> str:
    o = results["overall"]
    lines = [
        "# Detection benchmark",
        "",
        "<!-- Generated by `python scripts/run_benchmark.py --markdown`. Do not edit by hand. -->",
        "",
        "Measures the three scanners against the hand-labeled corpus in",
        "`data/benchmark/`. Every input is a checked-in fixture and the extension",
        "pass is pinned to the built-in blocklist, so the numbers are reproducible",
        "and nothing reads the host machine. `tests/test_benchmark.py` gates CI on",
        "recall (no missed case) and untracked precision (no new false positive).",
        "",
        "## How the corpus is built",
        "",
        "- **secrets** - realistic config/credential files (`.aws/credentials`,",
        "  `.git-credentials`, `.env`, `pip.conf`, `id_ed25519`, ...) with planted",
        "  fake-but-real-format secrets as **positives**, and placeholder/template/",
        "  prose lines plus high-entropy non-secrets (git SHAs, image digests) as",
        "  **negatives**. Scored per line.",
        "- **extensions** - synthetic `manifest.json` trees: the cookies+webRequest",
        "  exfil combo, 3+ high-risk permissions, a single high-risk permission,",
        "  Manifest V2, a blocklisted ID, and two clean extensions.",
        "- **settings** - synthetic Chromium `Preferences` / Firefox `prefs.js` with",
        "  each insecure toggle, and a secure twin for each browser.",
        "",
        "## Results",
        "",
        "| Category | Cases | TP | FP | FN | TN | Precision | Recall | F1 |",
        "|---|--:|--:|--:|--:|--:|--:|--:|--:|",
    ]
    for cat in ("secrets", "extensions", "settings", "overall"):
        s = results[cat]
        lines.append(
            f"| {s.name} | {s.total} | {s.tp} | {s.fp} | {s.fn} | {s.tn} "
            f"| {s.precision:.3f} | {s.recall:.3f} | {s.f1:.3f} |"
        )
    lines += [
        "",
        f"**Overall: precision {o.precision:.1%}, recall {o.recall:.1%}, "
        f"F1 {o.f1:.3f}** over {o.total} labeled cases.",
        "",
    ]

    fp_all = [d for cat in ("secrets", "extensions", "settings") for d in results[cat].fp_detail]
    fn_all = [d for cat in ("secrets", "extensions", "settings") for d in results[cat].fn_detail]
    if fn_all:
        lines += ["## False negatives (missed)", ""] + [f"- {d}" for d in fn_all] + [""]
    if fp_all:
        lines += ["## False positives (mis-flagged)", ""] + [f"- {d}" for d in fp_all] + [""]
        lines += [
            "Entries tagged `[tracked]` are known placeholder/template shapes that match a "
            "format pattern. Fix: extend the placeholder negative-lookahead "
            "(`${`, `{{`, `%`, `CHANGEME`, ...) to the specific-format patterns "
            "(AWS secret, connection string) and skip `*.example` / `*.template` / `*.sample` files.",
            "",
        ]

    gaps = results["gaps"]
    if gaps:
        lines += ["## Known gaps (not scored)", ""]
        for file, line, detected, why in gaps:
            state = "**now detected**" if detected else "not detected"
            lines.append(f"- `{file}:{line}` - {state} - {why}")
        lines.append("")

    return "\n".join(lines)
