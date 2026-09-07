"""Run the detection benchmark and print a scorecard.

    python scripts/run_benchmark.py              # print the scorecard
    python scripts/run_benchmark.py --markdown   # (re)write docs/benchmark.md

Exit code is 0 on a clean run, 1 if there is an untracked false positive or any
false negative (the same condition tests/test_benchmark.py gates on).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from credaudit.benchmark import format_markdown, format_scorecard, run_all  # noqa: E402


def main() -> int:
    results = run_all()
    print(format_scorecard(results))

    if "--markdown" in sys.argv[1:]:
        out = Path(__file__).resolve().parent.parent / "docs" / "benchmark.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(format_markdown(results) + "\n", encoding="utf-8")
        print(f"\nwrote {out}")

    overall = results["overall"]
    regressions = overall.untracked_fp + overall.fn
    if regressions:
        print(f"\nFAIL: {overall.untracked_fp} untracked false positive(s), {overall.fn} false negative(s)")
        return 1
    print("\nOK: no untracked false positives, no false negatives")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
