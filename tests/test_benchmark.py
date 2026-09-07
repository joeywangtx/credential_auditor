"""Gate on the labeled detection benchmark (data/benchmark/).

These assertions are deliberately floors, not exact matches: the corpus is
allowed to grow, and a couple of placeholder-shaped false positives are
tracked in labels.json. What must not regress is recall (no planted secret or
malicious fixture may be missed) and untracked precision (no *new* false
positive).
"""

import pytest

from credaudit.benchmark import load_labels, run_all


@pytest.fixture(scope="module")
def results():
    return run_all()


def test_no_false_negatives(results):
    for cat in ("secrets", "extensions", "settings"):
        s = results[cat]
        assert s.fn == 0, f"{cat} missed: {s.fn_detail}"


def test_no_untracked_false_positives(results):
    for cat in ("secrets", "extensions", "settings"):
        s = results[cat]
        assert s.untracked_fp == 0, f"{cat} new false positive(s): {s.fp_detail}"


def test_secrets_precision_floor(results):
    # 0.90 today (2 tracked placeholder FPs / 20 positives); alert if it drops.
    assert results["secrets"].precision >= 0.85


def test_extensions_and_settings_are_exact(results):
    for cat in ("extensions", "settings"):
        s = results[cat]
        assert s.fp == 0 and s.fn == 0
        assert not s.notes, f"{cat} category/severity mismatch: {s.notes}"


def test_overall_f1_floor(results):
    assert results["overall"].f1 >= 0.90


def test_every_case_is_scored(results):
    # guards against a fixture file going missing (which would silently shrink the corpus)
    assert results["secrets"].total >= 45
    assert results["extensions"].total == 7
    assert results["settings"].total == 6


def test_labels_reference_existing_fixtures():
    from credaudit.benchmark import BENCHMARK_ROOT

    labels = load_labels()
    for entry in labels["secrets"]["positives"] + labels["secrets"]["negatives"]:
        assert (BENCHMARK_ROOT / entry["file"]).is_file(), entry["file"]
    for case in labels["extensions"]["cases"] + labels["settings"]["cases"]:
        assert (BENCHMARK_ROOT / case["dir"]).is_dir(), case["dir"]
