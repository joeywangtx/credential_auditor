# Credential Auditor

[![CI](https://github.com/joeywangtx/credential_auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/joeywangtx/credential_auditor/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A local, read-only browser/credential hygiene auditor. It scans **your own machine** for three classes of credential-related risk and produces a severity-ranked report:

1. **Over-permissioned browser extensions** — parses installed Chrome/Edge/Brave and Firefox extension manifests directly (no browser APIs or network calls) and flags permissions or permission *combinations* commonly abused to steal session cookies, clipboard secrets, or browsing history. Extension IDs are also checked against a built-in, cited blocklist, with an opt-in `credaudit update-blocklist` command to pull in a much larger community-maintained feed (see [Extension blocklist](#extension-blocklist)).
2. **Plaintext credentials in local config files** — walks common dev-tool config locations (`.aws/credentials`, `.npmrc`, `.netrc`, `.git-credentials`, `.docker/config.json`, `.env` files, etc.) and pattern-matches for AWS/GitHub/Slack/Google keys, private key blocks, JWTs, and generic password/token assignments. Matched values are redacted in the report (`abcd…ef (32 chars)`), never printed in full.
3. **Risky browser settings** — reads Chromium's `Preferences` JSON and Firefox's `prefs.js` for things like Safe Browsing disabled, the password manager on without a master password, or breach-alert detection off.

**Everything here is read-only and, by default, fully offline.** The tool never modifies browser state and only reads files already on disk. The one exception is `credaudit update-blocklist`, an explicit opt-in command that downloads a public extension-ID feed — a normal `credaudit` scan makes no network calls.

## Why

Browser extensions and locally saved dev credentials are a real, underrated attack surface — a single over-permissioned extension can silently exfiltrate session cookies from every site you visit, and secrets left in `.env` or `.aws/credentials` are a common source of real-world breaches. This automates the audit a security-conscious engineer would otherwise do by hand.

## Results

The extension, secrets, and settings passes are graded against a hand-labeled corpus (`data/benchmark/`, 62 checked-in fixture cases). Every input is a fixture and the extension pass is pinned to the built-in blocklist, so the numbers are reproducible and nothing reads the host machine.

| Category | Cases | Precision | Recall | F1 |
|---|--:|--:|--:|--:|
| secrets | 49 | 0.900 | 1.000 | 0.947 |
| extensions | 7 | 1.000 | 1.000 | 1.000 |
| settings | 6 | 1.000 | 1.000 | 1.000 |
| **overall** | **62** | **0.931** | **1.000** | **0.964** |

Recall is 100% (no labeled case missed). The two false positives are committed `.env.example` / `.template` files with credential-shaped placeholder values — the honest failure mode, documented in [`docs/benchmark.md`](docs/benchmark.md) along with the known coverage gaps. `tests/test_benchmark.py` gates CI on both recall and untracked precision. Reproduce with `python scripts/run_benchmark.py`.

Extended writeup with worked examples: [`Detail.md`](Detail.md).

## Install

```bash
cd credential_auditor
pip install -e .
```

## Usage

```bash
# Full audit (extensions + settings + default config paths), console report
credaudit

# Only scan for plaintext secrets, and also crawl an extra project directory
credaudit --skip extensions --skip settings --scan-dir /path/to/project

# Machine-readable output, only HIGH/CRITICAL findings, written to a file
credaudit --json --min-severity HIGH --out report.json

# Check extension IDs against the built-in blocklist plus a custom list
credaudit --blocklist my-blocklist.json

# Fetch and cache the external malicious-extension-ID feed (opt-in, one network call)
credaudit update-blocklist
```

Exit code is `1` if any `HIGH` or `CRITICAL` finding is present, `0` otherwise — useful for CI or a scheduled check.

## Extension blocklist

The built-in list (`credaudit/blocklist.py`) is small and individually cited — enough to demonstrate the mechanism, not enough for real coverage. Run:

```bash
credaudit update-blocklist
```

to fetch [The Privacy Commons Institute's chrome-mal-ids feed](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids) (CC BY 4.0) — an actively maintained database of several thousand extension IDs removed from the Chrome/Edge stores — and cache it to `~/.cache/credaudit/blocklist_feed.json`. Every subsequent scan merges the cached feed in automatically; no further network access happens unless `update-blocklist` is run again. A `--blocklist <file>` JSON file, if supplied, is layered on top of both.

## How it works

| Module | Responsibility |
|---|---|
| `credaudit/browsers.py` | Locates installed Chrome/Edge/Brave/Firefox profiles across Windows/macOS/Linux without needing the browser open |
| `credaudit/extensions.py` | Reads each extension's `manifest.json` (Chromium) or unpacks Firefox `.xpi`, checking permissions against a curated high-risk list plus dangerous combinations |
| `credaudit/blocklist.py` / `feed.py` | Check extension IDs against the built-in list plus the optional cached external feed |
| `credaudit/secrets_scan.py` | Scans known credential-file locations and, optionally, arbitrary directories (`--scan-dir`) with regexes for common secret formats; skips binaries, caps file size |
| `credaudit/settings.py` | Inspects browser preference files for security-relevant toggles |
| `credaudit/report.py` | Renders findings sorted by severity, as console text or JSON |

Full architecture notes: [`DESIGN.md`](DESIGN.md).

## Development

```bash
pip install -e ".[dev]"
pytest
```

29 tests across extensions, feed, secrets-scan, settings, and the detection benchmark. Tests use temporary, synthetic profile/manifest/config fixtures — they never touch your real browser data. CI (`.github/workflows/ci.yml`) runs the suite plus the benchmark scorecard on Linux, macOS, and Windows against Python 3.10, 3.12, and 3.13.

## Integration with host_intrusion_detector

The companion [`host_intrusion_detector`](https://github.com/joeywangtx/host_intrusion_detector) project can run this tool as a periodic check: `hids audit-credentials` shells out to `credaudit --json` (once `pip install -e .` here puts it on PATH) and reports findings in HIDS's own risk-score format, so a single command covers both process-level and credential-hygiene attack surfaces. See `hids/credaudit_bridge.py`.

## Possible extensions

- Safari extension support (macOS `.appex` bundles).
- Check OS keychain / Credential Manager entries for weak or reused secrets.
- Periodically re-run `update-blocklist` on a schedule instead of requiring a manual refresh.

## License

MIT — see [LICENSE](LICENSE). The optional external feed fetched by `credaudit update-blocklist` is The Privacy Commons Institute's chrome-mal-ids database, licensed CC BY 4.0 and attributed in each finding it produces.
