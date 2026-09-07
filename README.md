# Credential Auditor

A local, read-only browser/credential hygiene auditor. It scans **your own machine**
for three classes of credential-related risk and produces a severity-ranked report:

1. **Over-permissioned browser extensions** - parses installed Chrome/Edge/Brave and
   Firefox extension manifests directly (no browser APIs or network calls) and flags
   permissions or permission *combinations* that are commonly abused to steal session
   cookies, clipboard secrets, or browsing history (e.g. `cookies` + `webRequest`).
   Extension IDs are also checked against a built-in blocklist of extension IDs from
   real, cited security research reports on malicious/removed extensions
   (`credaudit/blocklist.py`, sources linked in the module docstring). For much broader
   coverage, `credaudit update-blocklist` fetches and caches
   [The Privacy Commons Institute's chrome-mal-ids feed](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids)
   (CC BY 4.0), an actively maintained, community-curated database of several thousand
   removed extension IDs -- see [Extension blocklist](#extension-blocklist) below. A
   custom `--blocklist` JSON file can also be supplied.
2. **Plaintext credentials in local config files** - walks common dev-tool config
   locations (`.aws/credentials`, `.npmrc`, `.netrc`, `.git-credentials`,
   `.docker/config.json`, `.env` files, etc.) and pattern-matches for AWS/GitHub/Slack/
   Google keys, private key blocks, JWTs, and generic password/token assignments.
   Matched values are **redacted** in the report (`abcd…ef (32 chars)`), never printed
   in full.
3. **Risky browser settings** - reads Chromium's `Preferences` JSON and Firefox's
   `prefs.js` to flag things like Safe Browsing being disabled, the built-in password
   manager being on without a Primary/master password, and breach-alert detection
   being turned off.

## Why this project

Browser extensions and locally saved dev credentials are a real, underrated attack
surface - a single over-permissioned extension can silently exfiltrate session
cookies from every site you visit, and secrets accidentally left in `.env` or
`.aws/credentials` are a common source of real-world breaches. This tool automates
the kind of manual audit a security-conscious engineer would otherwise do by hand.

**Everything here is read-only and, by default, fully offline.** The tool never
modifies browser state and only reads files already present on the local disk. The
one exception is `credaudit update-blocklist`, an explicit, opt-in command that
downloads a public extension-ID feed (see [Extension blocklist](#extension-blocklist));
a normal `credaudit` scan makes no network calls.

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

Exit code is `1` if any `HIGH` or `CRITICAL` finding is present, `0` otherwise - handy
for CI or a scheduled check.

## Extension blocklist

`credaudit/blocklist.py` ships with a small, individually-cited built-in list (see
the module docstring for sources). That's enough to demonstrate the mechanism, but
real-world coverage needs more than ~10 hand-picked IDs. Run:

```bash
credaudit update-blocklist
```

to fetch [The Privacy Commons Institute's chrome-mal-ids feed](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids)
(CC BY 4.0) - an actively maintained, community-curated database of several thousand
extension IDs removed from the Chrome/Edge stores for malware, spyware, adware,
search hijacking, and similar violations - and cache it to
`~/.cache/credaudit/blocklist_feed.json`. Every subsequent `credaudit` scan
transparently merges the cached feed into the blocklist check; no further network
access happens unless `update-blocklist` is run again. A `--blocklist <file>` JSON
file, if supplied, is layered on top of both.

## Design notes

- `credaudit/browsers.py` locates installed Chrome/Edge/Brave/Firefox profiles across
  Windows/macOS/Linux without depending on the browsers being open.
- `credaudit/extensions.py` reads each extension's `manifest.json` (Chromium) or
  unpacks Firefox `.xpi` archives, checking `permissions`/`host_permissions` against a
  curated high-risk list plus a small set of dangerous *combinations*.
- `credaudit/blocklist.py` / `credaudit/feed.py` check extension IDs against a small
  cited built-in list plus an optionally cached external feed (see
  [Extension blocklist](#extension-blocklist)).
- `credaudit/secrets_scan.py` scans known credential-file locations and, optionally,
  arbitrary directories (`--scan-dir`) with regexes for common secret formats. It skips
  binary files and caps file size to stay fast and avoid false positives on assets.
- `credaudit/settings.py` inspects browser preference files for security-relevant
  toggles.
- `credaudit/report.py` renders findings sorted by severity, either as a console
  report or JSON.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

Tests use temporary, synthetic profile/manifest/config fixtures - they never touch
your real browser data. CI (`.github/workflows/ci.yml`) runs the suite on Linux,
macOS, and Windows against Python 3.10-3.13.

## Detection benchmark

`data/benchmark/` is a hand-labeled corpus - realistic credential/config files
with planted fake-but-real-format secrets and hard negatives (placeholders,
templated DSNs, git SHAs), synthetic extension manifests (permission combos,
Manifest V2, a blocklisted ID), and browser preference files (each insecure
toggle plus a secure twin). `python scripts/run_benchmark.py` scores the
scanners against it and prints a confusion matrix:

```
category     cases   TP   FP   FN   TN  precision   recall     F1
secrets         49   18    2    0   29      0.900    1.000  0.947
extensions       7    5    0    0    2      1.000    1.000  1.000
settings         6    4    0    0    2      1.000    1.000  1.000
overall         62   27    2    0   33      0.931    1.000  0.964
```

Full write-up, including the two tracked false positives and the known
uncovered formats, is in [docs/benchmark.md](docs/benchmark.md) (regenerate
with `--markdown`). `tests/test_benchmark.py` gates CI on recall (nothing
missed) and untracked precision (no new false positive).

## Integration with host_intrusion_detector

The companion [`host_intrusion_detector`](../host_intrusion_detector) project can run
this tool as a periodic check: `hids audit-credentials` shells out to `credaudit --json`
(after `pip install -e .` here puts it on PATH) and reports findings in HIDS's own
risk-score format, so a single command covers both process-level and
credential-hygiene attack surfaces. See `hids/credaudit_bridge.py`.

## Possible extensions

- Add Safari extension support (macOS `.appex` bundles).
- Check OS keychain / Credential Manager entries for weak or reused secrets.
- Periodically re-run `update-blocklist` (e.g. via a scheduled task) instead of
  requiring a manual refresh.

## License

MIT - see [LICENSE](LICENSE). The optional external feed fetched by
`credaudit update-blocklist` is The Privacy Commons Institute's chrome-mal-ids
database, licensed CC BY 4.0 and attributed in each finding it produces.
