# Architecture Review — Credential Auditor

*For people reading, extending, or reviewing the code. It covers the design
decisions and the order the project was built in. For what it does and how to
run it, see [README.md](README.md).*

---

## 1. Design goals, in priority order

1. **Read-only and offline by default.** The tool inspects a machine; it must
   never modify browser state, and a plain `credaudit` run must make zero
   network calls. The one network path (`update-blocklist`) is a separate
   subcommand a user has to type.
2. **Generalize, don't just blocklist.** A fixed list of bad extension IDs ages
   out immediately. The permission-based checks must catch an *unknown*
   over-permissioned extension. The ID blocklist is a secondary signal.
3. **Never print a secret in full.** Matched credential values are redacted at
   the point of detection, before they enter a `Finding`.
4. **One finding shape, severity-ranked.** Every check — extensions, secrets,
   settings — emits the same `Finding` dataclass so reporting, filtering, and
   the exit code have one code path.
5. **No runtime dependencies.** `pyproject.toml` `dependencies = []`. Standard
   library only (`json`, `re`, `zipfile`, `urllib`, `pathlib`, `platform`).
   This keeps it trivially installable on a locked-down machine and auditable in
   one sitting.

---

## 2. Module map and data flow

```
                       cli.py
        (argparse; defaults to the `scan` subcommand)
                          │
        ┌─────────────────┼──────────────────────────┐
        ▼                 ▼                          ▼
  browsers.py        secrets_scan.py            (feed.py — only via
  find_all_profiles()  scan_local_configs()      `update-blocklist`)
        │                 │                          │
        ▼                 │                          ▼
  extensions.py           │                    ~/.cache/credaudit/
  scan_extensions()       │                     blocklist_feed.json
        │                 │                          │
        ▼                 │                          │
  blocklist.py ◄──────────┼──────────────────────────┘
  load_blocklist()        │   (built-in dict + cached feed + --blocklist file)
        │                 │
  settings.py             │
  scan_settings()         │
        │                 │
        └────────┬────────┘
                 ▼
          list[Finding]   (findings.py: dataclass + Severity enum)
                 ▼
        severity filter (--min-severity)
                 ▼
          report.py  →  to_console() / to_json()
                 ▼
        exit code 1 if any HIGH/CRITICAL else 0
```

`findings.py` depends on nothing. `browsers.py` depends on nothing. Everything
else depends on those two and, where relevant, on `blocklist.py`/`feed.py`.
No scanner imports another scanner.

---

## 3. `Finding` and `Severity` ([`credaudit/findings.py`](credaudit/findings.py))

```python
class Severity(str, Enum):
    LOW / MEDIUM / HIGH / CRITICAL
    @property
    def rank(self) -> int: ...   # 0..3, the single source of truth for ordering

@dataclass
class Finding:
    category: str          # machine slug: "extension_permission", "plaintext_secret", ...
    severity: Severity
    title: str             # human summary
    detail: str            # specifics (redacted where needed)
    location: str          # "chrome:Default:<ext_id>" or an absolute file path
    recommendation: str    # what to do about it
    metadata: dict         # structured extras for JSON consumers
```

Decisions:

- **`Severity` subclasses `str`** so `json.dumps` needs no custom encoder and
  `Severity["HIGH"]` works for the `--min-severity` argument.
- **`rank` is a property, not stored.** Sorting (`report.py`), filtering
  (`cli.py`), and the exit-code check all call `.rank`. One definition.
- **`location` is a convention, not a type.** Extensions use
  `browser:profile:ext_id`; secrets and settings use a path. The report prints
  it verbatim; nothing parses it back, so the loose format is fine.
- **`metadata` exists for the JSON path.** The console report ignores it; a SIEM
  or the `hids` bridge can read `extension_id`, `permissions`, `line`, etc.

---

## 4. Browser discovery ([`credaudit/browsers.py`](credaudit/browsers.py))

`BrowserProfile(browser, profile_name, profile_dir, extensions_dir)`.

The job is: find Chrome/Edge/Brave/Firefox profile directories on
Windows/macOS/Linux **without the browser running and without any browser API**.

- `_chromium_roots()` returns per-OS `(name, user_data_dir)` pairs, filtered to
  those that actually exist. The three Chromium browsers share a directory
  layout, so one function handles all three by path.
- Chromium profiles are `Default` and `Profile N` subdirectories; each has an
  `Extensions/` folder (may be absent → `extensions_dir=None`).
- Firefox is separate (`_firefox_root` / `find_firefox_profiles`) because its
  layout and extension packaging differ entirely.
- `extensions_dir` is set to `None` rather than a non-existent path so callers
  do one `is None` check instead of `try`-ing an `iterdir()`.

Everything downstream takes `list[BrowserProfile]`, which is also the test seam —
tests build synthetic profile trees in `tmp_path` and never touch real browser
data.

---

## 5. Extension scanning ([`credaudit/extensions.py`](credaudit/extensions.py))

Three independent checks per extension, each producing its own `Finding`:

### 5.1 Manifest loading — the fiddly part

- **Version directory selection** (`_version_sort_key`): Chromium stores
  `Extensions/<id>/<version>_<n>/`. A string sort puts `9.0_0` above `10.0_0`,
  so the key parses the dotted version to an int tuple, with a
  `(1, ...)` vs `(0, name)` prefix so any parseable version beats an
  unparseable directory name. The scanner walks candidates newest-first and
  takes the first that has a readable `manifest.json`.
- **`utf-8-sig`** everywhere — Chrome ships manifests with a BOM.
- **`__MSG_name__` i18n placeholders** (`_resolve_i18n_message`): an extension's
  display name is often a locale key. Resolve it against `_locales/`, trying
  `default_locale`, then `en`/`en_US`, then any present locale, matching keys
  case-insensitively (as Chrome does). Falls back to `id (raw placeholder)`.
  For Firefox `.xpi` this resolution is skipped — the strings are inside the
  zip and it wasn't worth the complexity for a display string; it falls back to
  the ID.

### 5.2 The permission model

Two data structures drive it:

```python
HIGH_RISK_PERMISSIONS = { "<all_urls>": "...", "cookies": "...", "webRequest": "...", ... }
DANGEROUS_COMBOS = [ ({"cookies", "webRequest"}, "can exfiltrate session tokens"), ... ]
```

- A single high-risk permission → `Finding`. Severity is **`HIGH` if ≥ 3**
  flagged permissions, else `MEDIUM` — a rough proxy for "how much does this
  extension over-reach."
- A `DANGEROUS_COMBOS` set that is a subset of the extension's permissions →
  always **`CRITICAL`**. The combos are pairs that are each individually
  plausible but together enable a specific attack (read cookies + observe
  network = lift session tokens).
- `permissions` and `host_permissions` are unioned before checking, because MV3
  split host access into its own key.
- Manifest V2 → a `LOW` finding (persistent background pages, looser CSP; being
  phased out).

The Chromium and Firefox paths duplicate the three checks rather than sharing a
helper. That's a conscious trade: the inputs differ (dir tree vs. zip, `_locales`
resolution vs. not, `host_permissions` present vs. not) enough that a shared
function would be mostly branching. If a fourth browser type appears, factor then.

### 5.3 Blocklist check

`ext_id in blocklist` → `CRITICAL`. The blocklist is built by
`load_blocklist()` (next section).

---

## 6. The blocklist, in three layers ([`blocklist.py`](credaudit/blocklist.py) + [`feed.py`](credaudit/feed.py))

```
load_blocklist(extra_path) =
    BUILTIN_BLOCKLIST                     # ~10 hand-picked, each cited to a named report
    |> .update(load_cached_feed())       # thousands, from a community feed — only if cached
    |> .update(user --blocklist file)    # optional per-run override
```

Each layer can override IDs from the previous one. All three merge into one
`dict[ext_id, reason_string]`.

Design decisions:

- **The built-in list is tiny and individually sourced.** Every entry's comment
  cites a specific security-research report (Socket.dev's 108-extension C2
  cluster, The Hacker News' "Phantom Shuttle"). It exists to *demonstrate the
  mechanism* credibly, not to be comprehensive.
- **Broad coverage is opt-in.** `credaudit update-blocklist` fetches The Privacy
  Commons Institute's `chrome-mal-ids` feed (CC BY 4.0) once and caches it to
  `~/.cache/credaudit/blocklist_feed.json`. Every later scan reads the cache —
  **offline** — and merges it transparently. A scan never fetches.
- **`_describe_feed_entry` tolerates schema drift.** The feed's per-entry shape
  has changed over time; the parser accepts several spellings of the threat
  field (`threat_types`/`threat_type`/`category`, list or string) and falls back
  to `notes`, then to a bare "removed from the store" label.
- **Attribution is carried into the finding.** Feed-sourced reasons end with the
  CC BY 4.0 attribution string, so the license travels with the data.
- `feed.py` is the *only* module that imports `urllib.request`, and the one call
  site is marked `# noqa: S310` to document that the lint suppression is a
  deliberate opt-in fetch.

---

## 7. Secret scanning ([`credaudit/secrets_scan.py`](credaudit/secrets_scan.py))

### 7.1 What gets scanned

- A fixed list of `CANDIDATE_RELATIVE_PATHS` under `$HOME` — `.aws/credentials`,
  `.npmrc`, `.netrc`, `.git-credentials`, `.docker/config.json`, `.env`, shell
  histories, VS Code / Postman settings, etc. These are the files that
  empirically hold plaintext secrets.
- Optionally, `--scan-dir` roots walked with `os.walk`, pruning
  `.git`/`node_modules`/`__pycache__`/`.venv`/`venv`, matching `.env*` and
  common config extensions (`.ini`, `.cfg`, `.conf`, `.json`, `.yml`, `.yaml`).

### 7.2 Guards that keep it fast and quiet

- `SKIP_EXTENSIONS` — binary/asset types are skipped outright.
- `MAX_FILE_SIZE = 5 MB` — anything larger is skipped (avoids scanning a
  bundled `.json` data blob).
- `read_text(errors="ignore")` — never crash on a bad byte.
- Per-file dedupe on `(pattern_name, lineno)` so one line matching a pattern
  twice yields one finding.

### 7.3 The patterns

`PATTERNS` is a `list[SecretPattern(name, regex, severity)]`. Specific,
high-confidence formats first (`AKIA…`, `ghp_…`, Slack `xox…`, Google `AIza…`,
PEM headers, JWT), then the generic assignment patterns
(`password = ...`, `api_key: ...`, `scheme://user:pass@host`). The generic
patterns carry inline negative lookaheads for template/placeholder markers
(`{{`, `${`, `%`, `CHANGEME`, `xxxx`, `<`) so `password = ${DB_PASS}` doesn't
fire.

### 7.4 Redaction ([`_redact`](credaudit/secrets_scan.py))

Runs *before* the value is put in a `Finding`:
`value[:4] + "…" + value[-2:] + " (N chars)"`, or all-asterisks if ≤ 8 chars.
The full secret never enters the object graph, so it can't leak via `--json` or
a stack trace.

---

## 8. Settings scanning ([`credaudit/settings.py`](credaudit/settings.py))

- **Chromium:** `_get(prefs, "a.b.c", default)` walks the `Preferences` JSON by
  dotted path. Each check compares against the *secure* expected value and only
  flags the insecure state — password manager on, Safe Browsing off, leak
  detection off, credit-card autofill on, geolocation defaulted to allow.
- **Firefox:** `prefs.js` is not JSON — it's `user_pref("key", value);` lines.
  A single regex (`_FIREFOX_BOOL_RE`) pulls the boolean prefs into a dict, then
  the same style of check applies (saved logins without a Primary Password,
  breach alerts off, Safe Browsing off).
- The default in each `_get`/`.get` call encodes the browser's own default, so a
  pref that simply isn't present is treated correctly.

---

## 9. Reporting and exit code ([`credaudit/report.py`](credaudit/report.py), [`cli.py`](credaudit/cli.py))

- `_SEVERITY_ORDER = sorted(Severity, key=lambda s: -s.rank)` — derived from
  `rank`, so adding a severity level doesn't need a second edit.
- `to_json` emits `{generated_at, summary, findings[]}` with a UTC timestamp;
  `to_console` groups by severity, highest first.
- **Exit code**: `1` if any finding at or above `HIGH` survives the
  `--min-severity` filter, else `0`. This is the CI / scheduled-check contract,
  and it's computed *after* filtering so `--min-severity CRITICAL` narrows both
  the report and the failure condition consistently.
- **`cli.main` injects a default subcommand:** if `argv[0]` isn't a known
  command, it prepends `scan`, so `credaudit --skip extensions` keeps working
  alongside `credaudit scan --skip extensions`.

---

## 10. Testing strategy

`pytest`, stdlib only, CI on Linux/macOS/Windows × Python 3.10–3.13.

| File | Approach |
|---|---|
| `test_extensions.py` | synthetic `Extensions/<id>/<ver>/manifest.json` trees in `tmp_path`; asserts permission/combo/blocklist/MV2 findings and version-dir selection |
| `test_secrets_scan.py` | temp files with planted fake secrets; asserts detection, redaction (full value absent from output), size/binary skips |
| `test_settings.py` | synthetic `Preferences` JSON and `prefs.js`; asserts each insecure toggle flags and each secure one doesn't |
| `test_feed.py` | feed parsing / schema-drift tolerance / cache round-trip with `urllib` mocked — no network |

The consistent pattern: build a fake home/profile tree, point the scanner at it,
assert on `Finding`s. Nothing reads the developer's real browser or config.

---

## 11. Extension points

- **New secret format:** append a `SecretPattern` to `PATTERNS`.
- **New config location:** add to `CANDIDATE_RELATIVE_PATHS`.
- **New risky setting:** add one `_get`/`values.get` check in `settings.py`.
- **New high-risk permission or combo:** add to `HIGH_RISK_PERMISSIONS` /
  `DANGEROUS_COMBOS`.
- **Safari support:** a new `browsers.py` discovery function + an
  `extensions.py` path for `.appex` bundles — the `Finding` contract is
  unchanged.
- **Consumers:** anything that wants structured output reads `--json`; that's
  how `host_intrusion_detector`'s `hids audit-credentials` integrates
  (subprocess + parse `findings[]`, see `hids/credaudit_bridge.py`).

---

## 12. Known limitations

- Regex secret detection has no entropy check — a random-looking 40-char value
  not assigned to a known-key name is missed, and a long non-secret assigned to
  `api_key` is a false positive.
- The permission model is heuristic; a legitimately broad extension (a real
  password manager) will flag as `HIGH`. The recommendation text says "review,"
  not "remove," for that reason.
- `update-blocklist` is a manual refresh — no TTL, no auto-update.
- Chromium `Preferences` can be locked while the browser is open on some
  platforms; the scanner reads what it can and moves on.
