from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

from credaudit.blocklist import load_blocklist
from credaudit.browsers import BrowserProfile, find_all_profiles
from credaudit.findings import Finding, Severity

# Permissions that alone justify a flag, with rationale.
HIGH_RISK_PERMISSIONS = {
    "<all_urls>": "Can read/modify content on every website, including banking and email.",
    "http://*/*": "Broad host access across all HTTP sites.",
    "https://*/*": "Broad host access across all HTTPS sites.",
    "tabs": "Can read the URL and title of every open tab.",
    "history": "Can read the user's entire browsing history.",
    "cookies": "Can read/write cookies, potentially hijacking authenticated sessions.",
    "webRequest": "Can observe all network requests made by the browser.",
    "webRequestBlocking": "Can intercept and modify network requests before they complete.",
    "management": "Can enumerate, disable, or install other extensions.",
    "debugger": "Can attach a debugger to any page and read/inject arbitrary content.",
    "nativeMessaging": "Can exchange messages with a native executable outside the sandbox.",
    "clipboardRead": "Can read the system clipboard, which often holds copied passwords/OTPs.",
    "browsingData": "Can silently clear history, cookies, and cached credentials.",
    "proxy": "Can redirect all browser traffic through an attacker-controlled proxy.",
    "privacy": "Can change browser privacy/security settings.",
    "geolocation": "Can access the user's physical location.",
}

# Combinations that are individually plausible but dangerous together.
DANGEROUS_COMBOS = [
    ({"cookies", "webRequest"}, "Combined cookie + network access can exfiltrate session tokens."),
    ({"cookies", "<all_urls>"}, "Site-wide cookie access can silently steal session cookies from any domain."),
    ({"clipboardRead", "webRequest"}, "Can read clipboard secrets and exfiltrate them over the network."),
    ({"history", "webRequest"}, "Can correlate browsing history with live network traffic."),
]


def _version_sort_key(version_dir: Path) -> tuple:
    """Sort key for Chromium extension version directories.

    Names look like ``1.2.3_0``; a plain string sort would rank ``9.0_0``
    above ``10.0_0``. Parse the numeric components instead, falling back to
    the raw name for anything that doesn't look like a version.
    """
    name = version_dir.name.split("_", 1)[0]
    parts = name.split(".")
    try:
        # (1, ...) ranks above (0, ...), so a real version always beats an unparseable name.
        return (1, tuple(int(p) for p in parts))
    except ValueError:
        return (0, version_dir.name)


def _load_chromium_manifest(ext_version_dir: Path) -> dict | None:
    manifest_path = ext_version_dir / "manifest.json"
    if not manifest_path.is_file():
        return None
    try:
        text = manifest_path.read_text(encoding="utf-8-sig")
        return json.loads(text)
    except (OSError, json.JSONDecodeError):
        return None


_MSG_RE = re.compile(r"^__MSG_(.+)__$")


def _resolve_i18n_message(key: str, version_dir: Path, manifest: dict) -> str | None:
    """Resolve a ``__MSG_key__`` placeholder against the extension's ``_locales``.

    Chrome looks up the manifest's ``default_locale`` first; we also try
    ``en``/``en_US`` and, failing that, any locale present. Message keys are
    matched case-insensitively, as Chrome does.
    """
    locales_dir = version_dir / "_locales"
    if not locales_dir.is_dir():
        return None

    candidates: list[str] = []
    default_locale = manifest.get("default_locale")
    if isinstance(default_locale, str):
        candidates.append(default_locale)
    candidates += ["en", "en_US"]
    try:
        candidates += [d.name for d in locales_dir.iterdir() if d.is_dir()]
    except OSError:
        return None

    seen: set[str] = set()
    for locale in candidates:
        if locale in seen:
            continue
        seen.add(locale)
        messages_path = locales_dir / locale / "messages.json"
        if not messages_path.is_file():
            continue
        try:
            messages = json.loads(messages_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        lookup = {k.lower(): v for k, v in messages.items() if isinstance(v, dict)}
        entry = lookup.get(key.lower())
        if entry and isinstance(entry.get("message"), str):
            return entry["message"]
    return None


def _chromium_extension_name(ext_id: str, manifest: dict, version_dir: Path) -> str:
    name = manifest.get("name", ext_id)
    if not isinstance(name, str):
        return ext_id
    match = _MSG_RE.match(name)
    if match:
        resolved = _resolve_i18n_message(match.group(1), version_dir, manifest)
        return resolved or f"{ext_id} ({name})"
    return name


def _scan_chromium_extension(
    ext_id: str, ext_dir: Path, profile: BrowserProfile, blocklist: dict[str, str]
) -> list[Finding]:
    findings: list[Finding] = []
    version_dirs = [d for d in ext_dir.iterdir() if d.is_dir()]
    if not version_dirs:
        return findings

    manifest = None
    version_dir = None
    for candidate in sorted(version_dirs, key=_version_sort_key, reverse=True):
        manifest = _load_chromium_manifest(candidate)
        if manifest:
            version_dir = candidate
            break
    if manifest is None or version_dir is None:
        return findings

    name = _chromium_extension_name(ext_id, manifest, version_dir)
    permissions = set(manifest.get("permissions", []) or [])
    host_permissions = set(manifest.get("host_permissions", []) or [])
    all_perms = permissions | host_permissions

    location = f"{profile.browser}:{profile.profile_name}:{ext_id}"

    if ext_id in blocklist:
        findings.append(
            Finding(
                category="extension_blocklisted",
                severity=Severity.CRITICAL,
                title=f"Extension '{name}' matches a known-malicious extension ID",
                detail=blocklist[ext_id],
                location=location,
                recommendation="Remove this extension immediately and rotate any credentials used while "
                               "it was installed.",
                metadata={"extension_id": ext_id},
            )
        )

    flagged = sorted(p for p in all_perms if p in HIGH_RISK_PERMISSIONS)
    if flagged:
        reasons = "; ".join(f"'{p}': {HIGH_RISK_PERMISSIONS[p]}" for p in flagged)
        severity = Severity.HIGH if len(flagged) >= 3 else Severity.MEDIUM
        findings.append(
            Finding(
                category="extension_permission",
                severity=severity,
                title=f"Extension '{name}' requests {len(flagged)} high-risk permission(s)",
                detail=reasons,
                location=location,
                recommendation="Review why this extension needs these permissions; remove it if unused or untrusted.",
                metadata={"extension_id": ext_id, "permissions": sorted(all_perms)},
            )
        )

    for combo, reason in DANGEROUS_COMBOS:
        if combo <= all_perms:
            findings.append(
                Finding(
                    category="extension_permission_combo",
                    severity=Severity.CRITICAL,
                    title=f"Extension '{name}' has a dangerous permission combination",
                    detail=f"Permissions {sorted(combo)} together: {reason}",
                    location=location,
                    recommendation="Treat this extension as high-risk; verify its publisher and necessity, or remove it.",
                    metadata={"extension_id": ext_id, "combo": sorted(combo)},
                )
            )

    if manifest.get("manifest_version") == 2:
        findings.append(
            Finding(
                category="extension_manifest_version",
                severity=Severity.LOW,
                title=f"Extension '{name}' uses legacy Manifest V2",
                detail="MV2 extensions can use persistent background pages and are being phased out; "
                       "they often carry looser CSP defaults than MV3.",
                location=location,
                recommendation="Prefer MV3 alternatives where available.",
                metadata={"extension_id": ext_id},
            )
        )

    return findings


def _scan_firefox_extension_xpi(
    xpi_path: Path, profile: BrowserProfile, blocklist: dict[str, str]
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(xpi_path) as zf:
            names = zf.namelist()
            manifest_name = next((n for n in names if n.endswith("manifest.json")), None)
            if manifest_name is None:
                return findings
            manifest = json.loads(zf.read(manifest_name).decode("utf-8-sig"))
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError):
        return findings

    ext_id = xpi_path.stem
    name = manifest.get("name", ext_id)
    if isinstance(name, str) and _MSG_RE.match(name):
        # Firefox stores localized strings in _locales inside the xpi; resolving
        # that is more involved, so just fall back to the id for readability.
        name = ext_id
    permissions = set(manifest.get("permissions", []) or [])
    location = f"firefox:{profile.profile_name}:{ext_id}"

    if ext_id in blocklist:
        findings.append(
            Finding(
                category="extension_blocklisted",
                severity=Severity.CRITICAL,
                title=f"Extension '{name}' matches a known-malicious extension ID",
                detail=blocklist[ext_id],
                location=location,
                recommendation="Remove this extension immediately and rotate any credentials used while "
                               "it was installed.",
                metadata={"extension_id": ext_id},
            )
        )

    flagged = sorted(p for p in permissions if p in HIGH_RISK_PERMISSIONS)
    if flagged:
        reasons = "; ".join(f"'{p}': {HIGH_RISK_PERMISSIONS[p]}" for p in flagged)
        severity = Severity.HIGH if len(flagged) >= 3 else Severity.MEDIUM
        findings.append(
            Finding(
                category="extension_permission",
                severity=severity,
                title=f"Extension '{name}' requests {len(flagged)} high-risk permission(s)",
                detail=reasons,
                location=location,
                recommendation="Review why this extension needs these permissions; remove it if unused or untrusted.",
                metadata={"extension_id": ext_id, "permissions": sorted(permissions)},
            )
        )

    for combo, reason in DANGEROUS_COMBOS:
        if combo <= permissions:
            findings.append(
                Finding(
                    category="extension_permission_combo",
                    severity=Severity.CRITICAL,
                    title=f"Extension '{name}' has a dangerous permission combination",
                    detail=f"Permissions {sorted(combo)} together: {reason}",
                    location=location,
                    recommendation="Treat this extension as high-risk; verify its publisher and necessity, or remove it.",
                    metadata={"extension_id": ext_id, "combo": sorted(combo)},
                )
            )

    return findings


def scan_extensions(
    profiles: list[BrowserProfile] | None = None,
    blocklist_path: Path | None = None,
    use_cached_feed: bool = True,
) -> list[Finding]:
    profiles = profiles if profiles is not None else find_all_profiles()
    blocklist = load_blocklist(blocklist_path, use_cached_feed=use_cached_feed)
    findings: list[Finding] = []

    for profile in profiles:
        if profile.extensions_dir is None:
            continue

        if profile.browser == "firefox":
            for item in profile.extensions_dir.iterdir():
                if item.is_file() and item.suffix == ".xpi":
                    findings.extend(_scan_firefox_extension_xpi(item, profile, blocklist))
        else:
            for ext_dir in profile.extensions_dir.iterdir():
                if ext_dir.is_dir():
                    findings.extend(_scan_chromium_extension(ext_dir.name, ext_dir, profile, blocklist))

    return findings
