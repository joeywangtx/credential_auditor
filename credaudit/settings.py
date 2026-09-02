from __future__ import annotations

import json
import re
from pathlib import Path

from credaudit.browsers import BrowserProfile, find_all_profiles
from credaudit.findings import Finding, Severity


def _get(d: dict, dotted_path: str, default=None):
    cur = d
    for part in dotted_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _scan_chromium_preferences(profile: BrowserProfile) -> list[Finding]:
    findings: list[Finding] = []
    prefs_path = profile.profile_dir / "Preferences"
    if not prefs_path.is_file():
        return findings

    try:
        prefs = json.loads(prefs_path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return findings

    location = f"{profile.browser}:{profile.profile_name}:Preferences"

    if _get(prefs, "credentials_enable_service", True) is True:
        findings.append(
            Finding(
                category="risky_setting",
                severity=Severity.MEDIUM,
                title="Built-in password manager is enabled",
                detail="Chromium's password manager stores saved credentials encrypted at rest, but they decrypt "
                       "automatically for any process running as the logged-in user (e.g. malware, infostealers).",
                location=location,
                recommendation="Prefer a dedicated password manager with a separate master password, "
                               "or at least confirm OS-level disk encryption is on.",
            )
        )

    if _get(prefs, "autofill.credit_card_enabled", True) is True:
        findings.append(
            Finding(
                category="risky_setting",
                severity=Severity.LOW,
                title="Credit card autofill is enabled",
                detail="Stored card data is available to autofill on any site, increasing exposure to malicious "
                       "or spoofed forms.",
                location=location,
                recommendation="Disable credit card autofill if not needed, or restrict to trusted sites only.",
            )
        )

    if _get(prefs, "profile.password_manager_leak_detection", True) is False:
        findings.append(
            Finding(
                category="risky_setting",
                severity=Severity.LOW,
                title="Password breach/leak detection is disabled",
                detail="The browser will not warn when saved credentials appear in known breach datasets.",
                location=location,
                recommendation="Re-enable leak detection in browser privacy settings.",
            )
        )

    safe_browsing = _get(prefs, "safebrowsing.enabled", True)
    if safe_browsing is False:
        findings.append(
            Finding(
                category="risky_setting",
                severity=Severity.MEDIUM,
                title="Safe Browsing / phishing protection is disabled",
                detail="The browser will not warn about known phishing or malware-hosting sites, which are a "
                       "primary vector for credential theft.",
                location=location,
                recommendation="Re-enable Safe Browsing (standard or enhanced protection).",
            )
        )

    if _get(prefs, "profile.default_content_setting_values.geolocation") == 1:
        findings.append(
            Finding(
                category="risky_setting",
                severity=Severity.LOW,
                title="Geolocation is allowed by default for all sites",
                detail="Sites can access precise location without a per-site prompt.",
                location=location,
                recommendation="Set geolocation default back to 'ask' unless intentionally allowed globally.",
            )
        )

    return findings


_FIREFOX_BOOL_RE = re.compile(r'user_pref\("([^"]+)",\s*(true|false)\)')


def _scan_firefox_prefs(profile: BrowserProfile) -> list[Finding]:
    findings: list[Finding] = []
    prefs_path = profile.profile_dir / "prefs.js"
    if not prefs_path.is_file():
        return findings

    try:
        text = prefs_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    values = {name: (val == "true") for name, val in _FIREFOX_BOOL_RE.findall(text)}
    location = f"firefox:{profile.profile_name}:prefs.js"

    if values.get("signon.rememberSignons") is True:
        findings.append(
            Finding(
                category="risky_setting",
                severity=Severity.MEDIUM,
                title="Firefox saved logins are enabled",
                detail="Firefox will offer to store site credentials; without a Primary Password they decrypt "
                       "for any local process running as the user.",
                location=location,
                recommendation="Set a Firefox Primary Password (about:preferences#privacy) to encrypt saved logins.",
            )
        )

    if values.get("signon.management.page.breach-alerts.enabled", True) is False:
        findings.append(
            Finding(
                category="risky_setting",
                severity=Severity.LOW,
                title="Firefox breach alerts are disabled",
                detail="Firefox will not warn when saved logins match a known data breach.",
                location=location,
                recommendation="Re-enable breach alerts in Firefox privacy settings.",
            )
        )

    if values.get("browser.safebrowsing.malware.enabled", True) is False or \
       values.get("browser.safebrowsing.phishing.enabled", True) is False:
        findings.append(
            Finding(
                category="risky_setting",
                severity=Severity.MEDIUM,
                title="Firefox phishing/malware protection is disabled",
                detail="The browser will not warn about known phishing or malware-hosting sites.",
                location=location,
                recommendation="Re-enable Safe Browsing-equivalent protection in Firefox privacy settings.",
            )
        )

    return findings


def scan_settings(profiles: list[BrowserProfile] | None = None) -> list[Finding]:
    profiles = profiles if profiles is not None else find_all_profiles()
    findings: list[Finding] = []
    for profile in profiles:
        if profile.browser == "firefox":
            findings.extend(_scan_firefox_prefs(profile))
        else:
            findings.extend(_scan_chromium_preferences(profile))
    return findings
