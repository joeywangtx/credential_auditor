import json
from pathlib import Path

from credaudit.browsers import BrowserProfile
from credaudit.settings import scan_settings


def test_flags_password_manager_enabled(tmp_path):
    profile_dir = tmp_path / "Default"
    profile_dir.mkdir()
    (profile_dir / "Preferences").write_text(json.dumps({
        "credentials_enable_service": True,
        "safebrowsing": {"enabled": True},
    }))
    profile = BrowserProfile("chrome", "Default", profile_dir, None)

    findings = scan_settings([profile])

    assert any("password manager" in f.title.lower() for f in findings)


def test_flags_safe_browsing_disabled(tmp_path):
    profile_dir = tmp_path / "Default"
    profile_dir.mkdir()
    (profile_dir / "Preferences").write_text(json.dumps({
        "credentials_enable_service": False,
        "safebrowsing": {"enabled": False},
    }))
    profile = BrowserProfile("chrome", "Default", profile_dir, None)

    findings = scan_settings([profile])

    assert any("safe browsing" in f.title.lower() for f in findings)


def test_firefox_prefs_flags_remember_signons(tmp_path):
    profile_dir = tmp_path / "abc.default"
    profile_dir.mkdir()
    (profile_dir / "prefs.js").write_text(
        'user_pref("signon.rememberSignons", true);\n'
        'user_pref("browser.safebrowsing.phishing.enabled", false);\n'
    )
    profile = BrowserProfile("firefox", "abc.default", profile_dir, None)

    findings = scan_settings([profile])

    titles = [f.title.lower() for f in findings]
    assert any("saved logins" in t for t in titles)
    assert any("phishing" in t or "malware" in t for t in titles)


def test_missing_preferences_file_returns_empty(tmp_path):
    profile_dir = tmp_path / "Default"
    profile_dir.mkdir()
    profile = BrowserProfile("chrome", "Default", profile_dir, None)

    assert scan_settings([profile]) == []
