import json
from pathlib import Path
from unittest.mock import patch

import pytest

from credaudit.browsers import BrowserProfile
from credaudit.extensions import scan_extensions


@pytest.fixture(autouse=True)
def _no_cached_feed():
    """Tests must not depend on whatever feed cache happens to exist on the
    machine running them -- isolate against the built-in list only."""
    with patch("credaudit.blocklist.load_cached_feed", return_value={}):
        yield


def _make_chromium_profile(tmp_path: Path, manifest: dict, ext_id: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"):
    profile_dir = tmp_path / "Default"
    ext_version_dir = profile_dir / "Extensions" / ext_id / "1.0_0"
    ext_version_dir.mkdir(parents=True)
    (ext_version_dir / "manifest.json").write_text(json.dumps(manifest))
    return BrowserProfile(
        browser="chrome",
        profile_name="Default",
        profile_dir=profile_dir,
        extensions_dir=profile_dir / "Extensions",
    )


def test_flags_high_risk_permissions(tmp_path):
    manifest = {
        "name": "Suspicious Extension",
        "manifest_version": 3,
        "permissions": ["cookies", "webRequest", "tabs"],
        "host_permissions": ["<all_urls>"],
    }
    profile = _make_chromium_profile(tmp_path, manifest)

    findings = scan_extensions([profile])

    categories = {f.category for f in findings}
    assert "extension_permission" in categories
    assert "extension_permission_combo" in categories
    assert any(f.severity.value == "CRITICAL" for f in findings)


def test_benign_extension_produces_no_permission_findings(tmp_path):
    manifest = {
        "name": "Simple Note Taker",
        "manifest_version": 3,
        "permissions": ["storage"],
    }
    profile = _make_chromium_profile(tmp_path, manifest)

    findings = scan_extensions([profile])

    assert not any(f.category == "extension_permission" for f in findings)


def test_manifest_v2_flagged_as_low_severity(tmp_path):
    manifest = {"name": "Old Extension", "manifest_version": 2, "permissions": ["storage"]}
    profile = _make_chromium_profile(tmp_path, manifest)

    findings = scan_extensions([profile])

    mv2_findings = [f for f in findings if f.category == "extension_manifest_version"]
    assert len(mv2_findings) == 1
    assert mv2_findings[0].severity.value == "LOW"


def test_flags_blocklisted_extension_id(tmp_path):
    blocklisted_id = "obifanppcpchlehkjipahhphbcbjekfa"
    manifest = {"name": "Innocuous Name", "manifest_version": 3, "permissions": ["storage"]}
    profile = _make_chromium_profile(tmp_path, manifest, ext_id=blocklisted_id)

    findings = scan_extensions([profile])

    blocklist_findings = [f for f in findings if f.category == "extension_blocklisted"]
    assert len(blocklist_findings) == 1
    assert blocklist_findings[0].severity.value == "CRITICAL"


def test_custom_blocklist_file(tmp_path):
    custom_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    manifest = {"name": "Custom Flagged", "manifest_version": 3, "permissions": ["storage"]}
    profile = _make_chromium_profile(tmp_path, manifest, ext_id=custom_id)

    blocklist_file = tmp_path / "blocklist.json"
    blocklist_file.write_text(json.dumps([{"id": custom_id, "reason": "flagged internally"}]))

    findings = scan_extensions([profile], blocklist_path=blocklist_file)

    blocklist_findings = [f for f in findings if f.category == "extension_blocklisted"]
    assert len(blocklist_findings) == 1
    assert blocklist_findings[0].detail == "flagged internally"


def test_resolves_msg_placeholder_name_from_locales(tmp_path):
    manifest = {
        "name": "__MSG_appName__",
        "default_locale": "en",
        "manifest_version": 3,
        "permissions": ["cookies", "webRequest", "tabs"],
    }
    profile = _make_chromium_profile(tmp_path, manifest)
    version_dir = profile.profile_dir / "Extensions" / "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" / "1.0_0"
    locale_dir = version_dir / "_locales" / "en"
    locale_dir.mkdir(parents=True)
    (locale_dir / "messages.json").write_text(json.dumps({"appName": {"message": "Real Name"}}))

    findings = scan_extensions([profile])

    assert findings
    assert all("Real Name" in f.title for f in findings if f.category == "extension_permission")
    assert not any("__MSG_" in f.title for f in findings)


def test_picks_highest_version_dir(tmp_path):
    ext_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    profile_dir = tmp_path / "Default"
    for version, perms in (("9.0_0", ["storage"]), ("10.0_0", ["cookies", "webRequest", "tabs"])):
        vdir = profile_dir / "Extensions" / ext_id / version
        vdir.mkdir(parents=True)
        (vdir / "manifest.json").write_text(json.dumps({"name": "X", "manifest_version": 3, "permissions": perms}))
    profile = BrowserProfile("chrome", "Default", profile_dir, profile_dir / "Extensions")

    findings = scan_extensions([profile])

    # The 10.0 manifest (high-risk perms) must be the one scanned, not 9.0 (storage only).
    assert any(f.category == "extension_permission" for f in findings)


def test_no_extensions_dir_returns_empty(tmp_path):
    profile = BrowserProfile(
        browser="chrome", profile_name="Default", profile_dir=tmp_path, extensions_dir=None
    )
    assert scan_extensions([profile]) == []
