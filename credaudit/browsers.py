from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BrowserProfile:
    browser: str          # "chrome", "edge", "brave", "firefox"
    profile_name: str
    profile_dir: Path
    extensions_dir: Path | None


def _chromium_roots() -> list[tuple[str, Path]]:
    """Return (browser_name, user_data_dir) pairs for Chromium-based browsers."""
    system = platform.system()
    home = Path.home()
    roots: list[tuple[str, Path]] = []

    if system == "Windows":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        roots += [
            ("chrome", local / "Google" / "Chrome" / "User Data"),
            ("edge", local / "Microsoft" / "Edge" / "User Data"),
            ("brave", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
        ]
    elif system == "Darwin":
        app_support = home / "Library" / "Application Support"
        roots += [
            ("chrome", app_support / "Google" / "Chrome"),
            ("edge", app_support / "Microsoft Edge"),
            ("brave", app_support / "BraveSoftware" / "Brave-Browser"),
        ]
    else:  # Linux
        roots += [
            ("chrome", home / ".config" / "google-chrome"),
            ("edge", home / ".config" / "microsoft-edge"),
            ("brave", home / ".config" / "BraveSoftware" / "Brave-Browser"),
        ]

    return [(name, path) for name, path in roots if path.is_dir()]


def find_chromium_profiles() -> list[BrowserProfile]:
    profiles: list[BrowserProfile] = []
    for browser_name, root in _chromium_roots():
        for entry in sorted(root.iterdir()):
            if not entry.is_dir():
                continue
            if entry.name not in ("Default",) and not entry.name.startswith("Profile "):
                continue
            ext_dir = entry / "Extensions"
            profiles.append(
                BrowserProfile(
                    browser=browser_name,
                    profile_name=entry.name,
                    profile_dir=entry,
                    extensions_dir=ext_dir if ext_dir.is_dir() else None,
                )
            )
    return profiles


def _firefox_root() -> Path | None:
    system = platform.system()
    home = Path.home()
    if system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        path = appdata / "Mozilla" / "Firefox" / "Profiles"
    elif system == "Darwin":
        path = home / "Library" / "Application Support" / "Firefox" / "Profiles"
    else:
        path = home / ".mozilla" / "firefox"
    return path if path.is_dir() else None


def find_firefox_profiles() -> list[BrowserProfile]:
    root = _firefox_root()
    if root is None:
        return []
    profiles: list[BrowserProfile] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        ext_dir = entry / "extensions"
        profiles.append(
            BrowserProfile(
                browser="firefox",
                profile_name=entry.name,
                profile_dir=entry,
                extensions_dir=ext_dir if ext_dir.is_dir() else None,
            )
        )
    return profiles


def find_all_profiles() -> list[BrowserProfile]:
    return find_chromium_profiles() + find_firefox_profiles()
