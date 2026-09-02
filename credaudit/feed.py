"""Optional external threat-intel feed for the extension blocklist.

By design, credaudit's default scan is fully offline (see README: "The tool
never modifies browser state, never sends data anywhere, and only reads
files already present on the local disk"). This module is the one deliberate
exception, and it is opt-in only: `credaudit update-blocklist` explicitly
fetches a known, cited, community-maintained feed of malicious Chrome/Edge
extension IDs and caches it locally. A normal `credaudit` scan never touches
the network -- it just reads whatever was last cached, if anything.

Feed: The Privacy Commons Institute's chrome-mal-ids database
(CC BY 4.0, https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids),
an actively updated, community-curated aggregation of extensions removed
from the Chrome/Edge stores for malware, spyware, adware, search hijacking,
and similar policy violations (several thousand entries as of 2026, vs. the
~10 hand-picked, individually-cited entries in blocklist.py's built-in list).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

FEED_URL = (
    "https://raw.githubusercontent.com/The-Privacy-Commons-Institute/"
    "chrome-mal-ids/master/data/current-list.json"
)
FEED_ATTRIBUTION = (
    "The Privacy Commons Institute, chrome-mal-ids (CC BY 4.0): "
    "https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids"
)


def default_cache_path() -> Path:
    return Path.home() / ".cache" / "credaudit" / "blocklist_feed.json"


def fetch_feed(timeout: float = 15.0) -> dict:
    """Download the raw feed JSON. Raises urllib.error.URLError/HTTPError on failure."""
    request = urllib.request.Request(FEED_URL, headers={"User-Agent": "credaudit/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (explicit opt-in fetch)
        return json.loads(response.read().decode("utf-8"))


def update_cache(cache_path: Path | None = None, timeout: float = 15.0) -> tuple[Path, int]:
    """Fetch the feed and write it to the local cache. Returns (path, entry_count)."""
    cache_path = cache_path or default_cache_path()
    payload = fetch_feed(timeout=timeout)
    entries = payload.get("extensions", [])

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(payload), encoding="utf-8")
    return cache_path, len(entries)


def load_cached_feed(cache_path: Path | None = None) -> dict[str, str]:
    """Load a previously cached feed into {extension_id: reason}. Returns {} if no cache exists."""
    cache_path = cache_path or default_cache_path()
    if not cache_path.is_file():
        return {}

    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    result: dict[str, str] = {}
    for entry in payload.get("extensions", []):
        ext_id = entry.get("ext_id")
        if not ext_id:
            continue
        result[ext_id] = f"{_describe_feed_entry(entry)} ({FEED_ATTRIBUTION})"
    return result


def _describe_feed_entry(entry: dict) -> str:
    """Build a human-readable reason string from one feed entry.

    The feed's per-entry schema has shifted over time and varies by source;
    accept a few spellings for the threat classification and fall back to the
    free-text ``notes`` field, then to a bare label.
    """
    name = entry.get("name") or entry.get("ext_id_name") or "unknown"

    threat = entry.get("threat_types") or entry.get("threat_type") or entry.get("category")
    if isinstance(threat, (list, tuple)):
        threat = ", ".join(str(t) for t in threat if t)
    threat = (threat or "").strip()

    if threat:
        return f"'{name}' -- {threat}"

    notes = (entry.get("notes") or "").strip()
    if notes:
        return f"'{name}' -- {notes}"

    return f"'{name}' -- removed from the Chrome/Edge store"
