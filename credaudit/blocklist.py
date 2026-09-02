"""Known-malicious / removed browser extension IDs.

The built-in list below is drawn from publicly documented security research
reports naming specific Chrome Web Store extension IDs removed for
credential/session theft, data exfiltration, or malicious backdoors. Each
entry cites its source. This is illustrative, not exhaustive -- it will not
catch a novel or unlisted malicious extension, and store-side removal does
not automatically uninstall an extension a user already has. Pair it with
the permission-based checks in extensions.py, which generalize to unknown
extensions instead of relying on a fixed ID list.

For much broader (but less individually-vetted) coverage, run
`credaudit update-blocklist` to fetch and cache The Privacy Commons
Institute's chrome-mal-ids feed (see feed.py) -- an actively maintained,
community-curated database of several thousand removed extension IDs. That
fetch is opt-in and explicit; a normal scan reads only the cached copy, if
any, and never touches the network on its own.

A custom blocklist can be supplied via `--blocklist <file>`: a JSON file
containing either a list of extension IDs, or a list of {"id": ..., "reason": ...}
objects. That file is merged on top of (and can override) the built-in list
and the cached feed.

Sources for the built-in list:
- Socket Threat Research, "108 Chrome Extensions Linked to Data Exfiltration
  and Session Theft via Shared C2 Infrastructure" (2026):
  https://socket.dev/blog/108-chrome-ext-linked-to-data-exfil-session-theft-shared-c2
- The Hacker News, "Two Chrome Extensions Caught Secretly Stealing
  Credentials from Over 170 Sites" (Dec 2025):
  https://thehackernews.com/2025/12/two-chrome-extensions-caught-secretly.html
"""

from __future__ import annotations

import json
from pathlib import Path

from credaudit.feed import load_cached_feed

# extension_id -> human-readable reason it was flagged/removed, with source.
BUILTIN_BLOCKLIST: dict[str, str] = {
    # Socket.dev, "108 Chrome Extensions Linked to Data Exfiltration and
    # Session Theft via Shared C2 Infrastructure" (2026). All route stolen
    # data to shared C2 infrastructure at cloudapi[.]stream.
    "obifanppcpchlehkjipahhphbcbjekfa": (
        "'Telegram Multi-account' -- steals active Telegram Web session, "
        "transmitted to attacker C2 every 15s (Socket.dev, 2026)"
    ),
    "mdcfennpfgkngnibjbpnpaafcjnhcjno": (
        "'Web Client for Telegram - Teleside' -- Telegram session theft "
        "infrastructure, strips security headers (Socket.dev, 2026)"
    ),
    "mmecpiobcdbjkaijljohghhpfgngpjmk": (
        "'YouSide - Youtube Sidebar' -- strips YouTube security headers, "
        "injects ads/gambling overlay (Socket.dev, 2026)"
    ),
    "bfoofgelpmalhcmedaaeogahlmbkopfd": (
        "'Web Client for Youtube - SideYou' -- strips YouTube security "
        "headers, injects ads/gambling overlay (Socket.dev, 2026)"
    ),
    "cbfhnceafaenchbefokkngcbnejached": (
        "'Web Client for TikTok' -- strips TikTok security headers, "
        "injects ads/gambling overlay, opens arbitrary WebSocket "
        "connections (Socket.dev, 2026)"
    ),
    "ogogpebnagniggbnkbpjioobomdbmdcj": (
        "'Text Translation' -- proxies all translation requests through "
        "attacker server, exfiltrates user content (Socket.dev, 2026)"
    ),
    "ldmnhdllijbchflpbmnlgndfnlgmkgif": (
        "'Page Locker' -- contains a universal backdoor that opens "
        "arbitrary URLs on browser startup (Socket.dev, 2026)"
    ),
    "lnajjhohknhgemncbaomjjjpmpdigedg": (
        "'Page Auto Refresh' -- contains a universal backdoor that opens "
        "arbitrary URLs on browser startup (Socket.dev, 2026)"
    ),
    # The Hacker News, "Two Chrome Extensions Caught Secretly Stealing
    # Credentials from Over 170 Sites" (Dec 2025). "Phantom Shuttle" --
    # traffic-interception/MITM proxy harvesting passwords, credit cards,
    # API keys, and auth tokens; two published copies of the same malware.
    "fbfldogmkadejddihifklefknmikncaj": (
        "'Phantom Shuttle' -- MITM proxy intercepting credentials from "
        "170+ domains (The Hacker News, Dec 2025)"
    ),
    "ocpcmfmiidofonkbodpdhgddhlcmcofd": (
        "'Phantom Shuttle' (second published copy) -- same MITM "
        "credential/token harvesting (The Hacker News, Dec 2025)"
    ),
}


def load_blocklist(extra_path: Path | None = None, use_cached_feed: bool = True) -> dict[str, str]:
    """Build the effective blocklist: built-in list, then the cached external
    feed (if `credaudit update-blocklist` has been run and use_cached_feed is
    True), then `extra_path` -- each layer can override IDs from the previous
    one. Loading the cached feed is itself offline; only `update-blocklist`
    touches the network.
    """
    blocklist = dict(BUILTIN_BLOCKLIST)
    if use_cached_feed:
        blocklist.update(load_cached_feed())

    if extra_path is None:
        return blocklist

    try:
        payload = json.loads(extra_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return blocklist

    if isinstance(payload, list):
        for entry in payload:
            if isinstance(entry, str):
                blocklist[entry] = "Listed in user-supplied blocklist"
            elif isinstance(entry, dict) and "id" in entry:
                blocklist[entry["id"]] = entry.get("reason", "Listed in user-supplied blocklist")

    return blocklist
