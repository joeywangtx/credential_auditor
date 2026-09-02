from __future__ import annotations

import argparse
import sys
import urllib.error
from pathlib import Path

from credaudit.browsers import find_all_profiles
from credaudit.extensions import scan_extensions
from credaudit.feed import FEED_URL, default_cache_path, update_cache
from credaudit.findings import Severity
from credaudit.report import to_console, to_json
from credaudit.secrets_scan import scan_local_configs
from credaudit.settings import scan_settings


def cmd_scan(args: argparse.Namespace) -> int:
    profiles = find_all_profiles()
    findings = []

    if "extensions" not in args.skip:
        findings.extend(scan_extensions(profiles, blocklist_path=args.blocklist))
    if "settings" not in args.skip:
        findings.extend(scan_settings(profiles))
    if "secrets" not in args.skip:
        findings.extend(scan_local_configs(args.scan_dir))

    min_rank = Severity[args.min_severity].rank
    findings = [f for f in findings if f.severity.rank >= min_rank]

    output = to_json(findings) if args.json else to_console(findings)

    if args.out:
        try:
            if args.out.parent and not args.out.parent.exists():
                args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(output, encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write report to {args.out}: {exc}", file=sys.stderr)
            return 2
        print(f"Report written to {args.out}")
    else:
        print(output)

    has_critical_or_high = any(f.severity.rank >= Severity.HIGH.rank for f in findings)
    return 1 if has_critical_or_high else 0


def cmd_update_blocklist(args: argparse.Namespace) -> int:
    cache_path = args.cache_path or default_cache_path()
    print(f"Fetching {FEED_URL} ...")
    try:
        path, count = update_cache(cache_path)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"error: could not fetch the blocklist feed: {exc}", file=sys.stderr)
        return 2
    print(f"Cached {count} extension IDs to {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credaudit",
        description="Audit locally installed browser extensions, config files, and browser settings "
                     "for credential-hygiene risks. Read-only; scans this machine only.",
    )
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="Run the audit (default if no subcommand is given).")
    scan_parser.add_argument(
        "--skip", action="append", choices=["extensions", "secrets", "settings"], default=[],
        help="Skip a scan category (can be repeated).",
    )
    scan_parser.add_argument(
        "--scan-dir", action="append", type=Path, default=[],
        help="Additional directory to scan for plaintext secrets (e.g. a project folder). Can be repeated.",
    )
    scan_parser.add_argument(
        "--blocklist", type=Path, default=None,
        help="Extra JSON file of known-malicious extension IDs to check against "
             "(list of IDs, or list of {id, reason} objects), merged with the built-in list "
             "and any cached feed from `update-blocklist`.",
    )
    scan_parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of a console report.",
    )
    scan_parser.add_argument(
        "--out", type=Path, default=None,
        help="Write the report to this file instead of stdout.",
    )
    scan_parser.add_argument(
        "--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW",
        help="Only include findings at or above this severity.",
    )
    scan_parser.set_defaults(func=cmd_scan)

    update_parser = sub.add_parser(
        "update-blocklist",
        help="Fetch and cache an external malicious-extension-ID feed (the only network call this tool makes).",
    )
    update_parser.add_argument(
        "--cache-path", type=Path, default=None,
        help=f"Where to write the cached feed (default: {default_cache_path()}).",
    )
    update_parser.set_defaults(func=cmd_update_blocklist)

    return parser


_KNOWN_COMMANDS = {"scan", "update-blocklist", "-h", "--help"}


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])

    # Default to the `scan` subcommand when none is given, so old-style
    # `credaudit --skip extensions` invocations keep working.
    if not argv or argv[0] not in _KNOWN_COMMANDS:
        argv = ["scan", *argv]

    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
