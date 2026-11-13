"""Command-line interface: read a log file, run the rules, print a report."""

from __future__ import annotations

import argparse
import sys
from datetime import date, timedelta

from logsentry.detectors import run_all
from logsentry.parser import parse_lines
from logsentry.report import alerts_to_json, format_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsentry",
        description="Find suspicious SSH login activity in a Linux auth.log.",
    )
    parser.add_argument("logfile", help="path to the auth.log file to analyse")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="failed logins from one address that count as brute force (default: 5)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=5,
        metavar="MINUTES",
        help="time window for the brute-force rule (default: 5)",
    )
    parser.add_argument(
        "--min-usernames",
        type=int,
        default=5,
        help="different usernames from one address that count as a spray (default: 5)",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=date.today().year,
        help="year the log was written in; syslog does not record it (default: this year)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="also write the alerts to FILE as JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        # errors="replace" because a log can contain any bytes an attacker
        # sends, and one bad byte should not crash the whole analysis.
        with open(args.logfile, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError as error:
        print(f"logsentry: cannot read {args.logfile}: {error}", file=sys.stderr)
        return 2

    events = list(parse_lines(lines, args.year))
    alerts = run_all(
        events,
        threshold=args.threshold,
        window=timedelta(minutes=args.window),
        min_usernames=args.min_usernames,
    )

    print(format_report(args.logfile, len(lines), events, alerts))

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as handle:
                handle.write(alerts_to_json(alerts) + "\n")
        except OSError as error:
            print(f"logsentry: cannot write {args.json}: {error}", file=sys.stderr)
            return 2
        print(f"\nAlerts written to {args.json}")

    return 0
