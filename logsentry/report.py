"""Turn events and alerts into something a person (or another program) can read."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict

from logsentry.detectors import Alert
from logsentry.parser import LoginEvent


def format_report(
    source: str, lines_read: int, events: list[LoginEvent], alerts: list[Alert]
) -> str:
    """Build the plain-text report that is printed to the terminal."""
    failed = [event for event in events if not event.success]
    successful = len(events) - len(failed)
    unique_ips = len({event.ip for event in events})

    out = [
        f"logsentry report for {source}",
        "",
        f"Lines read:         {lines_read}",
        f"SSH login attempts: {len(events)} "
        f"({len(failed)} failed, {successful} successful)",
        f"Source addresses:   {unique_ips}",
    ]

    if failed:
        out += ["", "Most failed logins by address:"]
        for ip, count in Counter(event.ip for event in failed).most_common(5):
            out.append(f"  {ip:<40}{count:>5}")

    out += ["", f"Alerts: {len(alerts)}"]
    for alert in alerts:
        out.append(
            f"  [{alert.severity:<6}] {alert.rule:<23} {alert.ip:<16} {alert.detail}"
        )
    if not alerts:
        out.append("  Nothing suspicious found.")

    return "\n".join(out)


def alerts_to_json(alerts: list[Alert]) -> str:
    """Serialise alerts as JSON so another tool can pick them up."""
    rows = []
    for alert in alerts:
        row = asdict(alert)
        row["first_seen"] = alert.first_seen.isoformat()
        row["last_seen"] = alert.last_seen.isoformat()
        rows.append(row)
    return json.dumps(rows, indent=2)
