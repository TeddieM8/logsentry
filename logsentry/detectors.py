"""Detection rules. Each one takes a list of LoginEvents and returns Alerts."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from logsentry.parser import LoginEvent

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1}


@dataclass(frozen=True)
class Alert:
    """Something a rule decided is worth a human looking at."""

    rule: str
    severity: str
    ip: str
    detail: str
    first_seen: datetime
    last_seen: datetime


def _group_by_ip(events: Iterable[LoginEvent]) -> dict[str, list[LoginEvent]]:
    """Group events by source address, each group in time order."""
    groups: dict[str, list[LoginEvent]] = defaultdict(list)
    for event in events:
        groups[event.ip].append(event)
    for group in groups.values():
        # sorted() is stable, so two events in the same second keep file order.
        group.sort(key=lambda event: event.timestamp)
    return groups


def detect_brute_force(
    events: Iterable[LoginEvent],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
) -> list[Alert]:
    """Flag an address with `threshold` or more failed logins inside `window`.

    Uses a sliding window: `recent` holds the failures that are still within
    `window` of the one being looked at, and old ones drop off the left.
    """
    alerts = []
    failures = (event for event in events if not event.success)

    for ip, ip_failures in _group_by_ip(failures).items():
        recent: deque[datetime] = deque()
        peak = 0
        peak_start = peak_end = ip_failures[0].timestamp

        for event in ip_failures:
            recent.append(event.timestamp)
            while event.timestamp - recent[0] > window:
                recent.popleft()
            if len(recent) > peak:
                peak = len(recent)
                peak_start, peak_end = recent[0], event.timestamp

        if peak >= threshold:
            alerts.append(
                Alert(
                    rule="brute-force",
                    severity="MEDIUM",
                    ip=ip,
                    detail=(
                        f"{peak} failed logins between "
                        f"{peak_start:%H:%M:%S} and {peak_end:%H:%M:%S}"
                    ),
                    first_seen=peak_start,
                    last_seen=peak_end,
                )
            )
    return alerts


def detect_username_spray(
    events: Iterable[LoginEvent], min_usernames: int = 5
) -> list[Alert]:
    """Flag an address that failed to log in as many different usernames.

    There is no time window on purpose. A patient attacker spaces attempts out
    to stay under the brute-force threshold, but still leaves a trail of
    different usernames behind.
    """
    alerts = []
    failures = (event for event in events if not event.success)

    for ip, ip_failures in _group_by_ip(failures).items():
        usernames = {event.username for event in ip_failures}
        if len(usernames) >= min_usernames:
            alerts.append(
                Alert(
                    rule="username-spray",
                    severity="MEDIUM",
                    ip=ip,
                    detail=f"failed logins for {len(usernames)} different usernames",
                    first_seen=ip_failures[0].timestamp,
                    last_seen=ip_failures[-1].timestamp,
                )
            )
    return alerts


def detect_success_after_failures(
    events: Iterable[LoginEvent], min_failures: int = 3
) -> list[Alert]:
    """Flag a successful login that follows a run of failures from one address.

    This is the alert that matters most: it may mean a guess finally worked.
    """
    alerts = []

    for ip, ip_events in _group_by_ip(events).items():
        failures = 0
        first_failure = ip_events[0].timestamp

        for event in ip_events:
            if not event.success:
                if failures == 0:
                    first_failure = event.timestamp
                failures += 1
                continue

            if failures >= min_failures:
                alerts.append(
                    Alert(
                        rule="success-after-failures",
                        severity="HIGH",
                        ip=ip,
                        # !a escapes odd characters: the username is untrusted
                        # and ends up printed in somebody's terminal.
                        detail=(
                            f"login as {event.username!a} succeeded after "
                            f"{failures} failed attempts"
                        ),
                        first_seen=first_failure,
                        last_seen=event.timestamp,
                    )
                )
            failures = 0
    return alerts


def run_all(
    events: Iterable[LoginEvent],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
    min_usernames: int = 5,
) -> list[Alert]:
    """Run every rule and return the alerts, most severe first."""
    events = list(events)
    alerts = (
        detect_brute_force(events, threshold, window)
        + detect_username_spray(events, min_usernames)
        + detect_success_after_failures(events)
    )
    alerts.sort(key=lambda alert: (SEVERITY_ORDER[alert.severity], alert.first_seen))
    return alerts
