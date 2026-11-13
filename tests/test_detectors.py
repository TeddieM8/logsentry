from datetime import datetime, timedelta

from logsentry.detectors import (
    detect_brute_force,
    detect_success_after_failures,
    detect_username_spray,
)
from logsentry.parser import LoginEvent

START = datetime(2026, 11, 12, 9, 0, 0)
ATTACKER = "203.0.113.45"


def event(seconds, ip=ATTACKER, username="root", success=False):
    """Build a LoginEvent `seconds` after START."""
    return LoginEvent(START + timedelta(seconds=seconds), ip, username, success)


# --- brute force ---------------------------------------------------------


def test_brute_force_fires_when_threshold_is_reached():
    events = [event(i * 10) for i in range(5)]
    alerts = detect_brute_force(events, threshold=5)

    assert len(alerts) == 1
    assert alerts[0].ip == ATTACKER
    assert alerts[0].rule == "brute-force"


def test_brute_force_stays_quiet_one_below_threshold():
    events = [event(i * 10) for i in range(4)]

    assert detect_brute_force(events, threshold=5) == []


def test_brute_force_ignores_failures_spread_over_a_long_time():
    # Five failures, but ten minutes apart: never five inside one window.
    events = [event(i * 600) for i in range(5)]

    assert detect_brute_force(events, threshold=5, window=timedelta(minutes=5)) == []


def test_brute_force_counts_each_address_separately():
    # Five failures in total, but no single address is responsible for five.
    events = [event(i, ip="203.0.113.1") for i in range(3)]
    events += [event(i, ip="203.0.113.2") for i in range(2)]

    assert detect_brute_force(events, threshold=5) == []


def test_brute_force_ignores_successful_logins():
    events = [event(i, success=True) for i in range(10)]

    assert detect_brute_force(events, threshold=5) == []


def test_brute_force_finds_a_burst_after_a_quiet_start():
    # One old failure, a long gap, then a burst of five.
    events = [event(0)] + [event(3600 + i) for i in range(5)]
    alerts = detect_brute_force(events, threshold=5)

    assert len(alerts) == 1
    assert alerts[0].first_seen == START + timedelta(seconds=3600)


# --- username spray ------------------------------------------------------


def test_spray_fires_on_many_different_usernames():
    names = ["admin", "test", "oracle", "postgres", "ubuntu"]
    events = [event(i * 600, username=name) for i, name in enumerate(names)]
    alerts = detect_username_spray(events, min_usernames=5)

    assert len(alerts) == 1
    assert alerts[0].rule == "username-spray"


def test_spray_does_not_fire_on_one_username_tried_many_times():
    events = [event(i) for i in range(50)]

    assert detect_username_spray(events, min_usernames=5) == []


# --- success after failures ----------------------------------------------


def test_success_after_several_failures_is_high_severity():
    events = [event(i) for i in range(4)] + [event(10, success=True)]
    alerts = detect_success_after_failures(events, min_failures=3)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert "4 failed attempts" in alerts[0].detail


def test_one_typo_then_success_is_not_an_alert():
    events = [event(0), event(5, success=True)]

    assert detect_success_after_failures(events, min_failures=3) == []


def test_failures_from_a_different_address_do_not_count():
    events = [event(i, ip="203.0.113.1") for i in range(4)]
    events.append(event(10, ip="10.0.0.15", success=True))

    assert detect_success_after_failures(events, min_failures=3) == []


def test_failure_count_resets_after_a_success():
    # 2 failures, success, 2 failures, success: never 3 in a row.
    events = [
        event(0),
        event(1),
        event(2, success=True),
        event(3),
        event(4),
        event(5, success=True),
    ]

    assert detect_success_after_failures(events, min_failures=3) == []
