from datetime import datetime

from logsentry.parser import parse_line, parse_lines

YEAR = 2026


def test_failed_password_line():
    line = "Nov 12 09:14:02 web01 sshd[2101]: Failed password for root from 203.0.113.45 port 41822 ssh2"
    event = parse_line(line, YEAR)

    assert event.timestamp == datetime(2026, 11, 12, 9, 14, 2)
    assert event.ip == "203.0.113.45"
    assert event.username == "root"
    assert event.success is False


def test_accepted_publickey_line_with_fingerprint_on_the_end():
    line = "Nov 12 08:01:12 web01 sshd[1201]: Accepted publickey for alice from 10.0.0.15 port 50112 ssh2: ED25519 SHA256:abc123"
    event = parse_line(line, YEAR)

    assert event.username == "alice"
    assert event.ip == "10.0.0.15"
    assert event.success is True


def test_invalid_user_prefix_is_not_part_of_the_username():
    line = "Nov 12 10:00:07 web01 sshd[2390]: Failed password for invalid user admin from 198.51.100.23 port 40022 ssh2"
    event = parse_line(line, YEAR)

    assert event.username == "admin"


def test_single_digit_day_is_padded_with_a_space():
    line = "Nov  3 09:14:02 web01 sshd[2101]: Failed password for root from 203.0.113.45 port 41822 ssh2"
    event = parse_line(line, YEAR)

    assert event.timestamp == datetime(2026, 11, 3, 9, 14, 2)


def test_ipv6_address():
    line = "Nov 12 09:14:02 web01 sshd[2101]: Failed password for root from 2001:db8::1 port 41822 ssh2"
    event = parse_line(line, YEAR)

    assert event.ip == "2001:db8::1"


def test_lines_that_are_not_login_attempts_are_ignored():
    lines = [
        "Nov 12 08:15:01 web01 CRON[1250]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        "Nov 12 10:00:05 web01 sshd[2390]: Invalid user admin from 198.51.100.23 port 40022",
        "Nov 12 08:01:12 web01 sshd[1201]: pam_unix(sshd:session): session opened for user alice(uid=1001) by (uid=0)",
        "",
        "complete rubbish",
    ]

    assert list(parse_lines(lines, YEAR)) == []


def test_address_hidden_in_the_username_does_not_fool_the_parser():
    # The attacker at 203.0.113.9 used a username written to look like the
    # rest of a log line, trying to pin the attempt on 10.0.0.1.
    line = (
        "Nov 12 09:14:02 web01 sshd[2101]: Failed password for invalid user "
        "root from 10.0.0.1 port 22 ssh2 from 203.0.113.9 port 4000 ssh2"
    )
    event = parse_line(line, YEAR)

    assert event.ip == "203.0.113.9"
    assert event.username == "root from 10.0.0.1 port 22 ssh2"


def test_line_with_something_that_is_not_an_ip_address_is_rejected():
    line = "Nov 12 09:14:02 web01 sshd[2101]: Failed password for root from not.an.ip port 41822 ssh2"

    assert parse_line(line, YEAR) is None


def test_line_with_an_impossible_date_is_rejected():
    line = "Nov 31 09:14:02 web01 sshd[2101]: Failed password for root from 203.0.113.45 port 41822 ssh2"

    assert parse_line(line, YEAR) is None
