"""End-to-end check: run the whole pipeline over the sample log."""

from pathlib import Path

from logsentry.detectors import run_all
from logsentry.parser import parse_lines

SAMPLE = Path(__file__).parent.parent / "samples" / "auth.log"


def test_sample_log_produces_the_expected_alerts():
    lines = SAMPLE.read_text(encoding="utf-8").splitlines()
    events = list(parse_lines(lines, year=2026))
    alerts = run_all(events)

    assert len(events) == 29
    assert [(alert.rule, alert.ip) for alert in alerts] == [
        ("success-after-failures", "192.0.2.77"),
        ("brute-force", "203.0.113.45"),
        ("username-spray", "198.51.100.23"),
        ("brute-force", "192.0.2.77"),
    ]
