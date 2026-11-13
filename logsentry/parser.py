"""Parse sshd entries from a Linux auth.log into LoginEvent objects.

Only lines that record the outcome of a login attempt are kept, for example:

    Nov 12 09:14:02 web01 sshd[2101]: Failed password for root from 203.0.113.45 port 41822 ssh2
    Nov 12 08:01:12 web01 sshd[1201]: Accepted publickey for alice from 10.0.0.15 port 50112 ssh2: ED25519 SHA256:...

Everything else in the file (cron, sudo, sessions opening and closing) is ignored.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator


@dataclass(frozen=True)
class LoginEvent:
    """One SSH login attempt."""

    timestamp: datetime
    ip: str
    username: str
    success: bool


# The username is typed by whoever is connecting, so it cannot be trusted.
# Someone can try to log in as the "user"
#
#     root from 10.0.0.1 port 22 ssh2
#
# hoping a careless parser reads 10.0.0.1 as the source address and blames the
# wrong machine. sshd always writes the real address last, so the username
# group below is greedy (.*) and the pattern is anchored to the end of the
# line. That way the final "from <ip> port <n>" is the one that gets captured.
_LOGIN_LINE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"\S+ sshd\[\d+\]: "
    r"(?P<result>Failed|Accepted) \S+ for "
    r"(?:invalid user )?(?P<username>.*) "
    r"from (?P<ip>\S+) port \d+ ssh2(?:: .*)?$"
)


def parse_line(line: str, year: int) -> LoginEvent | None:
    """Return a LoginEvent for a login line, or None for any other line.

    Syslog timestamps do not include the year, so the caller has to supply it.
    """
    match = _LOGIN_LINE.match(line.strip())
    if match is None:
        return None

    try:
        ip = str(ipaddress.ip_address(match["ip"]))
        timestamp = datetime.strptime(
            f"{year} {match['timestamp']}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        # Not a real IP address or not a real date: treat the line as junk.
        return None

    return LoginEvent(
        timestamp=timestamp,
        ip=ip,
        username=match["username"],
        success=match["result"] == "Accepted",
    )


def parse_lines(lines: Iterable[str], year: int) -> Iterator[LoginEvent]:
    """Yield a LoginEvent for every login line, skipping everything else."""
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event
