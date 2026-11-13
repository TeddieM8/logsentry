# logsentry

A small command-line tool that reads a Linux `auth.log` and reports suspicious SSH login activity. Written in Python using only the standard library.

Any server with SSH open to the internet gets password-guessing attempts all day. The log records every one of them, but nobody reads thousands of lines by hand. logsentry reads the file and points out the addresses worth looking at.

## Example

```
$ python -m logsentry samples/auth.log --year 2026
logsentry report for samples/auth.log

Lines read:         43
SSH login attempts: 29 (25 failed, 4 successful)
Source addresses:   5

Most failed logins by address:
  203.0.113.45                               12
  198.51.100.23                               6
  192.0.2.77                                  6
  10.0.0.22                                   1

Alerts: 4
  [HIGH  ] success-after-failures  192.0.2.77       login as 'deploy' succeeded after 6 failed attempts
  [MEDIUM] brute-force             203.0.113.45     12 failed logins between 09:14:02 and 09:14:35
  [MEDIUM] username-spray          198.51.100.23    failed logins for 6 different usernames
  [MEDIUM] brute-force             192.0.2.77       6 failed logins between 11:42:10 and 11:43:08
```

`samples/auth.log` is a made-up log. The addresses in it come from the ranges reserved for documentation (RFC 5737), so they don't belong to anyone.

## Usage

Needs Python 3.10 or newer. There is nothing to install to run the tool.

```
python -m logsentry <logfile> [options]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--threshold N` | 5 | Failed logins from one address that count as brute force |
| `--window MINUTES` | 5 | Time window for the brute-force rule |
| `--min-usernames N` | 5 | Different usernames from one address that count as a spray |
| `--year YYYY` | this year | Year the log was written in (syslog timestamps leave it out) |
| `--json FILE` | off | Also write the alerts to a JSON file |

## The three rules

| Rule | Fires when | Severity | MITRE ATT&CK |
| --- | --- | --- | --- |
| `brute-force` | One address fails to log in `threshold` times inside `window` minutes | Medium | T1110.001 Password Guessing |
| `username-spray` | One address fails to log in as `min-usernames` different users, however slowly | Medium | T1110.003 Password Spraying |
| `success-after-failures` | An address logs in successfully straight after 3 or more failures | High | T1078 Valid Accounts |

The sample log shows why there is more than one rule. `198.51.100.23` waits four minutes between attempts, so it never trips the brute-force rule, but it tries six different usernames and the spray rule catches it. `192.0.2.77` is the serious one: six wrong passwords for `deploy`, then a correct one.

Meanwhile `bob` mistypes his password once and then gets in. That produces no alert, because one failure is below every threshold.

## How it works

```
auth.log -> parser.py -> list of LoginEvent -> detectors.py -> list of Alert -> report.py
```

- `logsentry/parser.py` uses one regular expression to pick out the `Failed ...` and `Accepted ...` lines from sshd and turns each into a `LoginEvent` (time, address, username, success).
- `logsentry/detectors.py` has one function per rule. Each takes the events and returns `Alert` objects. The rules don't know anything about log files, which is what makes them easy to test.
- `logsentry/report.py` formats the text report and the JSON output.
- `logsentry/cli.py` handles the command-line arguments and file reading.

### Design decisions

**The log is untrusted input.** The username in a log line is whatever the person connecting typed, so an attacker controls part of the file this tool reads. Two places deal with that:

- Someone can use a username like `root from 10.0.0.1 port 22 ssh2` so the line appears to contain a different source address. sshd always writes the real address at the end of the line, so the regex anchors to the end and takes the last address. There is a test for this in `tests/test_parser.py`.
- Usernames are escaped before being printed, so one containing terminal control characters can't mess with the output.

**Sliding window for brute force.** The simple approach is to chop time into fixed five-minute blocks and count failures in each. That misses a burst that straddles two blocks. The rule keeps a queue of recent failure times for each address and drops the ones older than the window, so it finds the busiest five minutes wherever they fall.

**No time window on the spray rule.** An attacker who knows about rate-based detection slows down. Counting distinct usernames without a window catches that, at the cost of possibly flagging a shared office address over a long log.

**Standard library only.** Nothing to install and no third-party code to trust. `pytest` is the only dependency, and only for the tests.

## Tests

```
pip install -r requirements-dev.txt
python -m pytest
```

There are 22 tests: the parser, each rule (including the cases where it should stay quiet), and one end-to-end run over the sample log. GitHub Actions runs them on every push (`.github/workflows/tests.yml`).

## Limitations

- Only understands the classic syslog format used by Debian and Ubuntu's `auth.log`. Systems that log to journald, or use ISO timestamps, would need another parser.
- Syslog timestamps have no year, so a log that runs from December into January is handled wrongly.
- rsyslog can collapse repeated lines into `message repeated 3 times: [...]`. Those are skipped, so failures can be undercounted.
- It analyses a file after the fact. It doesn't watch a live log or block anything. On a real server, fail2ban does that job.
- The thresholds are fixed numbers. There is no allow-list for trusted addresses.

## Possible next steps

- An `--allow` option to ignore known-good addresses.
- Read `.gz` rotated logs directly.
- A `--follow` mode that watches the file as it grows.
- Handle the `message repeated N times` lines.
