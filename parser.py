r"""Turn raw auth.log text into structured `Event` objects.

A syslog line looks like:

    Mar 10 02:08:14 web01 sshd[2025]: Failed password for admin from 198.51.100.7 port 51234 ssh2
    \_______________/ \___/ \__/\__/  \_________________ message ____________________________/
        timestamp      host  proc pid

We split the prefix once, then run the trailing message past a table of
compiled regexes to decide the `event_type` and pull out user / ip / port.

Two deliberate simplifications, documented because judges will ask:
  * IPv4 only. IPv6 source addresses fall through to `event_type="other"`.
  * No year in syslog timestamps, so we infer one (see `_YearClock`).
Unknown lines never raise — they become `OTHER` and are counted, so a weird
log degrades gracefully instead of crashing the demo.
"""

from __future__ import annotations

import re
from datetime import datetime

from .models import Event, EventType

# --------------------------------------------------------------------------- #
# Line structure
# --------------------------------------------------------------------------- #

_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"

# Message matchers, tried in order; first hit wins. Each may expose named
# groups `user`, `ip`, `port` (all optional). Order matters where messages
# overlap — e.g. "Failed password for invalid user x" must match FAILED_PASSWORD
# (a failed auth) rather than the standalone INVALID_USER enumeration line.
_MESSAGE_MATCHERS: list[tuple[str, re.Pattern[str]]] = [
    (EventType.ACCEPTED_PASSWORD, re.compile(
        rf"Accepted password for (?P<user>\S+) from (?P<ip>{_IPV4}) port (?P<port>\d+)")),
    (EventType.ACCEPTED_PUBLICKEY, re.compile(
        rf"Accepted publickey for (?P<user>\S+) from (?P<ip>{_IPV4}) port (?P<port>\d+)")),
    (EventType.FAILED_PASSWORD, re.compile(
        rf"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>{_IPV4}) port (?P<port>\d+)")),
    (EventType.INVALID_USER, re.compile(
        rf"Invalid user (?P<user>\S+) from (?P<ip>{_IPV4})(?: port (?P<port>\d+))?")),
    (EventType.NO_IDENT_STRING, re.compile(
        rf"Did not receive identification string from (?P<ip>{_IPV4})")),
    (EventType.CONNECTION_CLOSED_PREAUTH, re.compile(
        rf"Connection closed by (?:authenticating user (?P<user>\S+) )?(?P<ip>{_IPV4}) port (?P<port>\d+) \[preauth\]")),
    (EventType.SESSION_OPENED, re.compile(
        r"session opened for user (?P<user>\S+)")),
    # sudo: "kalixte : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    (EventType.SUDO_COMMAND, re.compile(
        r"(?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; USER=\S+ ; COMMAND=")),
    # useradd[...]: "new user: name=backup1, UID=0, ..."
    (EventType.USERADD, re.compile(
        r"new user: name=(?P<user>[^,]+)")),
    (EventType.USERMOD, re.compile(
        r"(?:add '(?P<user>\S+)' to group|change user '(?P<user2>\S+)')")),
    (EventType.PASSWD_CHANGE, re.compile(
        r"password changed for (?P<user>\S+)")),
]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


class _YearClock:
    """Assigns a year to year-less syslog timestamps.

    Starts at `base_year` and bumps forward by one whenever the month number
    goes *backwards* (a Dec -> Jan rollover inside a single log file). Good
    enough for the single-file forensic case and easy to explain on camera.
    """

    def __init__(self, base_year: int) -> None:
        self.year = base_year
        self._prev_month: int | None = None

    def year_for(self, month: int) -> int:
        if self._prev_month is not None and month < self._prev_month:
            self.year += 1
        self._prev_month = month
        return self.year


def _to_int(value: str | None) -> int | None:
    return int(value) if value is not None else None


def parse_line(line: str, line_no: int, clock: _YearClock) -> Event | None:
    """Parse one raw line into an Event, or None if it isn't a syslog line."""
    m = _SYSLOG_PREFIX.match(line)
    if not m:
        return None

    month = _MONTHS.get(m["month"])
    if month is None:
        return None
    year = clock.year_for(month)
    try:
        timestamp = datetime.strptime(
            f"{year} {month} {m['day']} {m['time']}", "%Y %m %d %H:%M:%S")
    except ValueError:
        return None

    message = m["msg"]
    event_type = EventType.OTHER
    user = ip = None
    port = None

    for etype, pattern in _MESSAGE_MATCHERS:
        hit = pattern.search(message)
        if not hit:
            continue
        event_type = etype
        groups = hit.groupdict()
        user = groups.get("user") or groups.get("user2")
        ip = groups.get("ip")
        port = _to_int(groups.get("port"))
        break

    return Event(
        timestamp=timestamp,
        host=m["host"],
        process=m["proc"],
        pid=_to_int(m["pid"]),
        event_type=event_type,
        raw=line.rstrip("\n"),
        line_no=line_no,
        user=user,
        source_ip=ip,
        port=port,
    )


def parse_log_text(text: str, base_year: int | None = None) -> tuple[list[Event], int]:
    """Parse a whole auth.log.

    Returns ``(events, unparsed_count)`` where `unparsed_count` is the number
    of non-empty lines that did not look like syslog at all.
    """
    if base_year is None:
        base_year = datetime.now().year
    clock = _YearClock(base_year)

    events: list[Event] = []
    unparsed = 0
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        event = parse_line(line, line_no, clock)
        if event is None:
            unparsed += 1
        else:
            events.append(event)
    return events, unparsed


def parse_log_file(path: str, base_year: int | None = None) -> tuple[list[Event], int]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_log_text(fh.read(), base_year=base_year)
