"""Core data types for Killchain.

Everything in the pipeline speaks these four objects:

    Event   -> one parsed line from an auth.log
    Finding -> one thing a detector noticed (with the events that prove it)
    AttackStory -> all findings for a single attacker, ordered into a kill-chain
    Report  -> the whole analysis of one log file

Kept dependency-free on purpose: stdlib only, no third-party imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum


# --------------------------------------------------------------------------- #
# Severity + kill-chain phases
# --------------------------------------------------------------------------- #
# IntEnum (not Enum) so we can compare/sort/max() them directly: a CRITICAL
# finding is literally `> HIGH`, which keeps the scoring code readable.

class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def color(self) -> str:
        """Hex colour used by the HTML report's severity badges."""
        return {
            Severity.INFO: "#5c6b80",     # quiet slate — info shouldn't shout
            Severity.LOW: "#3f9d6b",      # muted green
            Severity.MEDIUM: "#c8932f",   # amber
            Severity.HIGH: "#d4683a",     # burnt orange
            Severity.CRITICAL: "#e0443e",  # the one true red, reserved for the worst
        }[self]


class Phase(IntEnum):
    """The MITRE-flavoured stages of an intrusion, in the order they happen.

    The numeric order matters: 'how far did the attacker get' is just
    `max(phase for finding in story)`, and a higher phase = a worse day.
    """

    RECON = 0
    BRUTE_FORCE = 1
    INITIAL_ACCESS = 2
    PRIVILEGE_ESCALATION = 3
    PERSISTENCE = 4

    @property
    def label(self) -> str:
        return self.name.replace("_", " ").title()


# --------------------------------------------------------------------------- #
# Event types
# --------------------------------------------------------------------------- #
# Plain string constants rather than an enum: the parser assigns them, the
# detectors read them, and they show up verbatim in the report, so a readable
# string is friendlier than EventType.FAILED_PASSWORD everywhere.

class EventType:
    FAILED_PASSWORD = "failed_password"
    ACCEPTED_PASSWORD = "accepted_password"
    ACCEPTED_PUBLICKEY = "accepted_publickey"
    INVALID_USER = "invalid_user"
    CONNECTION_CLOSED_PREAUTH = "connection_closed_preauth"
    NO_IDENT_STRING = "no_ident_string"
    SUDO_COMMAND = "sudo_command"
    USERADD = "useradd"
    USERMOD = "usermod"
    PASSWD_CHANGE = "passwd_change"
    SESSION_OPENED = "session_opened"
    OTHER = "other"

    #: event types that count as a failed authentication attempt. INVALID_USER
    #: is intentionally excluded: for one bad attempt sshd logs an "Invalid
    #: user" line *and* a "Failed password" line, so counting both would
    #: double-count. The failed-password line alone represents the attempt.
    FAILURES = frozenset({FAILED_PASSWORD})
    #: event types that represent a successful login
    SUCCESSES = frozenset({ACCEPTED_PASSWORD, ACCEPTED_PUBLICKEY})


@dataclass
class Event:
    """One line of an auth.log, parsed into fields.

    `raw` and `line_no` are always kept so every Finding can point back at the
    exact source line — that traceability is what makes the report credible.
    """

    timestamp: datetime
    host: str
    process: str
    pid: int | None
    event_type: str
    raw: str
    line_no: int
    user: str | None = None
    source_ip: str | None = None
    port: int | None = None

    @property
    def is_failure(self) -> bool:
        return self.event_type in EventType.FAILURES

    @property
    def is_success(self) -> bool:
        return self.event_type in EventType.SUCCESSES

    @property
    def time_str(self) -> str:
        return self.timestamp.strftime("%H:%M:%S")


@dataclass
class Finding:
    """Something a detector noticed, plus the evidence that proves it.

    A Finding is self-contained: it names the MITRE technique, the phase it
    belongs to, who/where, the time window, the supporting events, and a
    plain-English sentence a human can read aloud. The narrative report is just
    these explanations stitched together.
    """

    id: str
    technique_id: str          # e.g. "T1110"
    technique_name: str        # e.g. "Brute Force"
    phase: Phase
    severity: Severity
    source_ip: str | None
    explanation: str
    evidence: list[Event] = field(default_factory=list)
    user: str | None = None

    @property
    def start(self) -> datetime | None:
        return min((e.timestamp for e in self.evidence), default=None)

    @property
    def end(self) -> datetime | None:
        return max((e.timestamp for e in self.evidence), default=None)


@dataclass
class AttackStory:
    """Every finding attributed to one attacker, ordered into a kill-chain."""

    source_ip: str
    findings: list[Finding] = field(default_factory=list)
    threat_score: int = 0
    summary: str = ""

    @property
    def phases_reached(self) -> list[Phase]:
        return sorted({f.phase for f in self.findings})

    @property
    def max_phase(self) -> Phase:
        return max((f.phase for f in self.findings), default=Phase.RECON)

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def first_seen(self) -> datetime | None:
        times = [f.start for f in self.findings if f.start]
        return min(times) if times else None

    @property
    def last_seen(self) -> datetime | None:
        times = [f.end for f in self.findings if f.end]
        return max(times) if times else None


@dataclass
class Report:
    """The complete analysis of one log file."""

    source_filename: str
    generated_at: datetime
    stories: list[AttackStory] = field(default_factory=list)
    total_events: int = 0
    unparsed_lines: int = 0
    hosts: list[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(len(s.findings) for s in self.stories)

    @property
    def worst_severity(self) -> Severity:
        return max((s.max_severity for s in self.stories), default=Severity.INFO)
