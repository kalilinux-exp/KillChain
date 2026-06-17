"""Detection rules: a stream of `Event`s in, a list of `Finding`s out.

Each detector is a small, independently testable function with one job. They
share two ideas:

  * Most rules group events by ``source_ip`` — the attacker's address is the
    thread we pull on.
  * The "post-breach" rules (privilege escalation, persistence) can't group by
    IP, because sudo/useradd lines have no source IP. Instead they re-use
    `_find_breaches` and link a local action back to a breach by *user + host +
    time window*. That join is what reconstructs a single attacker's chain.

Thresholds live in `Config` so they're tunable and explainable on camera.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import Event, EventType, Finding, Phase, Severity


@dataclass
class Config:
    """Detection thresholds. Defaults are tuned for the demo logs but every
    one of these is a knob a defender would tune for their own environment."""

    bruteforce_min_failures: int = 5      # failures within the window => brute force
    bruteforce_window_seconds: int = 120
    enumeration_min_invalid_users: int = 5  # distinct nonexistent users => enumeration
    privesc_window_seconds: int = 600      # sudo within 10 min of breach => escalation
    persistence_window_seconds: int = 1800  # account change within 30 min => persistence
    recon_min_events: int = 3              # scan-like connects with no auth


# --------------------------------------------------------------------------- #
# Small shared helpers
# --------------------------------------------------------------------------- #

def _by_ip(events: list[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source_ip:
            grouped[e.source_ip].append(e)
    return grouped


def _has_burst(timestamps: list[datetime], n: int, window_s: int) -> bool:
    """True if at least `n` of these timestamps fall within `window_s` seconds.

    Classic sliding window: walk the sorted times, keep a deque of the ones
    still inside the window, and check whether the window ever holds `n`.
    """
    window = deque()
    for t in sorted(timestamps):
        window.append(t)
        while (t - window[0]).total_seconds() > window_s:
            window.popleft()
        if len(window) >= n:
            return True
    return False


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


@dataclass
class _Breach:
    source_ip: str
    user: str | None
    host: str
    time: datetime
    failures_before: int
    success: Event


def _find_breaches(events: list[Event], config: Config) -> list[_Breach]:
    """A breach = a successful login from an IP that already racked up enough
    failures. We keep the first success per IP; that's the moment of entry."""
    breaches: list[_Breach] = []
    for ip, evs in _by_ip(events).items():
        evs_sorted = sorted(evs, key=lambda e: e.timestamp)
        failures = [e for e in evs_sorted if e.is_failure]
        for e in evs_sorted:
            if e.is_success:
                before = sum(1 for f in failures if f.timestamp <= e.timestamp)
                if before >= config.bruteforce_min_failures:
                    breaches.append(_Breach(ip, e.user, e.host, e.timestamp, before, e))
                break  # only consider the first login outcome per IP
    return breaches


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #

def detect_bruteforce(events: list[Event], config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for ip, evs in _by_ip(events).items():
        failures = sorted((e for e in evs if e.is_failure), key=lambda e: e.timestamp)
        if len(failures) < config.bruteforce_min_failures:
            continue
        if not _has_burst([f.timestamp for f in failures],
                          config.bruteforce_min_failures,
                          config.bruteforce_window_seconds):
            continue
        users = sorted({f.user for f in failures if f.user})
        span = (failures[-1].timestamp - failures[0].timestamp).total_seconds()
        findings.append(Finding(
            id=f"T1110-{ip}",
            technique_id="T1110",
            technique_name="Brute Force",
            phase=Phase.BRUTE_FORCE,
            severity=Severity.HIGH,
            source_ip=ip,
            explanation=(
                f"{ip} made {len(failures)} failed SSH logins over "
                f"{_fmt_duration(span)} against {len(users)} username(s) "
                f"({', '.join(users[:6])}{'…' if len(users) > 6 else ''})."),
            evidence=failures,
        ))
    return findings


def detect_enumeration(events: list[Event], config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for ip, evs in _by_ip(events).items():
        invalid = [e for e in evs if e.event_type == EventType.INVALID_USER]
        distinct = sorted({e.user for e in invalid if e.user})
        if len(distinct) < config.enumeration_min_invalid_users:
            continue
        findings.append(Finding(
            id=f"T1110.001-{ip}",
            technique_id="T1110.001",
            technique_name="Username Enumeration",
            phase=Phase.BRUTE_FORCE,
            severity=Severity.MEDIUM,
            source_ip=ip,
            explanation=(
                f"{ip} probed {len(distinct)} nonexistent usernames "
                f"({', '.join(distinct[:6])}{'…' if len(distinct) > 6 else ''}), "
                f"a sign of automated account enumeration."),
            evidence=invalid,
        ))
    return findings


def detect_breach(events: list[Event], config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for b in _find_breaches(events, config):
        findings.append(Finding(
            id=f"T1078-{b.source_ip}",
            technique_id="T1078",
            technique_name="Valid Accounts",
            phase=Phase.INITIAL_ACCESS,
            severity=Severity.CRITICAL,
            source_ip=b.source_ip,
            user=b.user,
            explanation=(
                f"{b.source_ip} successfully logged in as '{b.user}' at "
                f"{b.time.strftime('%H:%M:%S')} after {b.failures_before} failed "
                f"attempts — the brute force broke through."),
            evidence=[b.success],
        ))
    return findings


def detect_privilege_escalation(events: list[Event], config: Config) -> list[Finding]:
    findings: list[Finding] = []
    sudo = [e for e in events if e.event_type == EventType.SUDO_COMMAND]
    window = timedelta(seconds=config.privesc_window_seconds)
    for b in _find_breaches(events, config):
        related = [s for s in sudo
                   if s.user == b.user and s.host == b.host
                   and b.time <= s.timestamp <= b.time + window]
        if not related:
            continue
        findings.append(Finding(
            id=f"T1548-{b.source_ip}",
            technique_id="T1548",
            technique_name="Abuse Elevation Control (sudo)",
            phase=Phase.PRIVILEGE_ESCALATION,
            severity=Severity.CRITICAL,
            source_ip=b.source_ip,
            user=b.user,
            explanation=(
                f"After breaching '{b.user}', {b.source_ip}'s session ran "
                f"{len(related)} sudo command(s) to escalate toward root."),
            evidence=related,
        ))
    return findings


def detect_persistence(events: list[Event], config: Config) -> list[Finding]:
    findings: list[Finding] = []
    account_changes = [e for e in events if e.event_type in (
        EventType.USERADD, EventType.USERMOD, EventType.PASSWD_CHANGE)]
    window = timedelta(seconds=config.persistence_window_seconds)
    for b in _find_breaches(events, config):
        related = [a for a in account_changes
                   if a.host == b.host and b.time <= a.timestamp <= b.time + window]
        if not related:
            continue
        new_users = sorted({a.user for a in related if a.user})
        findings.append(Finding(
            id=f"T1136-{b.source_ip}",
            technique_id="T1136",
            technique_name="Create / Modify Account",
            phase=Phase.PERSISTENCE,
            severity=Severity.CRITICAL,
            source_ip=b.source_ip,
            explanation=(
                f"Following the breach from {b.source_ip}, {len(related)} account "
                f"change(s) were made ({', '.join(new_users) or 'account modified'}) "
                f"— a foothold for persistent access."),
            evidence=related,
        ))
    return findings


def detect_recon(events: list[Event], config: Config) -> list[Finding]:
    findings: list[Finding] = []
    scan_types = {EventType.NO_IDENT_STRING, EventType.CONNECTION_CLOSED_PREAUTH}
    for ip, evs in _by_ip(events).items():
        # Recon fires for any IP that opened enough no-auth connections — even
        # if it later brute-forced, so the attacker's chain keeps its Recon
        # stage. Benign IPs produce no scan events, so they stay quiet.
        scans = [e for e in evs if e.event_type in scan_types]
        if len(scans) < config.recon_min_events:
            continue
        findings.append(Finding(
            id=f"T1595-{ip}",
            technique_id="T1595",
            technique_name="Active Scanning",
            phase=Phase.RECON,
            severity=Severity.LOW,
            source_ip=ip,
            explanation=(
                f"{ip} opened {len(scans)} connections without completing "
                f"authentication — port/service probing."),
            evidence=scans,
        ))
    return findings


ALL_DETECTORS = (
    detect_recon,
    detect_bruteforce,
    detect_enumeration,
    detect_breach,
    detect_privilege_escalation,
    detect_persistence,
)


def run_all_detectors(events: list[Event], config: Config | None = None) -> list[Finding]:
    """Run every detector and return the combined findings."""
    config = config or Config()
    findings: list[Finding] = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(events, config))
    return findings
