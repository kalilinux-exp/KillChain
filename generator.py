"""Synthesize a realistic SSH auth.log with a known attack buried inside it.

Why ship a generator at all? Two reasons:
  * Reproducible demos — the same seed always produces the same attack, so the
    recorded video and the live run match.
  * It doubles as a test oracle: we know exactly what the log contains, so the
    pipeline's output can be checked against ground truth (see tests).

All addresses use RFC 5737 / RFC 3849 documentation ranges (203.0.113.0/24,
192.0.2.0/24, 198.51.100.0/24) — they are reserved for examples and can never
be a real host, which keeps the synthetic data honest.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

_HOST = "web01"
_ATTACKER_IP = "203.0.113.66"                 # the intruder (TEST-NET-3)
_BENIGN_IPS = ["192.0.2.10", "192.0.2.25", "198.51.100.7"]
_VALID_USERS = ["kalixte", "deploy"]
_BREACHED_USER = "admin"
_WORDLIST = ["root", "test", "oracle", "postgres", "ubuntu",
             "git", "ftpuser", "mysql", "jenkins", "pi"]


def _prefix(ts: datetime) -> str:
    # syslog uses a space-padded day: "Mar  9" / "Mar 10"
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')} {_HOST}"


def _line(ts: datetime, proc: str, pid: int, msg: str) -> str:
    return f"{_prefix(ts)} {proc}[{pid}]: {msg}"


def generate_auth_log(seed: int = 1337) -> str:
    """Return a full auth.log as text: benign noise + one complete intrusion."""
    rng = random.Random(seed)
    base = datetime(2025, 3, 10, 0, 0, 0)
    entries: list[tuple[datetime, str]] = []

    def add(ts: datetime, proc: str, pid: int, msg: str) -> None:
        entries.append((ts, _line(ts, proc, pid, msg)))

    # --- background: normal logins through the early morning ----------------
    for _ in range(8):
        ts = base + timedelta(minutes=rng.randint(0, 110), seconds=rng.randint(0, 59))
        user = rng.choice(_VALID_USERS)
        ip = rng.choice(_BENIGN_IPS)
        pid = rng.randint(1000, 3000)
        add(ts, "sshd", pid, f"Accepted password for {user} from {ip} port {rng.randint(40000, 60000)} ssh2")
        add(ts + timedelta(seconds=1), "sshd", pid,
            f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
    for _ in range(3):  # a few harmless fat-finger failures
        ts = base + timedelta(minutes=rng.randint(0, 110), seconds=rng.randint(0, 59))
        add(ts, "sshd", rng.randint(1000, 3000),
            f"Failed password for {rng.choice(_VALID_USERS)} from {rng.choice(_BENIGN_IPS)} port {rng.randint(40000, 60000)} ssh2")

    # --- the attack, from a single IP, at ~02:00 ----------------------------
    atk = base + timedelta(hours=2)

    # 1) Recon — connections that never complete authentication
    for i in range(4):
        ts = atk + timedelta(seconds=i * 12)
        pid = rng.randint(3000, 4000)
        if i % 2 == 0:
            add(ts, "sshd", pid, f"Did not receive identification string from {_ATTACKER_IP}")
        else:
            add(ts, "sshd", pid, f"Connection closed by {_ATTACKER_IP} port {rng.randint(40000, 60000)} [preauth]")

    # 2) Brute force — ~70 failures over ~6 min against many usernames
    bf_start = atk + timedelta(minutes=2)
    targets = _WORDLIST + [_BREACHED_USER]
    n_attempts = 70
    for i in range(n_attempts):
        ts = bf_start + timedelta(seconds=int(i * (360 / n_attempts)) + rng.randint(0, 2))
        user = rng.choice(targets)
        port = rng.randint(40000, 60000)
        pid = rng.randint(4000, 6000)
        if user in _WORDLIST:  # nonexistent account: sshd logs both lines
            add(ts, "sshd", pid, f"Invalid user {user} from {_ATTACKER_IP} port {port}")
            add(ts, "sshd", pid, f"Failed password for invalid user {user} from {_ATTACKER_IP} port {port} ssh2")
        else:
            add(ts, "sshd", pid, f"Failed password for {user} from {_ATTACKER_IP} port {port} ssh2")

    # 3) Initial access — the brute force finally works
    breach = atk + timedelta(minutes=8, seconds=14)
    sess_pid = rng.randint(4000, 6000)
    add(breach, "sshd", sess_pid,
        f"Accepted password for {_BREACHED_USER} from {_ATTACKER_IP} port {rng.randint(40000, 60000)} ssh2")
    add(breach + timedelta(seconds=1), "sshd", sess_pid,
        f"pam_unix(sshd:session): session opened for user {_BREACHED_USER} by (uid=0)")

    # 4) Privilege escalation — sudo to root
    add(breach + timedelta(seconds=40), "sudo", rng.randint(6000, 7000),
        f"  {_BREACHED_USER} : TTY=pts/1 ; PWD=/home/{_BREACHED_USER} ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
    add(breach + timedelta(seconds=63), "sudo", rng.randint(6000, 7000),
        f"  {_BREACHED_USER} : TTY=pts/1 ; PWD=/home/{_BREACHED_USER} ; USER=root ; COMMAND=/usr/sbin/useradd backup1")

    # 5) Persistence — a rogue UID-0 account with a password
    add(breach + timedelta(seconds=66), "useradd", rng.randint(6000, 7000),
        "new user: name=backup1, UID=0, GID=0, home=/home/backup1, shell=/bin/bash")
    add(breach + timedelta(seconds=70), "passwd", rng.randint(6000, 7000),
        "password changed for backup1")

    entries.sort(key=lambda pair: pair[0])
    return "\n".join(line for _, line in entries) + "\n"


# Ground truth about the default (seed=1337) scenario, for tests + the demo.
SCENARIO_TRUTH = {
    "attacker_ip": _ATTACKER_IP,
    "host": _HOST,
    "breached_user": _BREACHED_USER,
    "rogue_account": "backup1",
}


if __name__ == "__main__":  # `py -m killchain.generator > sample.log`
    import sys
    sys.stdout.write(generate_auth_log())
