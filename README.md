# Killchain

**Drop in an SSH `auth.log` and watch the attack reconstruct itself.**

Killchain is a forensic log analyzer that reads a raw Linux `auth.log`, correlates
the events back to each attacker, and rebuilds the **kill-chain** — recon →
brute-force → breach → privilege escalation → persistence — as a narrated,
severity-scored incident report. It maps every finding to a
[MITRE ATT&CK](https://attack.mitre.org/) technique.

It is **pure Python, standard library only** — no `pip install`, no Node, no
framework. If you have Python 3, you can run it.

> Screenshot: open `sample_report.html` in any browser, or run the app below.

---

## Quickstart

```bash
# launch the local web app (opens your browser)
py -3 -m killchain

# or analyze a log file straight to an HTML report
py -3 -m killchain analyze /var/log/auth.log -o report.html

# or write a synthetic sample log to disk
py -3 -m killchain gen -o sample.log
```

On the web page you can **drag in any `auth.log`**, or click **Generate a random
attack** — each click rolls a different intrusion and the engine reacts to it live.

---

## What it does

1. **Parse** every `auth.log` line into a structured event (timestamp, host,
   process, user, source IP, event type). Unknown lines are counted, never fatal.
2. **Detect** six behaviours, each an isolated, tunable rule:

   | Technique | Detector | Kill-chain phase |
   |---|---|---|
   | T1595 Active Scanning | connections that never authenticate | Recon |
   | T1110 Brute Force | N failed logins inside a sliding time window | Brute Force |
   | T1110.001 Username Enumeration | one IP probing many invalid users | Brute Force |
   | T1078 Valid Accounts | a success **after** a brute-force burst | Initial Access |
   | T1548 Abuse Elevation Control | `sudo` to root right after the breach | Privilege Escalation |
   | T1136 Create Account | a rogue account added after the breach | Persistence |

3. **Correlate** the findings per attacker IP, order them along the kill-chain,
   compute a 0–100 threat score, and write a one-paragraph narrative.
4. **Report** it as a single self-contained HTML page (no external assets).

---

## How Python is used

Everything is standard library:

- **`re`** — a table of compiled regexes turns syslog lines into structured events.
- **`dataclasses` + `enum.IntEnum`** — the `Event` / `Finding` / `AttackStory`
  model. `IntEnum` lets "how far did the attacker get?" be a plain `max()`.
- **`datetime` + `collections.deque`** — timestamp handling and the sliding-window
  brute-force detector.
- **`http.server`** — the zero-dependency web app.
- **`unittest`** — 17 tests, including a generator→pipeline "golden round-trip".

## Project layout

```
killchain/
  models.py       data types (Event, Finding, AttackStory, Report)
  parser.py       auth.log text  -> events
  detectors.py    events         -> findings (the 6 rules above)
  correlator.py   findings       -> per-attacker kill-chain + score + narrative
  report.py       report         -> self-contained HTML
  server.py       stdlib web app (drag-drop, random demo, per-archetype buttons)
  generator.py    one fixed canonical attack (demo + golden test)
  scenarios.py    six randomised attack archetypes for the live demo
  cli.py          py -m killchain  (serve / analyze / gen)
  tests/          unittest suite
```

## Testing

```bash
py -3 -m unittest killchain.tests.test_killchain
```

17 tests: parser, each detector, the correlator, a **golden round-trip** (the
generator emits a known attack and the pipeline must recover the exact
kill-chain), and **per-archetype invariants** (every scenario type detects
correctly across many seeds; benign traffic raises nothing).

## A note on the data

All sample logs are **synthetic** and use
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation IP ranges
(`203.0.113.x`, `198.51.100.x`, `192.0.2.x`) — reserved addresses that can never
be a real host. The `scenarios.py` generator exists so the demo is reproducible
and so the detectors can be tested against ground truth. Killchain parses the
real OpenSSH/sudo log format, so a genuine `auth.log` works the same way.

---

## Challenges & what I learned

- **Privilege-escalation and persistence have no source IP.** `sudo` and
  `useradd` lines are local actions — there's no attacker address on them. The
  fix that makes the whole project work: link those events back to the breach by
  matching **user + host + time window**. That join is what turns a pile of log
  lines into *one attacker's story*.
- **An invalid login is logged twice.** sshd writes both `Invalid user x` *and*
  `Failed password for invalid user x`. Counting both doubled every brute-force
  total, so only the `Failed password` line counts as an attempt; the
  `Invalid user` line feeds enumeration instead.
- **Syslog has no year.** `Mar 10 02:08:14` — no year, and logs roll over Dec→Jan.
  I infer the year and bump it when the month goes backwards.
- **Sliding-window detection.** "5 failures in 2 minutes" is a `deque` that drops
  timestamps as they age out of the window — not just a total count.
- **No `cgi` module in Python 3.13+.** It was removed, so the web upload sends the
  file's raw text as the POST body (read in the browser with `FileReader`) instead
  of multipart form data — keeping the whole thing dependency-free.
- **Making a *random* demo safe.** A randomised demo could roll an attack the
  detectors miss → "ATTACK DETECTED, 0 findings" in front of a judge. The fix:
  randomise the *surface* (IPs, users, timestamps, counts) but fix the
  *structure*, and add a test that every archetype detects correctly across 60
  seeds. Determinism where it matters, variety where it helps.
