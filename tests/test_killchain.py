"""Tests for the Killchain pipeline (stdlib unittest, no third-party deps).

The most important test is `TestGoldenRoundTrip`: the generator emits a log with
a *known* attack, and we assert the pipeline recovers that exact kill-chain.
That single test guards the whole demo — if any stage regresses, it goes red.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from killchain import analyze_text
from killchain.correlator import correlate, score_story
from killchain.detectors import (
    Config, detect_breach, detect_bruteforce, detect_persistence,
    detect_privilege_escalation, run_all_detectors,
)
from killchain.generator import SCENARIO_TRUTH, generate_auth_log
from killchain.scenarios import generate_scenario
from killchain.models import AttackStory, Event, EventType, Phase, Severity
from killchain.parser import parse_log_text

T0 = datetime(2025, 3, 10, 2, 0, 0)


def ev(offset_s, event_type, ip=None, user=None, host="web01", proc="sshd"):
    """Build a synthetic Event `offset_s` seconds after T0."""
    return Event(
        timestamp=T0 + timedelta(seconds=offset_s), host=host, process=proc,
        pid=1, event_type=event_type, raw="", line_no=0, user=user, source_ip=ip)


class TestParser(unittest.TestCase):
    def test_failed_password(self):
        line = "Mar 10 02:08:14 web01 sshd[2025]: Failed password for admin from 198.51.100.7 port 51234 ssh2"
        events, unparsed = parse_log_text(line, base_year=2025)
        self.assertEqual(unparsed, 0)
        e = events[0]
        self.assertEqual(e.event_type, EventType.FAILED_PASSWORD)
        self.assertEqual(e.user, "admin")
        self.assertEqual(e.source_ip, "198.51.100.7")
        self.assertEqual(e.port, 51234)
        self.assertTrue(e.is_failure)

    def test_invalid_user_is_not_double_counted(self):
        # An invalid attempt logs BOTH lines; only the Failed password is a failure.
        text = ("Mar 10 02:00:01 web01 sshd[1]: Invalid user oracle from 203.0.113.66 port 5\n"
                "Mar 10 02:00:01 web01 sshd[1]: Failed password for invalid user oracle from 203.0.113.66 port 5 ssh2\n")
        events, _ = parse_log_text(text, base_year=2025)
        types = [e.event_type for e in events]
        self.assertIn(EventType.INVALID_USER, types)
        self.assertIn(EventType.FAILED_PASSWORD, types)
        self.assertEqual(sum(1 for e in events if e.is_failure), 1)

    def test_accepted_and_sudo(self):
        text = ("Mar 10 02:09:00 web01 sshd[3]: Accepted password for admin from 203.0.113.66 port 9 ssh2\n"
                "Mar 10 02:09:40 web01 sudo[4]:   admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/id\n")
        events, _ = parse_log_text(text, base_year=2025)
        self.assertTrue(events[0].is_success)
        self.assertEqual(events[1].event_type, EventType.SUDO_COMMAND)
        self.assertEqual(events[1].user, "admin")

    def test_unparsed_line_counted_not_crashed(self):
        events, unparsed = parse_log_text("this is not a syslog line at all", base_year=2025)
        self.assertEqual(events, [])
        self.assertEqual(unparsed, 1)

    def test_year_rollover(self):
        text = ("Dec 31 23:59:59 web01 sshd[1]: Accepted password for a from 192.0.2.1 port 1 ssh2\n"
                "Jan 01 00:00:05 web01 sshd[1]: Accepted password for a from 192.0.2.1 port 1 ssh2\n")
        events, _ = parse_log_text(text, base_year=2024)
        self.assertEqual(events[0].timestamp.year, 2024)
        self.assertEqual(events[1].timestamp.year, 2025)


class TestDetectors(unittest.TestCase):
    def setUp(self):
        self.cfg = Config()

    def test_bruteforce_threshold(self):
        ip = "203.0.113.66"
        events = [ev(i, EventType.FAILED_PASSWORD, ip=ip, user=f"u{i}") for i in range(6)]
        self.assertEqual(len(detect_bruteforce(events, self.cfg)), 1)
        # Four attempts is below the default threshold of five.
        self.assertEqual(len(detect_bruteforce(events[:4], self.cfg)), 0)

    def test_breach_requires_prior_failures(self):
        ip = "203.0.113.66"
        failures = [ev(i, EventType.FAILED_PASSWORD, ip=ip, user="admin") for i in range(6)]
        success = [ev(10, EventType.ACCEPTED_PASSWORD, ip=ip, user="admin")]
        breach = detect_breach(failures + success, self.cfg)
        self.assertEqual(len(breach), 1)
        self.assertEqual(breach[0].severity, Severity.CRITICAL)
        self.assertEqual(breach[0].phase, Phase.INITIAL_ACCESS)
        # A clean success with no failures is not a breach.
        self.assertEqual(detect_breach(success, self.cfg), [])

    def test_privesc_and_persistence_link_back_to_breach(self):
        ip = "203.0.113.66"
        events = [ev(i, EventType.FAILED_PASSWORD, ip=ip, user="admin") for i in range(6)]
        events.append(ev(10, EventType.ACCEPTED_PASSWORD, ip=ip, user="admin"))
        events.append(ev(40, EventType.SUDO_COMMAND, user="admin", proc="sudo"))  # no ip
        events.append(ev(70, EventType.USERADD, user="backup1", proc="useradd"))  # no ip
        priv = detect_privilege_escalation(events, self.cfg)
        pers = detect_persistence(events, self.cfg)
        self.assertEqual(len(priv), 1)
        self.assertEqual(priv[0].source_ip, ip)        # attributed to the attacker
        self.assertEqual(len(pers), 1)
        self.assertEqual(pers[0].source_ip, ip)


class TestCorrelator(unittest.TestCase):
    def test_full_chain_scores_max_and_orders_phases(self):
        ip = "203.0.113.66"
        events = [ev(i, EventType.NO_IDENT_STRING, ip=ip) for i in range(3)]
        events += [ev(120 + i, EventType.FAILED_PASSWORD, ip=ip, user=f"u{i}") for i in range(6)]
        events.append(ev(200, EventType.ACCEPTED_PASSWORD, ip=ip, user="admin"))
        events.append(ev(230, EventType.SUDO_COMMAND, user="admin", proc="sudo"))
        events.append(ev(260, EventType.USERADD, user="backup1", proc="useradd"))
        stories = correlate(run_all_detectors(events))
        self.assertEqual(len(stories), 1)
        story = stories[0]
        self.assertEqual(story.max_phase, Phase.PERSISTENCE)
        self.assertEqual(story.threat_score, 100)
        # phases come back in kill-chain order
        phases = [f.phase for f in story.findings]
        self.assertEqual(phases, sorted(phases))


class TestGoldenRoundTrip(unittest.TestCase):
    """Generator emits a known attack; the pipeline must recover it exactly."""

    def test_pipeline_recovers_known_attack(self):
        report = analyze_text(generate_auth_log(seed=1337), "golden.log")
        self.assertEqual(report.unparsed_lines, 0)
        self.assertEqual(len(report.stories), 1)
        story = report.stories[0]
        self.assertEqual(story.source_ip, SCENARIO_TRUTH["attacker_ip"])
        self.assertEqual(story.threat_score, 100)
        reached = {p for p in story.phases_reached}
        self.assertEqual(reached, set(Phase))  # all five phases present
        self.assertIn(SCENARIO_TRUTH["breached_user"], story.summary)
        self.assertIn(SCENARIO_TRUTH["rogue_account"], story.summary)

    def test_clean_log_has_no_findings(self):
        clean = "\n".join(
            f"Mar 10 0{h}:00:00 web01 sshd[1]: Accepted password for kalixte from 192.0.2.10 port 5 ssh2"
            for h in range(1, 6))
        report = analyze_text(clean, "clean.log")
        self.assertEqual(report.stories, [])


class TestScenarioArchetypes(unittest.TestCase):
    """Every archetype must detect correctly across many seeds — no bad-seed
    'attack with zero findings' — and benign traffic must stay silent. This is
    what makes the randomised /demo safe to click live in front of judges."""

    SEEDS = range(20)

    @staticmethod
    def _phases(stories):
        return {s.max_phase for s in stories}

    @staticmethod
    def _techs(stories):
        return {f.technique_id for s in stories for f in s.findings}

    def test_full_breach_reaches_persistence(self):
        for seed in self.SEEDS:
            stories = analyze_text(generate_scenario("full_breach", seed=seed)[0], "x").stories
            self.assertTrue(stories and Phase.PERSISTENCE in self._phases(stories),
                            f"seed {seed}: did not reach Persistence")

    def test_brute_force_stops_at_brute(self):
        for seed in self.SEEDS:
            stories = analyze_text(generate_scenario("brute_force", seed=seed)[0], "x").stories
            self.assertEqual(len(stories), 1, f"seed {seed}")
            self.assertEqual(stories[0].max_phase, Phase.BRUTE_FORCE, f"seed {seed}")

    def test_password_spray_enumerates(self):
        for seed in self.SEEDS:
            stories = analyze_text(generate_scenario("password_spray", seed=seed)[0], "x").stories
            self.assertEqual(len(stories), 1, f"seed {seed}")
            self.assertIn("T1110.001", self._techs(stories), f"seed {seed}")

    def test_recon_scan_stops_at_recon(self):
        for seed in self.SEEDS:
            stories = analyze_text(generate_scenario("recon_scan", seed=seed)[0], "x").stories
            self.assertEqual(len(stories), 1, f"seed {seed}")
            self.assertEqual(stories[0].max_phase, Phase.RECON, f"seed {seed}")

    def test_multi_host_has_multiple_attackers(self):
        for seed in self.SEEDS:
            stories = analyze_text(generate_scenario("multi_host", seed=seed)[0], "x").stories
            self.assertGreaterEqual(len(stories), 2, f"seed {seed}")

    def test_benign_is_silent(self):
        for seed in self.SEEDS:
            stories = analyze_text(generate_scenario("benign", seed=seed)[0], "x").stories
            self.assertEqual(stories, [], f"seed {seed}: benign traffic raised an alert")


if __name__ == "__main__":
    unittest.main()
