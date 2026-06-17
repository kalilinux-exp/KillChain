"""Turn a flat list of `Finding`s into per-attacker `AttackStory` objects.

This is the step that makes Killchain more than "grep with extra steps": we
group findings by attacker, order them along the kill-chain, score how far the
attacker got, and stitch their explanations into one narrated paragraph.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from .models import AttackStory, Finding, Phase

# How threatening each kill-chain stage is on its own. Reaching a later stage
# means the attacker got further, so the *furthest* phase dominates the score.
_PHASE_WEIGHT = {
    Phase.RECON: 15,
    Phase.BRUTE_FORCE: 35,
    Phase.INITIAL_ACCESS: 70,
    Phase.PRIVILEGE_ESCALATION: 85,
    Phase.PERSISTENCE: 100,
}


def score_story(story: AttackStory) -> int:
    """0–100 threat score.

    Base = weight of the furthest phase reached; plus a small bonus for breadth
    (more distinct stages = a more complete intrusion). This is the single most
    tunable piece of judgement in the project — a defender might weight breach
    and persistence far more heavily than recon.
    """
    if not story.findings:
        return 0
    base = _PHASE_WEIGHT[story.max_phase]
    breadth_bonus = min(15, (len(story.phases_reached) - 1) * 5)
    return min(100, base + breadth_bonus)


def _ordered(findings: list[Finding]) -> list[Finding]:
    """Findings in kill-chain order: by phase, then by time."""
    return sorted(findings, key=lambda f: (f.phase, f.start or datetime.min))


def narrate(story: AttackStory) -> str:
    """One readable paragraph: each finding's explanation, in chain order.

    The findings already carry plain-English explanations with the real
    numbers, so the narrative is honest by construction — it can't claim
    anything the evidence doesn't show.
    """
    return " ".join(f.explanation for f in _ordered(story.findings))


def correlate(findings: list[Finding]) -> list[AttackStory]:
    """Group findings into AttackStories, scored and sorted worst-first."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.source_ip:
            groups[f.source_ip].append(f)

    stories: list[AttackStory] = []
    for ip, fs in groups.items():
        story = AttackStory(source_ip=ip, findings=_ordered(fs))
        story.threat_score = score_story(story)
        story.summary = narrate(story)
        stories.append(story)

    stories.sort(key=lambda s: s.threat_score, reverse=True)
    return stories
