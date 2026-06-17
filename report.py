"""Render a `Report` into one self-contained HTML page.

No template engine, no assets, no JavaScript framework — just stdlib string
building with inline CSS. The output is a single file you can open offline,
which makes it bullet-proof for a screen-recorded demo and trivial to
screenshot. The page leads with the *narrative* (the attack story) because
that is the thing a judge understands in five seconds.
"""

from __future__ import annotations

import html

from .models import AttackStory, Finding, Phase, Report, Severity

# Fixed left-to-right order of the kill-chain for the phase strip.
_PHASE_ORDER = [
    Phase.RECON, Phase.BRUTE_FORCE, Phase.INITIAL_ACCESS,
    Phase.PRIVILEGE_ESCALATION, Phase.PERSISTENCE,
]


def _esc(value: object) -> str:
    return html.escape(str(value))


def _severity_badge(sev: Severity) -> str:
    return (f'<span class="badge" style="background:{sev.color}">'
            f'{_esc(sev.label)}</span>')


def _phase_strip(story: AttackStory) -> str:
    reached = set(story.phases_reached)
    chips = []
    for i, phase in enumerate(_PHASE_ORDER):
        on = phase in reached
        chips.append(
            f'<div class="phase {"on" if on else "off"}">'
            f'<span class="pnum">{i + 1}</span>{_esc(phase.label)}</div>')
        if i < len(_PHASE_ORDER) - 1:
            chips.append(f'<div class="arrow {"on" if on else "off"}">&rsaquo;</div>')
    return f'<div class="strip">{"".join(chips)}</div>'


def _evidence_block(finding: Finding) -> str:
    rows = "".join(
        f'<div class="ev"><span class="evt">{_esc(e.time_str)}</span>'
        f'<span class="evl">L{e.line_no}</span>'
        f'<code>{_esc(e.raw)}</code></div>'
        for e in finding.evidence[:60])
    extra = ""
    if len(finding.evidence) > 60:
        extra = f'<div class="evmore">…and {len(finding.evidence) - 60} more lines</div>'
    return (f'<details><summary>{len(finding.evidence)} log line(s) of evidence'
            f'</summary><div class="evbox">{rows}{extra}</div></details>')


def _finding_card(finding: Finding) -> str:
    return (
        '<div class="finding">'
        f'<div class="fhead">{_severity_badge(finding.severity)}'
        f'<span class="tech">{_esc(finding.technique_id)}</span>'
        f'<span class="techname">{_esc(finding.technique_name)}</span>'
        f'<span class="fphase">{_esc(finding.phase.label)}</span></div>'
        f'<p class="explain">{_esc(finding.explanation)}</p>'
        f'{_evidence_block(finding)}</div>')


def _story_card(story: AttackStory) -> str:
    span = ""
    if story.first_seen and story.last_seen:
        span = (f'{story.first_seen.strftime("%b %d %H:%M:%S")} '
                f'&rarr; {story.last_seen.strftime("%H:%M:%S")}')
    findings = "".join(_finding_card(f) for f in story.findings)
    sev = story.max_severity
    return (
        '<section class="story">'
        '<div class="shead">'
        f'<div class="ip">{_esc(story.source_ip)}</div>'
        f'<div class="score" style="--c:{sev.color}">'
        f'<div class="scoreval">{story.threat_score}</div>'
        '<div class="scorelab">THREAT</div></div></div>'
        f'<div class="meta">{span}</div>'
        f'<p class="summary">{_esc(story.summary)}</p>'
        f'{_phase_strip(story)}'
        f'<div class="findings">{findings}</div>'
        '</section>')


_CSS = """
:root {
  --bg:#0a0c0f; --panel:#12151b; --sunk:#0d1014; --line:#21262e; --line2:#2b323c;
  --ink:#e6e9ef; --muted:#8b93a1; --dim:#5a626e; --accent:#e0443e;
  --mono:ui-monospace,"SF Mono","Cascadia Mono",Menlo,Consolas,monospace;
  --sans:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font-family:var(--sans);
  font-size:15px; line-height:1.5; -webkit-font-smoothing:antialiased; }
.wrap { max-width:860px; margin:0 auto; padding:40px 24px 80px; }
.title { font-family:var(--mono); font-size:15px; font-weight:600; letter-spacing:.2em; text-transform:uppercase; }
.title::before { content:""; display:inline-block; width:8px; height:8px; margin-right:10px;
  background:var(--accent); vertical-align:middle; }
.sub { color:var(--muted); font-family:var(--mono); font-size:12.5px; letter-spacing:.02em; margin:10px 0 28px; }
.bar { display:flex; flex-wrap:wrap; border:1px solid var(--line); border-radius:4px; margin-bottom:26px; overflow:hidden; }
.bar .kv { font-family:var(--mono); font-size:12px; color:var(--muted); padding:11px 16px; border-right:1px solid var(--line); }
.bar .kv b { color:var(--ink); font-weight:600; }
.story { border:1px solid var(--line); border-radius:5px; background:var(--panel); margin-bottom:20px; }
.shead { display:flex; align-items:stretch; justify-content:space-between; border-bottom:1px solid var(--line); }
.ip { font-family:var(--mono); font-size:21px; font-weight:600; padding:17px 20px; }
.score { display:flex; flex-direction:column; align-items:center; justify-content:center; min-width:92px;
  border-left:1px solid var(--line); background:var(--sunk); }
.scoreval { font-family:var(--mono); font-size:23px; font-weight:700; color:var(--c); line-height:1; }
.scorelab { font-family:var(--mono); font-size:9px; letter-spacing:.22em; color:var(--dim); margin-top:5px; }
.meta { color:var(--dim); font-family:var(--mono); font-size:11.5px; letter-spacing:.03em; padding:13px 20px 0; }
.summary { font-size:14.5px; line-height:1.65; color:var(--ink); padding:11px 20px 2px; }
.strip { display:flex; align-items:center; flex-wrap:wrap; padding:18px 20px 22px; }
.phase { display:flex; align-items:center; gap:8px; font-family:var(--mono); font-size:11px; letter-spacing:.04em;
  padding:9px 12px; border:1px solid var(--line2); opacity:0; animation:kc-rise .45s ease both; }
.phase.off { color:var(--dim); background:transparent; }
.phase.on { color:#fff; background:#e0443e14; border-color:#e0443e66; }
.pnum { display:inline-flex; align-items:center; justify-content:center; width:17px; height:17px; font-size:9px; }
.phase.on .pnum { background:var(--accent); color:var(--bg); }
.phase.off .pnum { border:1px solid var(--line2); color:var(--dim); }
.arrow { font-family:var(--mono); color:var(--line2); padding:0 6px; opacity:0; animation:kc-rise .45s ease both; }
.arrow.on { color:#e0443e99; }
.strip > :nth-child(1){animation-delay:.04s} .strip > :nth-child(2){animation-delay:.10s}
.strip > :nth-child(3){animation-delay:.16s} .strip > :nth-child(4){animation-delay:.22s}
.strip > :nth-child(5){animation-delay:.28s} .strip > :nth-child(6){animation-delay:.34s}
.strip > :nth-child(7){animation-delay:.40s} .strip > :nth-child(8){animation-delay:.46s}
.strip > :nth-child(9){animation-delay:.52s}
@keyframes kc-rise { from{opacity:0;transform:translateY(5px)} to{opacity:1;transform:none} }
.findings { padding:2px 20px 14px; }
.finding { padding:15px 0; border-top:1px solid var(--line); }
.finding:first-child { border-top:none; }
.fhead { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.badge { font-family:var(--mono); font-size:10px; font-weight:700; letter-spacing:.06em; text-transform:uppercase;
  color:var(--bg); padding:2px 7px; border-radius:3px; }
.tech { font-family:var(--mono); font-size:12px; color:var(--muted); font-weight:600; }
.techname { font-weight:600; font-size:14px; }
.fphase { margin-left:auto; font-family:var(--mono); font-size:10px; color:var(--dim); text-transform:uppercase; letter-spacing:.1em; }
.explain { margin:9px 0 8px; color:#c4ccd6; line-height:1.6; font-size:14px; }
details { margin-top:4px; }
summary { cursor:pointer; color:var(--muted); font-size:12px; font-family:var(--mono); list-style:none; }
summary::-webkit-details-marker { display:none; }
summary::before { content:"+ "; color:var(--dim); }
details[open] summary::before { content:"- "; color:var(--dim); }
.evbox { margin-top:8px; max-height:240px; overflow:auto; background:var(--sunk); border:1px solid var(--line); border-radius:4px; }
.ev { display:flex; gap:14px; align-items:baseline; padding:5px 11px; font-size:12px; border-top:1px solid #181c22; }
.ev:first-child { border-top:none; }
.ev:nth-child(even) { background:#0b0e12; }
.evt { color:#6fae7e; font-family:var(--mono); }
.evl { color:var(--dim); font-family:var(--mono); min-width:42px; }
.ev code { color:var(--muted); font-family:var(--mono); white-space:pre-wrap; word-break:break-all; }
.evmore { color:var(--dim); font-size:12px; padding:6px 11px; font-family:var(--mono); }
.clean { border:1px solid var(--line); border-radius:5px; padding:32px; text-align:center;
  color:#6fae7e; font-family:var(--mono); font-size:14px; }
.foot { color:var(--dim); font-size:11px; text-align:center; margin-top:32px; font-family:var(--mono); letter-spacing:.03em; }
"""


def render_report(report: Report) -> str:
    """Build the full HTML document for a Report."""
    worst = report.worst_severity
    bar = (
        f'<div class="kv">File <b>{_esc(report.source_filename)}</b></div>'
        f'<div class="kv">Events parsed <b>{report.total_events}</b></div>'
        f'<div class="kv">Unparsed lines <b>{report.unparsed_lines}</b></div>'
        f'<div class="kv">Hosts <b>{_esc(", ".join(report.hosts) or "—")}</b></div>'
        f'<div class="kv">Attackers <b>{len(report.stories)}</b></div>'
        f'<div class="kv">Worst {_severity_badge(worst)}</div>')

    if report.stories:
        body = "".join(_story_card(s) for s in report.stories)
    else:
        body = ('<div class="clean">No attack chains detected. '
                'Every authentication in this log looks benign.</div>')

    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>Killchain — {_esc(report.source_filename)}</title>'
        f'<style>{_CSS}</style></head><body><div class="wrap">'
        '<div class="title">killchain</div>'
        '<div class="sub">SSH auth.log &rarr; attack-chain reconstruction</div>'
        f'<div class="bar">{bar}</div>'
        f'{body}'
        f'<div class="foot">Generated {report.generated_at.strftime("%Y-%m-%d %H:%M:%S")} '
        '· pure-Python stdlib · MITRE ATT&CK technique IDs</div>'
        '</div></body></html>')


def write_report(report: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_report(report))
