"""Killchain — a forensic SSH auth.log kill-chain analyzer (stdlib only).

The public entry points are `analyze_text` / `analyze_file`, which run the full
pipeline (parse -> detect -> correlate) and hand back a `Report`.
"""

from __future__ import annotations

import os
from datetime import datetime

from .correlator import correlate
from .detectors import Config, run_all_detectors
from .models import Report
from .parser import parse_log_text

__all__ = ["analyze_text", "analyze_file", "Config", "Report"]

__version__ = "0.1.0"


def analyze_text(
    text: str,
    source_filename: str = "(in-memory)",
    config: Config | None = None,
    base_year: int | None = None,
) -> Report:
    """Run the whole pipeline over raw auth.log text and return a Report."""
    events, unparsed = parse_log_text(text, base_year=base_year)
    findings = run_all_detectors(events, config)
    stories = correlate(findings)
    hosts = sorted({e.host for e in events})
    return Report(
        source_filename=source_filename,
        generated_at=datetime.now(),
        stories=stories,
        total_events=len(events),
        unparsed_lines=unparsed,
        hosts=hosts,
    )


def analyze_file(
    path: str,
    config: Config | None = None,
    base_year: int | None = None,
) -> Report:
    """Read an auth.log file and analyze it."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return analyze_text(
        text, source_filename=os.path.basename(path), config=config, base_year=base_year)
