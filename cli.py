"""Command-line entry point for Killchain.

    py -m killchain                  # launch the web app (default)
    py -m killchain serve --port N   # launch the web app on a port
    py -m killchain analyze <log>    # write an HTML report for a log file
    py -m killchain gen -o out.log   # write a synthetic sample auth.log
"""

from __future__ import annotations

import argparse
import os
import webbrowser

from . import analyze_file
from .generator import generate_auth_log
from .report import write_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="killchain",
        description="Forensic SSH auth.log kill-chain analyzer (pure stdlib).")
    sub = parser.add_subparsers(dest="cmd")

    p_analyze = sub.add_parser("analyze", help="analyze a log file into an HTML report")
    p_analyze.add_argument("logfile")
    p_analyze.add_argument("-o", "--output", default="killchain_report.html")
    p_analyze.add_argument("--no-open", action="store_true", help="don't open the report")

    p_serve = sub.add_parser("serve", help="launch the local web app (default)")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--no-open", action="store_true", help="don't open a browser")

    p_gen = sub.add_parser("gen", help="write a synthetic sample auth.log")
    p_gen.add_argument("-o", "--output", default="killchain/samples/generated_attack.log")
    p_gen.add_argument("--seed", type=int, default=1337)

    args = parser.parse_args(argv)
    cmd = args.cmd or "serve"

    if cmd == "analyze":
        report = analyze_file(args.logfile)
        write_report(report, args.output)
        print(f"Report written to {args.output} "
              f"({report.total_findings} findings across {len(report.stories)} attacker(s)).")
        if not args.no_open:
            webbrowser.open("file://" + os.path.abspath(args.output))
    elif cmd == "gen":
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(generate_auth_log(args.seed))
        print(f"Sample auth.log written to {args.output}.")
    else:  # serve
        from .server import serve  # imported lazily so analyze/gen don't need it
        serve(port=args.port, open_browser=not args.no_open)
    return 0
