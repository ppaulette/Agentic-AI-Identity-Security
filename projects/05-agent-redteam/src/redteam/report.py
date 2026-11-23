"""Run every attack against a fresh lab and write a Markdown report."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from agentlab import build_lab

from .attacks import ATTACKS, Outcome


def run_all() -> list[tuple]:
    results = []
    for attack in ATTACKS:
        try:
            outcome = attack.run(build_lab())
        except Exception as exc:  # an attack that crashes the system is a finding too
            outcome = Outcome(False, f"unhandled error: {exc!r}")
        results.append((attack, outcome))
    return results


def to_markdown(results: list[tuple]) -> str:
    blocked = sum(o.blocked for _, o in results)
    lines = [
        "# Red-team report: agent identity stack",
        "",
        f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} by `python -m redteam`. "
        f"**{blocked} of {len(results)} attacks blocked.**",
        "",
        "| ID | Attack | Threat | Result | Control that stopped it | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for attack, outcome in results:
        result = "Blocked" if outcome.blocked else "**NOT BLOCKED**"
        evidence = outcome.evidence.replace("|", "\\|")
        lines.append(
            f"| {attack.id} | {attack.name} | {attack.threat} | {result} | "
            f"{attack.expected_control} | `{evidence}` |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redteam")
    parser.add_argument("--out", default="reports/redteam-report.md")
    args = parser.parse_args(argv)
    results = run_all()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_markdown(results))
    for attack, outcome in results:
        mark = "BLOCKED" if outcome.blocked else "OPEN   "
        print(f"[{mark}] {attack.id} {attack.name}")
    print(f"\nreport written to {out}")
    return 0 if all(o.blocked for _, o in results) else 1
