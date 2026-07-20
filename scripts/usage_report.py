#!/usr/bin/env python3
"""Summarize the hosted server's usage log (logs/usage.jsonl + daily
rotations): calls per day, calls per tool, unique sessions.

The log contains only UTC timestamp, tool name, and a SHA-256-hashed
session identifier — never tool arguments, request bodies, or IPs.
"""

import json
from collections import Counter, defaultdict
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"


def main() -> None:
    rows = []
    for path in sorted(LOG_DIR.glob("usage.jsonl*")):
        for line in path.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not rows:
        print(f"No usage records found in {LOG_DIR}/usage.jsonl*")
        return

    per_day = Counter(r["ts"][:10] for r in rows)
    per_tool = Counter(r["tool"] for r in rows)
    sessions = {r["session"] for r in rows if r.get("session")}
    sessions_per_day = defaultdict(set)
    for r in rows:
        if r.get("session"):
            sessions_per_day[r["ts"][:10]].add(r["session"])

    print(f"Total tool calls: {len(rows)}   Unique sessions: {len(sessions)}")
    print("\nCalls per day:")
    for day in sorted(per_day):
        print(f"  {day}  {per_day[day]:5} calls  "
              f"{len(sessions_per_day[day]):4} unique sessions")
    print("\nCalls per tool:")
    for tool, count in per_tool.most_common():
        print(f"  {tool:28} {count:5}")


if __name__ == "__main__":
    main()
