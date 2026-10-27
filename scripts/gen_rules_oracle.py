#!/usr/bin/env python3
"""Generate the Python rules-engine oracle fixture.

Reads the captured parser output (golden.jsonl), reconstructs the row dicts
the Python detector would have seen, runs the original detect_rules, and
writes a sorted "TYPE|entity" list. The Go rules engine is then compared
against this file.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.rules_engine import detect_rules  # noqa: E402

GOLDEN = ROOT / "internal/parser/testdata/golden.jsonl"
OUT = ROOT / "internal/rules/testdata/python_hits.txt"

rows = []
with GOLDEN.open() as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))

hits = detect_rules(rows, 30)
lines = sorted(f"{h['type']}|{h.get('entity') or ''}" for h in hits)

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text("\n".join(lines) + ("\n" if lines else ""))

print(f"{len(rows)} rows -> {len(hits)} hits")
for line in lines:
    print("  " + line)