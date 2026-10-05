"""Read-only, bounded Replay research; names are candidates, not ABI proof."""

import argparse
import json
import sqlite3
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("patterns", nargs="+")
p.add_argument("--output", required=True, type=Path)
a = p.parse_args()
database = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
rows = {}
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for pattern in a.patterns:
        candidates = db.execute(
            "select name,address,rva,prototype,pseudocode,assembly from functions where name like ? limit 201",
            (pattern,),
        ).fetchall()
        if len(candidates) > 200:
            raise ValueError("Narrow the symbol pattern: " + pattern)
        for row in candidates:
            rows[row[1]] = dict(
                zip(
                    ("name", "address", "rva", "prototype", "pseudocode", "assembly"),
                    row,
                )
            )
result = sorted(rows.values(), key=lambda row: int(row["address"]))
a.output.write_text(
    json.dumps(
        {"database": str(database), "patterns": a.patterns, "functions": result},
        indent=2,
    )
    + "\n"
)
for row in result:
    print(hex(int(row["address"])), row["name"])
