"""Bounded read-only same-Replay function window by original virtual address."""

import argparse, json, sqlite3
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("start", type=lambda v: int(v, 0))
p.add_argument("end", type=lambda v: int(v, 0))
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
assert 0 < a.end - a.start <= 0x20000 and len(str(a.start)) == len(str(a.end))
dbpath = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
with sqlite3.connect(dbpath.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    # Fixed-width positive address strings have the same lexical ordering.
    rows = db.execute(
        "select name,address,rva,prototype,pseudocode,assembly from functions where address>=? and address<? order by address limit 257",
        (str(a.start), str(a.end)),
    ).fetchall()
    assert len(rows) <= 256
result = [
    dict(zip(("name", "address", "rva", "prototype", "pseudocode", "assembly"), r))
    for r in rows
]
a.output.write_text(
    json.dumps({"database": str(dbpath), "functions": result}, indent=2) + "\n"
)
for r in result:
    print(hex(int(r["address"])), r["name"])
