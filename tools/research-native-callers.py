"""Read bounded same-Replay callers, treating names only as candidates."""

import argparse
import json
import sqlite3
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("callees", nargs="+", type=lambda value: int(value, 0))
parser.add_argument("--start", type=lambda value: int(value, 0), default=0x140000000)
parser.add_argument("--end", type=lambda value: int(value, 0), default=0x142380000)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
assert args.start < args.end and len(str(args.start)) == len(str(args.end))
database = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    names = []
    for address in args.callees:
        row = db.execute(
            "select name from functions where address=? limit 1", (str(address),)
        ).fetchone()
        names.extend([hex(address)[2:].upper(), hex(address)[2:].lower()])
        if row:
            names.extend([row[0], row[0].replace("::", "__")])
    conditions = " or ".join("(assembly like ? or pseudocode like ?)" for _ in names)
    patterns = [part for name in names for part in ("%" + name + "%", "%" + name + "%")]
    rows = db.execute(
        "select name,address,rva,prototype,pseudocode,assembly from functions where address>=? and address<? and ("
        + conditions
        + ") limit 101",
        [str(args.start), str(args.end), *patterns],
    ).fetchall()
    if len(rows) > 100:
        raise ValueError("Narrow caller range")
result = [
    dict(zip(("name", "address", "rva", "prototype", "pseudocode", "assembly"), row))
    for row in rows
]
args.output.write_text(
    json.dumps(
        {
            "database": str(database),
            "callees": list(map(hex, args.callees)),
            "functions": result,
        },
        indent=2,
    )
    + "\n"
)
for row in result:
    print(hex(int(row["address"])), row["name"])
