"""Bounded read-only original-Replay pseudocode/assembly substring research."""

import argparse
import json
from pathlib import Path
import sqlite3

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("terms", nargs="+")
parser.add_argument("--start", type=lambda value: int(value, 0), required=True)
parser.add_argument("--end", type=lambda value: int(value, 0), required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument(
    "--all-terms",
    action="store_true",
    help="Require every substring in a candidate function",
)
args = parser.parse_args()
if not (
    args.start < args.end
    and args.end - args.start <= 0x1000000
    and len(str(args.start)) == len(str(args.end))
    and len(args.terms) <= 8
):
    raise ValueError("Narrow the target range or search terms")
database = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    conditions = (" and " if args.all_terms else " or ").join(
        "(pseudocode like ? or assembly like ?)" for _ in args.terms
    )
    patterns = [
        part for term in args.terms for part in ("%" + term + "%", "%" + term + "%")
    ]
    rows = db.execute(
        "select name,address,rva,prototype,pseudocode,assembly from functions "
        "where address>=? and address<? and (" + conditions + ") limit 65",
        [str(args.start), str(args.end), *patterns],
    ).fetchall()
    if len(rows) > 64:
        raise ValueError("More than 64 candidates; narrow the search")
result = [
    dict(zip(("name", "address", "rva", "prototype", "pseudocode", "assembly"), row))
    for row in rows
]
args.output.write_text(
    json.dumps(
        {
            "database": str(database),
            "terms": args.terms,
            "all_terms": args.all_terms,
            "start": hex(args.start),
            "end": hex(args.end),
            "functions": result,
        },
        indent=2,
    )
    + "\n"
)
for row in result:
    print(hex(int(row["address"])), row["name"])
