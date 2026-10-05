"""Bounded, read-only same-Replay function research by original VA/RVA."""

import argparse
import json
import sqlite3
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("addresses", nargs="+", type=lambda value: int(value, 0))
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
database = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
    connection.execute("pragma query_only=on")
    result = []
    for address in args.addresses:
        rva = address - 0x140000000 if address >= 0x140000000 else address
        row = connection.execute(
            "select name,address,rva,prototype,pseudocode,assembly from functions where rva=? limit 1",
            (str(rva),),
        ).fetchone()
        if row is None:
            raise RuntimeError("No same-build function at " + hex(address))
        result.append(
            dict(
                zip(
                    ("name", "address", "rva", "prototype", "pseudocode", "assembly"),
                    row,
                )
            )
        )
args.output.write_text(
    json.dumps({"database": str(database), "functions": result}, indent=2) + "\n"
)
for row in result:
    print(hex(int(row["address"])), row["name"], row["prototype"])
    print(row["pseudocode"] or row["assembly"])
