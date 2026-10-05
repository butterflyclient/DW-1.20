"""Find candidate Replay counter DTOs by their observed UInt32/Int64 wire operations."""

import json
import sqlite3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
database = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    rows = db.execute(
        """select name,address,rva,prototype,pseudocode,assembly from functions
        where address>=? and address<? and
        (pseudocode like ? or pseudocode like ?) limit 101""",
        (str(0x1420F6000), str(0x142180000), "%1420F02F0%", "%writeInt64%"),
    ).fetchall()
    if len(rows) > 100:
        raise RuntimeError("Too many candidate serializers")
result = [
    dict(zip(("name", "address", "rva", "prototype", "pseudocode", "assembly"), row))
    for row in rows
]
(root / "data/native-counter-layout-candidates.json").write_text(
    json.dumps({"database": str(database), "functions": result}, indent=2) + "\n"
)
for row in result:
    print(hex(int(row["address"])), row["name"], row["pseudocode"])
