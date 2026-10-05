"""Read-only same-Replay candidate serializers for additional DW domains."""

import sqlite3, json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
database = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
patterns = [
    "%bdScheduledMatchInfo%",
    "%bdMatchEventInfo%",
    "%bdPerformanceValue%",
    "%bdStoredPerformanceValue%",
    "%bdMLG%",
    "%bdRedeemableCode%",
    "%bdLootGeneration%",
    "%bdGetFriendsResponse%",
]
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    result = []
    for pattern in patterns:
        rows = db.execute(
            "select name,address,rva,prototype,pseudocode,assembly from functions where name like ?",
            (pattern,),
        ).fetchall()
        result.extend(
            dict(
                zip(
                    ("name", "address", "rva", "prototype", "pseudocode", "assembly"),
                    row,
                )
            )
            for row in rows
        )
(root / "data/native-scheduled-domain-symbols.json").write_text(
    json.dumps({"database": str(database), "candidates": result}, indent=2) + "\n"
)
for row in result:
    print(hex(int(row["address"])), row["name"])
