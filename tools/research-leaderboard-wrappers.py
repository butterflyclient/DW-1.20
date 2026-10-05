"""Read-only target callers of Replay's included-column leaderboard tasks."""

import json
from pathlib import Path
import sqlite3

root = Path(__file__).resolve().parents[1]
database = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
    connection.execute("pragma query_only=on")
    rows = connection.execute(
        "select name,address,rva,prototype,pseudocode from functions where assembly like ? or assembly like ?",
        ("%call    sub_142128500%", "%call    sub_142128100%"),
    ).fetchall()
result = [
    dict(zip(("name", "address", "rva", "prototype", "pseudocode"), row))
    for row in rows
]
(root / "data" / "native-leaderboard-wrapper-calls.json").write_text(
    json.dumps({"database": str(database), "functions": result}, indent=2) + "\n"
)
for row in result:
    print(hex(int(row["address"])), row["name"])
    print(row["pseudocode"])
