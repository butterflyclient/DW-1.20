"""Read-only packet research in the exact Replay SQLite export."""

import json
from pathlib import Path
import re
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
DB = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
rows = []
with sqlite3.connect(DB.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for name, address, rva, prototype, code, assembly in db.execute(
        "select name,address,rva,prototype,pseudocode,assembly from functions"
    ):
        address = int(address)
        if not 0x142160000 <= address < 0x1421A0000:
            continue
        text = (code or "") + "\n" + (assembly or "")
        # QoS request/reply constructors write packet kinds 40/41. Candidate
        # status is not an assertion that unrelated constants are packets.
        if re.search(
            r"mov\s+(?:byte ptr )?\[(?:rcx|rbx|rdi|rsi)(?:\+[^\]]+)?\],\s*2[89]h",
            assembly or "",
            re.I,
        ) or re.search(r"(?i)qos|relay|commonaddr", name):
            rows.append(
                dict(
                    name=name,
                    address=address,
                    prototype=prototype,
                    pseudocode=code,
                    assembly=assembly,
                )
            )
(ROOT / "data/native-qos-packet-candidates.json").write_text(
    json.dumps(rows, indent=2) + "\n"
)
for row in rows:
    print(hex(row["address"]), row["name"])
print("Candidates", len(rows))
