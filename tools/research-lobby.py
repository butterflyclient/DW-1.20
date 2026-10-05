"""Read-only same-Replay evidence; numeric addresses are research, not runtime bindings."""

import json, sqlite3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
db = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
conn = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
terms = [
    "bdBitBuffer::",
    "bdTitleUtilities::getServerTime",
    "bdProfile",
    "bdAntiCheat::reportExtendedAuthInfo",
    "bdAntiCheat::reportBNetSessionToken",
    "bdLoginTaskUmbrellaLegacyLogin::",
    "bdRemoteTask::handleTaskReply",
    "bdRemoteTask::deserializeTaskReply",
    "bdByteBuffer::writeBlob",
    "bdStorage::get",
    "bdStorage::set",
    "bdStorage::upload",
    "bdPublisherVariables::retrieve",
    "bdPublisherVariablesInfo::deserialize",
    "bdFileInfo::deserialize",
    "bdFileData::deserialize",
    "bdTimeStamp::deserialize",
]
rows = []
for term in terms:
    rows.extend(
        dict(zip(["name", "rva", "prototype", "pseudocode", "assembly"], row))
        for row in conn.execute(
            "select name,rva,prototype,pseudocode,assembly from functions where name like ?",
            ("%" + term + "%",),
        )
    )
rows = list({row["rva"]: row for row in rows}.values())
(root / "data" / "service-native-research.json").write_text(
    json.dumps(rows, indent=2) + "\n"
)
for row in rows:
    print(f"{int(row['rva']):x} {row['name']} cpp={len(row['pseudocode'] or '')}")
print("--- KDF constant reference ---")
prepare = json.loads((root / "data" / "lobby-native-research.json").read_text())[0]
lines = prepare["assembly"].splitlines()
for i, line in enumerate(lines):
    if "126h" in line:
        print("\n".join(lines[max(0, i - 6) : i + 8]))
