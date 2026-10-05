"""Record native counter task completion and reverse only our test increment.

The cleanup uses a separate signed account, never the running game's issuer.
The exact pre-cleanup total is checked so unrelated contributions are preserved.
"""

import hashlib
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from native_wire_client import NativeClient, u32

root = Path(__file__).resolve().parents[1]
data = root / "data"
deployment = json.loads((data / "deployment.json").read_text())
names = [
    "runtime-counter-native-queued.json",
    "runtime-counter-native-uploaded.json",
    "runtime-counter-native-restored.json",
]
observations = [json.loads((data / name).read_text()) for name in names]
for observation in observations:
    assert observation["sha256"] == deployment["sha256"]
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_profile_sign_in_state"] == 2
states = [observation["native_global_counters"] for observation in observations]
# Validate field names from the read-only native observer before publishing.
assert any(row["id"] == 3 and row["value"] == 11 for row in states[0]["pending"])
assert all(row["value"] == 0 for row in states[1]["pending"])
assert any(row["id"] == 3 and row["value"] == 11 for row in states[1]["upload"])
assert not states[1]["write_pending"] and not states[1]["active_tasks"]
assert states[2]["write_interval"] == 15
log_line = next(
    line
    for line in (data / "server.log").read_text().splitlines()
    if line.startswith("2026-10-05T06:24:26Z ")
    and "service=23 task=1 operation=global-counter-increments-persisted error=0"
    in line
)
path = data / "counters/5800.json"
before = json.loads(path.read_text())
assert before == {"schema": 1, "title": 5800, "totals": {"3": 11}}
with NativeClient(root, profile="native-social") as client:
    assert (
        client.task(23, 1, u32(3) + b"\x09" + struct.pack("<q", -11), structured=False)
        == b""
    )
    expected = u32(3) + b"\x09" + struct.pack("<q", 0)
    assert client.task(23, 2, u32(3), structured=False) == expected
after = json.loads(path.read_text())
assert after == {"schema": 1, "title": 5800, "totals": {"3": 0}}
server = root / "build/Release/iw8-dw-server.exe"
assert hashlib.sha256(server.read_bytes()).hexdigest() == deployment["server_sha256"]
proof = {
    "schema": 1,
    "game_sha256": deployment["sha256"],
    "server_sha256": deployment["server_sha256"],
    "observations": names,
    "native_game_verified": True,
    "native_read_task_verified": False,
    "evidence": "Stock incrementcounter command queued ID 3/value 11; the native periodic writer sent 23/1, cleared pending values and retired its task.",
    "native_service_log": log_line,
    "write_interval_restored_minutes": 15,
    "temporary_increment_reversed": True,
    "totals_after": after["totals"],
    "utc": datetime.now(timezone.utc).isoformat(),
}
(data / "native-counter-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
print(
    "Native counter upload completion recorded; temporary increment reversed through signed tasks."
)
