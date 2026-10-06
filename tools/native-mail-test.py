"""Send one inert diagnostic through native DW mail to a verified running game.

Uses the existing separate native-social fixture identity, never the game's
credentials. The native consumer alone reads/deletes the message; duration
limits an unconsumed diagnostic to five minutes. No friendships are created.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from native_wire_client import NativeClient, u32, u64

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--observation", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
observation_path, output = args.observation.resolve(), args.output.resolve()
assert observation_path.is_relative_to((ROOT / "data").resolve())
assert output.is_relative_to((ROOT / "data").resolve())
observation = json.loads(observation_path.read_text())
deployment = json.loads((ROOT / "data/deployment.json").read_text())
launch = json.loads(
    (ROOT / "data/current-runtime-launch.json").read_text(encoding="utf-8-sig")
)
assert observation["pid"] == launch["pid"]
age = (
    datetime.now(timezone.utc) - datetime.fromisoformat(observation["observed_utc"])
).total_seconds()
assert 0 <= age <= 60, "Use a fresh read-only game observation"
assert observation["sha256"] == deployment["sha256"]
assert (
    hashlib.sha256(Path(deployment["executable"]).read_bytes()).hexdigest()
    == deployment["sha256"]
)
assert observation["server_process_verified"]["verified_live_process"]
assert observation["server_process_verified"]["sha256"] == deployment["server_sha256"]
assert observation["native_profile_sign_in_state"] == 2
assert observation["native_dw_hsm_connected_state_33"]
assert len(observation["native_fences_controller_0"]) == 27
assert all(
    row["passing"] and not row["failed"]
    for row in observation["native_fences_controller_0"]
)
manager = observation["native_mail_manager"]
assert manager["enabled"] == 1 and manager["controller_0_initialized"] == 1
assert manager["state"] == 0 and not manager["task_active"]
assert manager["context"] == ""  # Same-Replay wrapper's actual empty context.
assert (ROOT / "data/platform-profiles/native-social.bin").is_file()
target = observation["native_user_xuid"]
body = b"REPLAY_DW_NATIVE_MAIL_DIAGNOSTIC_20261006\n"


def text(value):
    return b"\x10" + value.encode("ascii") + b"\0"


mailbox = ROOT / "data/mail/5800/_default/messages.json"
with NativeClient(ROOT, profile="native-social") as sender:
    assert sender.user != target
    if mailbox.exists():
        previous = json.loads(mailbox.read_bytes())
        assert not any(
            row["sender"] == sender.user
            and row["recipient"] == target
            and base64.b64decode(row["content"], validate=True) == body
            for row in previous["messages"]
        ), "An earlier diagnostic is still pending; allow native consumption or expiration"
    parameters = (
        text("")
        + b"\x13"
        + u32(len(body))
        + body
        + b"\x06"
        + struct.pack("<H", 0)
        + u32(1)
        + u64(target)
        + text("uno")
        + u32(300)
        + b"\x01\x00"
    )
    assert sender.task(29, 9, parameters, structured=False) == b""
    stored = json.loads(mailbox.read_bytes())
    rows = [
        row
        for row in stored["messages"]
        if row["sender"] == sender.user
        and row["recipient"] == target
        and base64.b64decode(row["content"], validate=True) == body
    ]
    assert len(rows) == 1
    row = rows[0]
    receipt = {
        "schema": 1,
        "sent_utc": datetime.now(timezone.utc).isoformat(),
        "pid": observation["pid"],
        "game_sha256": deployment["sha256"],
        "server_sha256": deployment["server_sha256"],
        "observation_sha256": hashlib.sha256(observation_path.read_bytes()).hexdigest(),
        "sender": sender.user,
        "recipient": target,
        "context": "",
        "mail_id": row["id"],
        "body_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "duration": row["duration"],
        "native_consumer_verified": False,
        "mailbox": str(mailbox),
    }
output.write_text(json.dumps(receipt, indent=2) + "\n")
print(
    "Sent one bounded inert diagnostic from the separate fixture account; native consumption remains to be observed"
)
