"""Verify a real peer's first message reaches Replay's native chat history.

Requires a game-owned private-party chat and the existing labelled diagnostic
peer. Changes no game memory, profile option, friendship or identity file.
Only body hashes are recorded; the peer leaves its temporary membership.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time
import uuid

from native_wire_client import NativeClient, binary, integer, structure, text

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--observation", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
initial_path, output = args.observation.resolve(), args.output.resolve()
assert initial_path.is_relative_to((ROOT / "data").resolve())
assert output.is_relative_to((ROOT / "validation").resolve())


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


deployment = load(ROOT / "data/deployment.json")
launch = load(ROOT / "data/current-runtime-launch.json")
initial = load(initial_path)
assert digest(Path(deployment["executable"])) == deployment["sha256"]
assert digest(ROOT / "build/Release/iw8-dw-server.exe") == deployment["server_sha256"]
age = (
    datetime.now(timezone.utc) - datetime.fromisoformat(initial["observed_utc"])
).total_seconds()
assert 0 <= age <= 60, "Use a fresh native --channels observation"
owner = initial["native_user_xuid"]
store = load(ROOT / "data/channels/5800.json")
candidates = [
    (chat, row)
    for chat in initial["native_channels"]["chats"]
    for row in store["channels"].values()
    if chat["channel"] == row["id"]
    and row["owner"] == owner
    and chat["type"] == 3
    and row["category"] == "chat"
    and {member["user"] for member in chat["members"]} == {owner}
]
assert len(candidates) == 1, "Create a native private-party channel first"
chat, channel = candidates[0]
channel_id, category = channel["id"], channel["category"]
profile = (ROOT / "data/platform-profiles/native-social.bin").read_bytes()
assert len(profile) == 56 and profile[20:56].split(b"\0")[0] == b"DWBackendValidation"
peer_user = struct.unpack_from("<Q", profile, 8)[0]
assert peer_user != owner and str(peer_user) not in channel["members"]
trace = ROOT / "data" / (output.stem + "-observations")
trace.mkdir(exist_ok=True)
observations = {"created": initial_path}


def valid(observation):
    assert observation["pid"] == initial["pid"] == launch["pid"]
    assert observation["sha256"] == deployment["sha256"]
    server = observation["server_process_verified"]
    assert server["verified_live_process"]
    assert server["sha256"] == deployment["server_sha256"]
    assert server["pid"] == initial["server_process_verified"]["pid"]
    assert observation["native_user_xuid"] == owner
    assert observation["native_profile_sign_in_state"] == 2
    assert observation["native_dw_hsm_connected_state_33"]
    fences = observation["native_fences_controller_0"]
    assert len(fences) == 27 and all(
        row["passing"] and not row["failed"] for row in fences
    )


def wait_native(label, expected, body_hash=None):
    path = trace / (label + ".json")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "tools/observe-game.py"),
                "--channels",
                "--output",
                str(path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            cwd=ROOT,
        )
        observation = load(path)
        valid(observation)
        found = [
            row
            for row in observation["native_channels"]["chats"]
            if row["channel"] == channel_id
        ]
        if len(found) == 1:
            row = found[0]
            members = {member["user"] for member in row["members"]}
            messages = [
                message
                for message in row["messages"]
                if message["sender"] == peer_user
                and message["sender_name"] == "DWBackendValidation"
                and message["body_sha256"] == body_hash
                and message["message_state"] == 2
            ]
            if members == expected and (body_hash is None or len(messages) == 1):
                assert row["member_count"] == len(expected)
                observations[label] = path
                return row
        time.sleep(0.25)
    raise AssertionError("Native channel message/lifecycle did not complete: " + label)


valid(initial)
parameters = structure(text(1, category) + integer(2, channel_id) + integer(3, 0))
message = ("REPLAY_DW_NATIVE_CHAT_" + uuid.uuid4().hex).encode("ascii")
body_hash = hashlib.sha256(message).hexdigest()
with NativeClient(ROOT, profile="native-social") as peer:
    assert peer.user == peer_user
    assert peer.task(198, 1, parameters, structured=True) == b""
    # Deliberately send immediately, without polling native member arrival.
    payload = structure(
        text(1, category)
        + integer(2, channel_id)
        + binary(3, message + b"\0")
        + integer(4, 256)  # The diagnostic sender permits crossplay visibility.
    )
    assert peer.task(198, 3, payload, structured=True) == b""
    received = wait_native("first-message", {owner, peer_user}, body_hash)
    assert ((received["message_sequence"] - chat["message_sequence"]) & 0xFFFFFFFF) > 0
    assert peer.task(198, 2, parameters, structured=True) == b""
    wait_native("unsubscribed", {owner}, body_hash)
wait_native("disconnected", {owner}, body_hash)
final_store = load(ROOT / "data/channels/5800.json")
assert set(final_store["channels"][f"{category}:{channel_id}"]["members"]) == {
    str(owner)
}
receipt = {
    "schema": 1,
    "verified_at": datetime.now(timezone.utc).isoformat(),
    "passed": True,
    "server_sha256": deployment["server_sha256"],
    "game_sha256": deployment["sha256"],
    "pid": initial["pid"],
    "scope": "First authenticated peer message is consumed by one native root-folder game's private-party chat",
    "native_channel": channel_id,
    "native_category": category,
    "native_chat_type": chat["type"],
    "separate_existing_test_peer": peer_user,
    "native_channel_message_verified": True,
    "positive_native_member_callback_verified": True,
    "native_channel_create_completion_verified": True,
    "message_body_sha256": body_hash,
    "checks": [
        "Game-owned private-party create installed the actual channel and host member",
        "Peer subscribed and immediately sent its first message without waiting for the delayed join",
        "Native chat history contains exactly one incoming record with the real peer ID/name and body hash",
        "Peer unsubscribe and socket close retain the native message and remove only its membership",
    ],
    "observations": {
        name: {"path": str(path), "sha256": digest(path)}
        for name, path in observations.items()
    },
    "source_sha256": {
        name: digest(ROOT / name)
        for name in ("tools/observe-game.py", "tools/native-channel-message-test.py")
    },
    "friendship_or_profile_created": False,
    "two_network_multiplayer_verified": False,
}
output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
print(
    "PASS: first peer message consumed in native chat history; peer membership cleaned up"
)
