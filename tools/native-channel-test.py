"""Exercise one native private-party member join/leave using an existing test peer.

The game creates its own channel through its registered private-party command.
This tool changes no native memory and never logs in as the game's account.
It creates no friendship or profile and closes its separately labelled peer.
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

from native_wire_client import NativeClient, integer, structure, text

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
    and {member["user"] for member in chat["members"]} == {owner}
]
assert len(candidates) == 1, "Create a native private-party channel first"
chat, channel = candidates[0]
channel_id = channel["id"]
category = channel["category"]
profile = (ROOT / "data/platform-profiles/native-social.bin").read_bytes()
assert len(profile) == 56 and profile[20:56].split(b"\0")[0] == b"DWBackendValidation"
peer_user = struct.unpack_from("<Q", profile, 8)[0]
assert peer_user != owner and str(peer_user) not in channel["members"]
observations = {"created": initial_path}
trace = ROOT / "data" / (output.stem + "-observations")
trace.mkdir(exist_ok=True)


def valid(observation):
    assert observation["pid"] == initial["pid"] == launch["pid"]
    assert observation["sha256"] == deployment["sha256"]
    server = observation["server_process_verified"]
    assert (
        server["verified_live_process"]
        and server["sha256"] == deployment["server_sha256"]
    )
    assert server["pid"] == initial["server_process_verified"]["pid"]
    assert observation["native_user_xuid"] == owner
    assert observation["native_profile_sign_in_state"] == 2
    assert observation["native_dw_hsm_connected_state_33"]
    fences = observation["native_fences_controller_0"]
    assert len(fences) == 27 and all(
        row["passing"] and not row["failed"] for row in fences
    )


def wait_members(label, expected):
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
        if len(found) == 1 and {row["user"] for row in found[0]["members"]} == expected:
            assert found[0]["member_count"] == len(expected)
            assert next(row for row in found[0]["members"] if row["user"] == owner)[
                "host"
            ]
            if peer_user in expected:
                assert (
                    next(
                        row for row in found[0]["members"] if row["user"] == peer_user
                    )["name"]
                    == "DWBackendValidation"
                )
            observations[label] = path
            return
        time.sleep(0.25)
    raise AssertionError("Native channel membership did not complete: " + label)


valid(initial)
parameters = structure(text(1, category) + integer(2, channel_id) + integer(3, 0))
with NativeClient(ROOT, profile="native-social") as peer:
    assert peer.user == peer_user
    assert peer.task(198, 1, parameters, structured=True) == b""
    wait_members("joined", {owner, peer_user})
    assert peer.task(198, 2, parameters, structured=True) == b""
    wait_members("unsubscribed", {owner})
    assert peer.task(198, 1, parameters, structured=True) == b""
    wait_members("rejoined", {owner, peer_user})
wait_members("disconnected", {owner})
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
    "scope": "Native channel creation and event-24/25 membership callbacks in one root-folder game",
    "native_channel": channel_id,
    "native_category": category,
    "native_chat_type": chat["type"],
    "separate_existing_test_peer": peer_user,
    "positive_native_member_callback_verified": True,
    "native_channel_create_completion_verified": True,
    "checks": [
        "Game-owned native private-party create completion installed the actual channel and host member",
        "Real authenticated peer subscription event 24 added the named member to the native chat pool",
        "Owned peer unsubscribe event 25 removed the member from the native chat pool",
        "Same-session rejoin restored native membership, and last-socket disconnect removed it again",
    ],
    "observations": {
        name: {"path": str(path), "sha256": digest(path)}
        for name, path in observations.items()
    },
    "source_sha256": {
        name: digest(ROOT / name)
        for name in ("tools/observe-game.py", "tools/native-channel-test.py")
    },
    "friendship_or_profile_created": False,
    "native_channel_message_verified": False,
    "two_network_multiplayer_verified": False,
}
output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
print(
    "PASS: native channel create and peer join/unsubscribe/rejoin/disconnect; no map or friendship test"
)
