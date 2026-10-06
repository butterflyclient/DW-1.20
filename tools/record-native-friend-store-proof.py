"""Record game-owned invitations and durable friendship callbacks, then cleanup."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--directory", required=True, type=Path)
parser.add_argument("--reconnect", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
directory, output, reconnect = (
    args.directory.resolve(),
    args.output.resolve(),
    args.reconnect.resolve(),
)
assert directory.is_relative_to(ROOT / "data")
assert output.is_relative_to(ROOT / "validation")
assert reconnect.is_relative_to(ROOT / "validation")


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


deployment = load(ROOT / "data/deployment.json")
invitation = load(ROOT / "data/native-social-invite.json")
removal = load(ROOT / "data/native-social-remove.json")
restart = load(reconnect)
labels = ("before", "outgoing", "accepted", "reconnected", "removed")
observations = {label: load(directory / (label + ".json")) for label in labels}
peer = invitation["peer"]
for observation in observations.values():
    assert observation["sha256"] == deployment["sha256"]
    server = observation["server_process_verified"]
    assert server["verified_live_process"]
    assert server["sha256"] == deployment["server_sha256"]
    assert observation["pid"] == observations["before"]["pid"]
    assert observation["native_profile_sign_in_state"] == 2
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_social_online_status"] == 2
    assert len(observation["native_fences_controller_0"]) == 27 and all(
        row["passing"] and not row["failed"]
        for row in observation["native_fences_controller_0"]
    )
    assert observation["native_user_xuid"] == invitation["target"]


def users(label, index):
    rows = observations[label]["native_crossplay_friend_lists"]
    assert len(rows) == 3 and {row["list_index"] for row in rows} == {0, 1, 2}
    row = next(row for row in rows if row["list_index"] == index)
    assert row["fetch_state"] == 2 and row["local_client"] == 0
    ids = [entry["user"] for entry in row["entries"]]
    assert len(ids) == len(set(ids)) == row["count"]
    return set(ids)


expected = {
    "before": (set(), set(), set()),
    "outgoing": (set(), set(), {peer}),
    "accepted": ({peer}, set(), set()),
    "reconnected": ({peer}, set(), set()),
    "removed": (set(), set(), set()),
}
for label, lists in expected.items():
    assert tuple(users(label, index) for index in range(3)) == lists
assert restart["passed"] and restart["native_accepted_friend_ids_preserved"] == [peer]
assert restart["game_sha256"] == deployment["sha256"]
assert restart["server_sha256"] == deployment["server_sha256"]
assert restart["native_relay_stability_after_restart_verified"]
for receipt in (invitation, removal):
    assert receipt["peer"] == peer and receipt["context"] == "cod-shared"
    assert receipt["server_sha256"] == deployment["server_sha256"]
    assert receipt["game_sha256"] == deployment["sha256"]
assert removal["temporary_relationship_removed"]
log = observations["outgoing"]["server_log_since_launch"]
for operation in ("cross-platform-username-search", "friend-invitations-persisted"):
    assert any(f"operation={operation} error=0" in line for line in log)
assert any(
    "DW_LOCAL_TEST_FRIEND native name search queued" in line
    for line in observations["outgoing"]["client_markers"]
)
graph = (
    ROOT
    / "data/social/5800"
    / hashlib.sha256(b"cod-shared").hexdigest()
    / "friends.json"
)
state = load(graph)
owner = invitation["target"]
for collection, fields in (("friends", ("a", "b")), ("pending", ("from", "to"))):
    assert not any(
        {row[field]["userID"] for field in fields} == {owner, peer}
        for row in state[collection]
    )
assert digest(Path(deployment["executable"])) == deployment["sha256"]
assert digest(ROOT / "build/Release/iw8-dw-server.exe") == deployment["server_sha256"]
proof = dict(
    schema=1,
    observed_utc=datetime.now(timezone.utc).isoformat(),
    passed=True,
    game_sha256=deployment["sha256"],
    server_sha256=deployment["server_sha256"],
    native_game_owned_name_search_and_outgoing_invitation=True,
    native_peer_acceptance_callback=True,
    accepted_friendship_persisted_across_backend_and_dw_restart=True,
    native_revocation_callback_and_empty_handoff_lists=True,
    diagnostic_peer_only=True,
    human_profile_or_initial_friendship_created=False,
    map_or_match_test_performed=False,
    two_native_game_or_remote_network_test_performed=False,
    full_backend_complete=False,
    source_sha256={
        name: digest(ROOT / name)
        for name in (
            "src/social_services.cpp",
            "src/rest_services.cpp",
            "tools/observe-game.py",
            "tools/record-native-friend-store-proof.py",
        )
    },
    reconnect_proof={
        "path": str(reconnect.relative_to(ROOT)),
        "sha256": digest(reconnect),
    },
    observations={label: digest(directory / (label + ".json")) for label in labels},
)
output.write_text(json.dumps(proof, indent=2) + "\n")
print(
    "PASS: native invitation, acceptance, restart persistence and revocation; diagnostic relationship removed"
)
