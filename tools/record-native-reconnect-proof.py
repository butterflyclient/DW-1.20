"""Verify a focused native restart pass against exact deployed game/server images."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("before", type=Path)
parser.add_argument("after", type=Path)
parser.add_argument(
    "--output",
    type=Path,
    default=ROOT / "validation/20261006-native-reconnect.json",
    help="Receipt inside validation; use a new filename to retain historical image proofs",
)
parser.add_argument(
    "--stability",
    type=Path,
    help="Later observation proving at least 60 seconds of relay keepalives",
)
parser.add_argument(
    "--expected-friend",
    type=int,
    action="append",
    default=[],
    help="Exact accepted diagnostic peer UID expected before and after restart; pending lists stay empty",
)
args = parser.parse_args()
expected_friends = set(args.expected_friend)
assert len(expected_friends) == len(args.expected_friend) and all(
    0 < user < 2**64 - 1 for user in expected_friends
)


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


deployment = load(ROOT / "data/deployment.json")
before, after = load(args.before), load(args.after)
for observation in (before, after):
    assert observation["sha256"] == deployment["sha256"]
    server = observation["server_process_verified"]
    assert server["verified_live_process"]
    assert observation["platform_auth_state"] == 2
    assert observation["native_profile_sign_in_state"] == 2
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_social_online_status"] == 2
    network = observation["native_network"]
    assert network["mode"] == 1 and 2 <= network["state"] <= 4
    fences = observation["native_fences_controller_0"]
    assert len(fences) == 27 and all(
        row["passing"] and not row["failed"] for row in fences
    )
    lists = observation["native_crossplay_friend_lists"]
    assert len(lists) == 3 and all(row["fetch_state"] == 2 for row in lists)
    # Default remains the empty-list pass. Explicit peer IDs permit a controlled
    # persistence check without silently accepting another owner's relationships.
    assert {row["list_index"] for row in lists} == {0, 1, 2}
    for row in lists:
        users = [entry["user"] for entry in row["entries"]]
        assert len(set(users)) == len(users) == row["count"]
        assert set(users) == (expected_friends if row["list_index"] == 0 else set())
    relay = observation["native_relay_transport"]
    association = observation["native_relay_association"]
    assert relay["state"] == 6 and relay["native_connected_callback_observed"]
    assert association["state"] == 3 and association["type"] == 1
    assert association["relay_id"] == relay["relay_id"]
    assert association["user"] == observation["native_user_xuid"]
    assert (
        association["title"] == 5800 and association["route"] and association["join_id"]
    )
    assert observation["native_relay_client_auth"]["state"] == 2
assert before["pid"] == after["pid"]
assert after["server_process_verified"]["sha256"] == deployment["server_sha256"]
if before["server_process_verified"]["sha256"] != deployment["server_sha256"]:
    assert (
        deployment["server_rebinding"]["previous_server_sha256"]
        == before["server_process_verified"]["sha256"]
    )
assert (
    before["server_process_verified"]["pid"] != after["server_process_verified"]["pid"]
)
for field in ("native_user_xuid", "native_user_platform_id", "native_user_name"):
    assert before[field] == after[field]
assert after["observed_utc"] > before["observed_utc"]
assert after["server_process_verified"]["connection_receipt_matches"]
assert after["connection_receipt"]["command"] == "dw_restart"
assert any("DW_RESTART_CONNECTED" in line for line in after["client_markers"])
assert any("DW_RESTART_RELAY_RESET" in line for line in after["client_markers"])
assert (
    before["native_relay_client_auth"]["native_wire_sha256"]
    != after["native_relay_client_auth"]["native_wire_sha256"]
)
assert (
    before["native_relay_transport"]["relay_id"]
    != after["native_relay_transport"]["relay_id"]
)
requests = after["server_log_since_launch"]
assert any("service=145 task=26 " in line and "error=0" in line for line in requests)
association = after["native_relay_association"]
started = datetime.fromisoformat(
    after["connection_receipt"]["requested_utc"]
).timestamp()
events_path = ROOT / "data/relay/transport-events.jsonl"
events = [json.loads(line) for line in events_path.read_text().splitlines()]
matching = [
    row
    for row in events
    if row["action"] == "established"
    and row["time"] >= started
    and all(
        row[key] == association[key]
        for key in ("relay_id", "route", "user", "title", "port", "verification_sha256")
    )
]
assert matching and matching[-1]["expires"] > datetime.now(timezone.utc).timestamp()
assert after["server"]["relay"]["active_associations"] == 1
assert after["server"]["relay"]["verified_associations"] == 1
relay_health = after["server"]["relay"]
retired_rejections = []
if relay_health["rejected_packets"]:
    # A packet can arrive from the game's previous association between server
    # startup and dw_restart. Permit only completely accounted, header-correlated
    # old routes rejected before the fresh association established. Unknown,
    # known-current-route, init, rate-limited and suppressed events still fail.
    established_position = events.index(matching[-1])
    retired_rejections = [
        (position, row)
        for position, row in enumerate(events)
        if row["action"] == "rejected" and row["relay_id"] == association["relay_id"]
    ]
    assert (
        len(retired_rejections)
        == relay_health["rejected_packets"]
        == relay_health["rejection_events"]
    )
    assert relay_health["suppressed_rejection_events"] == 0
    old_route = before["native_relay_association"]["route"]
    assert old_route != association["route"]
    assert all(
        position < established_position
        and row["reason"] == "unknown-route"
        and row["route"] == old_route
        and 2 <= row["packet_type"] <= 11
        for position, row in retired_rejections
    )
delta = after["server_counter_changes_since_launch"]
assert all(
    delta[key] > 0
    for key in ("auth_successes", "legacy_logins", "lobby_authenticated", "tasks")
)
assert delta["lobby_failures"] == 0
assert digest(Path(deployment["executable"])) == deployment["sha256"]
assert digest(ROOT / "build/Release/iw8-dw-server.exe") == deployment["server_sha256"]
receipt = {
    "schema": 2,
    "observed_utc": datetime.now(timezone.utc).isoformat(),
    "game_sha256": deployment["sha256"],
    "server_sha256": deployment["server_sha256"],
    "previous_server_sha256": before["server_process_verified"]["sha256"],
    "compiler_job": deployment["job_id"],
    "passed": True,
    "native_startup_fences_passed": 27,
    "native_profile_and_online_state_verified": True,
    "native_friend_lists_completed_and_empty": not expected_friends,
    "native_accepted_friend_ids_preserved": sorted(expected_friends),
    "backend_restart_and_dw_restart_same_game_process": True,
    "native_account_preserved_on_reconnect": True,
    "native_network_online_and_started": True,
    "fresh_backend_native_auth_and_lobby_session_verified": True,
    "native_relay_token_renewed_on_restart": True,
    "native_relay_bind_verify_established_after_restart": True,
    "native_relay_join_data_correlated_with_backend_event": True,
    "relay_id_after_restart": association["relay_id"],
    "relay_established_event": matching[-1],
    "two_network_party_gameplay_verified": False,
    "map_or_match_test_performed": False,
    "complete_backend_verified": False,
    "observations": {
        str(path.relative_to(ROOT)): digest(path)
        for path in (args.before.resolve(), args.after.resolve())
    },
    "transport_events_sha256": digest(events_path),
    "pre_connection_retired_route_rejections": [row for _, row in retired_rejections],
}
if args.stability:
    stable = load(args.stability)
    assert stable["sha256"] == after["sha256"] and stable["pid"] == after["pid"]
    assert stable["server_process_verified"] == after["server_process_verified"]
    elapsed = (
        datetime.fromisoformat(stable["observed_utc"])
        - datetime.fromisoformat(after["observed_utc"])
    ).total_seconds()
    assert elapsed >= 60
    assert stable["native_dw_hsm_connected_state_33"]
    assert stable["native_profile_sign_in_state"] == 2
    assert stable["native_relay_transport"] == after["native_relay_transport"]
    assert stable["native_relay_association"] == after["native_relay_association"]
    assert stable["native_relay_client_auth"] == after["native_relay_client_auth"]
    assert (
        stable["native_crossplay_friend_lists"]
        == after["native_crossplay_friend_lists"]
    )
    assert len(stable["native_fences_controller_0"]) == 27 and all(
        row["passing"] and not row["failed"]
        for row in stable["native_fences_controller_0"]
    )
    health, initial_health = stable["server"]["relay"], after["server"]["relay"]
    assert health["active_associations"] == health["verified_associations"] == 1
    assert health["rejected_packets"] == initial_health["rejected_packets"]
    pings = health["ping_replies"] - initial_health["ping_replies"]
    assert pings > 0
    receipt.update(
        native_relay_stability_after_restart_verified=True,
        stable_seconds=elapsed,
        keepalive_replies=pings,
    )
    receipt["observations"][str(args.stability.resolve().relative_to(ROOT))] = digest(
        args.stability
    )
output = args.output.resolve()
assert output.is_relative_to((ROOT / "validation").resolve())
output.write_text(json.dumps(receipt, indent=2) + "\n")
deployment["local_player_identity"]["native_runtime_verified"] = True
deployment["local_player_identity"]["native_proof"] = str(output)
deployment["runtime_test"] = (
    "Focused native startup, all 27 fences, profile/Online/friend lists and same-process "
    "dw_restart after backend restart, fresh relay token and native authenticated relay "
    "passed; two-network party gameplay remains pending"
)
(ROOT / "data/deployment.json").write_text(json.dumps(deployment, indent=2) + "\n")
readiness_path = ROOT / "data/auth-profile-readiness.json"
readiness = load(readiness_path)
assert readiness["executable_sha256"] == receipt["game_sha256"]
assert readiness["server_sha256"] == receipt["server_sha256"]
readiness["native_startup_reconnect_verified"] = True
readiness["native_relay_restart_verified"] = True
readiness["native_startup_reconnect_proof"] = str(output)
readiness["native_verified_scopes"] = [
    "startup login/profile/Online and 27 fences",
    (
        "completed accepted diagnostic friend list with no pending requests"
        if expected_friends
        else "completed empty accepted/incoming/outgoing friend lists"
    ),
    "same-process backend restart with unchanged player identity",
    "fresh relay credential and authenticated native UDP association",
]
readiness_path.write_text(json.dumps(readiness, indent=2) + "\n")
print(
    "PASS: native startup, same-process backend reconnect and fresh authenticated relay; "
    "no map or remote-game claim"
)
