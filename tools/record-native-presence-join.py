"""Verify a native invitation handshake and existing-lobby document assignment.

The controlled peer has no game server. This records the native backend gate,
not playable two-game or map validation. No credentials enter the receipt.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = root / "data"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--observation", default="runtime-presence-join-native-positive.json"
)
args = parser.parse_args()
if Path(args.observation).name != args.observation:
    raise ValueError("Use an observation basename within data")

observation = json.loads((data / args.observation).read_bytes())
peer = json.loads((data / "native-presence-join-peer.json").read_bytes())
deployment = json.loads((data / "deployment.json").read_text(encoding="utf-8-sig"))
fixture = json.loads((data / "lobby-verification.json").read_bytes())
server = observation["server_process_verified"]
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
assert server["verified_live_process"] and server["connection_receipt_matches"]
assert server["sha256"] == deployment["server_sha256"] == fixture["server_sha256"]
assert digest(server["executable"]) == server["sha256"] and fixture["passed"]
assert observation["sha256"] == deployment["sha256"] == digest(deployment["executable"])
assert observation["native_dw_hsm_connected_state_33"]
assert all(
    row["passing"] and not row["failed"]
    for row in observation["native_fences_controller_0"]
)
assert (
    peer["join_info_responses"] > 0
    and not peer["game_host"]
    and not peer["map_launched"]
)

native = observation["native_matchmaking_lobby"]
assert native["lobby_id"] == peer["id"] and native["host_user"] == peer["peer"]
assert native["state"] == 7 and native["lobby_state"] == 4
user = observation["native_user_xuid"]
state = json.loads(
    (data / "matchmaking/5800/lobbies" / f"{peer['id']}.json").read_bytes()
)
assert state["owner"] == peer["peer"] and set(state["members"]) == {user, peer["peer"]}
assert state["owner_session"] == peer["session_fingerprint"]
transaction = json.loads((data / "matchmaking/5800/transaction.json").read_bytes())
assert transaction["title"] == 5800 and transaction["phase"] == "applied"
assert transaction["writes"] == [] and transaction["revision"] > 0
search_id = state["backend_doc"]["player_id_to_mm_id"][str(user)]
search = json.loads(
    (data / "matchmaking/5800/searches" / f"{search_id}.json").read_bytes()
)
assert search["user"] == user and search["lobby_id"] == peer["id"]
fields = [
    name
    for name in ("lobby_id_to_presence_join", "player_id_to_presence_join")
    if name in search["query"]
]
assert len(fields) == 1
assert search["query"][fields[0]] == (
    peer["id"] if fields[0] == "lobby_id_to_presence_join" else peer["peer"]
)
assert search["query"]["members"] == [user]
assert any(
    "operation=matchmaker-presence-join-assigned error=0" in line
    for line in observation["server_log_since_launch"]
)

proof = dict(
    schema=1,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    observed_utc=observation["observed_utc"],
    server_sha256=server["sha256"],
    game_sha256=observation["sha256"],
    native_friend_menu_invitation_handshake_verified=True,
    native_presence_join_request_verified=True,
    native_presence_join_field=fields[0],
    native_assigned_lobby_and_host_verified=True,
    native_host_session_fingerprint_verified=True,
    native_transaction_applied_verified=True,
    native_matchmaking_state=native["state"],
    native_lobby_state=native["lobby_state"],
    native_startup_fences_passing=27,
    independent_protocol_checks=len(fixture["checks"]),
    controlled_peer_is_game_host=False,
    native_two_game_connection_verified=False,
    map_test_performed=False,
    engine_recompiled=False,
    full_backend_verified=False,
    expected_final_result="Unable to connect to host: the controlled peer supplies session/lobby documents but has no game/DTLS server",
)
(data / "native-presence-join-verification.json").write_text(
    json.dumps(proof, indent=2) + "\n"
)
print(
    "Verified native friend-menu request and existing-lobby/host assignment; two-game connection remains untested"
)
