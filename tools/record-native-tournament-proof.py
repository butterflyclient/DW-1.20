"""Separate positive native registration/state-reader proof from wire fixtures."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = root / "data"
registration = json.loads(
    (data / "runtime-tournament-native-registered.json").read_bytes()
)
state = json.loads((data / "runtime-tournament-native-restarted.json").read_bytes())
deployment = json.loads((data / "deployment.json").read_bytes())
fixture = json.loads((data / "lobby-verification.json").read_bytes())
publication = json.loads(
    (data / "native-tournament-test-publication.json").read_bytes()
)

digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
for observation in (registration, state):
    server = observation["server_process_verified"]
    assert server["verified_live_process"] and server["connection_receipt_matches"]
    assert server["sha256"] == deployment["server_sha256"] == fixture["server_sha256"]
    assert digest(server["executable"]) == server["sha256"]
    assert (
        digest(observation["executable"])
        == observation["sha256"]
        == deployment["sha256"]
    )
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_profile_sign_in_state"] == 2
    assert observation["native_tournament_request"]["pending_task"] == 0
    assert observation["native_tournament_request"]["retry_count"] == 0

native = registration["native_tournament_request"]
assert (
    native["state"] == 2
    and native["parsed_search_offset"] == publication["expected_offset"]
)
assert json.loads(native["result_buffer"]) == {"start_search_offset_seconds": 600.25}
assert any(
    "service=145 task=29 operation=tournament-owner-registered error=0 results=1"
    in line
    for line in registration["server_log_since_launch"]
)
assert registration["pid"] != state["pid"]
assert (
    registration["server_process_verified"]["pid"]
    != state["server_process_verified"]["pid"]
)
restarted = state["native_tournament_request"]
result = json.loads(restarted["state_result_buffer"])
assert result["tournamentID"] == restarted["rejoin_tournament_id"]
assert result["tournamentID"] in publication["published_ids"]
assert {"playerID": publication["owner"]} in result["players"]
assert any(
    "service=145 task=20 operation=tournament-owner-state error=0 results=1" in line
    for line in state["server_log_since_launch"]
)
receipt = {
    "schema": 1,
    "passed": True,
    "recorded_utc": datetime.now(timezone.utc).isoformat(),
    "server_sha256": deployment["server_sha256"],
    "game_sha256": deployment["sha256"],
    "registration_game_pid": registration["pid"],
    "restarted_game_pid": state["pid"],
    "native_registration_callback_verified": True,
    "native_state_callback_verified": True,
    "native_registration_request": "0x142136240",
    "native_registration_callback": "0x141070FC0",
    "native_state_callback": "0x141077F20",
    "native_registration_state": native["state"],
    "native_parsed_search_offset": native["parsed_search_offset"],
    "native_registration_result_sha256": hashlib.sha256(
        native["result_buffer"].encode()
    ).hexdigest(),
    "native_state_result_sha256": hashlib.sha256(
        restarted["state_result_buffer"].encode()
    ).hexdigest(),
    "native_rejoin_candidate_matches_persisted_tournament": True,
    "backend_and_game_process_restart_verified": True,
    "bracket_rendering_and_playable_tournament_verified": False,
    "full_backend_verified": False,
    "map_tests_performed": False,
    "scope": "Actual native bdStringResult readers and completion callbacks: registration offset, task cleanup and persisted tournament-ID parsing after both process restarts. No match scheduling or bracket push consumer proof.",
}
(data / "native-tournament-verification.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print(
    "Native tournament registration and persisted state callbacks verified; no match started"
)
