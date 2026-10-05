"""Require the actual native event receiver and restored fixture data for proof."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = root / "data"


def load(name):
    return json.loads((data / name).read_bytes())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


registration = load("runtime-tournament-updates-enrolled.json")
forming = load("runtime-tournament-updates-consumed.json")
playing = load("runtime-tournament-updates-playing.json")
emission = load("native-tournament-update-emission.json")
publication = load("native-tournament-test-publication.json")
fixture = load("lobby-verification.json")
deployment = load("deployment.json")
assert publication["restored"] and emission["recipient_acceptance_seeded"]
assert fixture["passed"]
assert emission["server_sha256"] == deployment["server_sha256"]
assert emission["game_sha256"] == deployment["sha256"]
for entry in publication["files"]:
    path = Path(entry["path"])
    if entry["existed"]:
        import base64

        assert path.read_bytes() == base64.b64decode(entry["bytes"], validate=True)
    else:
        assert not path.exists()
for observation in (registration, forming, playing):
    server = observation["server_process_verified"]
    assert server["verified_live_process"] and server["connection_receipt_matches"]
    assert server["sha256"] == deployment["server_sha256"] == fixture["server_sha256"]
    assert digest(server["executable"]) == server["sha256"]
    assert (
        digest(observation["executable"])
        == observation["sha256"]
        == deployment["sha256"]
    )
    assert observation["pid"] == emission["game_pid"]
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_profile_sign_in_state"] == 2
    native = observation["native_tournament_request"]
    assert native["pending_task"] == native["retry_count"] == 0
assert registration["native_tournament_request"]["state"] == 2
assert registration["native_tournament_request"]["parsed_search_offset"] == 600
assert (
    registration["native_tournament_request"]["current_bracket"]["tournament_id"] == 0
)
assert any(
    "service=145 task=29 operation=tournament-owner-registered error=0 results=1"
    in line
    for line in registration["server_log_since_launch"]
)
assert emission["event_id"] == 2010 and emission["tournament_status"] == "PLAYING"
assert emission["peer_received_typed_bracket"] and not emission["map_started"]
for observation in (forming, playing):
    assert (
        observation["native_tournament_request"]["current_bracket"]["tournament_id"]
        == emission["tournament_id"]
    )
bracket = playing["native_tournament_request"]["current_bracket"]
assert all(
    bracket[key] == value for key, value in emission["expected_native_counts"].items()
)
proof = {
    "schema": 1,
    "passed": True,
    "recorded_utc": datetime.now(timezone.utc).isoformat(),
    "server_sha256": deployment["server_sha256"],
    "game_sha256": deployment["sha256"],
    "native_registration_callback_verified": True,
    "native_update_receiver_verified": True,
    "native_playing_bracket_parser_verified": True,
    "event_id": 2010,
    "target_decoder": "0x14213F1C0",
    "target_callback": "0x14103F3F0",
    "target_bracket_parser": "0x141074530",
    "observed_counts": {
        key: bracket[key] for key in emission["expected_native_counts"]
    },
    "recipient_acceptance_seeded": True,
    "temporary_publication_restored": True,
    "native_join_assignment_verified": False,
    "playable_tournament_verified": False,
    "full_backend_verified": False,
    "map_tests_performed": False,
    "independent_protocol_checks": len(fixture["checks"]),
    "scope": "Native registration, then encrypted event-2010 decoding and FORMING/PLAYING parsing. Recipient acceptance was seeded in backend data; native join assignment and playable tournaments are separate gates.",
    "evidence": [
        {"file": str(Path("data") / name), "sha256": digest(data / name)}
        for name in (
            "runtime-tournament-updates-enrolled.json",
            "runtime-tournament-updates-consumed.json",
            "runtime-tournament-updates-playing.json",
            "native-tournament-update-emission.json",
            "native-tournament-test-publication.json",
        )
    ],
}
(data / "native-tournament-update-verification.json").write_text(
    json.dumps(proof, indent=2) + "\n"
)
print(
    "Native event-2010 receiver and bracket arrays verified; fixture restored; join assignment remains unverified"
)
