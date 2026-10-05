"""Bind published CRM decoding/completion and native view requests to binaries."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = root / "data"
observation_name = "runtime-marketing-viewed.json"
observation = json.loads((data / observation_name).read_bytes())
publication = json.loads((data / "native-marketing-test-publication.json").read_bytes())
fixture = json.loads((data / "lobby-verification.json").read_bytes())
deployment = json.loads((data / "deployment.json").read_bytes())
server = observation["server_process_verified"]
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert server["verified_live_process"] and server["connection_receipt_matches"]
assert (
    fixture["passed"]
    and fixture["server_sha256"] == server["sha256"] == deployment["server_sha256"]
)
assert (
    observation["sha256"]
    == deployment["sha256"]
    == digest(Path(observation["executable"]))
)
assert server["sha256"] == digest(Path(server["executable"]))
assert publication["restored"]
native = observation["native_marketing_messages"]
assert not native["fetch_in_flight"] and not native["remote_task_present"]
assert native["response_count"] == 1 and len(native["messages"]) == 1
message = native["messages"][0]
assert (
    message["id"],
    message["assignment"],
    message["location"],
    message["language"],
) == (
    publication["message_id"],
    publication["assignment"],
    publication["location"],
    "en",
)
assert message["content_sha256"] == publication["content_sha256"]
assert message["metadata_sha256"] == publication["metadata_sha256"]
assert message["payload_size"] == message["signature_size"] == 0
parsed = next(row for row in native["parsed_locations"] if row["location"] == 1)
assert parsed["first_parsed"] and parsed["parsed_count"] == 1
assert parsed["first_json"] == publication["expected_json"]
assert (
    observation["native_dw_hsm_connected_state_33"]
    and observation["native_profile_sign_in_state"] == 2
)
fences = observation["native_fences_controller_0"]
assert len(fences) == 27 and all(row["passing"] and not row["failed"] for row in fences)
assert observation["native_game_connection"]["state"] == 9
assert observation["native_game_connection"]["frontend_scene"]
requests = [
    line
    for line in observation["server_log_since_launch"]
    if "service=104 task=7 operation=marketing-views-recorded error=0" in line
]
assert requests
journal = json.loads((data / "native-marketing-view-journal.json").read_bytes())
assert journal["owner"] == publication["owner"]
assert any(
    row["view"]
    == {
        "1": publication["message_id"],
        "2": 1,
        "3": publication["assignment"],
        "4": "en",
    }
    for row in journal["views"].values()
)
proof = dict(
    schema=1,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    passed=True,
    server_sha256=server["sha256"],
    game_sha256=observation["sha256"],
    native_message_deserialization_verified=True,
    native_fetch_completion_and_task_cleanup_verified=True,
    native_metadata_substitution_and_json_cache_verified=True,
    native_view_request_and_owned_persistence_verified=True,
    native_view_completion_callback_verified=False,
    temporary_publication_and_view_journals_restored=True,
    independent_protocol_checks=len(fixture["checks"]),
    full_backend_verified=False,
    map_tests_performed=False,
    message_id=message["id"],
    assignment=message["assignment"],
    native_response_reader="0x142114EC0",
    native_message_reader="0x142114CF0",
    native_fetch_callback="0x140F69AB0",
    native_parser="0x140F69E30",
    scope="Actual native populated message result, fetch task cleanup and parsed substitution cache; native viewed request and persistent receipt, without a viewed completion callback claim.",
    evidence=[
        dict(file=name, sha256=digest(data / name))
        for name in (
            observation_name,
            "native-marketing-test-publication.json",
            "native-marketing-view-journal.json",
            "lobby-verification.json",
        )
    ],
)
(data / "native-marketing-verification.json").write_text(
    json.dumps(proof, indent=2) + "\n"
)
print(
    "PASS: actual native CRM message decoding, callback cleanup and JSON substitution; viewed request/persistence; exact publication/journal restoration"
)
