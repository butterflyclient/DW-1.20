"""Record current-backend native receiver and durable managed-retirement evidence."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--state-root", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
state, output = args.state_root.resolve(), args.output.resolve()
assert state.is_relative_to(ROOT / "data")
assert output.is_relative_to(ROOT / "validation") and output.suffix == ".json"


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


publication = read(state / "publication.json")
assert publication["restored"] and publication["accepted_membership_seeded"]
assert publication["bracket_membership_seeded"]
assert publication["test_account_registration_count"] == 7
assert publication["native_registration_enrollment_was_seeded"]
assert not publication["map_started"]
build = read(ROOT / "data/backend-build-latest.json")
protocol = read(ROOT / "data/lobby-verification.json")
assert build["compile_passed"] and protocol["passed"]
server_hash = digest(ROOT / "build/Release/iw8-dw-server.exe")
assert server_hash == build["sha256"] == protocol["server_sha256"]
source_hash = digest(ROOT / "src/tournament_services.cpp")
assert source_hash == build["inputs"]["src/tournament_services.cpp"]
observer_hash = digest(ROOT / "tools/observe-game.py")
rows = {
    name: read(state / "alpha" / f"{name}.json")
    for name in ("online", "consumed", "cleared")
}
for row in rows.values():
    assert row["pid"] == publication["game_pid"]
    assert row["sha256"] == publication["game_sha256"]
    assert row["observer_source_sha256"] == observer_hash
    assert Path(row["executable"]).parent == Path(r"E:\IW8\Builds\1.20-replay")
    connection = row["server_process_verified"]
    assert (
        connection["verified_live_process"] and connection["connection_receipt_matches"]
    )
    assert connection["pid"] == publication["server_pid"]
    assert connection["sha256"] == server_hash
    assert row["native_dw_hsm_connected_state_33"]
    assert row["native_profile_sign_in_state"] == 2
    assert row["native_social_online_status"] == 2
    assert row["native_local_player_settings"]["profile_logged_in"]
    fences = row["native_fences_controller_0"]
    assert len(fences) == 27 and all(
        item["passing"] and not item["failed"] for item in fences
    )
    assert row["native_tournament_request"]["pending_task"] == 0
    assert row["native_tournament_request"]["retry_count"] == 0
assert (
    rows["online"]["native_tournament_request"]["current_bracket"]["tournament_id"] == 0
)
consumed = rows["consumed"]["native_tournament_request"]["current_bracket"]
assert consumed["tournament_id"] == publication["tournament_id"]
assert (
    consumed["team_size"] == 1
    and consumed["team_count"] == 8
    and consumed["round_count"] == 3
)
assert consumed["participant_count"] == 8 and consumed["local_team"] == 0
cleared = rows["cleared"]["native_tournament_request"]
assert cleared["state"] == 0
assert cleared["current_bracket"]["tournament_id"] == 0
assert cleared["current_bracket"]["participant_count"] == 0
registration_path = state / "alpha/after-signup.json"
registration = read(registration_path)
assert registration["pid"] == publication["game_pid"]
assert registration["sha256"] == publication["game_sha256"]
assert registration["server_process_verified"]["sha256"] == server_hash
assert registration["observer_source_sha256"] == observer_hash
native_registration = registration["native_tournament_request"]
assert native_registration["state"] == 2
assert native_registration["pending_task"] == native_registration["retry_count"] == 0
assert native_registration["parsed_search_offset"] == 600
assert any(
    "TASK service=145 task=29 operation=tournament-owner-registered error=0 results=1"
    in line
    for line in registration["server_log_since_launch"]
)
terminal = read(state / "terminal.json")
assert terminal["action"] == "publication-unavailable" and terminal["actor"] == 0
assert terminal["id"] == publication["tournament_id"]
assert terminal["state"] == publication["expected_bracket"]
assert all(
    match["winningTeamID"] == -1
    for round_ in terminal["state"]["rounds"]
    for match in round_["matches"]
)

for row in publication["files"]:
    path = Path(row["path"]).resolve()
    assert path.is_relative_to(ROOT / "data")
    assert (
        base64.b64encode(path.read_bytes()).decode() if path.exists() else None
    ) == row["bytes"]
baseline = read(state / "protected-files.json")
for row in baseline:
    assert digest(Path(row["path"])) == row["sha256"]
log = (state / "withdraw-log.txt").read_text()
assert (
    "TASK service=145 " not in log
), "Require native idle delivery without a tournament request"
groups = [
    item
    for item in protocol["checks"]
    if item.startswith("Managed ") and "publication unavailability" in item
]
assert len(groups) == 3

proof = dict(
    schema=1,
    passed=True,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    server_sha256=server_hash,
    game_sha256=publication["game_sha256"],
    tournament_source_sha256=source_hash,
    observer_source_sha256=observer_hash,
    recorder_source_sha256=digest(Path(__file__)),
    native_receiver_same_game_and_backend_processes=True,
    native_update_parser_verified=True,
    native_disband_callback_verified=True,
    native_state_cleared=True,
    native_startup_fences_passed=27,
    native_registration_verified=False,
    native_registration_response_callback_verified=True,
    native_registration_enrollment_was_seeded=True,
    native_join_assignment_verified=False,
    accepted_membership_seeded=True,
    bracket_membership_seeded=True,
    real_machine_registered_fixture_accounts=7,
    backend_only_fixture=True,
    native_map_started=False,
    native_allocated_round_retirement_verified=False,
    protocol_allocated_round_retirement_verified=True,
    native_two_network_gameplay_verified=False,
    exact_fixture_restoration_verified=True,
    protected_shipping_files_unchanged=True,
    independent_protocol_checks=len(protocol["checks"]),
    lifecycle_groups=groups,
    evidence=[
        dict(file=str(path.relative_to(ROOT)), sha256=digest(path))
        for path in (
            state / "alpha/online.json",
            state / "alpha/consumed.json",
            state / "alpha/cleared.json",
            registration_path,
            state / "publication.json",
            state / "terminal.json",
            state / "withdraw-log.txt",
            state / "protected-files.json",
            ROOT / "data/backend-build-latest.json",
            ROOT / "data/lobby-verification.json",
        )
    ],
    scope="Current backend managed-publication retirement and original native registration-response/update/disband receivers. Enrollment, acceptance and PLAYING bracket membership were explicitly seeded using real registered accounts. Fresh native enrollment, join assignment, match allocation and WAN gameplay are separate gates.",
)
output.write_text(json.dumps(proof, indent=2) + "\n")
print(
    "Verified current-backend native idle disband, durable retirement and exact fixture restoration"
)
