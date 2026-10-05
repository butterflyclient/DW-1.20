"""Edit a restored-after-test publication and require native idle push evidence.

This tool makes no client task or engine request. The receiver fixture must
already have registered through the game UI and consumed its PLAYING bracket.
Acceptance is seeded by that fixture; native join assignment is a separate gate.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = root / "data"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("mode", choices=("edit", "expire", "record"))
args = parser.parse_args()


def load(name):
    return json.loads((data / name).read_bytes())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    pending = path.with_suffix(path.suffix + ".pending")
    pending.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    pending.replace(path)


publication = load("native-tournament-test-publication.json")
emission = load("native-tournament-update-emission.json")
playing = load("runtime-tournament-updates-playing.json")
deployment = load("deployment.json")
server = load("server-process.json")
assert server["sha256"] == deployment["server_sha256"] == emission["server_sha256"]
assert digest(server["executable"]) == server["sha256"]
assert playing["pid"] == emission["game_pid"]
assert playing["sha256"] == deployment["sha256"] == emission["game_sha256"]
assert digest(playing["executable"]) == deployment["sha256"]
tournament = emission["tournament_id"]
assert tournament in publication["published_ids"]
assert emission["recipient_acceptance_seeded"] and not emission["map_started"]

if args.mode == "record":
    edit = load("native-tournament-live-edit.json")
    observation = load("runtime-tournament-live-edited.json")
    connection = observation["server_process_verified"]
    assert (
        connection["verified_live_process"] and connection["connection_receipt_matches"]
    )
    assert connection["pid"] == server["pid"] == edit["server_pid"]
    assert connection["sha256"] == server["sha256"] == edit["server_sha256"]
    assert observation["pid"] == playing["pid"] == edit["game_pid"]
    assert observation["sha256"] == deployment["sha256"] == edit["game_sha256"]
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_profile_sign_in_state"] == 2
    native = observation["native_tournament_request"]
    assert native["pending_task"] == native["retry_count"] == 0
    assert native["current_bracket"]["tournament_id"] == tournament
    before = playing["native_tournament_request"]["current_bracket"]
    assert before["participant_count"] == 16 and before["team_size"] == 2
    expected = dict(
        participant_count=8, team_size=1, team_count=8, round_count=3, local_team=0
    )
    assert all(
        native["current_bracket"][key] == value for key, value in expected.items()
    )
    # Read the bounded interval captured with the read-only native observation.
    # No task 145 request may explain the changed native bracket in this interval.
    end = observation["server_log_file_size"]
    assert edit["server_log_offset"] <= end <= (data / "server.log").stat().st_size
    with (data / "server.log").open("rb") as log:
        log.seek(edit["server_log_offset"])
        lines = log.read(end - edit["server_log_offset"]).decode(
            "utf-8", errors="replace"
        )
    assert (
        "TASK service=145 " not in lines
    ), "A tournament task invalidates idle-only proof"
    assert publication[
        "restored"
    ], "Restore exact publication bytes before recording proof"
    expiry = load("native-tournament-live-expire.json")
    expired = load("runtime-tournament-live-expired.json")
    expired_connection = expired["server_process_verified"]
    assert expired_connection["verified_live_process"]
    assert expired_connection["connection_receipt_matches"]
    assert expired_connection["pid"] == server["pid"] == expiry["server_pid"]
    assert expired_connection["sha256"] == server["sha256"] == expiry["server_sha256"]
    assert expired["pid"] == playing["pid"] == expiry["game_pid"]
    assert expired["sha256"] == deployment["sha256"] == expiry["game_sha256"]
    assert expiry["tournament_id"] == tournament
    assert expired["native_dw_hsm_connected_state_33"]
    cleared = expired["native_tournament_request"]
    assert cleared["state"] == cleared["pending_task"] == cleared["retry_count"] == 0
    assert cleared["current_bracket"]["tournament_id"] == 0
    assert cleared["current_bracket"]["participant_count"] == 0
    screenshot = data / "native-tournament-live-expired.jpg"
    assert screenshot.is_file() and screenshot.stat().st_size > 1024
    capture = load("native-tournament-live-expired.jpg.json")
    assert Path(capture["output"]) == screenshot
    assert datetime.fromisoformat(
        capture["captured_utc"].replace("Z", "+00:00")
    ) >= datetime.fromisoformat(expiry["edited_utc"])
    proof = dict(
        schema=1,
        passed=True,
        recorded_utc=datetime.now(timezone.utc).isoformat(),
        server_sha256=server["sha256"],
        game_sha256=deployment["sha256"],
        native_idle_publication_update_verified=True,
        game_or_server_restarted=False,
        client_tournament_task_during_edit=False,
        event_id=2010,
        observed_counts=expected,
        recipient_acceptance_seeded=True,
        temporary_publication_restored=True,
        native_join_assignment_verified=False,
        native_disband_callback_verified=True,
        disband_event_id=2012,
        disband_native_tournament_state_cleared=True,
        disband_screenshot_requires_visual_review=True,
        playable_tournament_verified=False,
        full_backend_verified=False,
        map_tests_performed=False,
        evidence=[
            dict(file="data/" + name, sha256=digest(data / name))
            for name in (
                "native-tournament-live-edit.json",
                "runtime-tournament-updates-playing.json",
                "runtime-tournament-live-edited.json",
                "native-tournament-live-expire.json",
                "runtime-tournament-live-expired.json",
                "native-tournament-live-expired.jpg",
                "native-tournament-live-expired.jpg.json",
                "native-tournament-test-publication.json",
            )
        ],
    )
    save(data / "native-tournament-live-verification.json", proof)
    print(
        "Native idle publication update verified with unchanged processes and no tournament task"
    )
else:
    assert not publication["restored"]
    assert playing["server_process_verified"]["pid"] == server["pid"]
    realm = data / "tournaments/5800"
    enrollment = json.loads((realm / "enrollments.json").read_bytes())
    entry = enrollment["players"][str(publication["owner"])]
    assert entry["id"] == tournament and entry["accepted"] and entry["live_updates"]
    path = realm / "catalog.json"
    catalog = json.loads(path.read_bytes())
    row = next(row for row in catalog["tournaments"] if row["id"] == tournament)
    assert row["live_updates"] and row["state"]["tournamentStatus"] == "PLAYING"
    assert not any(
        match["lobbyID"] for r in row["state"]["rounds"] for match in r["matches"]
    )
    now = datetime.now(timezone.utc)
    receipt = dict(
        schema=1,
        edited_utc=now.isoformat(),
        server_log_offset=(data / "server.log").stat().st_size,
        server_pid=server["pid"],
        game_pid=playing["pid"],
        server_sha256=server["sha256"],
        game_sha256=playing["sha256"],
        tournament_id=tournament,
        mode=args.mode,
        client_task_sent=False,
        engine_memory_written=False,
    )
    if args.mode == "edit":
        assert row["state"]["tournamentDefinition"]["teamSize"] == 2
        row["state"]["tournamentDefinition"].update(teamSize=1, numPlayers=8)
    else:
        row["expires"] = int(now.timestamp()) - 1
    # Record the log boundary before the atomic publication replacement.
    save(data / ("native-tournament-live-" + args.mode + ".json"), receipt)
    save(path, catalog)
    print(
        "Changed only the temporary publication; no task, reconnect or engine request"
    )
