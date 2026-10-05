"""Record current deployed server/game, native menu gates and persistent event ingestion."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = root / "data"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--observation", default="runtime-backend-final-verified.json")
parser.add_argument("--screenshot", default="native-backend-final-verified.jpg")
args = parser.parse_args()
for name in (args.observation, args.screenshot):
    if Path(name).name != name:
        raise ValueError("Use an evidence basename within data")

observation = json.loads((data / args.observation).read_bytes())
deployment = json.loads((data / "deployment.json").read_bytes())
fixture = json.loads((data / "lobby-verification.json").read_bytes())
launch = json.loads(
    (data / "current-runtime-launch.json").read_text(encoding="utf-8-sig")
)
server = observation["server_process_verified"]
hash_file = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert server["verified_live_process"] and server["connection_receipt_matches"]
assert server["sha256"] == deployment["server_sha256"] == fixture["server_sha256"]
assert hash_file(Path(server["executable"])) == server["sha256"]
assert (
    observation["sha256"]
    == deployment["sha256"]
    == hash_file(Path(observation["executable"]))
)
assert observation["pid"] == launch["pid"] and fixture["passed"]
assert (
    observation["native_dw_hsm_connected_state_33"]
    and observation["native_profile_sign_in_state"] == 2
)
assert (
    observation["platform_auth_state"] == observation["platform_connection_state"] == 2
)
assert observation["native_reconciliation"]["passing"]
fences = observation["native_fences_controller_0"]
assert len(fences) == 27 and all(row["passing"] and not row["failed"] for row in fences)
assert (
    observation["native_game_connection"]["frontend_scene"]
    and observation["native_game_connection"]["state"] == 9
)
queue = observation["native_presence_subscriptions"]
assert (
    queue["pending_unsubscribe"]
    == queue["batch_count"]
    == queue["unsubscribe_error_count"]
    == 0
)
requests = [
    line
    for line in observation["server_log_since_launch"]
    if "operation=achievement-events-recorded error=0" in line
    and "rest_service=ae.demonware.net" in line
]
assert requests
profile = (data / "platform-profile.bin").read_bytes()
import struct

user = struct.unpack_from("<Q", profile, 8)[0]
journal = json.loads(
    (data / "achievements/5800/5800" / str(user) / "events.json").read_bytes()
)
connection = observation.get("connection_receipt") or launch
started = int(
    datetime.fromisoformat(
        connection.get("requested_utc", connection.get("launched_utc")).replace(
            "Z", "+00:00"
        )
    ).timestamp()
)
assert any(
    row["event"]["name"] == "login_event" and row["event"]["timestamp"] >= started
    for row in journal["events"]
)
capture = json.loads(
    (data / (args.screenshot + ".json")).read_text(encoding="utf-8-sig")
)
proof = dict(
    schema=1,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    server_sha256=server["sha256"],
    game_sha256=observation["sha256"],
    game_pid=observation["pid"],
    server_pid=server["pid"],
    native_menu_verified=True,
    native_fences_verified=[row["name"] for row in fences],
    native_rest_event_request_and_persistence_verified=True,
    native_rest_event_task_completion_observed=False,
    native_binary_achievement_batch_completion_observed=False,
    native_multipart_upload_completion_observed=False,
    native_marketplace_purchase_completion_observed=False,
    full_backend_verified=False,
    map_tests_performed=False,
    independent_wire_checks=len(fixture["checks"]),
    successful_native_event_requests=requests,
    evidence=[
        dict(file=name, sha256=hash_file(data / name))
        for name in (args.observation, args.screenshot, "lobby-verification.json")
    ],
    capture=capture,
    source_sha256={
        str(path.relative_to(root)): hash_file(path)
        for path in (
            root / "src/achievement_services.cpp",
            root / "src/platform.cpp",
            root / "src/platform.h",
            root / "src/social_services.cpp",
            root / "src/content_services.cpp",
            root / "src/marketplace_services.cpp",
        )
    },
    scope="Native connected Multiplayer menu/startup gates and persistent game REST event request; binary batch proof remains wire-level",
)
(data / "native-backend-menu-verification.json").write_text(
    json.dumps(proof, indent=2) + "\n"
)
print(
    f'Native Multiplayer menu: 27 passing fences; {len(fixture["checks"])} independent checks; full backend still incomplete'
)
