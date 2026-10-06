"""Verify native dw_restart against a still-running backend, without a map test."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("before", type=Path)
parser.add_argument("after", type=Path)
parser.add_argument("stable", type=Path)
parser.add_argument(
    "--output",
    type=Path,
    default=ROOT / "validation/20261006-same-server-native-reconnect.json",
)
args = parser.parse_args()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


deployment = load(ROOT / "data/deployment.json")
before, after, stable = map(load, (args.before, args.after, args.stable))
for observation in (before, after, stable):
    assert observation["sha256"] == deployment["sha256"]
    assert observation["pid"] == before["pid"]
    server = observation["server_process_verified"]
    assert (
        server["verified_live_process"]
        and server["sha256"] == deployment["server_sha256"]
    )
    assert server["pid"] == before["server_process_verified"]["pid"]
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_profile_sign_in_state"] == 2
    assert observation["native_social_online_status"] == 2
    assert (
        observation["native_network"]["mode"] == 1
        and observation["native_network"]["error"] == 0
    )
    fences = observation["native_fences_controller_0"]
    assert len(fences) == 27 and all(
        row["passing"] and not row["failed"] for row in fences
    )
    lists = observation["native_crossplay_friend_lists"]
    assert len(lists) == 3 and all(
        row["fetch_state"] == 2 and row["count"] == 0 for row in lists
    )
    assert observation["native_relay_transport"]["state"] == 6
    assert observation["native_relay_client_auth"]["state"] == 2
    assert observation["native_relay_association"]["state"] == 3
for field in ("native_user_xuid", "native_user_platform_id", "native_user_name"):
    assert before[field] == after[field] == stable[field]
assert (
    before["native_relay_client_auth"]["native_wire_sha256"]
    != after["native_relay_client_auth"]["native_wire_sha256"]
)
old, current = before["native_relay_association"], after["native_relay_association"]
assert old["relay_id"] == current["relay_id"]
assert old["route"] != current["route"] and old["join_id"] != current["join_id"]
assert after["connection_receipt"]["command"] == "dw_restart"
assert after["server_process_verified"]["connection_receipt_matches"]
fallbacks = sum("DW_RESTART_RELAY_RESUME" in row for row in after["client_markers"])
assert fallbacks in (0, 1), "Native relay fallback dispatched more than once"
assert sum("DW_RESTART_RELAY_DRAINED" in row for row in after["client_markers"]) == 1
assert any("DW_RESTART_CONNECTED" in row for row in after["client_markers"])
assert any(
    "service=145 task=26 " in row and "error=0" in row
    for row in after["server_log_since_launch"]
)
elapsed = (
    datetime.fromisoformat(stable["observed_utc"])
    - datetime.fromisoformat(after["observed_utc"])
).total_seconds()
assert elapsed >= 60
for field in (
    "native_relay_association",
    "native_relay_transport",
    "native_relay_client_auth",
):
    assert stable[field] == after[field]
health, initial = stable["server"]["relay"], after["server"]["relay"]
assert health["active_associations"] == 1
# verified_associations is the backend's cumulative handshake counter, not the
# current association count. One old and one fresh verification is expected.
assert health["verified_associations"] == initial["verified_associations"]
assert (
    initial["verified_associations"]
    == before["server"]["relay"]["verified_associations"] + 1
)
assert health["rejected_packets"] == initial["rejected_packets"] == 0
pings = health["ping_replies"] - initial["ping_replies"]
assert pings > 0
events_path = ROOT / "data/relay/transport-events.jsonl"
events = [json.loads(line) for line in events_path.read_text().splitlines()]
started = datetime.fromisoformat(
    after["connection_receipt"]["requested_utc"]
).timestamp()
matching = [
    row
    for row in events
    if row["action"] == "established"
    and row["time"] >= started
    and all(
        row[key] == current[key]
        for key in ("relay_id", "route", "user", "title", "port", "verification_sha256")
    )
]
assert matching
retired = [
    row
    for row in events
    if row["action"] == "disconnect"
    # Relay events use integer Unix seconds; the dispatch receipt retains
    # fractional seconds. Its containing one-second event interval must overlap
    # dispatch, and the exact old route/token must retire before the fresh bind.
    and row["time"] + 1 > started
    and row["time"] < matching[-1]["time"]
    and all(
        row[key] == old[key]
        for key in ("relay_id", "route", "user", "title", "port", "verification_sha256")
    )
]
assert retired, "Old native association did not send an authenticated disconnect"
report = load(Path(deployment["build_directory"]) / "build-report.json")
source = "integration/replay/DW_LocalPlatform.cpp"
source_hash = digest(ROOT / source)
assert report["sha256"] == deployment["sha256"]
assert any(row["source_sha256"] == source_hash for row in report["cpp"])
assert "func_1412BF930" in report["symbols"]
assert "func_14219F1C0" in report["symbols"]
assert digest(Path(deployment["executable"])) == deployment["sha256"]
assert digest(ROOT / "build/Release/iw8-dw-server.exe") == deployment["server_sha256"]
receipt = dict(
    schema=1,
    passed=True,
    observed_utc=datetime.now(timezone.utc).isoformat(),
    game_sha256=deployment["sha256"],
    server_sha256=deployment["server_sha256"],
    compiler_job=deployment["job_id"],
    sources={
        source: source_hash,
        "tools/observe-game.py": digest(ROOT / "tools/observe-game.py"),
        "tools/record-native-same-server-reconnect.py": digest(Path(__file__)),
    },
    same_server_and_game_process_preserved=True,
    native_relay_dependency_callback_fallback_count=fallbacks,
    old_native_relay_authenticated_disconnect_verified=True,
    fresh_native_relay_token_and_udp_association_verified=True,
    native_account_and_profile_preserved=True,
    native_fences_passing=27,
    native_friend_lists_completed_and_empty=True,
    native_relay_stability_verified=True,
    stable_seconds=elapsed,
    keepalive_replies=pings,
    rejected_packets=0,
    established_event=matching[-1],
    disconnected_event=retired[-1],
    relay_event_clock_resolution_seconds=1,
    observations={
        path.resolve().relative_to(ROOT).as_posix(): digest(path)
        for path in (args.before, args.after, args.stable)
    },
    map_or_match_test_performed=False,
    two_network_party_gameplay_verified=False,
    complete_backend_verified=False,
)
output = args.output.resolve()
assert output.is_relative_to(ROOT / "validation")
output.write_text(json.dumps(receipt, indent=2) + "\n")
deployment["local_player_identity"]["native_runtime_verified"] = True
deployment["local_player_identity"]["native_proof"] = str(output)
deployment["runtime_test"] = (
    "Focused native startup and same-server dw_restart passed: unchanged account/profile, "
    "27 fences, empty completed friend lists, fresh credential and authenticated UDP relay; "
    "two-network gameplay remains pending"
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
    "completed empty accepted/incoming/outgoing friend lists",
    "same-server and same-game process reconnect with unchanged account",
    "fresh relay credential and authenticated native UDP association",
]
readiness_path.write_text(json.dumps(readiness, indent=2) + "\n")
print(
    "PASS: same-server native reconnect, fresh relay, 27 fences and stable keepalives"
)
