"""Bind a populated native AB-treatment/reconnect pass and its cleanup to exact images."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("active", type=Path)
parser.add_argument("restarted", type=Path)
parser.add_argument("restored", type=Path)
parser.add_argument("--expected", type=Path, required=True)
parser.add_argument("--preserved", type=Path, required=True)
parser.add_argument("--cleanup", type=Path, required=True)
parser.add_argument(
    "--output", type=Path, default=ROOT / "validation/20261006-abtesting-native.json"
)
args = parser.parse_args()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


deployment = load(ROOT / "data/deployment.json")
expected = load(args.expected)
active, restarted, restored = map(load, (args.active, args.restarted, args.restored))
for observation in (active, restarted, restored):
    assert observation["sha256"] == deployment["sha256"]
    assert observation["server_process_verified"]["verified_live_process"]
    assert (
        observation["server_process_verified"]["sha256"] == deployment["server_sha256"]
    )
    assert observation["pid"] == active["pid"]
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_profile_sign_in_state"] == 2
    assert observation["native_social_online_status"] == 2
    ab = observation["native_ab_testing"]
    assert ab["completed"] and not ab["failed"]
    assert observation["native_selected_dvars"][expected["dvar"]]["type"] == 5
for observation in (active, restarted):
    ab = observation["native_ab_testing"]
    assert ab["enrollment_count"] == len(ab["enrollments"]) == 1
    enrollment = ab["enrollments"][0]
    assert enrollment["test_id"] == expected["test_id"]
    assert enrollment["cohort_id"] == expected["cohort_id"]
    assert len(enrollment["treatments"]) == 1
    treatment = enrollment["treatments"][0]
    assert treatment["starts_in"] == 0 and treatment["ends_in"] > 0
    assert treatment["modifiers_sha256"] == expected["modifiers_sha256"]
    assert (
        observation["native_selected_dvars"][expected["dvar"]]["value"]
        == expected["value"]
    )
assert (
    active["server_process_verified"]["pid"]
    != restarted["server_process_verified"]["pid"]
)
assert restarted["server_process_verified"]["connection_receipt_matches"]
assert restarted["connection_receipt"]["command"] == "dw_restart"
assert any("DW_RESTART_CONNECTED" in row for row in restarted["client_markers"])
assert any(
    "service=194 task=1 " in row and "error=0" in row
    for row in restarted["server_log_since_launch"]
)
for observation in (restarted, restored):
    fences = observation["native_fences_controller_0"]
    assert len(fences) == 27 and all(
        row["passing"] and not row["failed"] for row in fences
    )
    assert observation["native_relay_transport"]["state"] == 6
assert restored["native_ab_testing"]["enrollment_count"] == 0
assert restored["native_ab_testing"]["enrollments"] == []
assert restored["native_selected_dvars"][expected["dvar"]]["value"] == 16
preserved = load(args.preserved)
assert len(preserved) == 3 and all(
    digest(Path(row["path"])) == row["sha256"] for row in preserved
)
cleanup = load(args.cleanup)
assert cleanup["temporary_catalogs_removed"]
assert cleanup["prior_enrollment_states_restored_before_native_refresh"]
assert cleanup["owned_game_closed_normally"] and cleanup["owned_test_controls_removed"]
assert digest(Path(deployment["executable"])) == deployment["sha256"]
assert digest(ROOT / "build/Release/iw8-dw-server.exe") == deployment["server_sha256"]
sources = (
    "src/abtesting_services.cpp",
    "src/abtesting_services.h",
    "src/engagement_services.cpp",
    "tools/observe-game.py",
    "tools/record-native-abtesting-proof.py",
)
receipt = {
    "schema": 1,
    "passed": True,
    "observed_utc": datetime.now(timezone.utc).isoformat(),
    "server_sha256": deployment["server_sha256"],
    "game_sha256": deployment["sha256"],
    "sources": {name: digest(ROOT / name) for name in sources},
    "native_ab_enrollment_completion_verified": True,
    "native_populated_treatment_and_registered_dvar_verified": True,
    "same_process_backend_restart_and_native_ab_refetch_verified": True,
    "native_test_id": expected["test_id"],
    "native_cohort_id": expected["cohort_id"],
    "native_modifier_sha256": expected["modifiers_sha256"],
    "native_context": expected["context"],
    "registered_dvar": expected["dvar"],
    "temporary_value": expected["value"],
    "restored_value": 16,
    "empty_default_enrollment_verified_after_cleanup": True,
    "native_fences_passed_after_restart_and_cleanup": 27,
    "game_ini_and_machine_identity_preserved": True,
    "owned_game_closed_normally": True,
    "owned_test_controls_removed": True,
    "map_or_match_test_performed": False,
    "two_network_multiplayer_verified": False,
    "complete_backend_verified": False,
    "observations": {
        path.resolve().relative_to(ROOT).as_posix(): digest(path)
        for path in (args.active, args.restarted, args.restored, args.cleanup)
    },
    "scope": "One explicit active dvar treatment consumed by the unchanged native game before and after backend restart; future schedules and other modifier types have separate validation scopes.",
}
output = args.output.resolve()
assert output.is_relative_to(ROOT / "validation")
output.write_text(json.dumps(receipt, indent=2) + "\n")
print("PASS: populated native AB treatment, reconnect, empty default and owned cleanup")
