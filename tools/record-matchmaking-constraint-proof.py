"""Bind Replay matchmaking constraint fixtures and native reconnect evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--native-proof", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


server_hash = digest(ROOT / "build/Release/iw8-dw-server.exe")
fixture_path = ROOT / "data/lobby-verification.json"
fixture = load(fixture_path)
deployment = load(ROOT / "data/deployment.json")
native_path = args.native_proof.resolve()
assert native_path.is_relative_to((ROOT / "validation").resolve())
native = load(native_path)
assert fixture["passed"] and fixture["server_sha256"] == server_hash
assert deployment["server_sha256"] == server_hash == native["server_sha256"]
assert (
    digest(Path(deployment["executable"]))
    == deployment["sha256"]
    == native["game_sha256"]
)
assert native["passed"] and native["native_relay_stability_after_restart_verified"]

prefixes = (
    "primary-slot requests reject",
    "native bnet platform constraints reject",
    "public and presence joins count primary plus secondary slots",
    "presence reassignments update secondary reservations",
    "pre-reservation persisted lobbies remain compatible",
)
covered = []
for prefix in prefixes:
    found = [check for check in fixture["checks"] if check.startswith(prefix)]
    assert len(found) == 1
    covered.extend(found)

receipt = {
    "schema": 1,
    "created_utc": datetime.now(timezone.utc).isoformat(),
    "server_sha256": server_hash,
    "game_sha256": deployment["sha256"],
    "engine_recompiled": False,
    "suite_grouped_checks": len(fixture["checks"]),
    "independent_encrypted_clients": 2,
    "covered_checks": covered,
    "lobby_verification_sha256": digest(fixture_path),
    "native_startup_reconnect_receipt": str(native_path.relative_to(ROOT)),
    "native_startup_reconnect_receipt_sha256": digest(native_path),
    "source_sha256": {
        name: digest(ROOT / name)
        for name in (
            "src/matchmaking_services.cpp",
            "tools/matchmaking_constraint_fixtures.py",
            "tools/matchmaking_membership_fixtures.py",
            "tools/public_matchmaking_fixtures.py",
            "tools/lobby_join_fixtures.py",
            "tools/tournament_fixtures.py",
            "tools/test-lobby.py",
        )
    },
    "target_contract_provenance": {
        "StartMatchmaking_primary_members_secondary_slots_platforms": "0x14104A450",
        "GetClientPlatform_bnet_enum_2": "0x1410AE340",
        "Platform_2_string_bnet": "0x1410AE2F0",
    },
    "native_secondary_slot_consumer_verified": False,
    "native_split_screen_gameplay_verified": False,
    "native_public_menu_join_verified": False,
    "two_network_gameplay_verified": False,
    "map_or_match_test_performed": False,
    "complete_backend_verified": False,
    "native_ui_limit": "Terms of Agreement screen remained unaccepted",
}
output = args.output.resolve()
assert output.is_relative_to((ROOT / "validation").resolve())
output.write_text(json.dumps(receipt, indent=2) + "\n")
print(
    "PASS: current-image primary-slot/platform constraints and scoped native reconnect"
)
