"""Record current-image protocol and separately scoped native lifecycle evidence."""

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


server = ROOT / "build/Release/iw8-dw-server.exe"
server_hash = digest(server)
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
    "host snapshots reject",
    "native WONT_CONNECT acknowledgment",
    "explicit READY_TO_REMOVE clears",
    "member removal recovers",
    "native in_game lobbies",
    "rejected relay packets retain",
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
            "src/relay_provider.cpp",
            "tools/matchmaking_membership_fixtures.py",
            "tools/public_matchmaking_fixtures.py",
            "tools/relay_transport_fixtures.py",
        )
    },
    "target_contract_provenance": {
        "StartMatchmaking_primary_members_and_tokens": "0x14104A450",
        "UpdateHostDoc_complete_snapshot_and_in_game": "0x14104BFA0",
        "TaskUpdateLobbyDocument_status_acknowledgment": "0x14104BA20",
        "UpdateLobbyDocument_strict_timestamp_order": "0x14104C6D0",
        "ReconcileExpectedPlayers": "0x141047E60",
        "SetPlayerCurrentStatus_enum_names": "0x141049B50",
    },
    "native_departure_callback_verified": False,
    "native_public_menu_join_verified": False,
    "host_migration_verified": False,
    "two_network_gameplay_verified": False,
    "map_or_match_test_performed": False,
    "complete_backend_verified": False,
    "native_ui_limit": "Terms of Agreement screen remained unaccepted",
}
output = args.output.resolve()
assert output.is_relative_to((ROOT / "validation").resolve())
output.write_text(json.dumps(receipt, indent=2) + "\n")
print(
    "PASS: current backend membership, native state values, document clocks and scoped reconnect receipts"
)
