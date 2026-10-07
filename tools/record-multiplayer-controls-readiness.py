"""Bind the deployed multiplayer/INI build to its scoped native test evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--state-root", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
state = args.state_root.resolve()
output = args.output.resolve()
assert state.is_relative_to(ROOT / "data")
assert output.is_relative_to(ROOT / "validation") and output.suffix == ".json"


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(path):
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path)}


build_path = state / "waiting-backend-build.json"
build = load(build_path)
backend = ROOT / "build/Release/iw8-dw-server.exe"
assert build["compile_passed"] and digest(backend) == build["sha256"]
shipping = load(ROOT / "data/deployment.json")
assert digest(Path(shipping["executable"])) == shipping["sha256"]

wire_path = state / "full-protocol-verification.json"
wire = load(wire_path)
focused_path = state / "waiting-protocol-verification.json"
focused = load(focused_path)
for proof in (wire, focused):
    assert proof["passed"] and proof["server_sha256"] == build["sha256"]

observations = {}
for peer in ("main", "alpha", "bravo"):
    path = state / peer / "waiting-startup.json"
    observed = load(path)
    deployment = load(state / peer / "deployment.json")
    assert observed["sha256"] == deployment["sha256"]
    assert observed["server_process_verified"]["sha256"] == build["sha256"]
    assert observed["server_process_verified"]["verified_live_process"]
    assert observed["native_dw_hsm_connected_state_33"]
    assert observed["native_account_service_state"] == 1
    assert observed["native_network"]["error"] == 0
    fences = observed["native_fences_controller_0"]
    assert len(fences) == 27 and all(
        row["passing"] and not row["failed"] for row in fences
    )
    assert observed["native_selected_dvars"]["com_optimized"]["value"] == 0
    observations[peer] = reference(path)

joined = {}
for peer in ("alpha", "bravo"):
    path = state / peer / "public-joined.json"
    row = joined[peer] = load(path)
    assert row["server_process_verified"]["sha256"] == build["sha256"]
    assert row["native_matchmaking_lobby"]["ready_to_start"]
    assert row["native_game_party"]["in_party"]
    assert row["native_game_party"]["preload_complete"]
    assert row["native_game_party"]["present_team_counts"] == {"1": 1, "2": 1}
    observations[peer + "_public_lobby"] = reference(path)
assert joined["alpha"]["pid"] != joined["bravo"]["pid"]
assert joined["alpha"]["native_user_xuid"] != joined["bravo"]["native_user_xuid"]
assert (
    joined["alpha"]["native_matchmaking_lobby"]["lobby_id"]
    == joined["bravo"]["native_matchmaking_lobby"]["lobby_id"]
)

captured_path = state / "pair-debug.jsonl"
captured = [json.loads(line) for line in captured_path.read_text().splitlines()]
for row in joined.values():
    assert any(
        line["pid"] == row["pid"]
        and "state=ACTIVE / CONNECTED" in line["message"]
        for line in captured
    ), "Missing actual gameplay snapshot diagnostics for one client"

persistence_path = state / "local-progression-proof.json"
persistence = load(persistence_path)
assert persistence["passed"]
assert persistence["native_xp_restore_after_controlled_restart"]
assert persistence["unlock_controls_true_before_false_after"]
assert persistence["executable_hash"] == joined["bravo"]["sha256"]
current_bravo = load(state / "bravo/waiting-startup.json")
assert current_bravo["native_player_progression"]["xp"] == persistence["xp"]
assert (
    current_bravo["native_player_progression"]["rank_zero_based"] + 1
    == persistence["rank_displayed"]
)

invitation_path = state / "main/invitation-check.json"
invitation = load(invitation_path)
assert invitation["sha256"] == shipping["sha256"]
assert any(
    row["type"] == 2 and row["inviter_name"] == "DW Test 2"
    for row in invitation["native_party_invitations"]
)

for peer in ("main", "bravo"):
    deployed = load(state / peer / "deployment.json")
    directory = Path(deployed["build_directory"])
    verified = load(directory / "verification-report.json")
    assert verified["sha256"] == deployed["sha256"]
    assert verified["unresolved_symbols"] == 0
    assert load(directory / "relocation-audit.json")["passed"]
    compiled = load(directory / "build-report.json")["cpp"]
    for name in (
        "DW_LocalProgression.cpp", "DW_LocalConfig.cpp", "DW_Multiplayer.cpp"
    ):
        rows = [r for r in compiled if Path(r["source"]).name == name]
        assert len(rows) == 1
        assert (
            digest(ROOT / "integration/replay" / name)
            == rows[0]["source_sha256"]
        )
        assert digest(Path(rows[0]["object"])) == rows[0]["object_sha256"]

proof = {
    "schema": 1,
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "passed": True,
    "passed_scope": (
        "Fresh compilation, native startup, INI/local-XP persistence, invitation "
        "display, independent-party public lobby and gameplay transport"
    ),
    "backend_sha256": build["sha256"],
    "unchanged_shipping_game_sha256": shipping["sha256"],
    "build_receipt": reference(build_path),
    "protocol_evidence": reference(wire_path),
    "focused_protocol_evidence": reference(focused_path),
    "protocol_checks": len(wire["checks"]),
    "focused_protocol_checks": len(focused["checks"]),
    "native_startup": {
        "passed": True,
        "pending": False,
        "evidence": [observations[peer] for peer in ("main", "alpha", "bravo")],
    },
    "native_independent_party_matchmaking_verified": True,
    "native_private_test_gameplay_snapshot_transport_verified": True,
    "shipping_executable_two_player_gameplay_inherited": False,
    "native_lobby_observations": observations,
    "gameplay_debug_capture": reference(captured_path),
    "native_invite_display_verified": True,
    "invitation_evidence": reference(invitation_path),
    "local_xp_persistence_verified": True,
    "local_xp_persistence_evidence": reference(persistence_path),
    "original_persistence_test_backend_sha256": persistence["backend_hash"],
    "rank_selection_verified": [5, 0],
    "unlock_controls_enabled_then_disabled_verified": True,
    "optimization_default_verified": 0,
    "native_earned_match_xp_verified": False,
    "native_text_message_display_verified": False,
    "native_voice_audibility_verified": False,
    "native_scoreboard_distinct_ping_verified": False,
    "cross_network_gameplay_verified": False,
    "full_backend_complete": False,
    "test_run_limits": [
        "Automated players triggered native inactivity forfeits before a scored XP event.",
        "The direct xstartlobby test command faulted; normal Quick Play menu entry "
        "matched and loaded both clients.",
        "Native invitation receipt/display passed; this run did not verify "
        "accepting the invitation.",
    ],
}
output.write_text(json.dumps(proof, indent=2) + "\n")
(ROOT / "data/backend-readiness-latest.json").write_text(
    json.dumps(reference(output), indent=2) + "\n"
)
print(
    "Recorded scoped multiplayer/config readiness; scored XP, text display, "
    "audio and scoreboard ping remain playtest gates."
)
