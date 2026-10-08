"""Verify shipping-game mission callbacks and restart persistence evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    folder = args.folder.resolve()
    assert folder.is_relative_to((ROOT / "data").resolve())
    before, after, restarted = [
        load(folder / name)
        for name in ("native-before.json", "native-after.json", "native-restarted.json")
    ]
    first, second = [
        load(folder / name)
        for name in ("native-first-launch.json", "native-second-launch.json")
    ]
    deployment = load(folder / "deployment-after.json")
    server_hash = deployment["server_sha256"]
    source = load(folder / "source.json")
    linux = load(folder / "linux-build.json")
    assert linux["linux_compile_passed"] and source["windows_compile_passed"]
    assert linux["linux_server_sha256"] == server_hash
    assert (
        linux["source_archive_sha256"]
        == source["source_archive_sha256"]
        == digest(folder / "source.tar")
    )
    assert digest(folder / "iw8-dw-server-linux") == server_hash
    assert digest(Path(deployment["executable"])) == deployment["sha256"]
    assert after["pid"] == first["pid"] and restarted["pid"] == second["pid"]
    assert before["pid"] != first["pid"] != second["pid"]
    assert before["native_quests"]["clients"] == [[]]
    assert before["native_quests"]["pending_id"] == 1500
    assets = load(ROOT / "validation/20261008-replay-quest-assets.json")
    expected = {row["id"]: row for row in assets["quests"]}
    assert len(expected) == 232
    expected_active = {1500, 50000, 10057}
    owner = before["native_user_xuid"]
    for observed, launch in ((after, first), (restarted, second)):
        assert observed["sha256"] == launch["sha256"] == deployment["sha256"]
        assert observed["native_user_xuid"] == owner
        assert (
            observed["native_player_progression"] == before["native_player_progression"]
        )
        server = observed["server_process_verified"]
        assert server["verified_live_process"] and server["launch_receipt_matches"]
        assert server["sha256"] == server["process_sha256"] == server_hash
        assert (
            server["pid"]
            == first["server_process"]["pid"]
            == second["server_process"]["pid"]
        )
        assert len(observed["native_fences_controller_0"]) == 27
        assert all(row["passing"] for row in observed["native_fences_controller_0"])
        quests = observed["native_quests"]
        assert quests["definitions_initialized"] and len(quests["clients"]) == 1
        definitions = {
            stage["id"]: (stage["target"], group["category"])
            for group in quests["definitions"]
            for stage in group["stages"]
        }
        assert definitions == {
            identity: (row["target"], row["category"])
            for identity, row in expected.items()
        }
        rows = quests["clients"][0]
        assert {row["id"] for row in rows} == expected_active and len(rows) == 3
        assert all(
            row["active"]
            and row["progress"] == 0
            and row["category"] == expected[row["id"]]["category"]
            for row in rows
        )
        assert any(
            "service=125 task=3" in line and "error=0" in line
            for line in observed["server_log_since_launch"]
        )
    activations = [
        line
        for line in after["server_log_since_launch"]
        if "service=125 task=5" in line
    ]
    assert len(activations) == 3
    assert all(
        "operation=achievement-activated error=0" in line for line in activations
    )
    assert not any(
        "service=125 task=5" in line for line in restarted["server_log_since_launch"]
    )
    saved, saved_again = [
        load(folder / name)
        for name in (
            "native-durable-states.json",
            "native-durable-states-restarted.json",
        )
    ]
    assert saved == saved_again
    assert {row["id"] for row in saved if row["kind"] == 15} == expected_active
    for row in saved:
        assert row["status"] == 1 and row["target"] == expected[row["id"]]["target"]
        assert row["progress"] == 0 and row["activationTimestamp"] > 0
    shipping = load(folder / "shipping-file-hashes-before.json")
    assert shipping["game_sha256"] == digest(Path(deployment["executable"]))
    assert shipping["ini_sha256"] == digest(
        Path(deployment["executable"]).with_suffix(".ini")
    )
    protocol = {}
    for platform in ("windows", "linux"):
        for kind in ("quest", "startup"):
            name = f"{platform}-{kind}-verification.json"
            proof = load(folder / name)
            expected_hash = (
                source["windows_server_sha256"]
                if platform == "windows"
                else server_hash
            )
            assert proof["passed"] and proof["server_sha256"] == expected_hash
            assert len(proof["checks"]) == (10 if kind == "quest" else 102)
            protocol[name] = digest(folder / name)
    evidence = {
        path.relative_to(ROOT).as_posix(): digest(path)
        for path in [
            folder / name
            for name in (
                "native-before.json",
                "native-after.json",
                "native-restarted.json",
                "native-first-launch.json",
                "native-second-launch.json",
                "deployment-after.json",
                "native-durable-states.json",
                "native-durable-states-restarted.json",
                "shipping-file-hashes-before.json",
                "fixture-overlay.json",
                "source.json",
                "linux-build.json",
                "windows-quest-verification.json",
                "windows-startup-verification.json",
                "linux-quest-verification.json",
                "linux-startup-verification.json",
            )
        ]
    }
    reader_source = folder / "source/tools/native_quests.py"
    assert digest(reader_source) == source["inputs"]["tools/native_quests.py"]
    evidence[reader_source.relative_to(ROOT).as_posix()] = digest(reader_source)
    fixture_source = folder / "fixture-source/tools/test-lobby.py"
    fixture_overlay = load(folder / "fixture-overlay.json")
    assert digest(fixture_source) == fixture_overlay["overlays"]["tools/test-lobby.py"]
    assert fixture_overlay["base_source_archive_sha256"] == source["source_archive_sha256"]
    evidence[fixture_source.relative_to(ROOT).as_posix()] = digest(fixture_source)
    proof = dict(
        schema=1,
        passed=True,
        generated_utc=datetime.now(timezone.utc).isoformat(),
        server_sha256=server_hash,
        game_sha256=deployment["sha256"],
        game_executable_recompiled=False,
        game_and_ini_unchanged=True,
        native_activation_task_completion_verified=True,
        native_saved_state_query_completion_verified=True,
        native_state_restored_after_game_restart=True,
        native_definition_query_completion_verified=False,
        native_deactivation_completion_verified=False,
        native_mission_event_progression_verified=False,
        native_reward_grants_verified=False,
        complete_backend_verified=False,
        native_activated_stage_ids=sorted(expected_active),
        native_loaded_mission_groups=32,
        native_loaded_stage_count=232,
        original_target_research_receipt="validation/20261008-replay-quest-target.json",
        original_target_research_sha256=digest(
            ROOT / "validation/20261008-replay-quest-target.json"
        ),
        native_asset_receipt_sha256=digest(
            ROOT / "validation/20261008-replay-quest-assets.json"
        ),
        recorder_sha256=digest(Path(__file__)),
        observer_sha256=digest(ROOT / "tools/observe-game.py"),
        native_quest_reader_source=reader_source.relative_to(ROOT).as_posix(),
        native_quest_reader_sha256=digest(reader_source),
        evidence=evidence,
        protocol=protocol,
        scope="Shipping Replay native 125/5 activation callbacks and 125/3 saved-state restoration; no earned mission progress or completion/reward claims",
    )
    args.output.write_text(json.dumps(proof, indent=2) + "\n", newline="\n")
    print(
        "PASS: shipping native mission activation and saved-state restart callbacks; "
        + str(args.output)
    )


if __name__ == "__main__":
    main()
