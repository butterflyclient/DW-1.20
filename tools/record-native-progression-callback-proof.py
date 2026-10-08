"""Verify private-game XP notification, local save, restart and retry evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return json.loads(path.read_bytes())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    folder = args.folder.resolve()
    assert folder.is_relative_to((ROOT / "data").resolve())
    before, after, restarted = [
        load(folder / name)
        for name in ("before.json", "after.json", "after-retry.json")
    ]
    first, second = [
        load(folder / name) for name in ("alpha/first-launch.json", "alpha/launch.json")
    ]
    initial, retry = [
        load(folder / name) for name in ("report.json", "retry-report.json")
    ]
    deployment = load(folder / "alpha/deployment.json")
    assert deployment["private_test_build"]
    assert digest(Path(deployment["executable"])) == deployment["sha256"]
    assert before["pid"] == after["pid"] == first["pid"]
    assert restarted["pid"] == second["pid"] != first["pid"]
    assert before["native_player_progression"]["xp"] == 0
    for observed, launch in ((before, first), (after, first), (restarted, second)):
        assert observed["sha256"] == launch["sha256"] == deployment["sha256"]
        assert observed["native_user_xuid"] == initial["user"] == retry["user"]
        server = observed["server_process_verified"]
        assert server["verified_live_process"] and server["launch_receipt_matches"]
        assert (
            server["sha256"] == server["process_sha256"] == deployment["server_sha256"]
        )
        assert (
            server["pid"]
            == first["server_process"]["pid"]
            == second["server_process"]["pid"]
        )
        assert len(observed["native_fences_controller_0"]) == 27
        assert all(row["passing"] for row in observed["native_fences_controller_0"])
    assert initial["accepted"] and retry["accepted"] and retry["retried"]
    assert initial["request_id"] == retry["request_id"]
    assert not initial["credentials_written"] and not retry["credentials_written"]
    assert not initial["sessions_reissued"] and not retry["sessions_reissued"]
    for row in (after, restarted):
        assert row["native_player_progression"]["xp"] == 3500
        assert row["native_player_progression"]["rank_zero_based"] == 1
    assert any(
        "service=125 task=2" in line and "error=0" in line
        for line in after["server_log_since_launch"]
    )
    journal = load(folder / "durable-events.json")
    assert journal["player_xp"] == 3500
    awards = [
        row
        for row in journal["events"]
        if row["event"]["name"] == "mp_addxp"
        and row["event"]["values"].get("Param0") == 3500
    ]
    assert len(awards) == 1 and awards[0]["event"]["timestamp"] == retry["timestamp"]
    saved = (folder / "local-progression-before-restart.bin").read_bytes()
    assert saved == (folder / "local-progression-after-retry.bin").read_bytes()
    assert len(saved) == 40
    magic, version, owner, xp, rank, reserved, checksum = struct.unpack(
        "<IIQQIIQ", saved
    )
    value = 14695981039346656037
    for byte in saved[:32]:
        value = ((value ^ byte) * 1099511628211) & (2**64 - 1)
    assert magic == 0x31505852 and version == 1 and owner == initial["user"]
    assert xp == 3500 and reserved == 0 and value == checksum
    evidence = [
        "before.json",
        "after.json",
        "after-retry.json",
        "alpha/first-launch.json",
        "alpha/launch.json",
        "alpha/deployment.json",
        "report.json",
        "retry-report.json",
        "send-self-initial.py",
        "durable-events.json",
        "local-progression-before-restart.bin",
        "local-progression-after-retry.bin",
    ]
    assert initial["tool_sha256"] == digest(folder / "send-self-initial.py")
    proof = dict(
        schema=1,
        passed=True,
        generated_utc=datetime.now(timezone.utc).isoformat(),
        server_sha256=deployment["server_sha256"],
        game_sha256=deployment["sha256"],
        private_test_game=True,
        native_player_xp_callback_verified=True,
        native_rank_callback_verified=True,
        local_progression_saved=True,
        native_progression_restored_after_game_restart=True,
        durable_retry_did_not_award_again=True,
        local_progression_bytes_preserved=True,
        game_issued_report_task_completion_verified=False,
        match_earned_xp_verified=False,
        after_action_animation_verified=False,
        shipping_image_completion_inherited=False,
        full_backend_complete=False,
        xp_before=0,
        xp_after=3500,
        rank_zero_based_after=1,
        recorder_sha256=digest(Path(__file__)),
        scope="Independent authenticated self-report reached the real native XP/rank callback, saved locally, survived game restart and did not double-award on retry. No match, game-issued report task or AAR animation was tested.",
        evidence={
            str((folder / name).relative_to(ROOT).as_posix()): digest(folder / name)
            for name in evidence
        },
    )
    args.output.write_text(json.dumps(proof, indent=2) + "\n", newline="\n")
    print(
        "PASS: native XP/rank callback, local save, restart restoration and durable retry"
    )


if __name__ == "__main__":
    main()
