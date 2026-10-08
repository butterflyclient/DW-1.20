"""Bind native counter download completion to a private compiler/game cohort.

This recorder is read-only. The diagnostic command calls the original getter;
the original frame, SDK reader and task manager own all cache/task changes.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    folder, output = args.evidence.resolve(), args.output.resolve()
    if not folder.is_relative_to(ROOT / "data") or not output.is_relative_to(ROOT):
        raise ValueError("Use owned project evidence and output paths")
    paths = [
        folder / name
        for name in (
            "native-before-read.json",
            "native-after-read.json",
            "deployment.json",
            "native-launch.json",
            "input.json",
            "job.json",
            "snapshot.json",
            "server-after-read.json",
            "counter-store-before.json",
            "counter-store-after.json",
            "native-read-command.txt",
        )
    ]
    before, after, deployment, launch, inputs = [load(path) for path in paths[:5]]
    job, snapshot, server, store_before, store_after = [
        load(path) for path in paths[5:10]
    ]
    assert job["status"] == "succeeded" and job["id"] == deployment["job_id"]
    assert Path(snapshot["snapshot"]) == Path(deployment["compiler_source_root"])
    build = Path(deployment["build_directory"]).resolve()
    assert build.is_relative_to(ROOT / "data/workstation-builds")
    report = load(build / "build-report.json")
    verification = load(build / "verification-report.json")
    relocations = load(build / "relocation-audit.json")
    game_hash = deployment["sha256"]
    assert (
        game_hash
        == launch["sha256"]
        == report["sha256"]
        == verification["sha256"]
        == relocations["sha256"]
    )
    assert verification["unresolved_symbols"] == 0 and relocations["passed"]
    assert deployment["diagnostic_only"] and deployment["shipping_executable_unchanged"]
    assert inputs["shipping_game_sha256"] == deployment["shipping_executable_sha256"]
    platform = [
        row
        for row in report["cpp"]
        if Path(row["source"]).name == "DW_LocalPlatform.cpp"
    ]
    assert (
        len(platform) == 1
        and platform[0]["source_sha256"] == inputs["private_platform_sha256"]
    )
    assert report["symbols"]["func_1414F2320"] > 0
    assert any("dw_localTestCounter" in name for name in report["symbols"])
    assert (
        server["verified_live_process"]
        and server["sha256"] == server["process_sha256"] == deployment["server_sha256"]
    )
    for observation in (before, after):
        assert (
            observation["pid"] == launch["pid"] and observation["sha256"] == game_hash
        )
        live = observation["server_process_verified"]
        assert live["verified_live_process"] and live["pid"] == server["pid"]
        assert live["sha256"] == live["process_sha256"] == server["sha256"]
        assert observation["native_dw_hsm_connected_state_33"]
    first, last = before["native_global_counters"], after["native_global_counters"]
    assert first["initialized"] and first["table_available"] and 0 < first["count"] < 64
    assert (
        first["csv_rows"] == last["csv_rows"]
        and len(first["csv_rows"]) == first["count"] == last["count"]
    )
    ids = [int(row[0]) for row in first["csv_rows"]]
    assert len(ids) == len(set(ids)) and all(0 <= value < 0xFFFFFFFF for value in ids)
    assert first["download"] == [dict(id=value, value=-1) for value in ids]
    assert (
        store_before == store_after
        and store_after["schema"] == 1
        and store_after["title"] == 5800
    )
    expected = [
        dict(id=value, value=store_after["totals"].get(str(value), 0)) for value in ids
    ]
    assert last["download"] == expected
    assert (
        last["initialized"] and last["table_available"] and not last["read_requested"]
    )
    assert not last["active_tasks"] and not last["write_pending"]
    assert (
        first["pending"]
        == last["pending"]
        == [dict(id=value, value=0) for value in ids]
    )
    assert first["upload"] == last["upload"]
    for state in (first, last):
        assert state["read_interval"] == state["write_interval"] == 15
        assert state["read_interval_registration"] == dict(
            name="MKMOOLQQLO", flags=0, type=5
        )
    assert before["native_player_progression"] == after["native_player_progression"]
    marker = f"TASK service=23 task=2 operation=global-counter-totals-read error=0 results={len(ids)}"
    lines = [
        line for line in after["server_log_since_launch"] if "TASK service=23 " in line
    ]
    assert (
        len(lines) == 1 and marker in lines[0]
    ), "Isolate one download, without uploads"
    start = datetime.fromisoformat(before["observed_utc"])
    finish = datetime.fromisoformat(after["observed_utc"])
    completed = datetime.fromisoformat(lines[0].split(" ", 1)[0])
    assert start <= completed <= finish
    sequence, command = paths[10].read_text().split(" ", 1)
    assert sequence.isdigit() and command == "dw_localTestCounter 0"
    restored_path = folder / "shipping-restored-ready.json"
    restored_launch_path = folder / "shipping-restored-launch.json"
    cleanup_path = folder / "cleanup.json"
    restored, restored_launch, cleanup = [
        load(path) for path in (restored_path, restored_launch_path, cleanup_path)
    ]
    assert (
        restored["sha256"]
        == restored_launch["sha256"]
        == inputs["shipping_game_sha256"]
    )
    assert (
        restored["pid"] == restored_launch["pid"] and restored["pid"] != launch["pid"]
    )
    assert (
        restored["native_dw_hsm_connected_state_33"]
        and restored["platform_auth_state"] == 2
    )
    assert len(restored["native_fences_controller_0"]) == 27
    assert all(fence["passing"] for fence in restored["native_fences_controller_0"])
    assert restored["native_player_progression"] == before["native_player_progression"]
    assert cleanup["shipping_executable_sha256"] == inputs["shipping_game_sha256"]
    assert not Path(cleanup["private_executable_removed"]).exists()
    assert not Path(cleanup["private_ini_removed"]).exists()
    paths += [restored_path, restored_launch_path, cleanup_path]
    paths += [
        build / name
        for name in (
            "build-report.json",
            "verification-report.json",
            "relocation-audit.json",
        )
    ]
    paths += [
        Path(__file__).resolve(),
        ROOT / "tools/prepare-native-counter-read-test.py",
        ROOT / "tools/observe-game.py",
    ]
    proof = dict(
        schema=1,
        passed=True,
        generated_utc=datetime.now(timezone.utc).isoformat(),
        server_sha256=server["sha256"],
        game_sha256=game_hash,
        shipping_game_sha256=inputs["shipping_game_sha256"],
        backend_pid=server["pid"],
        game_pid=launch["pid"],
        native_counter_read_completion_verified=True,
        native_original_getter_called=True,
        native_counter_cache_matches_durable_totals=True,
        native_counter_task_retired=True,
        private_diagnostic_command=True,
        shipping_executable_native_completion_inherited=False,
        counter_upload_verified=False,
        counter_store_unchanged=True,
        progression_unchanged=True,
        read_interval_minutes=15,
        original_getter_va=inputs["original_getter_va"],
        linked_getter_rva=report["symbols"]["func_1414F2320"],
        native_download=expected,
        native_service_log=lines,
        scope="Private freshly compiled root-folder game called the original counter getter. The original frame sent task 23/2, the SDK populated all CSV-defined cached values and the task retired. No uploads or direct cache/task writes; shipping-image completion is not inherited.",
        evidence=[
            dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(path))
            for path in paths
        ],
        full_backend_complete=False,
        normal_game_restored=True,
        normal_game_native_fences_passed=27,
        temporary_root_game_files_removed=True,
    )
    output.write_text(json.dumps(proof, indent=2) + "\n", newline="\n")
    print(
        f"PASS: native counter download populated {len(ids)} values and retired its task; server store unchanged"
    )


if __name__ == "__main__":
    main()
