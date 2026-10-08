"""Bind a stock signed counter upload and its native compensating update.

This recorder never changes the game or server. Read completion is a separate
gate: an upload acknowledgement cannot establish the counter download reader.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--counter-id", required=True, type=int)
    parser.add_argument("--counter-name", required=True)
    parser.add_argument("--increment", required=True, type=int)
    args = parser.parse_args()
    folder = args.evidence.resolve()
    output = args.output.resolve()
    if not folder.is_relative_to(ROOT) or not output.is_relative_to(ROOT):
        raise ValueError("Keep evidence and receipts inside the project")
    if not 0 < args.counter_id <= 0xFFFFFFFF or not args.increment:
        raise ValueError("Supply a real counter and nonzero signed increment")

    names = (
        "native-counter-queued.json",
        "native-counter-uploaded.json",
        "native-counter-compensated.json",
        "native-counter-restored.json",
    )
    paths = [folder / name for name in names]
    observations = [json.loads(path.read_bytes()) for path in paths]
    deployment_path = folder / "deployment.json"
    deployment = json.loads(deployment_path.read_bytes())
    launch_path = folder / "native-launch.json"
    launch = json.loads(launch_path.read_bytes())
    game_hash = launch["sha256"]
    states = []
    for item in observations:
        assert item["pid"] == launch["pid"] and item["sha256"] == game_hash
        live = item["server_process_verified"]
        assert live["verified_live_process"] and live["pid"] == deployment["pid"]
        assert live["sha256"] == live["process_sha256"] == deployment["sha256"]
        assert item["native_dw_hsm_connected_state_33"]
        state = item["native_global_counters"]
        assert state["initialized"] and state["table_available"]
        assert [str(args.counter_id), args.counter_name] in state["csv_rows"]
        assert state["write_interval_registration"] == dict(
            name="RKTNMKOMP", type=5, flags=0
        )
        states.append(state)
    assert any(
        row == dict(id=args.counter_id, value=args.increment)
        for row in states[0]["pending"]
    )
    for state, increment in zip(
        states[1:], (args.increment, -args.increment, -args.increment)
    ):
        assert any(
            row == dict(id=args.counter_id, value=increment) for row in state["upload"]
        )
        assert all(row["value"] == 0 for row in state["pending"])
        assert not state["write_pending"] and not state["active_tasks"]
    assert states[-1]["write_interval"] == 15
    times = [datetime.fromisoformat(item["observed_utc"]) for item in observations]
    assert times == sorted(times) and len(set(times)) == len(times)
    task_marker = "TASK service=23 task=1 operation=global-counter-increments-persisted error=0 results=0"
    lines = observations[-1]["server_log_since_launch"]
    uploads = [line for line in lines if task_marker in line]
    assert len(uploads) == 2, "Use an isolated two-upload observation window"
    for line, earliest, latest in zip(uploads, times[:2], times[1:3]):
        completed = datetime.fromisoformat(line.split(" ", 1)[0])
        assert earliest <= completed <= latest

    store_paths = [
        folder / name
        for name in (
            "counter-store-before.json",
            "counter-store-uploaded.json",
            "counter-store-restored.json",
        )
    ]
    before, uploaded, restored = [json.loads(path.read_bytes()) for path in store_paths]
    assert all(
        item["schema"] == 1 and item["title"] == 5800
        for item in (before, uploaded, restored)
    )
    key = str(args.counter_id)
    expected = dict(before["totals"])
    expected[key] = expected.get(key, 0) + args.increment
    assert uploaded["totals"] == expected
    assert (
        restored == before
    ), "A concurrent contribution requires a separately reviewed cleanup proof"
    assert (
        observations[0]["native_player_progression"]
        == observations[-1]["native_player_progression"]
    )
    paths += [
        deployment_path,
        launch_path,
        *store_paths,
        Path(__file__).resolve(),
        ROOT / "tools/observe-game.py",
    ]
    proof = dict(
        schema=1,
        passed=True,
        generated_utc=datetime.now(timezone.utc).isoformat(),
        server_sha256=deployment["sha256"],
        game_sha256=game_hash,
        backend_pid=deployment["pid"],
        game_pid=launch["pid"],
        native_counter_upload_completion_verified=True,
        native_compensating_signed_upload_verified=True,
        native_counter_read_completion_verified=False,
        counter_id=args.counter_id,
        counter_name=args.counter_name,
        temporary_increment=args.increment,
        temporary_increment_reversed=True,
        write_interval_restored_minutes=15,
        native_service_log=uploads,
        scope="Stock incrementcounter and periodic writer sent positive and negative signed values; native pending records and remote tasks retired, durable aggregate returned to its exact baseline. Task 23/2 download remains unverified.",
        evidence=[
            dict(path=path.resolve().relative_to(ROOT).as_posix(), sha256=digest(path))
            for path in paths
        ],
        full_backend_complete=False,
    )
    output.write_text(json.dumps(proof, indent=2) + "\n", newline="\n")
    print(
        "PASS: native signed counter upload, compensating upload and interval restoration; read gate remains open"
    )


if __name__ == "__main__":
    main()
