"""Deploy a verified private test image under two owned root-folder filenames."""

import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "data/native-pair-20261006"
job = json.loads((ROOT / "data/workstation-job.json").read_text())
assert job["status"] == "succeeded" and job["profile"] == "engine"
build = Path(job["build_directory"]).resolve()
assert build.parent == (ROOT / "data/workstation-builds").resolve()
report = json.loads((build / "build-report.json").read_text())
verification = json.loads((build / "verification-report.json").read_text())
audit = json.loads((build / "relocation-audit.json").read_text())
artifacts = [row for row in job["artifacts"] if row["path"].endswith(".exe")]
assert len(artifacts) == 1
artifact = Path(artifacts[0]["path"])
image = artifact.read_bytes()
digest = hashlib.sha256(image).hexdigest()
assert (
    digest
    == artifacts[0]["sha256"]
    == report["sha256"]
    == verification["sha256"]
    == audit["sha256"]
)
assert verification["unresolved_symbols"] == 0 and audit["passed"]
assert len(verification["dw_private_test_paths"]) == 28
assert all(row["passed"] for row in verification["dw_private_test_paths"])
helper = ROOT / "integration/testing/DW_TestHomePath.cpp"
assert any(
    row["source_sha256"] == hashlib.sha256(helper.read_bytes()).hexdigest()
    for row in report["cpp"]
)
STATE.mkdir(parents=True, exist_ok=True)
(STATE / "compiled-job.json").write_bytes(
    (ROOT / "data/workstation-job.json").read_bytes()
)
(STATE / "compiled-snapshot-receipt.json").write_bytes(
    (ROOT / "data/compiler-snapshot-receipt.json").read_bytes()
)
normal = json.loads((ROOT / "data/deployment.json").read_text())
game = Path(normal["executable"]).parent
assert game == Path(r"E:\IW8\Builds\1.20-replay")
assert (
    hashlib.sha256(Path(normal["executable"]).read_bytes()).hexdigest()
    == normal["sha256"]
)
for index, instance in enumerate(("alpha", "bravo")):
    state = STATE / instance
    state.mkdir(parents=True, exist_ok=True)
    for directory in ("appdata", "home"):
        (state / directory).mkdir(exist_ok=True)
    executable = game / f"game_dx12_ship_replay_pair_{instance}_dw.exe"
    receipt = state / "deployment.json"
    if executable.exists():
        assert receipt.exists(), "Refusing to replace an unowned game image"
        previous = json.loads(receipt.read_text())
        assert hashlib.sha256(executable.read_bytes()).hexdigest() == previous["sha256"]
    command_file = f"replay-dw-test-{instance}.command"
    enabled_file = f"replay-dw-test-{instance}.enabled"
    ini = executable.with_suffix(".ini")
    assert not ini.exists() or receipt.exists(), "Refusing to replace an unowned INI"
    ini.write_text(
        "host=127.0.0.1\n"
        f"player_name=DW Pair {instance.title()} 1006\n"
        f"game_port={3074 + index * 5}\n"
        "public_address=127.0.0.1\nlocal_address=127.0.0.1\n"
        f"test_command_file={command_file}\ntest_enabled_file={enabled_file}\n"
    )
    executable.write_bytes(image)
    record = copy.deepcopy(normal)
    record.update(
        executable=str(executable),
        sha256=digest,
        build_directory=str(build),
        compiler_source_root=report["source_root"],
        job_id=job["id"],
        private_test_build=True,
        private_test_home_helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),
        test_command_file=command_file,
        test_enabled_file=enabled_file,
        localappdata=str(state / "appdata"),
        home=str(state / "home"),
        game_port=3074 + index * 5,
        primary_executable_unchanged_sha256=normal["sha256"],
        evidence_scope="Private native pair test; no two-game connection asserted by deployment",
    )
    # Do not inherit the normal executable's compiled-source/native receipts.
    # This private image has its own source snapshot, objects and test gates.
    record.pop("platform_sources", None)
    record.pop("sources", None)
    record.pop("local_player_identity", None)
    record.pop("workstation_artifact", None)
    record["source_snapshot_receipt"] = str(STATE / "compiled-snapshot-receipt.json")
    record["private_compiled_sources"] = report["cpp"]
    receipt.write_text(json.dumps(record, indent=2) + "\n")
    (game / enabled_file).write_text("owned native pair development opt-in\n")
    print(
        f"Prepared {instance}: {executable.name}, configured port {record['game_port']}"
    )
print("Primary DW executable and INI were not replaced.")
