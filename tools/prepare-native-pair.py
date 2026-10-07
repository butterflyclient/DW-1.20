"""Deploy a verified private test image under two owned root-folder filenames."""

import copy
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "data/native-pair-20261006"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--job-receipt", type=Path, default=ROOT / "data/workstation-job.json"
)
parser.add_argument(
    "--snapshot-receipt",
    type=Path,
    default=ROOT / "data/compiler-snapshot-receipt.json",
)
parser.add_argument("--state-root", type=Path, default=STATE)
parser.add_argument("--profiles-root", type=Path, default=STATE)
parser.add_argument("--server-receipt", type=Path)
parser.add_argument("--instances", nargs="+", choices=("alpha", "bravo"),
                    default=("alpha", "bravo"))
parser.add_argument("--preserve-ini", action="store_true",
                    help="Keep an owned test instance's name and endpoint settings")
args = parser.parse_args()
STATE = args.state_root.resolve()
profiles_root = args.profiles_root.resolve()
for directory in (STATE, profiles_root):
    assert directory.is_relative_to(
        ROOT / "data"
    ), "Keep private test state inside data"
job_receipt = args.job_receipt.resolve()
snapshot_receipt = args.snapshot_receipt.resolve()
for receipt in (job_receipt, snapshot_receipt):
    assert receipt.is_relative_to(ROOT / "data"), "Use an owned private build receipt"
job_bytes = job_receipt.read_bytes()
snapshot_bytes = snapshot_receipt.read_bytes()
job = json.loads(job_bytes)
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
(STATE / "compiled-job.json").write_bytes(job_bytes)
(STATE / "compiled-snapshot-receipt.json").write_bytes(snapshot_bytes)
normal = json.loads((ROOT / "data/deployment.json").read_text())
server_sha256 = normal["server_sha256"]
if args.server_receipt:
    server_receipt = args.server_receipt.resolve()
    assert server_receipt.is_relative_to(ROOT / "data")
    server = json.loads(server_receipt.read_text(encoding="utf-8-sig"))
    server_image = Path(server["executable"]).resolve()
    assert server_image == (ROOT / "build/Release/iw8-dw-server.exe").resolve()
    assert hashlib.sha256(server_image.read_bytes()).hexdigest() == server["sha256"]
    server_sha256 = server["sha256"]
game = Path(normal["executable"]).parent
assert game == Path(r"E:\IW8\Builds\1.20-replay")
assert (
    hashlib.sha256(Path(normal["executable"]).read_bytes()).hexdigest()
    == normal["sha256"]
)
for instance in dict.fromkeys(args.instances):
    index = 0 if instance == "alpha" else 1
    state = STATE / instance
    state.mkdir(parents=True, exist_ok=True)
    profile = profiles_root / instance
    for directory in ("appdata", "home"):
        (profile / directory).mkdir(parents=True, exist_ok=True)
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
    if not (args.preserve_ini and ini.exists()):
        ini.write_text(
            "host=127.0.0.1\n"
            f"player_name=DW Pair {instance.title()} 1006\n"
            f"game_port={3074 + index * 5}\n"
            "public_address=127.0.0.1\nlocal_address=127.0.0.1\n"
            "unlock_all=0\nrank=0\n"
            f"test_command_file={command_file}\ntest_enabled_file={enabled_file}\n"
        )
    executable.write_bytes(image)
    record = copy.deepcopy(normal)
    record.update(
        executable=str(executable),
        sha256=digest,
        server_sha256=server_sha256,
        build_directory=str(build),
        compiler_source_root=report["source_root"],
        job_id=job["id"],
        private_test_build=True,
        private_test_home_helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),
        test_command_file=command_file,
        test_enabled_file=enabled_file,
        localappdata=str(profile / "appdata"),
        home=str(profile / "home"),
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
