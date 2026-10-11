"""Focused source ownership and single-target workflow checks; no game launch."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import dw_client

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--check-lock", action="store_true")
parser.add_argument("--output", type=Path)
args = parser.parse_args()
if args.check_lock:
    try:
        with dw_client.pipeline_lock():
            raise SystemExit("Unexpected concurrent build lock")
    except RuntimeError:
        print("Concurrent build refused")
        raise SystemExit(0)

root = dw_client.ROOT
config, state, base = dw_client.settings()
manifest = dw_client.read(state / "source-manifest.json")
latest = dw_client.read(state / "latest-job.json")
directory = Path(latest["directory"])
receipt = dw_client.read(directory / "source-receipt.json")
source = Path(receipt["snapshot"])
assert config["target"] == "game_dx12_ship_replay_dw.exe"
ready = dw_client.read(latest["readiness"])
assert ready["passed"] and len(receipt["cpp_sources"]) == ready["fresh_cpp_units"]
assert not receipt["source_options"]
assert (
    receipt["full_host_optimizations_required"] and receipt["active_updater_required"]
)
assert len(set(manifest["overlays"].values())) == len(manifest["overlays"])
for destination, authored in manifest["overlays"].items():
    assert not (base / destination).exists(), destination
    assert (root / authored).is_file()
authored = {item["compiled_source"]: item for item in receipt["source_inputs"]}
for name in receipt["cpp_sources"]:
    if name in authored:
        item = authored[name]
        assert dw_client.digest(root / item["source"]) == item["source_sha256"], name
        assert dw_client.digest(source / name) == item["compiled_sha256"], name
    elif (base / name).exists():
        assert (source / name).read_bytes() == (base / name).read_bytes(), name
    else:
        assert name in manifest["generated_sources"], name
    assert dw_client.digest(source / name) == receipt["cpp_sources"][name]
units = dw_client.read(source / "source-workstation/units.json")["units"]
identities = [unit["function_id"] for unit in units]
assert len(set(identities)) == len(identities)
for unit in units:
    if unit.get("kind") == "cpp":
        assert (
            unit["sha256"]
            == unit["revision"]
            == dw_client.digest(source / unit["source"])
        )
host = dw_client.read(source / "generated/host-scale-integration.json")
symbols = {item["symbol"] for item in host["replacements"]}
assert set(config["required_host_routines"]).issubset(symbols)
assert (
    'Dvar_RegisterInt("com_optimized", 1, 0, 2'
    in (source / "src/Com_Optimized.cpp").read_text()
)
assert (
    "unsigned s_state = 0, s_reported = 0;"
    in (source / "src/DW_ExecutableUpdate.cpp").read_text()
)
checks = [
    "One production filename and no source/revision feature selection",
    "Every compiled CPP source matches its current single authored owner or unchanged compiler foundation",
    "Authored sources have one owner; compiler base contains no duplicate editable copies",
    "Source identities remain unique and revisions match frozen CPP hashes",
    "Latest bot geometry/navigation are mandatory; com_optimized defaults to 1 and updater remains active",
]
with tempfile.TemporaryDirectory(
    prefix="source-revision-check-", dir=root / "data"
) as temporary:
    isolated = Path(temporary)
    (isolated / "src").mkdir()
    recovered = isolated / "src/Recovered.cpp"
    added = isolated / "src/Added.cpp"
    recovered.write_text('extern "C" int Recovered() { return 1; }\n')
    added.write_text('extern "C" int Added() { return 2; }\n')
    dw_client.save(
        isolated / "source-workstation/units.json",
        {
            "units": [
                {
                    "kind": "cpp",
                    "source": "src/Recovered.cpp",
                    "revision": "old",
                    "sha256": "old",
                }
            ]
        },
    )
    dw_client.save(
        isolated / "source-workstation/user-functions.json",
        {
            "functions": {
                "added": {"path": "src/Added.cpp", "revision": "old", "sha256": "old"}
            }
        },
    )
    for version in (2, 3):
        added.write_text(f'extern "C" int Added() {{ return {version}; }}\n')
        dw_client.sync_cpp_revisions(isolated)
        unit = dw_client.read(isolated / "source-workstation/units.json")["units"][0]
        user = dw_client.read(isolated / "source-workstation/user-functions.json")[
            "functions"
        ]["added"]
        assert unit["revision"] == unit["sha256"] == dw_client.digest(recovered)
        assert user["revision"] == user["sha256"] == dw_client.digest(added)
checks.append(
    "Edits to both recovered and new C++ functions refresh their compile-time revision hashes"
)
dw_client.require_current_sources(receipt)
with tempfile.TemporaryDirectory(
    prefix="source-drift-check-", dir=root / "data"
) as temporary:
    drift_source = Path(temporary) / "Current.cpp"
    drift_source.write_text('extern "C" int Current() { return 1; }\n')
    frozen = {
        "source_inputs": [
            {
                "source": str(drift_source.relative_to(root)),
                "source_sha256": dw_client.digest(drift_source),
            }
        ]
    }
    dw_client.require_current_sources(frozen)
    drift_source.write_text('extern "C" int Current() { return 2; }\n')
    try:
        dw_client.require_current_sources(frozen)
    except ValueError as error:
        assert "Authored source changed" in str(error)
    else:
        raise AssertionError(
            "Changed authored source passed the publication/deployment guard"
        )
checks.append(
    "Publication/deployment source guard accepts matching owners and rejects an edit after freezing"
)
for arguments in (
    ["tools/build-dw-client.py", "--host-scale"],
    ["tools/build-frozen-workstation.py", "--pin-experimental-updater"],
    ["tools/workstation-client.py", "--build"],
    ["tools/prepare-native-pair.py"],
):
    child = subprocess.run(
        [sys.executable, "-B", *arguments], cwd=root, capture_output=True, text=True
    )
    assert child.returncode != 0, arguments
assert dw_client.read(state / "latest-job.json") == latest
checks.append(
    "Legacy revision/source-selection and alternate test-target commands fail before changing build state"
)
with dw_client.pipeline_lock():
    child = subprocess.run(
        [sys.executable, "-B", str(Path(__file__)), "--check-lock"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert child.returncode == 0 and "Concurrent build refused" in child.stdout
checks.append("Concurrent build/deployment is rejected by the actual Windows file lock")
result = dict(
    passed=True,
    checks=checks,
    cpp_sources=len(receipt["cpp_sources"]),
    authored_source_owners=len(authored),
    game_runs_performed=False,
    owner_game_modified=False,
)
if args.output:
    dw_client.save(args.output, result)
print(json.dumps(result, indent=2))
