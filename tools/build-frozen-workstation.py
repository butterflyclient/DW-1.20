"""Compile a frozen copy of saved workstation inputs while shared recovery runs."""

from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--integration-root",
    type=Path,
    help="Explicit frozen DW integration inputs, keeping unrelated working-tree edits out of a private test build",
)
parser.add_argument("--optimized", action="store_true",
                    help="Include the existing runtime com_optimized 0/1/2 controls in this private DW build")
parser.add_argument("--include-player-data-path", action="store_true",
                    help="Explicitly include the separate Documents/Replay profile relocation; production retains the native path")
parser.add_argument("--receipt-directory", type=Path,
                    help="Keep this private build's job and source receipts separate from concurrent workstation builds")
args = parser.parse_args()
receipts = args.receipt_directory.resolve() if args.receipt_directory else ROOT / "data"
receipts.mkdir(parents=True, exist_ok=True)
ORIGINAL = Path(r"E:\replay-compiler")
snapshot = ROOT / "data" / ("compiler-snapshot-" + str(time.time_ns()))
snapshot.mkdir(parents=True)
records = []
revision_fallbacks = []

# Shared source development may alter a DW-authored file outside the editor's
# revision API. Do not rewrite that work or bless a metadata/hash mismatch.
# Only owned DW revisions may fall back to their last verified compiled source.
dw_sources = json.loads(
    (ROOT / "data" / "workstation-source-receipt.json").read_text()
)["sources"]
dw_expected = {item["id"]: item["content_sha256"] for item in dw_sources}
units = json.loads((ORIGINAL / "source-workstation" / "units.json").read_text())[
    "units"
]
dw_units_by_source = {
    Path(item["source"]).as_posix(): item
    for item in units
    if item.get("kind") == "cpp" and item.get("function_id") in dw_expected
}
prior_path = ROOT / "data" / "deployment.json"
prior = json.loads(prior_path.read_text()) if prior_path.exists() else None


def saved_dw_source(source):
    relative = source.relative_to(ORIGINAL).as_posix()
    unit = dw_units_by_source.get(relative)
    if (
        unit is None
        or hashlib.sha256(source.read_bytes()).hexdigest() == unit["sha256"]
    ):
        return source
    expected = dw_expected[unit["function_id"]]
    if (
        unit.get("sha256") != expected
        or unit.get("revision") != expected
        or prior is None
    ):
        raise RuntimeError(
            "DW saved revision changed; review before building: " + relative
        )
    candidates = [
        item
        for item in prior["sources"]
        if item["id"] == unit["function_id"] and item["content_sha256"] == expected
    ]
    if len(candidates) != 1:
        raise RuntimeError("No verified prior DW source revision: " + relative)
    old_root = Path(prior["compiler_source_root"]).resolve()
    old_source = (old_root / candidates[0]["compiled_source"]).resolve()
    if (
        not old_source.is_relative_to(old_root)
        or hashlib.sha256(old_source.read_bytes()).hexdigest() != expected
    ):
        raise RuntimeError("Prior DW source revision no longer verifies: " + relative)
    old_report = json.loads(
        (Path(prior["build_directory"]) / "build-report.json").read_text()
    )
    if old_report["sha256"] != prior["sha256"] or not any(
        item["source_sha256"] == expected
        and item["object_sha256"] == candidates[0]["object_sha256"]
        for item in old_report["cpp"]
    ):
        raise RuntimeError(
            "Prior DW source/object provenance does not verify: " + relative
        )
    revision_fallbacks.append(
        {
            "function_id": unit["function_id"],
            "shared_source": str(source),
            "shared_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "verified_source": str(old_source),
            "saved_revision_sha256": expected,
            "prior_verified_executable_sha256": prior["sha256"],
        }
    )
    return old_source


def copy_file(source, destination):
    before = source.read_bytes()
    digest = hashlib.sha256(before).hexdigest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(before)
    if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
        raise RuntimeError("Workstation input changed during snapshot: " + str(source))
    records.append(
        {"original": str(source), "snapshot": str(destination), "sha256": digest}
    )


for directory in ("src", "source-workstation", "generated"):
    for source in (ORIGINAL / directory).rglob("*"):
        if (
            source.is_file()
            and "__pycache__" not in source.parts
            and "validation" not in source.parts
        ):
            selected = saved_dw_source(source) if directory == "src" else source
            # DW owns this optional scheduling replacement. Keep the shared
            # compiler's implementation and other projects unchanged.
            if (source == ORIGINAL / "src/DB_ResetFileReader.cpp" or
                source == ORIGINAL / "src/ScrPlace_EndFrame.cpp" or
                (args.optimized and source == ORIGINAL / "src/Com_Optimized.cpp") or
                (args.optimized and source == ORIGINAL / "src/Sys_ProcessWorkerCmdsWithTimeoutAndFilter.cpp")):
                override = ((args.integration_root or ROOT / "integration/replay") / source.name).resolve()
                if override.is_file():
                    selected = override
            copy_file(selected, snapshot / source.relative_to(ORIGINAL))
for directory in ("tools", "workstation"):
    for source in (ORIGINAL / directory).glob("*"):
        if source.is_file() and source.suffix in (".py", ".json", ".cpp", ".h", ".hpp"):
            copy_file(source, snapshot / source.relative_to(ORIGINAL))
for source in (ORIGINAL / "tools" / "native").rglob("*"):
    if source.is_file() and source.suffix in (
        ".cpp",
        ".h",
        ".hpp",
        ".json",
        ".py",
        ".txt",
    ):
        copy_file(source, snapshot / source.relative_to(ORIGINAL))
if args.optimized:
    # Change only this private job's compiler invocation. The normal workstation
    # and its saved source revisions remain untouched.
    project_path = snapshot / "workstation/project.py"
    original = project_path.read_text()
    marker = "            if job['profile'] == 'current':\n                args += ['--frontend-probe'"
    if original.count(marker) != 1:
        raise RuntimeError("Private optimization compiler insertion point changed")
    project_path.write_text(original.replace(
        marker,
        "            if job['profile'] == 'engine':\n                args += ['--optimized']\n" + marker,
    ))
    record = next(item for item in records if Path(item["snapshot"]) == project_path)
    record["original_sha256"] = record["sha256"]
    record["sha256"] = hashlib.sha256(project_path.read_bytes()).hexdigest()
copy_file(ORIGINAL / "source-units.json", snapshot / "source-units.json")
# DW-owned endpoint implementation is overlaid in this private snapshot only.
# Its saved workstation ownership remains the same; the new content gets its
# own revision/hash and deployment must prove the exact compiled object.
private_overrides = []
user_path = snapshot / "source-workstation/user-functions.json"
user_document = json.loads(user_path.read_text())
frame_id, frame_unit = next(
    (key, value)
    for key, value in user_document["functions"].items()
    if value.get("name") == "DW_LocalBackend_Frame"
)
frame_source = (args.integration_root or ROOT / "integration/replay") / "DW_LocalBackend_Frame.cpp"
frame_destination = snapshot / frame_unit["path"]
frame_record = next(
    item for item in records if Path(item["snapshot"]) == frame_destination
)
frame_record["original_sha256"] = frame_record["sha256"]
frame_destination.write_bytes(frame_source.read_bytes())
frame_record["sha256"] = hashlib.sha256(frame_destination.read_bytes()).hexdigest()
frame_unit["sha256"] = frame_unit["revision"] = frame_record["sha256"]
unit_record = next(item for item in records if Path(item["snapshot"]) == user_path)
unit_record["original_sha256"] = unit_record["sha256"]
user_path.write_text(json.dumps(user_document, indent=2) + "\n")
unit_record["sha256"] = hashlib.sha256(user_path.read_bytes()).hexdigest()
private_overrides.append(
    {
        "id": frame_id,
        "content_sha256": frame_record["sha256"],
        "source": str(frame_source),
    }
)

# DW-only startup source stays outside the shared compiler/editor revisions.
# Its native function ownership and placement are derived by the usual linker.
private_sources = (args.integration_root or ROOT / "integration" / "replay").resolve()
if not private_sources.is_dir():
    raise RuntimeError("Private DW integration source directory is unavailable")
for source in sorted(private_sources.iterdir()):
    if source.name == "DW_PlayerDataPath.cpp" and not args.include_player_data_path:
        # Keep this separately authored source intact. Selecting all private
        # integration files must not silently move existing player profiles.
        continue
    # This existing unit is supplied by its saved editor revision above.
    if source.name == "DW_LocalBackend_Frame.cpp" or source.suffix not in (
        ".cpp",
        ".h",
    ):
        continue
    destination = snapshot / "src" / source.name
    if source.name in ("Sys_ProcessWorkerCmdsWithTimeoutAndFilter.cpp", "Com_Optimized.cpp", "DB_ResetFileReader.cpp", "ScrPlace_EndFrame.cpp"):
        # Already copied at its native optional-source association above.
        if (source.name in ("DB_ResetFileReader.cpp", "ScrPlace_EndFrame.cpp") or args.optimized) and source.read_bytes() != destination.read_bytes():
            raise RuntimeError("DW scheduler source changed during snapshot")
        continue
    if destination.exists():
        raise RuntimeError(
            "Private DW source collides with shared source: " + source.name
        )
    copy_file(source, destination)
# A private replacement of a saved source unit is a new source revision. Update
# only this frozen job's metadata; the shared workstation stays untouched.
units_path = snapshot / "source-workstation/units.json"
units_document = json.loads(units_path.read_text())
for unit in units_document["units"]:
    if unit.get("kind") == "cpp" and Path(unit.get("source", "")).name == "ScrPlace_EndFrame.cpp" and (private_sources / "ScrPlace_EndFrame.cpp").is_file():
        selected = snapshot / unit["source"]
        unit["sha256"] = unit["revision"] = hashlib.sha256(selected.read_bytes()).hexdigest()
        private_overrides.append({"id": unit["function_id"], "content_sha256": unit["sha256"], "source": str(private_sources / "ScrPlace_EndFrame.cpp")})
units_path.write_text(json.dumps(units_document, indent=2) + "\n")
units_record = next(item for item in records if Path(item["snapshot"]) == units_path)
units_record["original_sha256"] = units_record["sha256"]
units_record["sha256"] = hashlib.sha256(units_path.read_bytes()).hexdigest()
if (snapshot / "src/DW_ABTestingEnroll.cpp").exists():
    # Native dependencies and member offsets are derived while building this
    # frozen job. No shared source/editor revision or manual layout is changed.
    spec = importlib.util.spec_from_file_location(
        "prepare_private_ab_rest", ROOT / "tools/prepare-ab-rest-integration.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ab_rest = module.prepare(snapshot)
    for changed in (snapshot / "source-units.json", units_path):
        record = next(item for item in records if Path(item["snapshot"]) == changed)
        record.setdefault("original_sha256", record["sha256"])
        record["sha256"] = hashlib.sha256(changed.read_bytes()).hexdigest()
    for generated in (snapshot / "src/DW_ABTestingEnrollBindings.h",
                      snapshot / "generated/ab-rest-integration.json"):
        copy_file(generated, generated)
    private_overrides.append({"id": ab_rest["original_writer"]["function_id"],
                              "content_sha256": ab_rest["source_sha256"],
                              "source": str(private_sources / "DW_ABTestingEnroll.cpp"),
                              "derived_native_bindings": "generated/ab-rest-integration.json"})
# A normal build generates its own static updater from the selected, frozen
# client trust/ABI sources. Explicit reviewed integration snapshots may retain
# their already-built helper header, whose bytes remain compiler dependencies.
if (snapshot / "src/DW_ExecutableUpdate.cpp").exists() and not (snapshot / "src/DW_UpdateHelper.h").exists():
    generated_helper = snapshot / "generated-updater/DW_UpdateHelper.h"
    generated_helper.parent.mkdir(parents=True)
    subprocess.run([sys.executable, "-B", str(ROOT / "tools/embed-update-helper.py"),
                    "--source-root", str(snapshot / "src"), "--output", str(generated_helper)], check=True)
    copy_file(generated_helper, snapshot / "src/DW_UpdateHelper.h")

fixtures = (
    "evidence/mw131-canonical-selected-scripts/1806.gscbin",
    "evidence/replay120-global-mp-scriptfiles/1806.gscbin",
    "evidence/mw131-scriptfile-dump",
    "evidence/mw131-frontend6-scriptfiles",
)
fixture_count = 0
for relative in fixtures:
    path = ORIGINAL / relative
    sources = (
        [path]
        if path.is_file()
        else sorted(path.rglob("*.gscbin")) if path.is_dir() else []
    )
    for source in sources:
        copy_file(source, snapshot / source.relative_to(ORIGINAL))
        fixture_count += 1
if not fixture_count:
    raise RuntimeError("Retained ScriptFile verification fixtures are unavailable")
configuration = json.loads((ORIGINAL / "replay-project.local.json").read_text())
for tool in configuration.get("tools", {}).values():
    if isinstance(tool, dict) and tool.get("path"):
        path = Path(tool["path"])
        tool["path"] = str(path if path.is_absolute() else ORIGINAL / path)
configuration["build_root"] = str(ROOT / "data" / "workstation-builds")
configuration["publication_root"] = str(ROOT / "data" / "workstation-output")
# The job remains visible in the owner's workstation queue. Its compiler lock
# belongs to this snapshot, so shared IDA recovery is never interrupted.
(snapshot / "replay-project.local.json").write_text(
    json.dumps(configuration, indent=2) + "\n"
)
for item in records:
    if hashlib.sha256(Path(item["original"]).read_bytes()).hexdigest() != item.get(
        "original_sha256", item["sha256"]
    ):
        raise RuntimeError(
            "Workstation source changed before snapshot completion: " + item["original"]
        )

# The shared backend relinks independently proven callback thunks, while its
# current verifier still compares them as opaque, unchanged bytes. Strengthen
# this private verifier without modifying any parent compiler source.
overlay = ROOT / "integration" / "compiler" / "protected_callback_validation.py.inc"
verify_path = snapshot / "tools" / "verify.py"
verify_text = verify_path.read_text()
marker = '    lengths = (ROOT / "generated" / "instruction-lengths.bin").read_bytes()'
if verify_text.count(marker) != 1:
    raise RuntimeError(
        "Compiler callback validation insertion point changed; review before building"
    )
verify_text = verify_text.replace(marker, overlay.read_text() + "\n" + marker)
verify_text = verify_text.replace(
    '    counts["direct_branch_boundaries"] = 0',
    '    counts["direct_branch_boundaries"] = 0\n    counts["protected_callback_thunks"] = callback_count',
)
verify_text = verify_text.replace(
    "from verify_debug_states import verify as verify_debug_states",
    "from verify_debug_states import verify as verify_debug_states\n"
    "from verify_dw_endpoints import verify as verify_dw_endpoints\n"
    "from verify_dw_test_paths import verify as verify_dw_test_paths",
)
dw_marker = '        checks["debug_states"] = verify_debug_states(rebuilt, report)'
if verify_text.count(dw_marker) != 1:
    raise RuntimeError("Compiled endpoint validation insertion point changed")
verify_text = verify_text.replace(
    dw_marker,
    dw_marker
    + '\n    checks["dw_local_endpoints"] = verify_dw_endpoints(rebuilt, report)'
    + '\n    if any(item["source"].endswith("DW_TestHomePath.cpp") for item in report["cpp"]):'
    + '\n        checks["dw_private_test_paths"] = verify_dw_test_paths(rebuilt, report)',
)
verify_path.write_text(verify_text)
verify_record = next(item for item in records if Path(item["snapshot"]) == verify_path)
verify_record["original_sha256"] = verify_record["sha256"]
verify_record["sha256"] = hashlib.sha256(verify_path.read_bytes()).hexdigest()

debug_path = snapshot / "tools" / "verify_debug_states.py"
debug_text = debug_path.read_text()
platform_marker = '    query = symbols["__imp_VirtualQuery"]'
branch_marker = '        if name == "Sys_IsMainThread":'
if debug_text.count(platform_marker) != 1 or debug_text.count(branch_marker) != 1:
    raise RuntimeError("Overlay platform test insertion points changed")
debug_text = debug_text.replace(
    platform_marker,
    '    if report.get("optimized"):\n'
    '        for name in ("Dvar_BeginPermanentRegistration", "Dvar_EndPermanentRegistration", "Dvar_RegisterInt"):\n'
    '            intercepted[symbols[name]] = name\n'
    '    if "DW_LocalBackend_Frame" in symbols:\n'
    "        filename_thunk = arena + 0x39200\n"
    '        write(symbols["__imp_GetModuleFileNameA"], filename_thunk, "<Q")\n'
    '        intercepted[filename_thunk] = "GetModuleFileNameA"\n' + platform_marker,
)
debug_text = debug_text.replace(
    branch_marker,
    '        if name == "GetModuleFileNameA":\n'
    '            path = b"game_dx12_ship_replay.exe"\n'
    "            assert args[0] == 0 and args[2] > len(path)\n"
    '            machine.mem_write(args[1], path + b"\\0")\n'
    "            ret(len(path))\n"
    '        elif name == "Dvar_RegisterInt":\n'
    '            assert string(args[0]) == "com_optimized" and args[1:4] == [1, 0, 2]\n'
    '            write(arena + 0x7080 + 29, 5, "<B")\n'
    '            ret(arena + 0x7080)\n'
    '        elif name == "Sys_IsMainThread":',
)
if args.optimized:
    first_frame = '    run("ScrPlace_EndFrame")\n    expected_commands ='
    if debug_text.count(first_frame) != 1:
        raise RuntimeError("Optimized overlay fixture insertion point changed")
    # The optimized image intentionally starts with diagnostic text disabled.
    # Exercise its explicit command while retaining the actual frame/draw checks.
    debug_text = debug_text.replace(first_frame,
        '    if report.get("optimized"):\n        command("1")\n' + first_frame)
debug_path.write_text(debug_text)
debug_record = next(item for item in records if Path(item["snapshot"]) == debug_path)
debug_record["original_sha256"] = debug_record["sha256"]
debug_record["sha256"] = hashlib.sha256(debug_path.read_bytes()).hexdigest()
copy_file(
    ROOT / "tools" / "verify-dw-endpoints.py",
    snapshot / "tools" / "verify_dw_endpoints.py",
)
copy_file(
    ROOT / "tools" / "verify-dw-test-paths.py",
    snapshot / "tools" / "verify_dw_test_paths.py",
)

# Crash-marker initialization now starts the separate title worker. Keep this
# boundary explicit in the marker VM: verify exactly one dispatch while still
# executing the complete marker body and its adjacent-storage canaries.
marker_path = snapshot / "tools" / "verify_marker.py"
marker_text = marker_path.read_text()
entry_hook = "        if address == base + mapped(0x21CCF60):"
entry_run = "    machine.emu_start(base + entry, return_pc, count=100000)"
existing_title_hook = (
    "        if report and address == base + report['symbols'].get('Sys_UpdateGameWindowTitle', -1):\n"
    "            # Marker bounds/ABI are tested here; the title helper starts a real\n"
    "            # Win32 worker whose platform APIs are outside this isolated VM.\n"
    "            returned()\n"
    "        elif address == base + mapped(0x21CCF60):"
)
if marker_text.count(entry_run) != 1:
    raise RuntimeError("Crash marker worker boundary changed; review before building")
counted_title_hook = (
    '        if report and address == base + report["symbols"].get("Sys_UpdateGameWindowTitle", -1):\n'
    "            title_calls.append(address)\n"
    "            returned()\n"
    "        elif address == base + mapped(0x21CCF60):"
)
if marker_text.count(entry_hook) == 1:
    marker_text = marker_text.replace(entry_hook, counted_title_hook)
elif marker_text.count(existing_title_hook) == 1:
    # Shared verification now already isolates this same Win32 boundary.
    # Retain the DW-specific assertion that it is dispatched exactly once.
    marker_text = marker_text.replace(existing_title_hook, counted_title_hook)
else:
    raise RuntimeError("Crash marker worker boundary changed; review before building")
marker_text = marker_text.replace(
    entry_run,
    "    title_calls = []\n" + entry_run + "\n"
    "    if report and len(title_calls) != 1:\n"
    '        raise ValueError("Crash marker must dispatch its independent title worker once")',
)
marker_path.write_text(marker_text)
marker_record = next(item for item in records if Path(item["snapshot"]) == marker_path)
marker_record["original_sha256"] = marker_record["sha256"]
marker_record["sha256"] = hashlib.sha256(marker_path.read_bytes()).hexdigest()

crt_overlay = ROOT / "integration" / "compiler" / "crt_callback_validation.py.inc"
audit_path = snapshot / "tools" / "audit_relocations.py"
audit_text = audit_path.read_text()
audit_marker = "def audit(directory):"
loop_marker = "        site, target = callback['site'], callback['target']"
count_marker = "direct_crt_destructor_registrations=len(crt_callbacks),"
for marker in (audit_marker, loop_marker, count_marker):
    if audit_text.count(marker) != 1:
        raise RuntimeError("CRT registration audit insertion point changed")
audit_text = audit_text.replace(
    audit_marker, crt_overlay.read_text() + "\n\n" + audit_marker
)
audit_text = audit_text.replace(
    "    for callback in crt_callbacks:",
    "    retired_crt_callbacks = []\n    for callback in crt_callbacks:",
)
audit_text = audit_text.replace(
    loop_marker,
    loop_marker + "\n"
    "        if retired(site):\n"
    "            retired_crt_callbacks.append(verify_dw_retired_crt_callback(\n"
    "                site, target, report, original, rebuilt, lengths, text_start))\n"
    "            continue",
)
audit_text = audit_text.replace(
    count_marker,
    "direct_crt_destructor_registrations=len(crt_callbacks) - len(retired_crt_callbacks),\n"
    "                  retired_direct_crt_registrations=retired_crt_callbacks,",
)
audit_path.write_text(audit_text)
audit_record = next(item for item in records if Path(item["snapshot"]) == audit_path)
audit_record["original_sha256"] = audit_record["sha256"]
audit_record["sha256"] = hashlib.sha256(audit_path.read_bytes()).hexdigest()

# Recovery keys contain absolute source paths. Rebind paths only after proving
# identical algorithm/evidence bytes; never change recovered code or layouts.
manifest_path = snapshot / "generated" / "manifest.json"
manifest = json.loads(manifest_path.read_text())
for item in manifest["preparation_inputs"]:
    original_path = Path(item["path"])
    relative = original_path.relative_to(ORIGINAL)
    new_path = snapshot / relative
    if hashlib.sha256(new_path.read_bytes()).hexdigest() != item["sha256"]:
        raise RuntimeError("Recovery source snapshot is stale: " + item["path"])
    item["path"] = str(new_path)
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
(receipts / "compiler-snapshot-receipt.json").write_text(
    json.dumps(
        {
            "schema": 1,
            "snapshot": str(snapshot),
            "method": "saved workstation source snapshot with strict callback verification",
            "files": records,
            "preparation_path_rebinding": "same evidence, new source paths only",
            "dw_saved_revision_fallbacks": revision_fallbacks,
            "dw_private_revision_overrides": private_overrides,
            "validation_overlay": {
                "path": str(overlay),
                "sha256": hashlib.sha256(overlay.read_bytes()).hexdigest(),
                "crt_path": str(crt_overlay),
                "crt_sha256": hashlib.sha256(crt_overlay.read_bytes()).hexdigest(),
                "changes": "verify whole native callback, both relocated pointer slots, compiled DW/native endpoint selection and the empty startup constructor; prove retirement of DW-owned CRT registration sites; supply platform filename in the existing overlay VM",
            },
        },
        indent=2,
    )
    + "\n"
)
os.environ["REPLAY_GAME_ROOT"] = configuration["game"]
os.environ["REPLAY_SQLITE"] = configuration["sqlite"]
os.environ["REPLAY_WORKSTATION_CACHE"] = configuration["cache"]
sys.path[:0] = [str(snapshot), str(snapshot / "tools")]
from workstation.project import Project
from workstation.config import load_paths

paths = load_paths(snapshot)
project = Project(
    snapshot,
    paths["cache"],
    paths["game"],
    paths["sqlite"],
    paths["acts"],
    recover_jobs=False,
)
job = project.start_build("engine")
receipt = receipts / "workstation-job.json"
receipt.write_text(json.dumps(job, indent=2) + "\n")
print("Frozen saved-source workstation job:", job["id"], flush=True)
phase = None
while True:
    current = project.job(job["id"])
    if current.get("phase") != phase:
        phase = current.get("phase")
        print(current["status"], phase, flush=True)
    if current["status"] not in ("queued", "running"):
        receipt.write_text(json.dumps(current, indent=2) + "\n")
        print(current.get("error", ""), flush=True)
        raise SystemExit(0 if current["status"] == "succeeded" else 1)
    time.sleep(1)
