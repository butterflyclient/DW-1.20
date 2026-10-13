"""One DW client source selection, compiler pipeline and deployment target."""

from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

if os.name == "nt":
    import msvcrt

ROOT = Path(__file__).resolve().parents[1]
PUBLICATION_TOOLS = {
    'tools/publish-custom-map.py', 'tools/publish-full-executable.py',
    'tools/verify-full-executable-publication.py', 'tools/dw_publication.py',
    'tools/package-remote-guest.py',
}


def read(path):
    return json.loads(Path(path).read_bytes())


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_current_sources(receipt):
    """Reject a frozen job superseded by edits to its authored source owners."""
    for item in receipt["source_inputs"] + receipt.get("tool_inputs", []):
        # Older receipts also captured release-only tools here. They never
        # affect compiler bytes; their current hashes are bound separately to
        # the verified publication. Keep the original build receipt immutable.
        if item['source'] in PUBLICATION_TOOLS:
            continue
        path = inside(ROOT / item["source"])
        if digest(path) != item["source_sha256"]:
            raise ValueError(
                "Authored source changed since the build: " + item["source"]
            )


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    # Windows readers and scanners can briefly deny replacement of a receipt.
    # Keep the closed, durable temporary file and retry only that atomic rename.
    for attempt in range(6):
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.05 * (attempt + 1))


def inside(path):
    path = Path(path).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("DW compilation must remain under " + str(ROOT))
    return path


def settings():
    config = read(ROOT / "dw-client.json")
    if config["schema"] != 1 or config["target"] != "game_dx12_ship_replay_dw.exe":
        raise ValueError("Only the production DW executable is supported")
    return (
        config,
        inside(ROOT / config["build_state"]),
        inside(ROOT / config["compiler_base"]),
    )


@contextmanager
def pipeline_lock():
    """Serialize compilation/publication of the sole local client artifact."""
    _, state, _ = settings()
    state.mkdir(parents=True, exist_ok=True)
    with (state / "pipeline.lock").open("a+b") as stream:
        stream.seek(0, os.SEEK_END)
        if not stream.tell():
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise RuntimeError(
                "The production DW build/deployment is already running"
            ) from error
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def frame_source(path):
    """Integrate host scheduling once, without a separately edited frame copy."""
    text = Path(path).read_text(encoding="utf-8")
    marker = "    Com_Optimized_Frame();"
    if text.count(marker) != 1:
        raise ValueError("Native end-frame integration changed")
    if "    SV_HostScale_Frame();" not in text:
        text = 'extern "C" void SV_HostScale_Frame();\n' + text.replace(
            marker, marker + "\n    SV_HostScale_Frame();"
        )
    if text.count("    SV_HostScale_Frame();") != 1:
        raise ValueError("Host frame must run exactly once")
    if "    DW_AltKillcam_Init();" not in text:
        text = 'extern "C" void DW_AltKillcam_Init();\n' + text.replace(
            marker, "    DW_AltKillcam_Init();\n" + marker
        )
    if text.count("    DW_AltKillcam_Init();") != 1:
        raise ValueError("Local killcam registration must run exactly once")
    return text.encode("utf-8")


def source_bytes(path, destination):
    if destination == "src/ScrPlace_EndFrame.cpp":
        return frame_source(path)
    return Path(path).read_bytes()


def sync_cpp_revisions(source):
    """Bind recovered and new C++ units to the bytes this job will compile."""
    source = inside(source)
    units_path = source / "source-workstation/units.json"
    units = read(units_path)
    for unit in units["units"]:
        if unit.get("kind") == "cpp":
            path = inside(source / unit["source"])
            if not path.is_relative_to(source / "src"):
                raise ValueError("C++ unit escapes the compiled source directory")
            unit["sha256"] = unit["revision"] = digest(path)
    save(units_path, units)
    users_path = source / "source-workstation/user-functions.json"
    if users_path.exists():
        users = read(users_path)
        for user in users["functions"].values():
            path = inside(source / user["path"])
            if not path.is_relative_to(source / "src"):
                raise ValueError("User function escapes the compiled source directory")
            user["sha256"] = user["revision"] = digest(path)
        save(users_path, users)
    return units


def initialize():
    """Seed compiler infrastructure once from the verified production project.

    Authored sources stay exclusively in integration/. The reusable compiler
    base contains recovered game/compiler inputs and derived bindings. It does
    not retain a competing editable copy of an integration source.
    """
    config, state, base = settings()
    manifest_path = state / "source-manifest.json"
    if manifest_path.exists():
        return read(manifest_path)
    if base.exists():
        raise ValueError(
            "Incomplete compiler initialization; preserve and inspect " + str(base)
        )
    deployed = read(ROOT / "data/current-remote-deployment.json")
    readiness = read(ROOT / deployed["readiness"]["path"])
    if not readiness["passed"] or readiness["sha256"] != deployed["sha256"]:
        raise ValueError("Current production readiness does not bind the source")
    source = inside(deployed["compiler_source_root"])
    report_path = inside(Path(deployed["build_directory"]) / "build-report.json")
    report = read(report_path)
    if report["sha256"] != deployed["sha256"] or report["unresolved_symbols"]:
        raise ValueError("Current production compile does not verify")
    for unit in report["cpp"]:
        if digest(source / unit["source"]) != unit["source_sha256"]:
            raise ValueError("Verified compiled source changed: " + unit["source"])
    overlays = {}
    for directory in config["authored_source_roots"]:
        for path in sorted(inside(ROOT / directory).iterdir()):
            if path.suffix not in (".cpp", ".h", ".lua"):
                continue
            destination = "src/" + path.name
            if path.name == "DW_LocalBackend_Frame.cpp":
                # Resolve the saved user unit by its actual exported symbol.
                matches = [
                    unit["source"]
                    for unit in read(source / "source-units.json")["units"]
                    if unit["symbol"] == "DW_LocalBackend_Frame"
                ]
                users = read(source / "source-workstation/user-functions.json")
                matches.extend(
                    user["path"]
                    for user in users["functions"].values()
                    if user["name"] == "DW_LocalBackend_Frame"
                )
                if not matches:
                    raise ValueError("Backend frame has no recovered/user source owner")
                destination = next(iter(set(matches)))
                if len(set(matches)) > 1:
                    raise ValueError("Ambiguous backend frame ownership")
            compiled = source / destination
            if not compiled.exists():
                continue
            if source_bytes(path, destination).decode("utf-8").replace(
                "\r\n", "\n"
            ) != compiled.read_text(encoding="utf-8"):
                raise ValueError(
                    "Authored source differs from approved source; review " + str(path)
                )
            if destination in overlays:
                raise ValueError("Two authored owners for " + destination)
            overlays[destination] = path.relative_to(ROOT).as_posix()
    generated = {"src/DW_PlaylistUI_Source.h", "src/DW_LobbyControls_Native.cpp"}
    shutil.copytree(
        source,
        base,
        ignore=shutil.ignore_patterns("__pycache__", "*.lock", "*.obj", "*.log"),
    )
    # Paths are bounded above. Remove only the duplicate authored/generated
    # copies from this newly created base; original evidence remains untouched.
    for name in set(overlays) | generated:
        path = inside(base / name)
        if path.exists():
            path.unlink()
    inventory = [
        {"path": path.relative_to(base).as_posix(), "sha256": digest(path)}
        for path in sorted(base.rglob("*"))
        if path.is_file()
    ]
    manifest = dict(
        schema=1,
        initialized_utc=datetime.now(timezone.utc).isoformat(),
        target=config["target"],
        compiler_base=str(base),
        bootstrap_executable_sha256=deployed["sha256"],
        bootstrap_build_report=str(report_path),
        bootstrap_original_source_root=str(source),
        compiled_cpp_sources=sorted(unit["source"] for unit in report["cpp"]),
        bootstrap_readiness=deployed["readiness"],
        overlays=overlays,
        generated_sources=sorted(generated),
        files=inventory,
        native_import_bindings=read(source.parent / "source-receipt.json")["bindings"],
        one_authored_owner_per_source=True,
        separate_revision_targets=False,
    )
    save(manifest_path, manifest)
    print(
        "Initialized the single DW compiler base; authored source owners:",
        len(overlays),
        flush=True,
    )
    return manifest


def prepare():
    config, state, base = settings()
    subprocess.run(
        [sys.executable, "-B", str(ROOT / "tools/generate-bot-names.py"), "--check"],
        cwd=ROOT, check=True,
    )
    manifest = initialize()
    for item in manifest["files"]:
        if digest(base / item["path"]) != item["sha256"]:
            raise ValueError("Compiler base changed unexpectedly: " + item["path"])
    directory = inside(state / "jobs" / str(time.time_ns()))
    source = directory / "source"
    # Updater build products contain absolute CMake paths and old objects.
    # Regenerate them from the current authored helper and frozen client inputs.
    shutil.copytree(
        base, source,
        ignore=lambda folder, names: ["generated-updater"] if Path(folder) == base else [],
    )
    source_inputs = []
    tool_inputs = [
        dict(source="tools/" + name, source_sha256=digest(ROOT / "tools" / name))
        for name in (
            "prepare-playlist-ui.py", "prepare-lobby-native-clones.py",
            "test-playlist-ui.py",
            "prepare-host-scale-integration.py", "prepare-bot-style-data.py",
            "prepare-bot-think-integration.py", "generate-bot-names.py",
            "test-bot-slide-cancel.py", "test-bot-slide-cancel.cpp",
            "test-map-voting-client.py", "map_vote_harness.cpp",
            "test-ui-focus-lifetime.py",
            "prepare-bot-profile-ownership.py",
            "prepare-noclip-integration.py",
            "prepare-alt-killcam-integration.py", "prepare-alt-killcam-render.py",
            "alt_killcam_native.json", "alt_killcam_render_native.json",
            "replay_owned_clone.py", "alt_killcam_render_reference.cpp",
            "alt_killcam_harness.cpp", "alt_killcam_render_harness.cpp",
            "test-alt-killcam.py", "test-alt-killcam-render.py",
            "prepare-script-method-integration.py", "prepare-bot-style-scripts.py",
            "prepare-bot-style-zone.py", "prepare-matchmaking-assignments.py",
            "bot_style_paths.py",
            "prepare-join-in-progress.py",
            "prepare-dw-verifier.py",
            "prepare-bot-rank-integration.py",
            "dw_update_assets.py", "dw_update_maps.py", "embed-update-helper.py", "replay-update-client.rc",
            "replay-update-client.cpp", "replay-update-assets.h", "replay-update-maps.h",
            "test-update-maps.py", "update_maps_harness.cpp",
            "test-update-client-catchup.py", "test-map-publication.py",
        )
    ]
    overlays = dict(manifest["overlays"])
    for root in config["authored_source_roots"]:
        # Host replacements acquire their native bindings below. Other authored
        # modules keep the approved owner map; unrelated research prototypes
        # may share a filename but require a different generated binding set.
        replay_additions = {
            "DW_BotStyleSelection.h", "DW_BotStyleProfile.h", "DW_BotStyleWeapon.cpp",
            "DW_BotRank.cpp",
            "DW_ScriptMethods.cpp", "DW_BotStyleScripts.cpp", "DW_BotStyleZone.cpp",
            "dw_update_assets_protocol.h", "dw_update_maps_protocol.h",
            "DW_MatchmakingAssignments.cpp",
            "DW_JoinInProgress.cpp",
            "DW_Noclip.cpp", "DW_Noclip.h",
            "DW_AltKillcam.cpp", "DW_AltKillcam.h",
            "DW_AltKillcamRender.cpp", "DW_AltKillcamRender.h",
            "DW_MapVoting.h",
        }
        for path in sorted(inside(ROOT / root).iterdir()):
            if root != "integration/host-scale" and path.name not in replay_additions:
                continue
            name = path.relative_to(ROOT).as_posix()
            if path.suffix not in (".cpp", ".h", ".lua") or name in overlays.values():
                continue
            destination = "src/" + path.name
            if destination in overlays:
                raise ValueError("Two authored owners for " + destination)
            overlays[destination] = name
    for destination, name in overlays.items():
        authored = inside(ROOT / name)
        raw_hash = digest(authored)
        content = source_bytes(authored, destination)
        (source / destination).write_bytes(content)
        if digest(authored) != raw_hash:
            raise ValueError("Source changed while freezing: " + name)
        source_inputs.append(
            dict(
                source=name,
                source_sha256=raw_hash,
                compiled_source=destination,
                compiled_sha256=hashlib.sha256(content).hexdigest(),
            )
        )
    # The native overlay verifier follows the authored overlay's current rows.
    # Freeze it with the job and guard its owner just like the integration code.
    for validator_name in ("verify_debug_states.py", "verify_spatial.py"):
        validator = ROOT / "tools" / validator_name
        validation_target = source / "tools" / validator_name
        validator_hash = digest(validator)
        shutil.copyfile(validator, validation_target)
        if digest(validator) != validator_hash or digest(validation_target) != validator_hash:
            raise ValueError("Validator changed while freezing: " + validator_name)
        source_inputs.append(
            dict(source="tools/" + validator_name, source_sha256=validator_hash,
                 compiled_source="tools/" + validator_name,
                 compiled_sha256=digest(validation_target))
        )
    # Keep the supplied name corpus tied to the generated compiled pool.
    names = ROOT / "integration/replay/DW_BotNames.txt"
    names_target = source / "src/DW_BotNames.txt"
    shutil.copyfile(names, names_target)
    if digest(names) != digest(names_target):
        raise ValueError("Bot name corpus changed while freezing")
    source_inputs.append(dict(source="integration/replay/DW_BotNames.txt",
                              source_sha256=digest(names), compiled_source="src/DW_BotNames.txt",
                              compiled_sha256=digest(names_target)))
    ui = load_module("dw_client_playlist", ROOT / "tools/prepare-playlist-ui.py")
    ui.prepare(
        source,
        directory / "playlist-ui-preparation.json",
        source / "src/DW_PlaylistUI.lua",
    )
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "tools/prepare-lobby-native-clones.py"),
            "--snapshot",
            str(source),
            "--output",
            str(directory / "lobby-native-clones.json"),
        ],
        cwd=ROOT,
        check=True,
    )
    host = load_module(
        "dw_client_host", ROOT / "tools/prepare-host-scale-integration.py"
    )
    host.prepare(source, replace_owned=True)
    styles = load_module("dw_bot_style_data", ROOT / "tools/prepare-bot-style-data.py")
    styles.prepare(source)
    ranks = load_module("dw_bot_rank", ROOT / "tools/prepare-bot-rank-integration.py")
    ranks.prepare(source)
    methods = load_module("dw_bot_style_methods", ROOT / "tools/prepare-script-method-integration.py")
    methods.prepare(source)
    scripts = load_module("dw_bot_style_scripts", ROOT / "tools/prepare-bot-style-scripts.py")
    scripts.prepare(source)
    zones = load_module("dw_bot_style_zones", ROOT / "tools/prepare-bot-style-zone.py")
    zones.prepare(source)
    verifier = load_module("dw_image_verifier", ROOT / "tools/prepare-dw-verifier.py")
    verifier.prepare(source)
    assignments = load_module("dw_matchmaking_assignments", ROOT / "tools/prepare-matchmaking-assignments.py")
    assignments.prepare(source)
    joining = load_module("dw_join_in_progress", ROOT / "tools/prepare-join-in-progress.py")
    joining.prepare(source)
    noclip = load_module("dw_noclip", ROOT / "tools/prepare-noclip-integration.py")
    noclip.prepare(source)
    killcam = load_module("dw_alt_killcam", ROOT / "tools/prepare-alt-killcam-integration.py")
    killcam.prepare(source)
    killcam_render = load_module("dw_alt_killcam_render", ROOT / "tools/prepare-alt-killcam-render.py")
    killcam_render.prepare(source)
    assets = load_module("dw_update_assets", ROOT / "tools/dw_update_assets.py")
    assets.prepare(source)
    maps = load_module("dw_update_maps", ROOT / "tools/dw_update_maps.py")
    maps.prepare(source)
    helper_header = source / "generated-updater/DW_UpdateHelper.h"
    subprocess.run([
        sys.executable, "-B", str(ROOT / "tools/embed-update-helper.py"),
        "--source-root", str(source / "src"), "--output", str(helper_header),
    ], cwd=ROOT, check=True)
    shutil.copyfile(helper_header, source / "src/DW_UpdateHelper.h")
    units = sync_cpp_revisions(source)
    recovery_path = source / "generated/manifest.json"
    recovery = read(recovery_path)
    approved_root = Path(manifest["bootstrap_original_source_root"])
    for item in recovery["preparation_inputs"]:
        relative = Path(item["path"]).relative_to(approved_root)
        new_path = source / relative
        if digest(new_path) != item["sha256"]:
            raise ValueError("Recovered input provenance changed: " + str(relative))
        item["path"] = str(new_path)
    save(recovery_path, recovery)
    local_path = source / "replay-project.local.json"
    local = read(local_path)
    local.update(
        cache=str(directory / "cache"),
        build_root=str(directory / "builds"),
        publication_root=str(directory / "output"),
    )
    save(local_path, local)
    cpp = {
        unit["source"]: digest(source / unit["source"])
        for unit in units["units"]
        if unit.get("kind") == "cpp"
    }
    # User units are compiled too; derive them from the base report rather than
    # selecting a separate target or manufacturing a second set of bindings.
    for name in manifest["compiled_cpp_sources"]:
        cpp[name] = digest(source / name)
    host_proof = read(source / "generated/host-scale-integration.json")
    present = {item["symbol"] for item in host_proof["replacements"]}
    if not set(config["required_host_routines"]).issubset(present):
        raise ValueError("The production target is missing current bot optimizations")
    updater = (source / "src/DW_ExecutableUpdate.cpp").read_text()
    if "unsigned s_state = 0, s_reported = 0;" not in updater:
        raise ValueError("Production updater must remain enabled")
    # Helper modules have no original-function association, but are still
    # explicit, frozen source owners. Account for them alongside replacements.
    for item in source_inputs:
        if Path(item["compiled_source"]).suffix in (".cpp", ".c"):
            cpp[item["compiled_source"]] = item["compiled_sha256"]
    # The zone wrapper calls a generated, byte-proven copy of the complete
    # native loader. It has one compiler-generated owner and no original map.
    clone_source = source / "src/DW_BotStyleZone_Native.cpp"
    cpp[clone_source.relative_to(source).as_posix()] = digest(clone_source)
    noclip_clone = source / "src/DW_Noclip_Native.cpp"
    cpp[noclip_clone.relative_to(source).as_posix()] = digest(noclip_clone)
    for name in ("DW_AltKillcam_Native.cpp", "DW_AltKillcamRender_Native.cpp"):
        clone = source / "src" / name
        cpp[clone.relative_to(source).as_posix()] = digest(clone)
    receipt = dict(
        schema=1,
        target=config["target"],
        snapshot=str(source),
        source_inputs=source_inputs,
        tool_inputs=tool_inputs,
        cpp_sources=cpp,
        bindings=manifest["native_import_bindings"],
        baseline_executable_sha256=read(ROOT / "data/current-remote-deployment.json")[
            "sha256"
        ],
        full_host_optimizations_required=True,
        optimized_compiler_required=True,
        active_updater_required=True,
        source_options=[],
        game_runs_performed=False,
        files=[
            dict(path=path.relative_to(source).as_posix(), sha256=digest(path))
            for path in sorted(source.rglob("*"))
            if path.is_file()
        ],
    )
    require_current_sources(receipt)
    save(directory / "source-receipt.json", receipt)
    save(
        state / "latest-job.json",
        dict(directory=str(directory), prepared=True, deployed=False),
    )
    print("Prepared one production DW target:", directory, flush=True)
    return directory


def build(directory, publish_ready=True):
    directory = inside(directory)
    receipt = read(directory / "source-receipt.json")
    source = inside(receipt["snapshot"])
    for item in receipt["files"]:
        if digest(source / item["path"]) != item["sha256"]:
            raise ValueError("Frozen compiler input changed: " + item["path"])
    local = read(source / "replay-project.local.json")
    for key in ("REPLAY_WORKSTATION_BUILD_ROOT", "REPLAY_WORKSTATION_OUTPUT_ROOT"):
        os.environ.pop(key, None)
    os.environ.update(
        REPLAY_GAME_ROOT=local["game"],
        REPLAY_SQLITE=local["sqlite"],
        REPLAY_WORKSTATION_CACHE=local["cache"],
    )
    sys.path[:0] = [str(source), str(source / "tools")]
    from workstation.project import Project
    from workstation.config import load_paths

    paths = load_paths(source)
    project = Project(
        source,
        paths["cache"],
        paths["game"],
        paths["sqlite"],
        paths["acts"],
        recover_jobs=False,
    )
    job = project.start_build("engine")
    phase = None
    while True:
        current = project.job(job["id"])
        if current.get("phase") != phase:
            phase = current.get("phase")
            print(current["status"], phase, flush=True)
        save(directory / "workstation-job.json", current)
        if current["status"] not in ("queued", "running"):
            if current["status"] != "succeeded":
                raise RuntimeError(current.get("error", "DW compilation failed"))
            break
        time.sleep(1)
    report_path = (
        directory / "builds" / ("build-workstation-" + job["id"]) / "build-report.json"
    )
    verify(directory, report_path, publish_ready=publish_ready)


def verify(directory, report_path, publish_ready=True):
    """Bind every gate to the freshly compiled image, never a revision alias."""
    config, state, _ = settings()
    report = read(report_path)
    build_path = Path(report_path).parent
    source = Path(report["source_root"])
    receipt = read(directory / "source-receipt.json")
    expected = dict(receipt["cpp_sources"])
    for item in receipt["source_inputs"]:
        if Path(item["compiled_source"]).suffix in (".cpp", ".c"):
            expected[item["compiled_source"]] = item["compiled_sha256"]
    require_current_sources(receipt)
    actual = {unit["source"]: unit["source_sha256"] for unit in report["cpp"]}
    if (
        actual != expected
        or report["unresolved_symbols"]
        or digest(report["executable"]) != report["sha256"]
    ):
        raise ValueError("Fresh compilation/source/image gate failed")
    tools = ROOT / "tools"
    checks = (
        ("test-host-scale.py", ["--snapshot", str(source)], "host.json"),
        ("test-host-navigation.py", ["--snapshot", str(source)], "navigation.json"),
        ("test-host-safety.py", ["--snapshot", str(source)], "host-safety.json"),
        ("test-host-command-ownership.py", ["--snapshot", str(source)], "host-command-ownership.json"),
        ("test-bot-behavior.py", ["--snapshot", str(source)], "bot-behavior.json"),
        ("test-bot-slide-cancel.py", ["--snapshot", str(source)], "bot-slide-cancel.json"),
        ("test-lobby-controls.py", [], "controls.json"),
        ("test-map-voting-client.py", ["--snapshot", str(source)], "map-voting.json"),
        (
            "test-native-bot-roster.py",
            ["--header-source", str(source / "src/DW_BotBindings.h")],
            "roster.json",
        ),
        (
            "test-playlist-ui-native.py",
            ["--lua-source", str(source / "src/DW_PlaylistUI.lua")],
            "playlist.json",
        ),
        ("test-playlist-ui.py", ["--snapshot", str(source)], "playlist-ui-behavior.json"),
        ("test-ui-focus-lifetime.py", [], "ui-focus-lifetime.json"),
        (
            "test-lobby-native-clones.py",
            ["--preparation", str(directory / "lobby-native-clones.json")],
            "native-clones.json",
        ),
        ("test-executable-update-integration.py", [], "updater.json"),
        ("test-update-maps.py", [], "map-updater.json"),
        ("test-update-client-catchup.py", [], "updater-catchup.json"),
        ("test-map-publication.py", [], "map-publication.json"),
        ("test-compiled-unlock-progression.py", [], "unlock.json"),
        ("test-bot-style-selection.py", ["--snapshot", str(source)], "bot-styles.json"),
        ("test-script-method-integration.py", ["--snapshot", str(source)], "script-methods.json"),
        ("test-bot-style-weapon.py", ["--snapshot", str(source)], "bot-style-weapons.json"),
        ("test-bot-rank.py", ["--snapshot", str(source)], "bot-ranks.json"),
        ("test-bot-style-scripts.py", ["--snapshot", str(source)], "bot-style-scripts.json"),
        ("test-bot-style-zone.py", ["--snapshot", str(source)], "bot-style-zone.json"),
        ("test-matchmaking-assignments.py", ["--snapshot", str(source)], "matchmaking-assignments.json"),
        ("test-join-in-progress.py", ["--snapshot", str(source)], "join-in-progress.json"),
        ("test-dw-verifier.py", ["--snapshot", str(source)], "dw-verifier.json"),
        ("test-noclip.py", ["--snapshot", str(source)], "noclip.json"),
        ("test-alt-killcam.py", ["--snapshot", str(source)], "alt-killcam.json"),
        ("test-alt-killcam-render.py", ["--snapshot", str(source)], "alt-killcam-render.json"),
    )
    identity = dict(
        source_receipt_sha256=digest(directory / "source-receipt.json"),
        build_report_sha256=digest(report_path),
        executable_sha256=report["sha256"],
    )
    progress_path = directory / "verification-progress.json"
    completed = []
    if progress_path.exists():
        progress = read(progress_path)
        if any(progress.get(key) != value for key, value in identity.items()):
            raise ValueError("Validation progress belongs to different compiler inputs")
        completed = progress["proofs"]
        if len(completed) > len(checks):
            raise ValueError("Validation progress has extra checks")
    proofs = []
    for index, (checker, extra, name) in enumerate(checks):
        output = directory / name
        if index < len(completed):
            proof = completed[index]
            if (
                proof["checker"] != checker
                or Path(proof["path"]) != output
                or digest(output) != proof["sha256"]
                or digest(tools / checker) != proof["checker_sha256"]
                or not read(output)["passed"]
            ):
                raise ValueError("Completed validation check changed: " + checker)
            proofs.append(proof)
            continue
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(tools / checker),
                "--build",
                str(build_path),
                "--output",
                str(output),
                *extra,
            ],
            cwd=ROOT,
            check=True,
        )
        proof = read(output)
        if not proof["passed"]:
            raise ValueError("DW client gate failed: " + checker)
        proofs.append(
            dict(
                path=str(output),
                sha256=digest(output),
                checker=checker,
                checker_sha256=digest(tools / checker),
            )
        )
        save(progress_path, dict(**identity, proofs=proofs))
    compiled = Path(report["executable"])
    # A second editor can change source while compilation/linked checks run.
    # Catch that before publishing, not only at local deployment afterward.
    require_current_sources(read(directory / "source-receipt.json"))
    local = dict(
        passed=True, published=False, executable=str(compiled), sha256=report["sha256"],
        fresh_cpp_units=len(actual), unresolved_symbols=0, source_root=str(source),
        build_report=str(report_path), build_report_sha256=digest(report_path), proofs=proofs,
        source_receipt=str(directory / "source-receipt.json"),
        source_receipt_sha256=digest(directory / "source-receipt.json"),
        game_runs_performed=False,
    )
    save(directory / "local-readiness.json", local)
    if not publish_ready:
        save(state / "latest-job.json", dict(directory=str(directory), prepared=True,
                                             validated=True, passed=False, awaiting_publication=True))
        print("PASS production compilation and local gates; live publication deferred", flush=True)
        return local
    return publish_validated(directory)


def publish_validated(directory):
    """Publish an unchanged, locally verified job after the server is ready."""
    config, state, _ = settings()
    directory = inside(directory)
    local = read(directory / "local-readiness.json")
    if not local["passed"] or local["unresolved_symbols"]:
        raise ValueError("The production job has not passed local verification")
    report_path = inside(local["build_report"])
    receipt_path = inside(local["source_receipt"])
    if (digest(report_path) != local["build_report_sha256"] or
        digest(receipt_path) != local["source_receipt_sha256"]):
        raise ValueError("Validated compilation or source receipt changed")
    receipt = read(receipt_path)
    require_current_sources(receipt)
    report = read(report_path)
    source = inside(report["source_root"])
    compiled = inside(report["executable"])
    actual = {unit["source"]: unit["source_sha256"] for unit in report["cpp"]}
    if (actual != receipt["cpp_sources"] or report["unresolved_symbols"] or
        report["sha256"] != local["sha256"] or digest(compiled) != local["sha256"]):
        raise ValueError("Validated production source or image changed")
    proofs = local["proofs"]
    for proof in proofs:
        if (digest(inside(proof["path"])) != proof["sha256"] or
            digest(ROOT / "tools" / proof["checker"]) != proof["checker_sha256"] or
            not read(proof["path"])["passed"]):
            raise ValueError("Validated production proof or checker changed")
    from dw_publication import publish

    publication = publish(
        compiled,
        report_path,
        source,
        directory / "updater.json",
        directory / "publication",
    )
    require_current_sources(read(directory / "source-receipt.json"))
    artifact = state / config["target"]
    pending = artifact.with_suffix(".exe.pending")
    shutil.copyfile(compiled, pending)
    if digest(pending) != report["sha256"]:
        raise ValueError("Final client artifact copy failed")
    os.replace(pending, artifact)
    ready = dict(
        passed=True,
        target=config["target"],
        executable=str(artifact),
        sha256=report["sha256"],
        fresh_cpp_units=len(actual),
        unresolved_symbols=0,
        source_root=str(source),
        build_report=str(report_path),
        proofs=proofs,
        source_receipt=str(directory / "source-receipt.json"),
        source_receipt_sha256=digest(directory / "source-receipt.json"),
        latest_bot_optimizations_included=True,
        production_updater_active=True,
        game_runs_performed=False,
        deployed=False,
        publication=publication,
    )
    save(directory / "readiness.json", ready)
    save(
        state / "latest-job.json",
        dict(
            directory=str(directory),
            prepared=True,
            passed=True,
            readiness=str(directory / "readiness.json"),
        ),
    )
    print("PASS one production DW target, all exact-image gates:", artifact, flush=True)
    return ready


def running_games():
    output = subprocess.check_output(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Process -Filter \"Name = 'game_dx12_ship_replay_dw.exe'\" | ForEach-Object { $_.ProcessId }",
        ],
        text=True,
    )
    return [int(value) for value in output.split()]


def deploy(reviewed_previous_build=None):
    config, state, _ = settings()
    latest = read(state / "latest-job.json")
    ready_path = inside(latest["readiness"])
    ready = read(ready_path)
    if not ready["passed"] or not ready["latest_bot_optimizations_included"]:
        raise ValueError("The single DW target has not passed its build gates")
    for proof in ready["proofs"]:
        if digest(inside(proof["path"])) != proof["sha256"]:
            raise ValueError("Exact-image build proof changed")
    source = read(ready["source_receipt"])
    if digest(ready["source_receipt"]) != ready["source_receipt_sha256"]:
        raise ValueError("Source receipt changed")
    require_current_sources(source)
    image = inside(ready["executable"])
    if digest(image) != ready["sha256"]:
        raise ValueError("Verified production image changed")
    from dw_publication import require_current

    publication = ready.get("publication")
    if not publication or publication["sha256"] != ready["sha256"]:
        raise ValueError("Ready build is missing its verified public publication")
    public_proof = inside(publication["verification"])
    if digest(public_proof) != publication["verification_sha256"]:
        raise ValueError("Public updater verification receipt changed")
    verified_publication = read(public_proof)
    if (
        not verified_publication["passed"]
        or verified_publication["executable_sha256"] != ready["sha256"]
    ):
        raise ValueError("Public updater proof does not bind the ready image")
    public_catalog = require_current(ready)
    from remote_backend import verify as verify_backend

    backend = verify_backend()
    game = Path(
        read(Path(ready["source_root"]) / "replay-project.local.json")["game"]
    ).resolve(strict=True)
    target = game / config["target"]
    ini = target.with_suffix(".ini")
    ini_hash = digest(ini)
    before = digest(target)
    retained_previous = None
    if before != ready["sha256"]:
        if running_games():
            raise RuntimeError("DW game is running; close it before deployment")
        if before != source["baseline_executable_sha256"]:
            if reviewed_previous_build is None:
                raise ValueError(
                    "Owner EXE changed since the build; preserve it and review"
                )
            previous_report = inside(reviewed_previous_build)
            previous = read(previous_report)
            previous_image = inside(previous["executable"])
            if (previous["unresolved_symbols"] or previous["sha256"] != before
                    or digest(previous_image) != before):
                raise ValueError("Reviewed candidate does not match the owner EXE")
            retained_previous = dict(
                sha256=before, executable=str(previous_image),
                build_report=str(previous_report),
                build_report_sha256=digest(previous_report),
                reason="Owner manually installed this retained DW candidate",
            )
        pending = game / (config["target"] + ".pending")
        with pending.open("xb") as stream:
            stream.write(image.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        try:
            if (
                digest(pending) != ready["sha256"]
                or running_games()
                or digest(target) != before
            ):
                raise ValueError(
                    "Deployment changed concurrently; current game preserved"
                )
            os.replace(pending, target)
        finally:
            if pending.exists():
                pending.unlink()
    if digest(ini) != ini_hash or digest(target) != ready["sha256"]:
        raise ValueError("Deployed EXE/INI verification failed")
    deployed = dict(
        deployed=True,
        executable=str(target),
        sha256=ready["sha256"],
        owner_ini_preserved=True,
        ini_sha256=ini_hash,
        game_runs_performed=False,
        game_processes_stopped=False,
        readiness=str(ready_path),
        readiness_sha256=digest(ready_path),
        public_updater=public_catalog,
        retained_reviewed_previous=retained_previous,
    )
    save(state / "deployment.json", deployed)
    current_path = ROOT / "data/current-remote-deployment.json"
    current = read(current_path)
    evidence = [
        dict(
            path=inside(proof["path"]).relative_to(ROOT).as_posix(),
            sha256=proof["sha256"],
        )
        for proof in ready["proofs"]
    ]
    for path in (
        ready_path,
        Path(ready["source_receipt"]),
        public_proof,
        state / "deployment.json",
    ):
        evidence.append(
            dict(path=inside(path).relative_to(ROOT).as_posix(), sha256=digest(path))
        )
    current.update(
        created_utc=datetime.now(timezone.utc).isoformat(),
        job_id=read(
            Path(ready["build_report"]).parent.parent.parent / "workstation-job.json"
        )["id"],
        workstation_artifact=str(image),
        build_directory=str(Path(ready["build_report"]).parent),
        compiler_source_root=ready["source_root"],
        source_snapshot_receipt=ready["source_receipt"],
        executable=str(target),
        sha256=ready["sha256"],
        stage="Single production DW source pipeline; exact-image verified; no game run",
        native_runtime_verified=False,
        game_runs_performed=False,
        owner_ini_preserved=True,
        readiness=dict(
            path=ready_path.relative_to(ROOT).as_posix(), sha256=digest(ready_path)
        ),
        sole_client_build_target=True,
        latest_bot_optimizations_included=True,
        public_release=public_catalog["release"],
        public_client_publication=publication,
        server=backend,
        evidence=evidence,
    )
    save(current_path, current)
    print(json.dumps(deployed, indent=2), flush=True)
