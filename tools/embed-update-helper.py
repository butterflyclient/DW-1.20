"""Embed the exact statically linked update helper into private Replay sources."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def build(source_root, output):
    """Freeze the selected client trust/ABI inputs before compiling the helper."""
    project = output.parent / "helper-source"
    (project / "tools").mkdir(parents=True, exist_ok=True)
    integration = project / "integration/replay"
    integration.mkdir(parents=True, exist_ok=True)
    files = [(ROOT / "tools/replay-update-client.cpp", project / "tools/replay-update-client.cpp")]
    files += [
        (source_root / name, integration / name)
        for name in (
            "DW_LocalPlatformCrypto.cpp",
            "dw_local_trust.h",
            "dw_platform_protocol.h",
            "dw_update_protocol.h",
        )
    ]
    inputs = []
    for source, target in files:
        shutil.copyfile(source, target)
        inputs.append(
            {
                "source": str(source),
                "frozen": str(target),
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            }
        )
    (project / "CMakeLists.txt").write_text(
        """cmake_minimum_required(VERSION 3.24)
project(replay_update_helper LANGUAGES CXX)
add_executable(replay-update-client tools/replay-update-client.cpp integration/replay/DW_LocalPlatformCrypto.cpp)
target_compile_features(replay-update-client PRIVATE cxx_std_20)
target_compile_definitions(replay-update-client PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(replay-update-client PRIVATE bcrypt winhttp msdelta)
set_property(TARGET replay-update-client PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
""",
        encoding="ascii",
    )
    build_root = output.parent / "helper-build"
    subprocess.run(
        [
            "cmake",
            "-S",
            str(project),
            "-B",
            str(build_root),
            "-G",
            "Visual Studio 18 2026",
            "-A",
            "x64",
        ],
        check=True,
    )
    subprocess.run(
        [
            "cmake",
            "--build",
            str(build_root),
            "--config",
            "Release",
            "--target",
            "replay-update-client",
            "--parallel",
            "2",
        ],
        check=True,
    )
    helper = build_root / "Release/replay-update-client.exe"
    for entry in inputs:
        if hashlib.sha256(Path(entry["source"]).read_bytes()).hexdigest() != entry["sha256"]:
            raise RuntimeError("Updater source changed during helper compilation")
    output.with_suffix(".build.json").write_text(
        json.dumps(
            {
                "helper": str(helper),
                "sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
                "inputs": inputs,
            },
            indent=2,
        )
        + "\n"
    )
    return helper


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--helper", type=Path)
    choice.add_argument(
        "--source-root",
        type=Path,
        help="Compile against these frozen client headers and crypto source",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    blob = (build(args.source_root, args.output) if args.source_root else args.helper).read_bytes()
    if not blob.startswith(b"MZ") or not 1024 < len(blob) < 4 * 1024 * 1024:
        raise ValueError("Unexpected updater helper image")
    lines = [
        "#pragma once",
        "// Static helper SHA256: " + hashlib.sha256(blob).hexdigest(),
        "static const unsigned char s_dwUpdateHelper[] = {",
    ]
    lines += [
        "    " + ",".join(f"0x{x:02x}" for x in blob[at : at + 32]) + ","
        for at in range(0, len(blob), 32)
    ]
    lines += ["};", ""]
    args.output.write_text("\n".join(lines), encoding="ascii", newline="\n")
    print(hashlib.sha256(blob).hexdigest(), len(blob))
