"""Deferred behavioral gate for the frozen production inspection runtime.

An approved verify invocation compiles and runs an isolated harness, never the
game. Native WIR calls are modeled; asset decoding and live playback remain
separate gates. This file is source-only until that invocation is authorized.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path("C:/Program Files/LLVM/bin")
ORIGINAL_SHA256 = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
EXPECTED_CASES = 72
FIXTURE_ASSETS = """#pragma once
struct DWWeaponInspectAsset
{
    const char *package;
    const char *animation;
    unsigned durationMs;
};
inline constexpr DWWeaponInspectAsset kDWWeaponInspectAssets[] = {
    {"fixture_package_a", "fixture_inspect_a", 500},
    {"fixture_package_b", "fixture_inspect_b", 750},
};
"""


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def frozen_path(snapshot, relative):
    path = (snapshot / relative).resolve(strict=True)
    assert path.is_relative_to(snapshot), ("Input escapes frozen source", relative)
    return path


def production_inputs(build):
    """Check the real build inputs before substituting the tiny test asset table."""
    report = read(build / "build-report.json")
    snapshot = Path(report["source_root"]).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data"), "Different private source root"
    image = Path(report["executable"])
    image = (image if image.is_absolute() else build / image).resolve(strict=True)
    assert image.is_relative_to(build) and sha(image) == report["sha256"]
    assert not report["unresolved_symbols"]
    assert report["input_sha256"] == ORIGINAL_SHA256
    catalog = read(snapshot / "generated/function-catalog.json")
    assert catalog["image_sha256"] == report["input_sha256"]
    verification = read(build / "verification-report.json")
    assert verification["sha256"] == report["sha256"]
    assert not verification["unresolved_symbols"]

    source = frozen_path(snapshot, "src/DW_WeaponInspect.cpp")
    rows = [
        row
        for row in report["cpp"]
        if Path(row["source"]).as_posix() == "src/DW_WeaponInspect.cpp"
    ]
    assert len(rows) == 1, "Missing/duplicate production inspection owner"
    row = rows[0]
    assert row["source_sha256"] == sha(source), "Changed production runtime"
    obj = Path(row["object"])
    obj = (obj if obj.is_absolute() else build / obj).resolve(strict=True)
    assert obj.is_relative_to(build) and sha(obj) == row["object_sha256"]
    dependencies = {
        Path(item["path"]).resolve(strict=True): item["sha256"]
        for item in row["dependencies"]
    }
    assert len(dependencies) == len(row["dependencies"])
    for path, digest in dependencies.items():
        assert sha(path) == digest, ("Changed recorded compiler input", str(path))
    required = [
        source,
        *(
            frozen_path(snapshot, "src/" + name)
            for name in (
                "DW_WeaponInspect.h",
                "DW_WeaponInspectBindings.h",
                "DW_WeaponInspectAssets.h",
            )
        ),
    ]
    for path in required:
        assert dependencies[path] == sha(path), (
            "Untracked real generated input",
            path.name,
        )

    proof = read(snapshot / "generated/weapon-inspect-integration.json")
    assert proof["source"] == "src/DW_WeaponInspect.cpp"
    assert proof["source_sha256"] == sha(source)
    for relative, digest in proof["dependencies"].items():
        assert sha(frozen_path(snapshot, relative)) == digest, (
            "Changed inspection preparation input",
            relative,
        )
    harness = frozen_path(snapshot, "tools/weapon_inspect_harness.cpp")
    checker = frozen_path(snapshot, "tools/test-weapon-inspect-runtime.py")
    assert sha(checker) == sha(Path(__file__)), "Checker differs from frozen gate"
    return (
        snapshot,
        source,
        harness,
        dict(
            executable_sha256=report["sha256"],
            original_image_sha256=report["input_sha256"],
            production_source_sha256=sha(source),
            production_object_sha256=row["object_sha256"],
            production_inputs={
                str(path.relative_to(snapshot)): sha(path) for path in required
            },
            production_dependencies_verified=len(dependencies),
            harness_source_sha256=sha(harness),
            checker_sha256=sha(checker),
        ),
    )


def verify(build):
    build = Path(build).resolve(strict=True)
    snapshot, source, harness, receipt = production_inputs(build)
    # Quoted includes search the source directory first. A byte-identical copy
    # outside snapshot/src makes the test fixture override only Assets.h; the
    # actual generated Bindings.h and ABI header still come from snapshot/src.
    with tempfile.TemporaryDirectory(
        prefix="weapon-inspect-runtime-", dir=build
    ) as temporary:
        folder = Path(temporary)
        fixture = folder / "fixture"
        production = folder / "production"
        fixture.mkdir()
        production.mkdir()
        header = fixture / "DW_WeaponInspectAssets.h"
        header.write_text(FIXTURE_ASSETS, encoding="utf-8")
        copied_source = production / source.name
        copied_source.write_bytes(source.read_bytes())
        assert sha(copied_source) == receipt["production_source_sha256"]
        owner_object, harness_object = folder / "production.obj", folder / "harness.obj"
        executable = folder / "weapon-inspect-runtime.exe"
        flags = [
            "--target=x86_64-pc-windows-msvc",
            "-std=c++20",
            "-O2",
            "-fno-exceptions",
            "-fno-rtti",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-UNDEBUG",
            "-I" + str(fixture),
            "-I" + str(snapshot / "src"),
        ]
        compiler = str(LLVM / "clang++.exe")
        for unit, obj in ((copied_source, owner_object), (harness, harness_object)):
            subprocess.run(
                [compiler, *flags, "-c", str(unit), "-o", str(obj)], check=True
            )
        subprocess.run(
            [
                compiler,
                "--target=x86_64-pc-windows-msvc",
                str(owner_object),
                str(harness_object),
                "-o",
                str(executable),
            ],
            check=True,
        )
        result = subprocess.run([str(executable)], capture_output=True, text=True)
        assert result.returncode == 0, (
            "Production inspection fixture failed",
            result.returncode,
            result.stdout,
            result.stderr,
        )
        cases = re.findall(r"^CASE\t([^\r\n]+)$", result.stdout, re.MULTILINE)
        passed = re.findall(
            r"^PASS WEAPON_INSPECT_RUNTIME cases=(\d+)$", result.stdout, re.MULTILINE
        )
        assert len(passed) == 1 and int(passed[0]) == EXPECTED_CASES
        assert len(cases) == len(set(cases)) == EXPECTED_CASES
        receipt.update(
            fixture_assets_sha256=sha(header),
            compiled_production_copy_sha256=sha(copied_source),
            harness_object_sha256=sha(harness_object),
            modeled_owner_object_sha256=sha(owner_object),
            harness_executable_sha256=sha(executable),
            harness_stdout=result.stdout,
            harness_stderr=result.stderr,
            case_names=cases,
        )
    receipt.update(
        passed=True,
        source_root=str(snapshot),
        cases=EXPECTED_CASES,
        production_owner_compiled_separately=True,
        production_real_asset_header_verified=True,
        harness_uses_fixture_assets=True,
        harness_executes_linked_image=False,
        native_boundary_implementations_executed=False,
        live_game_animation_verified=False,
        modeled_boundaries=[
            "reliable command connection and enqueue",
            "native gameplay predicates",
            "native weapon/package lookup",
            "type16 animation name/index lookup",
            "native scripted setter ownership fields",
            "native idle and original PM_Weapon",
        ],
    )
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = verify(args.build)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(dict(passed=True, cases=receipt["cases"], output=str(args.output)))
    )


if __name__ == "__main__":
    main()
