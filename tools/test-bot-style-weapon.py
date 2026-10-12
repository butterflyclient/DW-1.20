"""Compile the actual script callback with native resource boundaries modeled."""

import argparse, hashlib, json, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--build", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    snapshot = a.snapshot.resolve()
    method = json.loads(
        (snapshot / "generated/bot-style-method-integration.json").read_bytes()
    )
    data = json.loads((snapshot / "generated/bot-style-data.json").read_bytes())
    assert (
        method["passed"]
        and method["method_id"] == 0x8787
        and method["argument_count"] == 2
        and data["passed"]
        and data["image_sha256"] == method["image_sha256"]
    )
    hashes = {
        name: hashlib.sha256((snapshot / "src" / name).read_bytes()).hexdigest()
        for name in [
            "DW_BotStyleWeapon.cpp",
            "DW_BotStyleData.h",
            "DW_BotStyleSelection.h",
            "DW_ScriptMethodBindings.h",
        ]
    }
    assert (
        hashes["DW_BotStyleData.h"] == data["generated_header_sha256"]
        and hashes["DW_BotStyleSelection.h"] == data["selector_sha256"]
        and hashes["DW_ScriptMethodBindings.h"] == method["header_sha256"]
    )
    linked_hash = None
    if a.build:
        build = json.loads((a.build / "build-report.json").read_bytes())
        executable = Path(build["executable"])
        assert (
            hashlib.file_digest(executable.open("rb"), "sha256").hexdigest()
            == build["sha256"]
        )
        assert build["unresolved_symbols"] == 0
        compiled = [
            row
            for row in build["cpp"]
            if row["source"].replace("\\", "/").endswith("src/DW_BotStyleWeapon.cpp")
        ]
        assert (
            len(compiled) == 1
            and compiled[0]["source_sha256"] == hashes["DW_BotStyleWeapon.cpp"]
        )
        dependencies = {
            Path(row["path"]).name: row["sha256"] for row in compiled[0]["dependencies"]
        }
        for name, expected in hashes.items():
            assert dependencies[name] == expected, (
                name,
                "Linked callback dependency differs from tested snapshot",
            )
        linked_hash = build["sha256"]
    with tempfile.TemporaryDirectory(
        prefix="bot-style-weapon-", dir=ROOT / "data"
    ) as directory:
        executable = Path(directory) / "bot-style-weapon-test.exe"
        command = [
            r"C:\Program Files\LLVM\bin\clang++.exe",
            "-std=c++20",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(snapshot / "src"),
            str(snapshot / "src/DW_BotStyleWeapon.cpp"),
            str(ROOT / "tools/bot_style_weapon_harness.cpp"),
            "-o",
            str(executable),
        ]
        compiled = subprocess.run(command, capture_output=True, text=True)
        if compiled.returncode:
            raise RuntimeError(compiled.stderr or compiled.stdout)
        result = subprocess.run(
            [str(executable)], cwd=directory, capture_output=True, text=True
        )
        if result.returncode:
            raise RuntimeError(
                f"Callback fixture exited {result.returncode}: " + result.stderr + result.stdout
            )
    report = dict(
        schema=1,
        passed=True,
        image_sha256=method["image_sha256"],
        source_hashes=hashes,
        fixture_sha256=hashlib.sha256(
            (ROOT / "tools/bot_style_weapon_harness.cpp").read_bytes()
        ).hexdigest(),
        profile_cases=454,
        preservation_cases=20,
        survival_predicate_cases=12,
        managed_weapon_capacity_cases=6,
        linked_image_sha256=linked_hash,
        linked_image_identity_verified=bool(linked_hash),
        callback_harness_executes_linked_image=False,
        output=result.stdout.strip(),
        modeled_boundaries=[
            "Script argument and managed clone ownership APIs",
            "Native full parser/base resource lookup and weapon validator",
            "Native bot identity and game phase",
            "Survival permission owner; exact botData pointer and scalar result tested",
        ],
        game_run_performed=False,
        native_weapon_resource_validation=False,
    )
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(report["output"])


if __name__ == "__main__":
    main()
