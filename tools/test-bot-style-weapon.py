"""Compile the actual script callback with native resource boundaries modeled."""

import argparse, hashlib, json, subprocess, tempfile
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check_recipes(output):
    """Independent stock Lua semantics over pinned original CSV joins."""
    spec = importlib.util.spec_from_file_location(
        "recipe_data", ROOT / "tools/prepare-bot-style-data.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    catalog = module.read_catalog()
    refs = catalog["recipe_refs"]
    weapons = {weapon["reference"]: weapon for weapon in catalog["weapons"]}
    conflicts = {row[0]: dict(zip(refs, row[1:])) for row in catalog["combos"][1:]}
    cases = 0
    for line in output.splitlines():
        if not line.startswith("RECIPE\t"):
            continue
        _, reference, choices, actual = line.split("\t")
        weapon = weapons[reference]
        tokens = dict(zip(refs, weapon["recipes"]))
        variants = {}
        pending = list(weapon["defaults"])
        for choice in choices.split(",") if choices else []:
            ref, variant = choice.split("|")
            pending.append(ref)
            if tokens[ref]["addition"]:
                pending.append(tokens[ref]["addition"])
            if int(variant):
                variants[ref] = int(variant)
        filtered = []
        at = 0
        while at < len(pending):
            assert len(pending) < 128, reference
            ref = pending[at]
            if ref not in filtered:
                for old in filtered:
                    replacement = conflicts.get(ref, {}).get(old, "")
                    if replacement:
                        filtered.remove(old)
                        pending.insert(
                            at + 1, ref if replacement == "no" else replacement
                        )
                        break
                else:
                    filtered.append(ref)
            at += 1
        expected = weapon["native_asset"]
        for ref in filtered:
            resolved = tokens[ref]["resolved"]
            if resolved and resolved != "none":
                expected += "+" + resolved
                if ref in variants:
                    expected += "|" + str(variants[ref])
        assert actual == expected, (reference, actual, expected)
        # Receiver is not a selectable Gunsmith choice. It must survive the
        # complete recipe for all stock weapons that define one.
        if "rec" in weapon["defaults"]:
            assert "+" + tokens["rec"]["resolved"] in actual
        assert len(filtered) <= 29
        cases += 1
    assert cases == 456, cases  # 454 profile cases and two full-table reuse cases.
    return cases


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
    ownership = json.loads(
        (snapshot / "generated/bot-profile-ownership.json").read_bytes()
    )
    assert (
        method["passed"]
        and method["method_id"] == 0x8787
        and method["argument_count"] == 2
        and data["passed"]
        and data["image_sha256"] == method["image_sha256"]
        and ownership["passed"]
        and ownership["image_sha256"] == method["image_sha256"]
    )
    hashes = {
        name: hashlib.sha256((snapshot / "src" / name).read_bytes()).hexdigest()
        for name in [
            "DW_BotStyleWeapon.cpp",
            "DW_BotStyleData.h",
            "DW_BotStyleSelection.h",
            "DW_ScriptMethodBindings.h",
            "DW_BotBindings.h",
        ]
    }
    assert (
        hashes["DW_BotStyleData.h"] == data["generated_header_sha256"]
        and hashes["DW_BotStyleSelection.h"] == data["selector_sha256"]
        and hashes["DW_ScriptMethodBindings.h"] == method["header_sha256"]
        and hashes["DW_BotBindings.h"] == ownership["header_sha256"]
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
                f"Callback fixture exited {result.returncode}: "
                + result.stderr
                + result.stdout
            )
    recipe_cases = check_recipes(result.stdout)
    report = dict(
        schema=1,
        passed=True,
        image_sha256=method["image_sha256"],
        source_hashes=hashes,
        fixture_sha256=hashlib.sha256(
            (ROOT / "tools/bot_style_weapon_harness.cpp").read_bytes()
        ).hexdigest(),
        profile_cases=454,
        preservation_cases=25,
        survival_predicate_cases=12,
        current_owner_cases=10,
        mp_class_readiness_cases=12,
        managed_weapon_capacity_cases=6,
        complete_stock_recipe_cases=recipe_cases,
        linked_image_sha256=linked_hash,
        linked_image_identity_verified=bool(linked_hash),
        callback_harness_executes_linked_image=False,
        output=result.stdout.splitlines()[-1],
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
