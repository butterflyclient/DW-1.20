"""Focused actual-table bot style selection gate; no game launch or deployment."""
import argparse
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"


def check_menu_weapons(snapshot, proof):
    """Use the stock Lua menu condition as the independent eligibility oracle."""
    spec = importlib.util.spec_from_file_location(
        "weapon_menu_catalog", ROOT / "tools/prepare-bot-style-data.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    catalog = module.read_catalog()
    sys.path.insert(0, str(ROOT / "data/unlock-lua-runtime"))
    from lupa.lua51 import LuaRuntime
    lua = LuaRuntime(unpack_returned_tuples=True)
    condition = catalog["weapon_menu_condition"]
    variable = re.search(r"tonumber\((\w+)\.displayOrder\)", condition).group(1)
    eligible = lua.eval("function(" + variable + ") return " + condition + " end")
    table = next(module.TABLES.glob("mp/statstable.csv.*.csv"))
    rows = list(csv.reader(table.read_text(encoding="utf-8-sig").splitlines()))
    accepted = {weapon["reference"] for weapon in catalog["weapons"]}
    excluded = {weapon["reference"] for weapon in catalog["hidden_weapons"]}
    for row in rows:
        if row[4] in accepted | excluded:
            shown = bool(eligible(lua.table_from({"displayOrder": row[41]})))
            assert shown == (row[4] in accepted), row[4]
    assert not accepted & excluded
    generated = (snapshot / "src/DW_BotStyleData.h").read_text()
    for weapon in catalog["hidden_weapons"]:
        assert json.dumps(weapon["reference"]) not in generated
        assert json.dumps(weapon["native_asset"]) not in generated
    assert proof["excluded_hidden_base_weapons"] == catalog["hidden_weapons"]
    assert proof["base_weapon_eligibility"] == condition
    return dict(stock_lua_menu_executed=True, displayed_base_weapons=len(accepted),
                excluded_hidden_base_weapons=sorted(excluded))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve()
    assert snapshot.is_relative_to((ROOT / "data").resolve())
    proof = json.loads((snapshot / "generated/bot-style-data.json").read_bytes())
    assert proof["image_sha256"] == TARGET and proof["passed"]
    generated = snapshot / "src/DW_BotStyleData.h"
    selector = snapshot / "src/DW_BotStyleSelection.h"
    assert hashlib.sha256(generated.read_bytes()).hexdigest() == proof["generated_header_sha256"]
    assert hashlib.sha256(selector.read_bytes()).hexdigest() == proof["selector_sha256"]
    menu = check_menu_weapons(snapshot, proof)
    if args.build:
        build_report = json.loads((args.build / "build-report.json").read_bytes())
        assert not build_report["unresolved_symbols"]
        assert hashlib.sha256(Path(build_report["executable"]).read_bytes()).hexdigest() == build_report["sha256"]
        roster = snapshot / "src/DW_BotRoster.cpp"
        assert hashlib.sha256(roster.read_bytes()).hexdigest() in {
            row["source_sha256"] for row in build_report["cpp"]
        }
    for path, expected in proof["source_inputs"].items():
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected, path
    data_root = (ROOT / "data").resolve()
    with tempfile.TemporaryDirectory(prefix="bot-style-test-", dir=data_root) as temporary:
        folder = Path(temporary).resolve()
        # The runner's automatically removed artifacts must remain private.
        assert folder.is_relative_to(data_root)
        executable = folder / "test-bot-style-selection.exe"
        command = [r"C:\Program Files\LLVM\bin\clang++.exe", "-std=c++17", "-O2",
                   "-Wall", "-Wextra", "-Werror", "-I" + str(snapshot / "src"),
                   str(ROOT / "tools/test-bot-style-selection.cpp"), "-o", str(executable)]
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
        result = subprocess.run([str(executable)], cwd=folder, check=True, capture_output=True, text=True)
    report = dict(passed=True, image_sha256=TARGET, actual_table_counts=proof["counts"],
                  base_weapon_menu=menu,
                  generated_header_sha256=proof["generated_header_sha256"],
                  selector_sha256=proof["selector_sha256"],
                  fixture_sha256=hashlib.sha256((ROOT / "tools/test-bot-style-selection.cpp").read_bytes()).hexdigest(),
                  output=result.stdout.strip(), compiler_command=command,
                  game_launched=False, native_runtime_verified=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(result.stdout.strip())


if __name__ == "__main__":
    main()
