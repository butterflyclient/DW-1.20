"""Bind Buy Station missions to Replay's original parser and shipped table.

Uses a private execution of ProcessParams and retained native ScriptFiles.
The original ScriptFile bytes corroborate the reporting and failure branches;
this does not launch the game or prove a live gameplay callback.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
KIOSK_SHA = "273740afbb626193bfd7ab378c3e811910eeffdc1f0711ff5a16897518275732"
ASSEMBLY_SHA = "cabc1a75dd9001f8fcfc9cff53908cb8ec5ca9667fec826b66f36b64a49678b2"


def digest(contents):
    return hashlib.sha256(contents).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-parser-proof", type=Path, required=True)
    parser.add_argument("--kiosk-assembly", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--table-proof", type=Path, required=True)
    args = parser.parse_args()
    for path in vars(args).values():
        assert path.resolve().is_relative_to(ROOT)
    parent = json.loads(args.parent_parser_proof.read_bytes())
    assert parent["target_image_sha256"] == IMAGE_SHA
    # The base tool validates the target image and every retained FF/FP/table.
    # run_path writes its base proof to --output, then we retain the full parent
    # cases and append only newly executed purchase inputs.
    original = ROOT / "tools/research-challenge-event-parser.py"
    previous_arguments = sys.argv
    try:
        sys.argv = [str(original), "--output", str(args.output)]
        environment = runpy.run_path(str(original))
    finally:
        sys.argv = previous_arguments
    native = environment["case"]
    lookup_proof_path = ROOT / "validation/20261010-replay-stringtable-lookup.json"
    lookup = json.loads(lookup_proof_path.read_bytes())
    assert lookup["passed"] and lookup["target_image_sha256"] == IMAGE_SHA
    assert lookup["ascii_case_insensitive"] and lookup["last_matching_row_selected"]
    assert lookup["tool_sha256"] == digest((ROOT / "tools/research-replay-stringtable-lookup.py").read_bytes())
    # The corrected table boundary applies to all parser families. Re-execute
    # the full retained parent rather than inheriting old boundary results.
    for row in parent["cases"]:
        if "error" in row:
            continue
        current = native(row["name"], row["input"])
        assert all(current[key] == row[key] for key in ("accepted", "parameter_count", "values")), row
    tables = {}
    for name in ("20261010-challenge-asset-tables.json", "20261010-challenge-br-asset-tables.json"):
        manifest = json.loads((ROOT / "validation" / name).read_bytes())
        assert manifest["passed"] and manifest["target_image_sha256"] == IMAGE_SHA
        tables.update({row["name"]: row for row in manifest["tables"]})
    refs = tables["mp/achievementenginerefs.csv"]
    table = tables["mp/brkioskpurchases.csv"]
    categories = {row[1]: int(row[0]) for row in csv.reader((ROOT / refs["path"]).read_text().splitlines())}
    purchases = list(csv.reader((ROOT / table["path"]).read_text().splitlines()))
    assert len(purchases) == 10 and {int(row[0]) for row in purchases} == set(range(10))
    enum_name = lambda name: "".join(part.capitalize() for part in name.split("_"))
    records, cases = [], []

    def execute(label, category, item, operators=" "):
        row = native("buy_item", f"{category},{item},{operators}")
        assert row["accepted"] and row["parameter_count"] == 3
        row["fixture_label"] = label
        cases.append(row)
        return row["values"]

    for row in purchases:
        item, category, name = int(row[0]), row[1], row[2]
        label = "buy_" + name
        assert execute(label, category, name) == [categories[category], item, 0]
        records.append(dict(id=item, category=category, category_id=categories[category],
                            name=name, enumerator=enum_name(name), fixture_label=label))
    for label, category, item, expected in (
        ("buy_unknown_category", "unknown", "uav", [0, 5, 0]),
        ("buy_unknown_item", "killstreak", "unknown", [2, 0, 0]),
        ("buy_wrong_category_uav", "special", "uav", [1, 5, 0]),
        ("buy_wrong_category_loadout", "killstreak", "supply_drop", [2, 9, 0]),
        ("buy_wrong_category_munitions", "special", "super_ammo_drop", [1, 8, 0]),
        ("buy_wrong_category_redeploy", "special", "teamrevive", [1, 7, 0]),
        ("buy_field_upgrade_case", "fieldUpgrade", "super_ammo_drop", [4, 8, 0]),
    ):
        actual = execute(label, category, item)
        assert actual == expected, (label, actual, expected)
    values = execute("buy_uav_operators", "killstreak", "uav", "wyatt_western|spetsnaz_eastern")
    assert values[:2] == [2, 5] and values[2] != 0
    assert len(cases) == 18

    script_folder = ROOT / "data/remaining-contracts-20261009/native-challenge-scripts"
    payload = (script_folder / "scripts/mp/gametypes/br_armory_kiosk.gscbin").read_bytes()
    assert digest(payload) == KIOSK_SHA
    compressed_size = struct.unpack_from("<I", payload, 4)[0]
    code = payload[16 + compressed_size:]
    source = zlib.decompress(payload[16:16 + compressed_size])
    assembly = args.kiosk_assembly.read_bytes()
    assert digest(assembly) == ASSEMBLY_SHA
    assembly_text = assembly.decode().replace("\r\n", "\n")
    functions = re.findall(r"// Params (\d+)\n// Size: 0x([0-9a-f]+)\nfunction ([^\n]+)\n", assembly_text)
    blocks, cursor = {}, 1
    for params, size, name in functions:
        # ACTS emits per-function offsets. Verify their concatenation spans
        # the exact original bytecode and every formal-parameter boundary.
        count = int(params)
        assert code[cursor] == (0xA6 if count else 0x4B)
        if count:
            assert code[cursor + 1] == count
        blocks[name[:-2]] = cursor
        cursor += int(size, 16)
    assert cursor == len(code) == 6600 and len(blocks) == 36
    for name in ("killstreak", "special", "teamrevive", "fieldUpgrade", "onkioskpurchaseitem"):
        assert name.encode() + b"\0" in source
    windows = []

    def window(function, offset, expected, meaning):
        absolute = blocks[function] + offset
        raw = bytes.fromhex(expected)
        assert code[absolute:absolute + len(raw)] == raw, (function, offset)
        windows.append(dict(function=function, relative_offset=offset, original_offset=absolute,
                            original_bytes_hex=expected, meaning=meaning))

    for function, offset, raw, meaning in (
        ("ref_8e5a", 0x83, "3392eeff5b083e724901", "Validate item, branch around purchase on failure"),
        ("_handlekillstreakpurchase", 0x64, "961493a658", "Report stored killstreak after grant and payment"),
        ("_handlekillstreakpurchase", 0x1AD, "725500", "Failed activation skips payment/report to function end"),
        ("_handlekillstreakpurchase", 0x1E5, "6022ef4758", "Report successfully activated killstreak"),
        ("_handlespecialpurchase", 0x128, "725900", "Failed special-item grant skips payment/report"),
        ("_handlespecialpurchase", 0x164, "602cea2658", "Report special purchase, including loadout drop"),
        ("ref_8e5a", 0xC9, "9654b23758", "Grant field upgrade after purchase validation"),
        ("ref_8e5a", 0x105, "606b0c1058", "Report fieldUpgrade after grant/payment"),
        ("ref_8e5a", 0x4D3, "9668e82858", "Report paid teammate redeploy"),
        ("ref_8e5a", 0x4F3, "155c5c5c441133ca000058", "Token redeploy has zero currency payment"),
        ("ref_8e5a", 0x50B, "9674dfa758", "Report token teammate redeploy too"),
    ):
        window(function, offset, raw, meaning)
    for function, offset, target in (("ref_8e5a", 0x8A, 0x1D6),
                                      ("_handlekillstreakpurchase", 0x1AD, 0x205),
                                      ("_handlespecialpurchase", 0x128, 0x184)):
        absolute = blocks[function] + offset
        assert offset + 3 + struct.unpack_from("<h", code, absolute + 1)[0] == target
    challenge = (script_folder / "scripts/cp_mp/challenges.gscbin").read_bytes()
    assert digest(challenge) == "074bcfaf5cd6fe39c6fde4f02321b7db9ab90197f1eab7d43afbc47a938694f7"
    challenge_asm = (script_folder / "disassembled/iw8/challenge-normalized.gscasm").read_bytes()
    assert digest(challenge_asm) == "eb56bccf022463022125d7374a15548a47fda3efb3628edc67dafa5ef8c51576"
    producer = challenge_asm.decode().split("sub:onkioskpurchaseitem\n", 1)[1].split("end:onkioskpurchaseitem", 1)[0]
    assert 'OP_GetString "buy_item"' in producer and "OP_CallBuiltinMethod4 reportchallengeuserevent" in producer
    assert "OP_ScriptLocalFunctionCall2 getoperators" in producer

    header = ROOT / "src/replay_kiosk_purchase_data.h"
    category_names = {"special": "Special", "killstreak": "Killstreak",
                      "teamrevive": "TeamRevive", "fieldupgrade": "FieldUpgrade"}
    lines = ["#pragma once", "#include <array>", "#include <cstdint>", "#include <string_view>", "",
             "// Generated from the native Replay mp/brkioskpurchases.csv and",
             "// mp/achievementenginerefs.csv; all ten shipped purchase rows retained.",
             "enum class ReplayKioskCategory : uint64_t", "{"]
    lines += [f"    {name} = {categories[ref]}," for ref, name in category_names.items()]
    lines += ["};", "", "enum class ReplayKioskItem : uint64_t", "{"]
    lines += [f"    {row['enumerator']} = {row['id']}," for row in records]
    lines += ["};", "", "struct ReplayKioskPurchase", "{", "    ReplayKioskItem id;",
              "    ReplayKioskCategory category;", "    std::string_view name;", "};", "",
              "inline constexpr std::array<ReplayKioskPurchase, 10> replayKioskPurchases = {{"]
    lines += [f'    {{ReplayKioskItem::{row["enumerator"]}, ReplayKioskCategory::{category_names[row["category"]]}, "{row["name"]}"}},'
              for row in records]
    lines += ["}};", ""]
    header.write_text("\n".join(lines), encoding="utf-8")
    labels = {row.get("fixture_label") for row in parent["cases"]}
    assert not labels.intersection(row["fixture_label"] for row in cases)
    parent["cases"].extend(cases)
    parent.update(kiosk_cases=len(cases), kiosk_tool_sha256=digest(Path(__file__).read_bytes()),
                  base_tool_sha256=digest(original.read_bytes()),
                  native_lookup_proof_sha256=digest(lookup_proof_path.read_bytes()),
                  retained_parent_cases_reexecuted=len(parent["cases"]) - len(cases),
                  parent_parser_proof_sha256=digest(args.parent_parser_proof.read_bytes()))
    args.output.write_text(json.dumps(parent, indent=2) + "\n")
    proof = dict(passed=True, target_image_sha256=IMAGE_SHA, purchases=records,
                 tables=[refs, table], parser_proof_sha256=digest(args.output.read_bytes()),
                 tool_sha256=digest(Path(__file__).read_bytes()), kiosk_payload_sha256=digest(payload),
                 kiosk_bytecode_sha256=digest(code), kiosk_assembly_sha256=digest(assembly),
                 original_reporting_windows=windows, function_boundaries_verified=36,
                 generated_path=header.relative_to(ROOT).as_posix(), generated_sha256=digest(header.read_bytes()),
                 event_fields={"Param0": "category ID", "Param1": "item ID", "Param2": "operator mask"},
                 failed_purchase_branches_verified=True, zero_payment_redeploy_report_verified=True,
                 native_game_callback_verified=False, game_runs_performed=False)
    args.table_proof.write_text(json.dumps(proof, indent=2) + "\n")
    print(f"Verified ten purchase rows, 18 native packets and success/failure reporting branches: {args.table_proof}")


if __name__ == "__main__":
    main()
