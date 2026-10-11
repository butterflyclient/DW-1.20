"""Recover Replay kill modifiers and BR context from original producers.

Correlates every mask assignment with unmodified ScriptFile operands, executes
native Lua rarity/Overkill definitions, and executes the original kill parser.
No game launch, source-oracle numeric substitution, or gameplay callback claim.
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

ROOT = Path(__file__).resolve().parents[1]
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--parent-parser-proof", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--layout-proof", type=Path, required=True)
    args = parser.parse_args()
    for path in vars(args).values():
        assert path.resolve().is_relative_to(ROOT)
    folder = args.evidence_directory.resolve()
    # This reader provides the complete instruction widths, including formal
    # parameters and switch tables. Hash it as an explicit research dependency.
    sys.dont_write_bytecode = True
    reader_path = Path(r"E:\replay-compiler\tools/workstation_asset_codecs.py")
    sys.path.insert(0, str(reader_path.parent))
    from workstation_asset_codecs import _script_instructions, _GSC_LOCAL_REFERENCES
    reader_sha = digest(reader_path)
    candidates = json.loads((folder / "modifier-script-candidates.json").read_bytes())
    row = next(value for value in candidates if value["name"] == "1843")
    original_path = folder / "candidates" / (str(row["rank"]) + ".gscbin")
    assert digest(original_path) == row["payload_sha256"] == "fafa6157e03c0f3900963014753a9294b923c8b13e518a5292aeb55ede2be4cc"
    normalized = folder / "modifiers-normalized.gscbin"
    assembly = folder / "disassembled/iw8/modifiers-normalized.gscasm"
    assert digest(normalized) == "789dacb4def432a5f53f4be8b316fce44cfbd03334d2c4e2d5e9e7f9f749894f"
    assert digest(assembly) == "370ff39cb6a6b60bd3174a585fc3143e0d2f84724fcf4f0fa0a81630630cbbe4"

    def bytecode(path):
        blob = path.read_bytes()
        return blob[16 + struct.unpack_from("<I", blob, 4)[0]:]

    original_code, normalized_code = bytecode(original_path), bytecode(normalized)
    original_instructions = list(_script_instructions(original_code))
    instructions = list(_script_instructions(normalized_code))
    assert original_instructions == instructions
    changed_operands = set()
    for pc, opcode, end in instructions:
        if opcode in _GSC_LOCAL_REFERENCES:
            changed_operands.update(range(pc + 1, pc + 4))
        if opcode == 0x56:
            count = struct.unpack_from("<H", original_code, pc + 1)[0]
            for index in range(count):
                changed_operands.update(range(pc + 7 + 7 * index, pc + 10 + 7 * index))
    assert len(original_code) == len(normalized_code)
    assert all(left == right or index in changed_operands
               for index, (left, right) in enumerate(zip(original_code, normalized_code)))
    operations = [line.strip() for line in assembly.read_text().splitlines()
                  if line.strip().startswith("OP_")]
    assert len(operations) == len(instructions) == 5665
    writes, flags = [], {}
    for index, operation in enumerate(operations):
        mask = re.fullmatch(r'OP_GetString "(mask2?)"', operation)
        if not mask or index < 4 or index + 8 >= len(operations):
            continue
        name = re.fullmatch(r'OP_GetString "([^"\n]+)"', operations[index - 4])
        constant = re.fullmatch(r"OP_Get(Byte|UnsignedShort|Integer) (\d+)", operations[index + 3])
        if not name or not constant:
            continue
        if operations[index - 3:index] != ["OP_EvalSelfFieldVariableRef modifiers", "OP_EvalArrayRef", "OP_SetVariableField"]:
            continue
        assert operations[index + 1:index + 3] == ["OP_EvalSelfFieldVariable modifiers", "OP_EvalArray"]
        assert operations[index + 4] == "OP_bit_or"
        assert operations[index + 5:index + 9] == [operation, "OP_EvalSelfFieldVariableRef modifiers",
                                                    "OP_EvalArrayRef", "OP_SetVariableField"]
        value = int(constant[2])
        assert value and value & (value - 1) == 0 and value <= (1 << 30)
        pc, opcode, end = instructions[index + 3]
        expected = {"Byte": bytes((0x16, value)) if value < 256 else None,
                    "UnsignedShort": b"\x66" + struct.pack("<H", value) if value < 65536 else None,
                    "Integer": b"\x49" + struct.pack("<I", value)}[constant[1]]
        assert expected and original_code[pc:end] == expected, (name[1], pc, opcode, original_code[pc:end].hex(), expected.hex() if expected else None)
        word = 0 if mask[1] == "mask" else 1
        combined = value << (word * 32)
        key = name[1]
        assert key not in flags or flags[key]["value"] == combined
        flags[key] = dict(name=key, word=word, bit=value, value=combined)
        writes.append(dict(name=key, word=word, bit=value, original_offset=pc,
                           original_bytes_hex=expected.hex()))
    assert len(writes) == 48 and len(flags) == 46
    assert len({value["value"] for value in flags.values()}) == 46

    lua_inputs, lua_definitions = [], {}
    sys.path.insert(0, str(ROOT / ".toolchains/lua-contract-tests"))
    from lupa.luajit21 import LuaRuntime
    for key, layout_name, asset_name in (("rarity", "br-loot-lua-native-layout.json", "ui/utils/brlootutils.lua"),
                                         ("perk", "perk-lua-native-layout.json", "ui/utils/mp/perkutils.lua")):
        layout_path = folder / layout_name
        layout = json.loads(layout_path.read_bytes())
        assert layout["status"] == "replay-luafile-native-root-and-child-trace-pass"
        assert layout["asset"]["type_id"] == 62 and layout["asset"]["name"] == asset_name
        for source in (layout["decode_source"], *layout["decode_source"]["patches"]):
            assert digest(Path(source["path"])) == source["sha256"]
        body_path = Path(layout["source_body"]["path"])
        assert digest(body_path) == layout["source_body"]["sha256"]
        assert digest(Path(layout["native_manifest"]["path"])) == layout["native_manifest"]["sha256"]
        body = body_path.read_bytes()
        asset = layout["asset"]
        assert asset["root_bytes"] == 24
        at, size = asset["bytecode_archive_offset"], asset["bytecode_bytes"]
        payload = body[at:at + size]
        assert hashlib.sha256(payload).hexdigest() == asset["bytecode_sha256"]
        lua = LuaRuntime(encoding=None)
        stop = None
        try:
            lua.execute(payload)
        except Exception as error:
            stop = str(error)
        if key == "rarity":
            assert stop and "SWATCHES" in stop
            values = {name.decode(): value for name, value in lua.globals()[b"BRLOOT"][b"itemRarities"].items()}
            assert values == {"COMMON": 0, "UNCOMMON": 1, "RARE": 2, "EPIC": 3,
                              "LEGENDARY": 4, "PLAYER": 5, "MISSION": 6, "SPECIAL_MISSION": 7}
        else:
            assert stop is None
            perk = lua.globals()[b"PERK"]
            keys = (b"perkOverkill", b"perkIncludesOverkill", b"perkMunitions", b"perkMunitions2")
            values = {name.decode(): perk[name].decode() for name in keys}
            predicate = perk[b"IsPerkOverkill"]
            assert all(predicate(value.encode()) for value in values.values())
            assert not predicate(b"specialty_ghost") and not predicate(b"specialty_null")
        lua_definitions[key] = values
        lua_inputs.append(dict(asset=asset_name, bytecode_sha256=asset["bytecode_sha256"],
                               layout_proof=layout_path.relative_to(ROOT).as_posix(), layout_sha256=digest(layout_path)))

    parent = json.loads(args.parent_parser_proof.read_bytes())
    parser_path = ROOT / "tools/research-challenge-event-parser.py"
    assert parent["target_image_sha256"] == IMAGE_SHA and parent["base_tool_sha256"] == digest(parser_path)
    previous_arguments = sys.argv
    try:
        sys.argv = [str(parser_path), "--output", str(args.output)]
        environment = runpy.run_path(str(parser_path))
    finally:
        sys.argv = previous_arguments
    native, kill_input = environment["case"], environment["kill_input"]
    new_cases = []

    def execute(label, weapon="iw8_pi_golf21_mp", mask=0, mask2=0, rarity=65535, circle=65535,
                target=1, attachments="no_attachments", perks="no_perks", mode=6):
        tokens = kill_input(weapon, attachments, target_type=target, perks=perks).split(",")
        tokens[2:4] = [str(mask), str(mask2)]
        tokens[5] = str(mode)
        tokens[12:14] = [str(rarity), str(circle)]
        result = native("kill", ",".join(tokens))
        assert result["accepted"] and result["parameter_count"] == 7
        assert result["values"][1] == mask | (mask2 << 32)
        assert result["values"][6] >> 32 & 0xFFFF == rarity
        assert result["values"][6] >> 48 == circle
        result["fixture_label"] = label
        new_cases.append(result)
        return result

    def flag_case(label, name, **parameters):
        flag = flags[name]
        parameters["mask" if flag["word"] == 0 else "mask2"] = flag["bit"]
        return execute(label, **parameters)

    for name in flags:
        flag_case("modifier_" + name, name)
    execute("modifier_none")
    execute("modifier_secondary_wrong_word", mask2=flags["secondary_weapon"]["bit"])
    execute("modifier_victim_down_wrong_word", mask=flags["victim_last_stand"]["bit"], mode=24)
    execute("modifier_king_wrong_word", mask=flags["kingslayer"]["bit"], weapon="iw8_ar_mcharlie_mp")
    execute("modifier_all", mask=sum(value["bit"] for value in flags.values() if value["word"] == 0),
            mask2=sum(value["bit"] for value in flags.values() if value["word"] == 1))
    for ref in ("specialty_twoprimaries", "specialty_munitions", "specialty_munitions_2",
                "perkpackage_munitions", "specialty_ghost"):
        flag_case("secondary_" + ref, "secondary_weapon", perks=ref)
        flag_case("secondary_smg_" + ref, "secondary_weapon", perks=ref, weapon="iw8_sm_mpapa5_mp")
    for ref in ("reflex", "thermal", "hybrid3", "acog", "unknown_optic"):
        flag_case("ads_" + ref, "ads", attachments=ref)
        flag_case("longshot_" + ref, "longshot", attachments=ref)
    for name, weapon, flag in (("oden_longshot", "iw8_ar_asierra12_mp", "longshot"),
                               ("fal_ads", "iw8_ar_falima_mp", "ads"),
                               ("m13_kingslayer", "iw8_ar_mcharlie_mp", "kingslayer")):
        flag_case(name, flag, weapon=weapon)
        execute(name + "_no_flag", weapon=weapon)
    for rarity in (0, 1, 2, 3, 4, 5, 6, 7, 65535):
        execute("br_rarity_" + str(rarity), rarity=rarity, mode=24)
        execute("br_rarity_equipment_" + str(rarity), rarity=rarity, mode=24, target=64)
    for circle in (0, 1, 2, 256, 65535):
        execute("br_circle_" + str(circle), circle=circle, mode=24)
    flag_case("br_victim_downed", "victim_last_stand", mode=24)
    flag_case("br_attacker_downed", "last_stand", mode=24)
    flag_case("br_equipment_downed", "victim_last_stand", mode=24, target=64)

    # Table identities are derived from exactly the assets used by the original
    # parser. Keep the Overkill package's absent numeric ID explicit; zero is
    # never admitted as a perk alias.
    table_hashes = {name: sha for result in parent["cases"] for name, sha in result.get("asset_sha256", {}).items()}
    table_root = Path(r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay"
                      r"\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable")
    table_inputs = {}

    def table(name):
        paths = list((table_root / Path(name).parent).glob(Path(name).name + ".*.csv"))
        assert len(paths) == 1 and digest(paths[0]) == table_hashes[name]
        table_inputs[name] = dict(path=str(paths[0]), sha256=digest(paths[0]))
        return list(csv.reader(paths[0].read_text().splitlines()))

    perks = {row[1]: int(row[0]) for row in table("mp/perktable.csv")}
    overkill = sorted({perks[ref] for ref in lua_definitions["perk"].values() if ref in perks and perks[ref]})
    assert overkill == [2, 26, 44] and "perkpackage_munitions" not in perks
    optics = {row[1]: int(row[5]) for row in table("mp/reticlecategorytable.csv") if row[5]}
    weapons = {}
    for row in table("loot/weapon_ids.csv"):
        weapons.setdefault(row[1], int(row[0]))
    constants = dict(Oden=weapons["iw8_ar_asierra12"], Fal=weapons["iw8_ar_falima"],
                     M13=weapons["iw8_ar_mcharlie"], Thermal=optics["thermal"], ThermalHybrid=optics["hybrid3"])
    values_by_label = {row["fixture_label"]: row["values"] for row in new_cases}
    assert values_by_label["oden_longshot"][0] & 0xFFFF == constants["Oden"]
    assert values_by_label["fal_ads"][0] & 0xFFFF == constants["Fal"]
    assert values_by_label["m13_kingslayer"][0] & 0xFFFF == constants["M13"]
    assert values_by_label["longshot_thermal"][6] & 0xFFFF == constants["Thermal"]
    assert values_by_label["longshot_hybrid3"][6] & 0xFFFF == constants["ThermalHybrid"]
    for ref in lua_definitions["perk"].values():
        assert values_by_label["secondary_" + ref][4] & 0xFFFF == perks.get(ref, 0)

    enum_name = lambda name: name[0].upper() + name[1:] if "_" not in name else "".join(part.capitalize() for part in name.split("_"))
    header = ROOT / "src/replay_kill_context.h"
    lines = ["#pragma once", "#include <array>", "#include <cstdint>", "",
             "// Generated from 48 original ScriptFile writes (46 named modifier bits).",
             "// Both words share Param1. Unknown bits remain in the packet.",
             "enum class ReplayKillModifier : uint64_t", "{"]
    lines += [f"    {enum_name(name)} = UINT64_C({value['value']})," for name, value in flags.items()]
    lines += ["};", "", "// Original native LuaFile BRLOOT.itemRarities.", "enum class ReplayLootRarity : uint16_t", "{"]
    lines += [f"    {enum_name(name.lower())} = {value}," for name, value in sorted(lua_definitions["rarity"].items(), key=lambda row: row[1])]
    lines += ["    Unknown = 65535,", "};", "", "namespace replay_kill_context", "{"]
    lines += ["    inline constexpr std::array<uint16_t, 3> OverkillPerks = {" + ", ".join(map(str, overkill)) + "};"]
    lines += [f"    inline constexpr uint16_t {name} = {value};" for name, value in constants.items()]
    lines += ["} // namespace replay_kill_context", ""]
    header.write_text("\n".join(lines), encoding="utf-8")
    assert digest(reader_path) == reader_sha
    existing = {row.get("fixture_label") for row in parent["cases"]}
    assert not existing.intersection(row["fixture_label"] for row in new_cases)
    parent["cases"].extend(new_cases)
    parent.update(modifier_cases=len(new_cases), modifier_tool_sha256=digest(Path(__file__)),
                  parent_parser_proof_sha256=digest(args.parent_parser_proof))
    args.output.write_text(json.dumps(parent, indent=2) + "\n")
    proof = dict(passed=True, target_image_sha256=IMAGE_SHA, tool_sha256=digest(Path(__file__)),
                 reader_dependency=dict(path=str(reader_path), sha256=reader_sha),
                 modifier_script_sha256=digest(original_path), modifier_assembly_sha256=digest(assembly),
                 normalization_changed_only_reference_operands=True, instruction_count=5665,
                 named_flags=list(flags.values()), original_assignments=writes,
                 lua_inputs=lua_inputs, lua_definitions=lua_definitions, table_inputs=table_inputs,
                 mapped_overkill_ids=overkill, unrepresented_overkill_reference="perkpackage_munitions",
                 constants=constants, fields={"Param1": "mask in low32, mask2 in high32",
                                              "Param6": "rarity in bits32..47, circle index in bits48..63"},
                 new_parser_cases=len(new_cases), parser_proof_sha256=digest(args.output),
                 generated_path=header.relative_to(ROOT).as_posix(), generated_sha256=digest(header),
                 native_game_callback_verified=False, game_runs_performed=False,
                 scope="Original producer operands and LuaFile definitions, plus original parser execution. Criteria are reconstructed from shipped descriptions; retail cloud predicate code is unavailable.")
    args.layout_proof.write_text(json.dumps(proof, indent=2) + "\n")
    print("Verified 46 modifier bits, eight rarity definitions and", len(new_cases), "new original parser cases")


if __name__ == "__main__":
    main()
