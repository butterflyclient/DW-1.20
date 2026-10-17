"""Derive native achievement-event imports/layout for one private compiler job."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

ROOT = Path(__file__).resolve().parents[1]


def prepare(snapshot, bind=True):
    snapshot = snapshot.resolve()
    assert snapshot.is_relative_to(ROOT / "data")
    proof_path = (
        ROOT / "data/remaining-event-ownership-20261010/native-event-capacity.json"
    )
    proof = json.loads(proof_path.read_bytes())
    assert proof["passed"] and proof["modeled_boundaries"] == []
    raw = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == proof["target_image_sha256"]
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    base = pe.OPTIONAL_HEADER.ImageBase
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    methods = []
    for row in proof["methods"]:
        code = pe.get_data(row["address"] - base, row["size"])
        assert hashlib.sha256(code).hexdigest() == row["sha256"]
        instructions = list(decoder.disasm(code, row["address"]))
        assert sum(i.size for i in instructions) == len(code)
        methods.append(instructions)
    constructor, append, reset, stamp, name, lobby = methods

    def one(rows):
        assert len(rows) == 1, rows
        return rows[0]

    def memory(rows, mnemonic, reg, base_reg):
        return one(
            [
                i.operands[1].mem.disp
                for i in rows
                if i.mnemonic == mnemonic
                and len(i.operands) == 2
                and i.operands[0].type == X86_OP_REG
                and i.reg_name(i.operands[0].reg) == reg
                and i.operands[1].type == X86_OP_MEM
                and i.reg_name(i.operands[1].mem.base) == base_reg
                and i.operands[1].mem.index == 0
            ]
        )

    def constant(rows, mnemonic, reg):
        return one(
            [
                i.operands[1].imm
                for i in rows
                if i.mnemonic == mnemonic
                and len(i.operands) == 2
                and i.operands[0].type == X86_OP_REG
                and i.reg_name(i.operands[0].reg) == reg
                and i.operands[1].type == X86_OP_IMM
            ]
        )

    assert [(i.mnemonic, i.op_str) for i in stamp][1:] == [("ret", "")]
    assert stamp[0].mnemonic == "mov" and stamp[0].operands[0].type == X86_OP_MEM
    timestamp = stamp[0].operands[0].mem.disp
    pair_base = memory(constructor, "lea", "rdi", "rbx")
    pair_count = constant(constructor, "mov", "esi")
    pair_stride = constant(constructor, "add", "rdi")
    count = pair_base + memory(append, "mov", "eax", "rbp")
    name_offset = memory(name, "lea", "rdi", "rcx")
    name_capacity = constant(name, "mov", "ebx") + 1
    key_capacity = constant(append, "mov", "ebx") + 1
    virtual_base = one(
        [
            i.operands[0].mem.disp
            for i in constructor
            if i.mnemonic == "mov"
            and i.operands[0].type == X86_OP_MEM
            and i.reg_name(i.operands[0].mem.base) == "rcx"
            and i.operands[0].size == 8
            and i.operands[0].mem.disp > count
        ]
    )
    calls = [
        i.operands[0].imm
        for i in constructor
        if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
    ]
    assert len(calls) == 2
    pair_ctor = calls[1]
    bounds = [
        r.struct
        for r in pe.DIRECTORY_ENTRY_EXCEPTION
        if base + r.struct.BeginAddress == pair_ctor
    ]
    assert len(bounds) == 1
    pair_code = pe.get_data(
        pair_ctor - base, bounds[0].EndAddress - bounds[0].BeginAddress
    )
    pair = list(decoder.disasm(pair_code, pair_ctor))
    key_offset = memory(pair, "lea", "rax", "rbx")
    value_offset = one(
        [
            i.operands[0].mem.disp
            for i in pair
            if i.mnemonic == "mov"
            and i.operands[0].type == X86_OP_MEM
            and i.reg_name(i.operands[0].mem.base) == "rbx"
            and i.operands[0].size == 8
            and i.operands[1].type == X86_OP_IMM
            and i.operands[1].imm == 0
        ]
    )
    pair_virtual = one(
        [
            i.operands[0].mem.disp
            for i in pair
            if i.mnemonic == "mov"
            and i.operands[0].type == X86_OP_MEM
            and i.reg_name(i.operands[0].mem.base) == "rcx"
            and i.operands[0].size == 8
            and i.operands[0].mem.disp > value_offset
        ]
    )
    layout = dict(
        timestamp=timestamp,
        pairs=pair_base,
        pair_capacity=pair_count,
        pair_stride=pair_stride,
        pair_count=count,
        string_name=name_offset,
        string_capacity=name_capacity,
        pair_key=key_offset,
        pair_key_capacity=key_capacity,
        pair_value=value_offset,
        virtual_referencable=virtual_base,
        event_size=virtual_base + pair_stride - pair_virtual,
    )
    assert all(proof["layout"][key] == value for key, value in layout.items())
    assert pair_virtual == value_offset + 8 and key_offset == 16 and name_offset == 24
    params = json.loads(
        (
            ROOT
            / "data/remaining-event-ownership-20261010/challenge-parser-verified.json"
        ).read_bytes()
    )
    names = sorted(
        {
            row["name"]
            for row in params["cases"]
            if row.get("accepted") and row["name"] != "start_match"
        }
    )
    assert (
        max(row["parameter_count"] for row in params["cases"] if row.get("accepted"))
        <= pair_count - 3
    )
    header = [
        "#pragma once",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "// Generated from original instructions and original-instruction proofs.",
        "struct DWReplayReferencable { uintptr_t vtable; uint32_t references; uint32_t alignment; };",
        "struct DWReplayAchievementPair",
        "{",
        "    uintptr_t vtable, virtualTable;",
        f"    char key[{key_capacity}];",
        f"    uint8_t alignment[{value_offset - key_offset - key_capacity}];",
        "    uint64_t value;",
        "    DWReplayReferencable referencable;",
        "};",
        "struct DWReplayAchievementEvent",
        "{",
        "    uintptr_t vtable, virtualTable;",
        "    uint64_t numericName;",
        f"    char name[{name_capacity}];",
        f"    uint8_t alignment[{timestamp - name_offset - name_capacity}];",
        "    uint64_t timestamp;",
        f"    DWReplayAchievementPair pairs[{pair_count}];",
        "    uint32_t pairCount, tailAlignment;",
        "    DWReplayReferencable referencable;",
        "};",
        f"inline constexpr unsigned DWReplayAchievementPairCapacity = {pair_count};",
        f"static_assert(sizeof(DWReplayAchievementPair) == {pair_stride});",
        f'static_assert(sizeof(DWReplayAchievementEvent) == {layout["event_size"]});',
    ]
    for field, offset in (
        ("name", name_offset),
        ("timestamp", timestamp),
        ("pairs", pair_base),
        ("pairCount", count),
    ):
        header.append(
            f"static_assert(offsetof(DWReplayAchievementEvent, {field}) == {offset});"
        )
    header += [
        'extern "C" {',
        "extern uint8_t DW_Achievement_Matchmaker[];",
        "uint64_t DW_Achievement_GetLobbyId(const void *);",
        "uint64_t DW_Achievement_GetMatchId();",
        "void *DW_Achievement_AddKeyValue(void *, const char *, uint64_t);",
        "}",
        "inline constexpr const char *DWReplayMatchEventNames[] = {",
    ]
    header += ["    " + json.dumps(n) + "," for n in names]
    header += ["};", ""]
    (snapshot / "src").mkdir(parents=True, exist_ok=True)
    generated = snapshot / "src/DW_AchievementEventBindings.h"
    generated.write_text("\n".join(header))
    source = snapshot / "src/DW_AchievementEvent.cpp"
    expected_source = (ROOT / "integration/replay/DW_AchievementEvent.cpp").read_bytes()
    if source.exists():
        assert source.read_bytes() == expected_source
    else:
        source.write_bytes(expected_source)
    bindings = []
    replacement = None
    if bind:
        catalog = json.loads(
            (snapshot / "generated/function-catalog.json").read_bytes()
        )
        assert catalog["image_sha256"] == digest
        by_address = {
            base + row["rva"]: row
            for row in catalog["functions"]
            if not row.get("quarantined")
        }
        stamp_row = by_address[proof["methods"][3]["address"]]
        get_match = one(
            [
                row
                for row in catalog["functions"]
                if "OnlineMatchId::GetMatchId" in (row["name"], *row["aliases"])
                and not row.get("quarantined")
            ]
        )
        code = list(
            decoder.disasm(pe.get_data(get_match["rva"], 8), base + get_match["rva"])
        )
        assert (
            len(code) == 2 and code[0].mnemonic == "mov" and code[-1].mnemonic == "ret"
        )
        imports = {
            "DW_Achievement_AddKeyValue": by_address[proof["methods"][1]["address"]],
            "DW_Achievement_GetLobbyId": by_address[proof["methods"][5]["address"]],
            "DW_Achievement_GetMatchId": get_match,
        }
        document = json.loads((snapshot / "source-units.json").read_bytes())
        # Resolve the recovered singleton by catalog identity. A previous build
        # need not have explicitly imported the legacy address-shaped alias.
        matchmaker = one(
            [
                row["id"]
                for row in catalog.get("symbols", [])
                if "OnlineMatchmakerOmniscient::ms_instance"
                in (row["name"], *row.get("aliases", []))
                and row.get("kind") == "data-address"
                and not row.get("quarantined")
            ]
        )
        spec = importlib.util.spec_from_file_location(
            "private_match_catalog", snapshot / "tools/source_catalog.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(snapshot / "tools"))
        spec.loader.exec_module(module)
        shim = importlib.util.spec_from_file_location("dw_catalog", Path(__file__).resolve().with_name("dw_catalog.py"))
        shim_module = importlib.util.module_from_spec(shim)
        shim.loader.exec_module(shim_module)
        shim_module.share_catalog(module)  # one catalog parse, not one per binding
        module.bind(
            stamp_row["id"],
            Path("src/DW_AchievementEvent.cpp"),
            "bdAchievementEvent_SetTimeStamp",
        )
        module.bind_import(matchmaker, "DW_Achievement_Matchmaker")
        for alias, row in imports.items():
            module.bind_import(row["id"], alias)
            bindings.append(dict(symbol=alias, identity=row["id"]))
        units_path = snapshot / "source-workstation/units.json"
        units = json.loads(units_path.read_bytes())
        sha = hashlib.sha256(source.read_bytes()).hexdigest()
        units["units"].append(
            dict(
                function_id=stamp_row["id"],
                kind="cpp",
                source="src/DW_AchievementEvent.cpp",
                symbol="bdAchievementEvent_SetTimeStamp",
                sha256=sha,
                revision=sha,
                language="cpp",
            )
        )
        units_path.write_text(json.dumps(units, indent=2) + "\n")
        replacement = stamp_row["id"]
    result = dict(
        passed=True,
        image_sha256=digest,
        derived_layout=layout,
        replacement=replacement,
        proof_sha256=hashlib.sha256(proof_path.read_bytes()).hexdigest(),
        pair_constructor_sha256=hashlib.sha256(pair_code).hexdigest(),
        header_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        bindings=bindings,
        no_manual_source_rvas_or_layouts=True,
        shared_workstation_modified=False,
        native_runtime_verified=False,
        cache_transition_ordering_verified=False,
    )
    (snapshot / "generated").mkdir(exist_ok=True)
    (snapshot / "generated/match-event-integration.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--headers-only", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, not args.headers_only), indent=2))
