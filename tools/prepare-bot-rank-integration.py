"""Bind the complete Replay setrank method and its pre-script bot rank handoff."""

import argparse
import hashlib
import json
from pathlib import Path

import capstone
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
TARGET = "fn_b46a5367a759107d"
SOURCE = "src/DW_BotRank.cpp"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect_native(snapshot):
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    raw = IMAGE.read_bytes()
    assert sha(raw) == catalog["image_sha256"] == IMAGE_SHA
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    byid = {r["id"]: r for r in catalog["functions"] + catalog["symbols"]}
    by_rva = {r["rva"]: r for r in catalog["functions"]}
    families = {}
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        owner = entry
        while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
            owner = owner.unwindinfo._chained_entry
        families.setdefault(owner.struct.BeginAddress, []).append(
            (entry.struct.BeginAddress, entry.struct.EndAddress)
        )
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True

    def body(identity):
        row = byid[identity]
        assert not row.get("quarantined")
        ranges = sorted(families.get(row["rva"], []))
        size = (
            max(e for _, e in ranges) - row["rva"]
            if ranges
            else min(r for r in by_rva if r > row["rva"]) - row["rva"]
        )
        code = pe.get_data(row["rva"], size)
        return dict(
            identity=identity,
            rva=row["rva"],
            bytes=size,
            sha256=sha(code),
            complete_body_hex=code.hex(),
            unwind_family_ranges=[list(r) for r in ranges],
        ), list(decoder.disasm(code, row["rva"]))

    target, instructions = body(TARGET)
    assert target["bytes"] == 265 and target["sha256"] == (
        "bed5972fcc4808f4c154435beca631c35c9cc28f05383c42619d797e3be53d4a"
    )
    calls = [
        i.operands[0].imm
        for i in instructions
        if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
    ]
    names = (
        "RK_Format",
        "RK_ObjectError",
        "RK_ObjectError",
        "RK_GetInt",
        "RK_GetNumParam",
        "RK_GetInt",
        "RK_Format",
        "RK_Format",
        "RK_Error",
    )
    assert len(calls) == len(names)
    imports = {}
    for name, address in zip(names, calls, strict=True):
        binding, _ = body(by_rva[address]["id"])
        binding["kind"] = "function"
        if name in imports:
            assert imports[name] == binding
        imports[name] = binding
    globals_ = [
        i.address + i.size + i.operands[1].mem.disp
        for i in instructions
        if i.mnemonic == "add" and i.op_str.startswith("rbx, qword ptr [rip")
    ]
    assert len(globals_) == 1
    entity = [
        r
        for r in catalog["symbols"]
        if r["rva"] == globals_[0]
        and r.get("kind") == "data-address"
        and not r.get("quarantined")
    ]
    assert len(entity) == 1
    imports["RK_Entities"] = dict(
        identity=entity[0]["id"], rva=globals_[0], kind="data"
    )
    assert any(
        i.mnemonic == "imul" and i.op_str == "rbx, rax, 0x5a0" for i in instructions
    )
    assert any(i.mnemonic == "cmp" and i.op_str == "eax, 0x3ff" for i in instructions)
    assert any(i.mnemonic == "cmp" and i.op_str == "eax, 0xff" for i in instructions)
    assert {336, 22168, 22170}.issubset(
        {o.mem.disp for i in instructions for o in i.operands if o.type == X86_OP_MEM}
    )
    begin, begin_instructions = body("fn_284e62a09807d6b2")
    assert begin["bytes"] == 292 and begin["sha256"] == (
        "90ccc9f1eb426b5a5622c2b97a6cbe53a4c4ec90c5851835c958cda7dbf7c5c8"
    )
    # Recover the getter from the call immediately before the native session.team write.
    write_index = next(
        n
        for n, i in enumerate(begin_instructions)
        if i.mnemonic == "mov" and i.op_str == "dword ptr [r15 + 0x5600], eax"
    )
    call = begin_instructions[write_index - 1]
    assert call.mnemonic == "call" and call.operands[0].type == X86_OP_IMM
    getter = by_rva[call.operands[0].imm]
    assert getter["id"] == "fn_32a98bad641a7a28"
    assert begin_instructions[-1].mnemonic == "jmp"
    return dict(
        image_sha256=IMAGE_SHA,
        target=target,
        imports=imports,
        client_begin=begin,
        pre_script_call=dict(
            getter_identity=getter["id"],
            call_rva=call.address,
            team_write_rva=begin_instructions[write_index].address,
            script_dispatch_rva=begin_instructions[-1].address,
        ),
        layout=dict(
            entity_stride=1440,
            client_pointer=336,
            rank=22168,
            prestige=22170,
            max_rank=1023,
            max_prestige=255,
        ),
    )


HEADER = """#pragma once
#include <stdint.h>
namespace HostScale { struct Entity; }
inline constexpr unsigned RK_RankOffset = 22168, RK_PrestigeOffset = 22170;
inline constexpr unsigned RK_MaxRank = 1023, RK_MaxPrestige = 255;
extern "C" {
extern HostScale::Entity *RK_Entities;
int32_t RK_GetInt(void *, uint32_t);
uint32_t RK_GetNumParam(void *);
const char *RK_Format(const char *, ...);
uint64_t RK_Error(uint32_t, void *, const char *);
void RK_ObjectError(uint32_t, void *, const char *);
}
"""


def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    assert not (snapshot.parent / "client-readiness.json").exists(), "Finished snapshot"
    assert not list(
        snapshot.parent.glob("builds/*/build-report.json")
    ), "Built snapshot"
    proof = inspect_native(snapshot)
    associations_path = snapshot / "source-units.json"
    units_path = snapshot / "source-workstation/units.json"
    assert associations_path.stat().st_nlink == units_path.stat().st_nlink == 1
    associations = json.loads(associations_path.read_bytes())
    units = json.loads(units_path.read_bytes())
    expected = dict(source=SOURCE, symbol="DW_BotRank_SetRank", function_id=TARGET)
    prior = [u for u in associations["units"] if u["function_id"] == TARGET]
    assert not prior or (
        replace_owned and prior == [expected]
    ), "Setrank has another owner"
    if not prior:
        associations["units"].append(expected)
    prior = [u for u in units["units"] if u["function_id"] == TARGET]
    assert not prior or (
        replace_owned and prior[0]["source"] == SOURCE
    ), "Editable owner conflict"
    content = (ROOT / "integration/replay/DW_BotRank.cpp").read_bytes()
    (snapshot / SOURCE).write_bytes(content)
    (snapshot / "src/DW_BotRankBindings.h").write_text(HEADER)
    units["units"] = [u for u in units["units"] if u["function_id"] != TARGET]
    units["units"].append(
        dict(
            function_id=TARGET,
            kind="cpp",
            source=SOURCE,
            symbol="DW_BotRank_SetRank",
            sha256=sha(content),
            revision=sha(content),
            language="cpp",
        )
    )
    for symbol, binding in proof["imports"].items():
        imported = dict(symbol=symbol, symbol_id=binding["identity"])
        previous = [
            i for i in associations.setdefault("imports", []) if i["symbol"] == symbol
        ]
        assert not previous or previous == [imported]
        if not previous:
            associations["imports"].append(imported)
    associations_path.write_text(json.dumps(associations, indent=2) + "\n")
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    proof.update(
        schema=1,
        passed=True,
        source=SOURCE,
        source_sha256=sha(content),
        header_sha256=sha((snapshot / "src/DW_BotRankBindings.h").read_bytes()),
        generator_sha256=sha(Path(__file__).read_bytes()),
        game_run_performed=False,
        dependencies={
            name: sha((snapshot / "src" / name).read_bytes())
            for name in (
                "DW_BotRank.cpp",
                "DW_BotRankBindings.h",
                "DW_BotStyleSelection.h",
                "DW_BotStyleData.h",
                "DW_BotStyleProfile.h",
                "DW_BotBindings.h",
                "sv_host_scale.h",
            )
        },
    )
    (snapshot / "generated/bot-rank-integration.json").write_text(
        json.dumps(proof, indent=2) + "\n"
    )
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, args.replace_owned), indent=2))
