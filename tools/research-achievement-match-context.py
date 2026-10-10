"""Record original achievement timestamp/correlation constraints without editing the game.

Catalog labels select candidates; original image instructions verify every
recorded operand and direct call. This is static context evidence, not proof of
cache ownership, reset ordering, historical authorization or gameplay delivery.
"""

import argparse
import hashlib
import json
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM, X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert args.catalog.resolve().is_relative_to(ROOT)
    assert args.output.resolve().is_relative_to(ROOT)
    image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    raw = image.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    catalog = json.loads(args.catalog.read_bytes())
    assert catalog["image_sha256"] == digest
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    entries = {row.struct.BeginAddress: row for row in pe.DIRECTORY_ENTRY_EXCEPTION}

    def owner(row):
        seen = set()
        while row.unwindinfo and row.unwindinfo.UNW_FLAG_CHAININFO:
            address = row.struct.BeginAddress
            assert address not in seen
            seen.add(address)
            row = entries[row.unwindinfo.FunctionEntry]
        return row.struct.BeginAddress

    chunks = {}
    for row in entries.values():
        chunks.setdefault(owner(row), []).append(row.struct)
    by_address = {base + row["rva"]: row for row in catalog["functions"]}

    def function(name):
        rows = [row for row in catalog["functions"]
                if name == row["name"] or name in row.get("aliases", [])]
        assert len(rows) == 1 and not rows[0].get("quarantined"), name
        return rows[0]

    setter = function("bdAchievementEvent::setTimeStamp")
    data = pe.get_data(setter["rva"], 32)
    decoded = []
    for instruction in decoder.disasm(data, base + setter["rva"]):
        decoded.append(instruction)
        if instruction.mnemonic == "ret":
            break
    assert len(decoded) == 2 and decoded[0].mnemonic == "mov" and decoded[1].mnemonic == "ret"
    destination, source = decoded[0].operands
    assert destination.type == X86_OP_MEM and destination.size == 8
    assert destination.mem.base == X86_REG_RCX and destination.mem.index == 0
    assert source.type == X86_OP_REG and source.reg == X86_REG_RDX
    setter_size = sum(instruction.size for instruction in decoded)
    setter_address = base + setter["rva"]
    getter = function("OnlineMatchId::GetMatchId")
    instructions = list(decoder.disasm(pe.get_data(getter["rva"], 8), base + getter["rva"]))
    assert len(instructions) == 2 and instructions[0].mnemonic == "mov" and instructions[1].mnemonic == "ret"
    assert instructions[0].operands[0].type == X86_OP_REG and instructions[0].operands[0].reg == X86_REG_RAX
    operand = instructions[0].operands[1]
    assert operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP and operand.size == 8
    match_global = instructions[0].address + instructions[0].size + operand.mem.disp
    records = []
    for name in ("OnlineChallengesManager::AddGamemode", "OnlineChallengesManager::FlushEventCache",
                 "OnlineChallengesManager::FlushXPCache"):
        row = function(name)
        assert row["rva"] in chunks, name
        decoded, parts = [], []
        for chunk in sorted(chunks[row["rva"]], key=lambda chunk: chunk.BeginAddress):
            code = pe.get_data(chunk.BeginAddress, chunk.EndAddress - chunk.BeginAddress)
            instructions = list(decoder.disasm(code, base + chunk.BeginAddress))
            assert sum(i.size for i in instructions) == len(code)
            decoded.extend(instructions)
            parts.append(dict(begin_rva=chunk.BeginAddress, end_rva=chunk.EndAddress,
                              original_code_sha256=hashlib.sha256(code).hexdigest()))
        calls, stamp_sites = [], []
        for instruction in decoded:
            if instruction.mnemonic == "call" and instruction.operands[0].type == X86_OP_IMM:
                target = instruction.operands[0].imm
                identity = by_address.get(target, {})
                entry = dict(site=instruction.address, target=target, candidate_name=identity.get("name"))
                if target == setter_address:
                    stamp_sites.append(dict(**entry, preceding_direct_calls=calls[-4:]))
                calls.append(entry)
        if name.endswith("FlushEventCache") or name.endswith("FlushXPCache"):
            assert stamp_sites, name
        records.append(dict(name=name, function_id=row["id"], rva=row["rva"],
            unwind_chunks=parts, timestamp_sites=stamp_sites,
            scope="Original direct call sequence across chained unwind chunks; branch feasibility and external callees not modeled"))
    result = dict(passed=True, target_image_sha256=digest,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        catalog=dict(path=args.catalog.resolve().relative_to(ROOT).as_posix(),
                     sha256=hashlib.sha256(args.catalog.read_bytes()).hexdigest()),
        timestamp_setter=dict(function_id=setter["id"], rva=setter["rva"],
            store_width=destination.size, member_offset=destination.mem.disp, code_size=setter_size,
            original_code_sha256=hashlib.sha256(data[:setter_size]).hexdigest()),
        native_match_getter=dict(function_id=getter["id"], rva=getter["rva"], global_rva=match_global - base),
        records=records, game_changed=False, native_runtime_verified=False,
        remaining=["Capture ownership before aggregation rather than tagging only reconstructed cache events",
                   "Prove SDK key/value capacity for every tagged path",
                   "Bind native match identity to authoritative allocation history and stable participant claims",
                   "Verify reset, departure, migration and delayed-report ordering"])
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("Verified original timestamp leaf, native match getter and cache call sites; no client changes")


if __name__ == "__main__":
    main()
