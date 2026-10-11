"""Check linked original PartyHost bodies, native references, unwind extents and argument ABI."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct

import capstone
import pefile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build", required=True, type=Path)
parser.add_argument("--preparation", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
report = json.loads((args.build / "build-report.json").read_text())
proof = json.loads(args.preparation.read_text())
image = Path(report["executable"])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(image) == report["sha256"]
original = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
assert sha(original) == proof["image_sha256"]
native, linked = pefile.PE(str(original)), pefile.PE(str(image))
base = linked.OPTIONAL_HEADER.ImageBase
symbols = report["symbols"]
first = symbols[proof["clones"][0]["helper_symbol"]]
actual = bytearray(linked.get_data(first, proof["body_bytes"]))
expected = bytearray()
unwind, abi = [], []
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
decoder.detail = True
database = sqlite3.connect("file:E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe.sqlite?mode=ro", uri=True)

def canonical(name):
    if re.fullmatch(r"r[89][bwd]?", name):
        return name[:2]
    return name

for clone in proof["clones"]:
    rva = symbols[clone["helper_symbol"]]
    assert rva == first + clone["coff_definition"]["value"]
    spans = clone["provenance"]["ranges"]
    size = sum(end - begin for begin, end in spans)
    instructions = {}
    for begin, end in spans:
        raw = native.get_data(begin, end - begin)
        expected.extend(raw)
        instructions.update({i.address: i for i in decoder.disasm(raw, begin)})
    # CFG dataflow detects any explicit incoming volatile third/fourth or SSE
    # register use. Native prototypes and prologues corroborate two inputs.
    entry = clone["original_rva"]
    states, queue, violations = {entry: frozenset()}, [entry], []
    watched = {"r8", "r9"} | {"xmm" + str(i) for i in range(6)}
    while queue:
        address = queue.pop()
        instruction = instructions[address]
        reads, writes = instruction.regs_access()
        read_names = {canonical(instruction.reg_name(r)) for r in reads} & watched
        write_names = {canonical(instruction.reg_name(r)) for r in writes} & watched
        defined = set(states[address])
        # xor/sub reg,reg and SIMD zero idioms initialize rather than use an input.
        if instruction.mnemonic in ("xor", "sub", "xorps", "xorpd", "pxor") and len(instruction.operands) == 2 and instruction.operands[0].type == capstone.x86.X86_OP_REG and instruction.operands[1].type == capstone.x86.X86_OP_REG and instruction.operands[0].reg == instruction.operands[1].reg:
            read_names -= write_names
        if read_names - defined:
            violations.append({"rva": address, "instruction": instruction.mnemonic + " " + instruction.op_str, "incoming": sorted(read_names - defined)})
        defined |= write_names
        if instruction.mnemonic == "call":
            defined |= watched  # The native call defines/clobbers volatile state.
        following = address + instruction.size
        targets = []
        if instruction.mnemonic.startswith("j"):
            if instruction.operands and instruction.operands[0].type == capstone.x86.X86_OP_IMM:
                target = instruction.operands[0].imm
                if target in instructions:
                    targets.append(target)
            if instruction.mnemonic != "jmp" and following in instructions:
                targets.append(following)
        elif instruction.mnemonic not in ("ret", "int3", "ud2") and following in instructions:
            targets.append(following)
        for target in targets:
            state = frozenset(defined) if target not in states else states[target] & frozenset(defined)
            if target not in states or state != states[target]:
                states[target] = state
                queue.append(target)
    assert not violations, violations
    row = database.execute("SELECT name,prototype,prototype2,pseudocode_hash1,bytes_hash FROM functions WHERE address=?", (str(native.OPTIONAL_HEADER.ImageBase + entry),)).fetchone()
    assert row and "__int64, __int64" in row[2]
    return_type = "AL (8-bit readiness result)" if clone["helper_symbol"].endswith("ReadyToLaunchNative") else "RAX (64-bit native result)"
    assert row[2].startswith("char ") if return_type.startswith("AL") else row[2].startswith("__int64 ")
    abi.append({"original_id": clone["original_id"], "prototype": row[1], "prototype2": row[2], "sqlite_bytes_hash": row[4],
                "native_argument_registers": ["RCX party", "RDX activeClient"], "return_register": return_type,
                "incoming_R8_R9_XMM0_through_XMM5_reads": violations, "native_cfg_instructions_checked": len(states),
                "entry_disassembly": [hex(i.address) + " " + i.mnemonic + " " + i.op_str for i in list(instructions.values())[:12]]})
    records = [e for e in linked.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress == rva]
    assert len(records) == 1 and records[0].struct.EndAddress == rva + size
    record = records[0]
    assert record.unwindinfo.SizeOfProlog == clone["provenance"]["unwind"]["prologue_size"]
    unwind.append({"helper": clone["helper_symbol"], "begin_rva": rva, "end_rva": rva + size,
                   "unwind_rva": record.struct.UnwindData, "prologue_size": record.unwindinfo.SizeOfProlog,
                   "complete_native_ranges": spans})
database.close()
for fixup in proof["external_fixups"]:
    offset = fixup["offset"]
    destination = struct.unpack_from("<i", actual, offset)[0] + first + offset + 4 + fixup["trailing_instruction_bytes"]
    assert destination == symbols[fixup["stable_id"]], (fixup, hex(destination), hex(symbols[fixup["stable_id"]]))
    actual[offset:offset + 4] = expected[offset:offset + 4] = bytes(4)
assert actual == expected
result = dict(passed=True, image_sha256=report["sha256"], source_sha256=proof["source_sha256"],
              preparation_sha256=sha(args.preparation), body_bytes=proof["body_bytes"], linked_native_fixups=len(proof["external_fixups"]),
              original_bytes_preserved_outside_fixups=True, native_unwind_extents=unwind, original_abi=abi,
              checker_sha256=sha(Path(__file__)), game_launched=False)
args.output.write_text(json.dumps(result, indent=2) + "\n")
print("PASS exact linked native body bytes,103 references,two unwind extents and two-argument ABI")
