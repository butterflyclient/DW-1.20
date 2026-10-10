"""Find original unwind-owned accesses to explicit structure displacements.

Raw matches nominate chunks only. Each retained hit must be a decoded memory
operand in that chunk. This does not establish its base object's type, CFG
reachability, virtual-table ownership or runtime use.
"""

import argparse
from bisect import bisect_right
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM
import numpy as np
import pefile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("fields", nargs="+", type=lambda value: int(value, 0))
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
assert args.output.resolve().is_relative_to(ROOT)
assert all(128 <= value < 0x80000000 for value in args.fields)
raw = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe").read_bytes()
image_hash = hashlib.sha256(raw).hexdigest()
assert image_hash == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
pe.parse_data_directories(directories=[3])
base = pe.OPTIONAL_HEADER.ImageBase
entries = {row.struct.BeginAddress: row for row in pe.DIRECTORY_ENTRY_EXCEPTION}
chunks = sorted((row.struct.BeginAddress, row.struct.EndAddress, row)
                for row in entries.values())
starts = [row[0] for row in chunks]


def owner(row):
    seen = set()
    while row.unwindinfo and row.unwindinfo.UNW_FLAG_CHAININFO:
        address = row.struct.BeginAddress
        assert address not in seen
        seen.add(address)
        row = entries[row.unwindinfo.FunctionEntry]
    return base + row.struct.BeginAddress


candidates = set()
unowned = []
for section in pe.sections:
    if not section.Characteristics & 0x20000000:
        continue
    content = section.get_data()
    for alignment in range(4):
        count = (len(content) - alignment) // 4
        words = np.frombuffer(content, dtype="<u4", count=count, offset=alignment)
        for index in np.flatnonzero(np.isin(words, args.fields)):
            rva = section.VirtualAddress + alignment + int(index) * 4
            position = bisect_right(starts, rva) - 1
            if position >= 0 and rva < chunks[position][1]:
                candidates.add(position)
            else:
                # Leaf functions may have no unwind record. Retain these raw
                # nominations without assigning them a guessed function owner.
                unowned.append(dict(address=base+rva, displacement=int(words[index])))

decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
matches = []
for position in sorted(candidates):
    start, end, row = chunks[position]
    body = pe.get_data(start, end - start)
    hits = []
    for instruction in decoder.disasm(body, base + start):
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM and operand.mem.disp in args.fields:
                hits.append(dict(address=instruction.address,
                                 mnemonic=instruction.mnemonic, operands=instruction.op_str,
                                 base=instruction.reg_name(operand.mem.base),
                                 index=instruction.reg_name(operand.mem.index), size=operand.size,
                                 displacement=operand.mem.disp))
    if hits:
        matches.append(dict(owner=owner(row), start=base+start, end=base+end,
                            bytes_sha256=hashlib.sha256(body).hexdigest(), hits=hits))
proof = dict(schema=1, recorded_utc=datetime.now(timezone.utc).isoformat(),
             target_image_sha256=image_hash,
             tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             fields=args.fields, candidate_chunks=len(candidates), matches=matches,
             unowned_raw_nominations=unowned,
             sqlite_names_used=False, linear_disassembly=True,
             scope="Original unwind chunk memory operands; displacement equality alone does not prove object type, CFG reachability, vtable ownership or runtime use")
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(proof, indent=2)+"\n")
print(json.dumps(dict(candidate_chunks=len(candidates), matched_chunks=len(matches),
                      owners=len({row['owner'] for row in matches}))))
