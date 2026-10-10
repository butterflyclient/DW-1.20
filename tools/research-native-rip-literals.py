"""Locate original RIP literal references without depending on display names.

The four byte-alignment scans only nominate owners. Every reported reference
must then appear in linear decoding from its actual PE unwind chunk start.
Reachability and embedded jump-table/data regions remain separate audit gates;
a reported reference is a candidate, not proof of a live consuming method.
"""
import argparse
from bisect import bisect_right
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import numpy as np
import pefile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("literals", nargs="*")
parser.add_argument("--addresses", type=Path,
                    help="Hash-bound original-code targets; labels are lookup hints, not type evidence")
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
assert args.literals or args.addresses
output = args.output.resolve()
assert any(output.is_relative_to(ROOT / name) for name in ("data", "validation"))
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
pe.parse_data_directories(directories=[3, 5])
base = pe.OPTIONAL_HEADER.ImageBase
entries = {row.struct.BeginAddress: row for row in pe.DIRECTORY_ENTRY_EXCEPTION}
chunks = sorted((base + row.struct.BeginAddress, base + row.struct.EndAddress, row)
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


references = {}
address_evidence = None
if args.addresses:
    path = args.addresses.resolve()
    assert path.is_relative_to(ROOT)
    document = json.loads(path.read_bytes())
    assert document["target_image_sha256"] == digest
    address_evidence = dict(path=path.relative_to(ROOT).as_posix(),
                            sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    for row in document["targets"]:
        address = row["address"]
        assert isinstance(address, int) and base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage
        size = row["code_size"]
        assert 0 < size <= 65536
        assert hashlib.sha256(pe.get_data(address - base, size)).hexdigest() == row["code_sha256"]
        references.setdefault(address, set()).add(row["label"])
for text in args.literals:
    needle = text.encode("ascii") + b"\0"
    for section in pe.sections:
        content = section.get_data()
        position = -1
        while (position := content.find(needle, position + 1)) >= 0:
            if not position or content[position - 1] == 0:
                address = base + section.VirtualAddress + position
                references.setdefault(address, set()).add(text)
literal_addresses = {text: sorted(address for address, names in references.items()
                                  if text in names) for text in args.literals}
relocated = {base + row.rva for block in pe.DIRECTORY_ENTRY_BASERELOC
             for row in block.entries if row.type == 10}
for section in pe.sections:
    if section.Characteristics & 0x20000000:
        continue
    content = section.get_data()
    for target, names in list(references.items()):
        needle = struct.pack("<Q", target)
        position = -1
        while (position := content.find(needle, position + 1)) >= 0:
            address = base + section.VirtualAddress + position
            if address % 8 == 0 and address in relocated:
                references.setdefault(address, set()).update(names)

targets = np.array(sorted(references), dtype=np.int64)
candidates = set()
unowned_nominations = []
for section in pe.sections:
    if not section.Characteristics & 0x20000000:
        continue
    content = section.get_data()
    for alignment in range(4):
        count = (len(content) - alignment) // 4
        values = np.frombuffer(content, dtype="<i4", count=count, offset=alignment)
        positions = np.arange(count, dtype=np.int64) * 4 + alignment
        ends = base + section.VirtualAddress + positions + 4
        for index in np.flatnonzero(np.isin(values.astype(np.int64) + ends, targets)):
            # At most one unwind chunk owns a particular encoded displacement.
            address = int(ends[index]) - 4
            which = bisect_right(starts, address) - 1
            if which >= 0 and chunks[which][0] <= address < chunks[which][1]:
                candidates.add(which)
            else:
                target = int(values[index]) + int(ends[index])
                unowned_nominations.append(dict(
                    displacement_address=address, target=target,
                    labels=sorted(references[target]), section=section.Name.rstrip(b"\0").decode(),
                    owner=None, instruction_boundary_verified=False))

decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
matches = []
decode_coverage = []
for which in sorted(candidates):
    start, end, entry = chunks[which]
    code = pe.get_data(start - base, end - start)
    hits = []
    decoded_bytes = 0
    for instruction in decoder.disasm(code, start):
        decoded_bytes += instruction.size
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                target = instruction.address + instruction.size + operand.mem.disp
                if target in references:
                    hits.append(dict(address=instruction.address, mnemonic=instruction.mnemonic,
                                     operands=instruction.op_str, target=target,
                                     literals=sorted(references[target])))
        if (args.addresses and instruction.mnemonic in ("call", "jmp") and
                instruction.operands[0].type == X86_OP_IMM):
            target = instruction.operands[0].imm
            if target in references:
                hits.append(dict(address=instruction.address, mnemonic=instruction.mnemonic,
                                 operands=instruction.op_str, target=target,
                                 literals=sorted(references[target]), direct_branch=True))
    decode_coverage.append(dict(start=start, end=end, decoded_bytes=decoded_bytes,
                                complete=decoded_bytes == len(code), matched=bool(hits)))
    if hits:
        matches.append(dict(owner=owner(entry), start=start, end=end,
                            bytes_sha256=hashlib.sha256(code).hexdigest(), hits=hits))
result = dict(schema=1, recorded_utc=datetime.now(timezone.utc).isoformat(),
              target_image_sha256=digest,
              tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              literal_addresses=literal_addresses, candidate_chunks=len(candidates),
              address_evidence=address_evidence,
              unowned_nominations=sorted(unowned_nominations, key=lambda row: row["displacement_address"]),
              decode_coverage=decode_coverage,
              matches=matches, sqlite_names_used=False,
              linear_disassembly=True, branch_feasibility_checked=False,
              scope="Potential references in linear-decoded original unwind chunks; one relocated pointer level. Unowned raw displacements remain nominations, with no guessed function owner. Missing matches do not establish absence: indirect control flow, incomplete decoding, embedded data, branch feasibility and live consumption remain unverified.")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(dict(candidate_chunks=len(candidates), matched_chunks=len(matches),
                      unowned_nominations=len(unowned_nominations),
                      incomplete_chunks=sum(not row["complete"] for row in decode_coverage),
                      owners=len({row['owner'] for row in matches}))))
