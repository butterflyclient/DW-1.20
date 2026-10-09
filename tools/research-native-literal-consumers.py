"""Find SDK literal consumers using original unwind ranges and indirect constants.

SQLite names are display aliases only. The untouched Replay bytes determine
instruction ownership, calls and string/pointer references.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("literals", nargs="+")
parser.add_argument("--start", type=lambda value: int(value, 0), default=0x1420F0000)
parser.add_argument("--end", type=lambda value: int(value, 0), default=0x142170000)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
destination = args.output.resolve()
if not any(destination.is_relative_to(ROOT / name) for name in ("data", "validation")):
    raise ValueError("Keep research outputs inside this repository")
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
if digest != "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0":
    raise ValueError("Unexpected original Replay image")
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
pe.parse_data_directories(
    directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
    ]
)
entries = {row.struct.BeginAddress: row for row in pe.DIRECTORY_ENTRY_EXCEPTION}


def primary(entry):
    seen = set()
    while entry.unwindinfo and entry.unwindinfo.UNW_FLAG_CHAININFO:
        address = entry.struct.BeginAddress
        if address in seen:
            raise ValueError("Cyclic original unwind chain")
        seen.add(address)
        entry = entries[entry.unwindinfo.FunctionEntry]
    return entry.struct.BeginAddress


groups = {}
for entry in entries.values():
    owner = base + primary(entry)
    groups.setdefault(owner, []).append(
        (base + entry.struct.BeginAddress, base + entry.struct.EndAddress)
    )
relocated_pointers = {
    base + row.rva
    for block in pe.DIRECTORY_ENTRY_BASERELOC
    for row in block.entries
    if row.type == 10
}
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
references = {}
literal_addresses = {}
for literal in args.literals:
    needle = literal.encode("ascii") + b"\0"
    addresses = set()
    for section in pe.sections:
        content = section.get_data()
        position = -1
        while (position := content.find(needle, position + 1)) >= 0:
            # Only complete strings: a suffix of another literal is not a match.
            if position == 0 or content[position - 1] == 0:
                addresses.add(base + section.VirtualAddress + position)
    literal_addresses[literal] = sorted(addresses)
    for address in addresses:
        references.setdefault(address, set()).add(literal)

# SDK constants often reference a pointer in .data rather than the text itself.
direct = list(references.items())
for section in pe.sections:
    if section.Characteristics & 0x20000000:
        continue
    content = section.get_data()
    for target, literals in direct:
        needle = struct.pack("<Q", target)
        position = -1
        while (position := content.find(needle, position + 1)) >= 0:
            address = base + section.VirtualAddress + position
            # A coincidental eight-byte constant is not a stored image pointer.
            if address % 8 == 0 and address in relocated_pointers:
                references.setdefault(address, set()).update(literals)

database = image.with_suffix(".exe.sqlite")
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
    connection.execute("pragma query_only=on")
    names = {
        int(address): name
        for address, name in connection.execute("select address,name from functions")
    }
consumers = []
for owner, chunks in sorted(groups.items()):
    if not args.start <= owner < args.end:
        continue
    chunks.sort()
    instructions = [
        instruction
        for begin, end in chunks
        for instruction in decoder.disasm(pe.get_data(begin - base, end - begin), begin)
    ]
    hits, calls = [], []
    for instruction in instructions:
        for operand in instruction.operands:
            pointer = None
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                pointer = instruction.address + instruction.size + operand.mem.disp
            elif operand.type == X86_OP_IMM:
                pointer = operand.imm
            if pointer in references:
                hits.append(
                    dict(
                        instruction=hex(instruction.address),
                        pointer=hex(pointer),
                        mnemonic=instruction.mnemonic,
                        operands=instruction.op_str,
                        literals=sorted(references[pointer]),
                    )
                )
        if instruction.mnemonic in ("call", "jmp") and instruction.operands[0].type == X86_OP_IMM:
            target = instruction.operands[0].imm
            calls.append(
                dict(
                    instruction=hex(instruction.address),
                    target=hex(target),
                    display_alias=names.get(target),
                )
            )
    if hits:
        consumers.append(
            dict(
                begin=hex(owner),
                end=hex(chunks[-1][1]),
                display_alias=names.get(owner),
                original_chunks=[
                    dict(
                        begin=hex(begin),
                        end=hex(end),
                        bytes_sha256=hashlib.sha256(
                            pe.get_data(begin - base, end - begin)
                        ).hexdigest(),
                    )
                    for begin, end in chunks
                ],
                literals=hits,
                direct_calls=calls,
                instructions=[
                    dict(address=hex(i.address), mnemonic=i.mnemonic, operands=i.op_str)
                    for i in instructions
                ],
            )
        )
result = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    target_image_sha256=digest,
    tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    scope=dict(
        start=hex(args.start),
        end=hex(args.end),
        ownership="original PE exception ranges",
        indirect_pointer_levels=1,
        indirect_pointers_require_dir64=True,
        chained_unwind_owners_resolved=True,
        aliases_are_proof=False,
    ),
    literal_addresses={
        key: [hex(value) for value in values] for key, values in literal_addresses.items()
    },
    consumers=consumers,
)
destination.write_text(json.dumps(result, indent=2) + "\n")
print(
    json.dumps(
        dict(consumer_count=len(consumers), literal_addresses=result["literal_addresses"]), indent=2
    )
)
