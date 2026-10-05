"""Resolve bounded direct calls from original Replay bytes, independent of IDA aliases."""

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import capstone

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("addresses", nargs="+", type=lambda value: int(value, 0))
p.add_argument("--output", required=True, type=Path)
a = p.parse_args()
if len(a.addresses) > 16:
    raise ValueError("Use at most 16 original functions per audit")
binary = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
database = binary.with_suffix(".exe.sqlite")
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
decoder.detail = True
records = []
with (
    binary.open("rb") as f,
    sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db,
):
    db.execute("pragma query_only=on")
    db.execute("begin")
    f.seek(0x3C)
    f.seek(struct.unpack("<I", f.read(4))[0])
    header = f.read(24)
    if header[:4] != b"PE\0\0":
        raise ValueError("Not an original PE image")
    optional = f.read(struct.unpack_from("<H", header, 20)[0])
    if struct.unpack_from("<H", optional)[0] != 0x20B:
        raise ValueError("PE64 required")
    base = struct.unpack_from("<Q", optional, 24)[0]
    sections = []
    for _ in range(struct.unpack_from("<H", header, 6)[0]):
        s = f.read(40)
        _, rva, rawsize, raw = struct.unpack_from("<IIII", s, 8)
        sections.append((rva, rawsize, raw))
    for address in a.addresses:
        address = address if address >= base else base + address
        row = db.execute(
            "select name,size,assembly_addrs from functions where address=?",
            (str(address),),
        ).fetchone()
        if row is None or not 0 < row[1] <= 0x40000:
            raise ValueError("Missing or oversized function at " + hex(address))
        points = sorted(set(json.loads(row[2])))
        if not points or len(points) > 32768 or points[0] != address - base:
            raise ValueError("Invalid original instruction-address list")
        calls = []
        for rva in points:
            section = next(s for s in sections if s[0] <= rva < s[0] + s[1])
            f.seek(section[2] + rva - section[0])
            insn = next(
                decoder.disasm(
                    f.read(min(15, section[0] + section[1] - rva)), base + rva, 1
                ),
                None,
            )
            if insn is None:
                raise ValueError(
                    "Undecodable original instruction at " + hex(base + rva)
                )
            if insn.mnemonic not in ("call", "jmp") or len(insn.operands) != 1:
                continue
            operand = insn.operands[0]
            record = dict(
                instruction=hex(insn.address),
                mnemonic=insn.mnemonic,
                bytes=insn.bytes.hex(),
                operand=insn.op_str,
            )
            if operand.type == capstone.x86.X86_OP_IMM:
                target = operand.imm
                if target - base in points:  # intra-function control flow
                    continue
                matches = db.execute(
                    "select name,address,prototype from functions where address=?",
                    (str(target),),
                ).fetchall()
                record.update(
                    target=hex(target),
                    direct=True,
                    target_candidates=[
                        dict(zip(("name", "address", "prototype"), item))
                        for item in matches
                    ],
                )
            else:
                record["direct"] = False
                if (
                    operand.type == capstone.x86.X86_OP_MEM
                    and operand.mem.base == capstone.x86.X86_REG_RIP
                ):
                    record["pointer_slot"] = hex(
                        insn.address + insn.size + operand.mem.disp
                    )
            calls.append(record)
        records.append(
            dict(
                address=hex(address),
                display_name=row[0],
                calls=calls,
                scope="Exported instruction locations only; indirect targets remain unresolved",
            )
        )
snapshot = database.stat()
with binary.open("rb") as stream:
    binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
a.output.write_text(
    json.dumps(
        dict(
            binary=str(binary),
            binary_sha256=binary_hash,
            database=str(database),
            database_size=snapshot.st_size,
            database_mtime_ns=snapshot.st_mtime_ns,
            functions=records,
        ),
        indent=2,
    )
    + "\n"
)
for function in records:
    print(function["address"], function["display_name"])
    for call in function["calls"]:
        print(
            " ",
            call["instruction"],
            call.get("target", "indirect"),
            ", ".join(item["name"] for item in call.get("target_candidates", [])),
        )
