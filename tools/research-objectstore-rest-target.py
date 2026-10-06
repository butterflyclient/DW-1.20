"""Verify Replay vector REST request/response bindings from the original PE."""

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
parser.add_argument("--output", required=True, type=Path)
output = parser.parse_args().output.resolve()
if not any(output.is_relative_to(ROOT / name) for name in ("data", "validation")):
    raise ValueError("Keep target receipts inside data or validation")
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
database = image.with_suffix(".exe.sqlite")
snapshot = database.stat()
raw = image.read_bytes()
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
bindings = (
    (0x14269F860, 0x14210F860, 0x14210F190),
    (0x14269F8E8, 0x142110BD0, 0x14210FDF0),
)
for table, handler, constructor in bindings:
    if struct.unpack("<Q", pe.get_data(table + 8 - base, 8))[0] != handler:
        raise ValueError("Unexpected vector REST response table")


def literal(address):
    return pe.get_data(address - base, 128).split(b"\0", 1)[0].decode("ascii")


hosts = []
for pointer in (0x145A532C0, 0x145A532C8, 0x145A532D0):
    target = struct.unpack("<Q", pe.get_data(pointer - base, 8))[0]
    value = literal(target)
    if not value.startswith("https://objectstore."):
        raise ValueError("Unexpected environment hostname")
    hosts.append(value[8:])
error_pointer = struct.unpack("<Q", pe.get_data(0x145A52188 - base, 8))[0]
assert literal(error_pointer) == "Error:ClientError:NotModified"
assert literal(0x1426A38A8) == "DW-Objectstore-ObjectIDs"
functions = []
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    error_reader = int(
        db.execute(
            "select address from functions where name=?",
            ("bdObjectStoreErrorWrappedObject::deserializeErrorFromJSON",),
        ).fetchone()[0]
    )
    for address in (
        0x1421443E0,
        0x142145630,
        0x142145DE0,
        0x142146E60,
        0x14210F190,
        0x14210FDF0,
        0x14210F860,
        0x142110BD0,
        error_reader,
    ):
        name, size = db.execute(
            "select name,size from functions where address=?", (str(address),)
        ).fetchone()
        code = pe.get_data(address - base, size)
        calls, references, strings = [], [], set()
        for instruction in decoder.disasm(code, address):
            if (
                instruction.mnemonic == "call"
                and instruction.operands[0].type == X86_OP_IMM
            ):
                calls.append(instruction.operands[0].imm)
            for operand in instruction.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    pointer = instruction.address + instruction.size + operand.mem.disp
                    references.append(pointer)
                    value = pe.get_data(pointer - base, 128).split(b"\0", 1)[0]
                    if (
                        value
                        and len(value) < 128
                        and all(32 <= byte < 127 for byte in value)
                    ):
                        strings.add(value.decode("ascii"))
        for table, handler, constructor in bindings:
            if address == constructor and table not in references:
                raise ValueError(
                    "Response constructor no longer references its REST table"
                )
        functions.append(
            dict(
                va=address,
                candidate_alias=name,
                exported_size=size,
                target_bytes_sha256=hashlib.sha256(code).hexdigest(),
                direct_calls=calls,
                rip_references=references,
                literal_strings=sorted(strings),
            )
        )
if database.stat().st_mtime_ns != snapshot.st_mtime_ns:
    raise ValueError("Database changed during the audit; retry")
receipt = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    target_image_sha256=hashlib.sha256(raw).hexdigest(),
    native_runtime_verified=False,
    environment_services=hosts,
    functions=functions,
    vtable_bindings=[
        dict(vtable=t, slot=1, handler=h, constructor=c, rest_base_offset=24)
        for t, h, c in bindings
    ],
    requests=[
        dict(
            va=0x142145DE0,
            resource="ObjectsVectorizedResourceUsers",
            operation="get_objects",
            method="GET",
            path="/v2/core/users/objects/",
            query=["client", "context"],
            object_ids_header="DW-Objectstore-ObjectIDs",
            cache_fields=["objectVersion", "checksum"],
        ),
        dict(
            va=0x142146E60,
            resource="ObjectsVectorizedResourceUsers",
            operation="put_objects",
            method="PUT",
            paths=["/v2/core/users/objects/", "/v2/users/objects/"],
            query=["client", "context", "optional extra=validationToken"],
            body="objects: content base64, metadata and optional tags",
        ),
    ],
    response=dict(
        get="objects/errors with one requestIndex per requested object",
        put="objects/errors/validationTokens; metadata matched by owner/name",
        cache_error="Error:ClientError:NotModified",
        body_capacity=262144,
    ),
    scope="Exact original request writers, environment getter, response constructors/vtables/readers. Native game method completion remains a separate gate.",
)
output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
print(
    "Verified Replay object-store REST vectors, environment services and native cache error."
)
