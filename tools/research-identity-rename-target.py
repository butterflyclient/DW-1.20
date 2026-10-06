"""Bind Replay's rename request/response and engine owner to original PE bytes."""

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
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
database = image.with_suffix(".exe.sqlite")
snapshot = database.stat()
raw = image.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
table = 0x14269E3D0
entries = struct.unpack("<4Q", pe.get_data(table - base, 32))
assert entries[1:3] == (0x142100900, 0x142100670)
assert pe.get_data(0x1423F2780 - base, 4) == b"uno\0"
functions = []
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address in (
        0x140F2E750,
        0x140F2EAF0,
        0x1421398E0,
        0x142100230,
        0x1421005E0,
        0x142100670,
        0x142100900,
        0x1421009B0,
    ):
        name, size = db.execute(
            "select name,size from functions where address=?", (str(address),)
        ).fetchone()
        code = pe.get_data(address - base, size)
        calls, pointers, literals, immediates = [], [], set(), set()
        for instruction in decoder.disasm(code, address):
            if (
                instruction.mnemonic == "call"
                and instruction.operands[0].type == X86_OP_IMM
            ):
                calls.append(instruction.operands[0].imm)
            for operand in instruction.operands:
                if operand.type == X86_OP_IMM:
                    immediates.add(operand.imm)
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    pointer = instruction.address + instruction.size + operand.mem.disp
                    pointers.append(pointer)
                    value = pe.get_data(pointer - base, 128).split(b"\0", 1)[0]
                    if (
                        value
                        and len(value) < 128
                        and all(32 <= byte < 127 for byte in value)
                    ):
                        literals.add(value.decode("ascii"))
        if address == 0x1421005E0:
            assert table in pointers
        if address == 0x142100230:
            assert 0x505554 in immediates
            assert {
                "UserResource",
                "renameUsername",
                "/v1.0/users/{uno_id}/securedfields/",
                "client",
                "userName",
                "Bearer  %s",
                "Authorization",
            }.issubset(literals)
        if address == 0x142100900:
            assert "success" in literals and 14116 in immediates
        if address == 0x1421009B0:
            assert {"code", "name", "msg"}.issubset(literals)
        functions.append(
            dict(
                va=address,
                candidate_alias=name,
                exported_size=size,
                target_bytes_sha256=hashlib.sha256(code).hexdigest(),
                direct_calls=calls,
                rip_references=pointers,
                literal_strings=sorted(literals),
            )
        )
assert database.stat().st_mtime_ns == snapshot.st_mtime_ns
receipt = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    target_image_sha256=digest,
    functions=functions,
    response_vtable=dict(
        va=table,
        entries=list(entries),
        success_slot=1,
        error_slot=2,
        error_code_offset=40,
    ),
    request=dict(
        service="uno",
        resource="UserResource",
        operation="renameUsername",
        method="PUT",
        path="/v1.0/users/{auth-info.userID}/securedfields/",
        query=["client"],
        json_body={"userName": "string"},
        authorization_prefix="Bearer  ",
    ),
    native_callback_verified=False,
    native_engine_preconditions="Original engine checks rename inventory/currency and uses CrossplayAccessInfo access token. Local legacy login does not establish that native flow.",
)
path = ROOT / "validation/20261006-native-identity-rename-layout.json"
path.write_text(json.dumps(receipt, indent=2) + "\n")
print(
    "Verified original Replay rename writer, response vtable, readers and engine owner; live rename callback remains separate."
)
