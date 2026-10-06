"""Bind Replay AB wire fields and actual engine allocations to original bytes."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_RIP,
    X86_REG_R8D,
    X86_REG_EDI,
    X86_REG_RDI,
)
import pefile

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
database = image.with_suffix(".exe.sqlite")
snapshot = database.stat()
raw = image.read_bytes()
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
functions = []
required_strings = {
    0x1420FF850: {"expiresIn", "ABToken", "enrollments"},
    0x1420FFB10: {"testID", "cohortID", "clientTreatments"},
    0x1420FFA60: {"startsIn", "endsIn", "modifiers"},
    0x140F290A0: {"type", "data", "key", "value"},
}
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    for address in (
        *required_strings,
        0x140F28810,
        0x140F28BA0,
        0x140F28E60,
        0x1420FFFC0,
        0x142139AD0,
    ):
        name, size = db.execute(
            "select name,size from functions where address=?", (str(address),)
        ).fetchone()
        code = pe.get_data(address - base, size)
        calls, strings, r8_immediates = [], set(), set()
        edi = None
        for ins in decoder.disasm(code, address):
            if (
                ins.mnemonic == "mov"
                and len(ins.operands) == 2
                and ins.operands[0].type == X86_OP_REG
                and ins.operands[0].reg == X86_REG_EDI
                and ins.operands[1].type == X86_OP_IMM
            ):
                edi = ins.operands[1].imm & 0xFFFFFFFF
            if (
                ins.mnemonic == "lea"
                and len(ins.operands) == 2
                and ins.operands[0].reg == X86_REG_R8D
                and ins.operands[1].type == X86_OP_MEM
                and ins.operands[1].mem.base == X86_REG_RDI
                and edi is not None
            ):
                r8_immediates.add((edi + ins.operands[1].mem.disp) & 0xFFFFFFFF)
            if ins.mnemonic == "call" and ins.operands[0].type == X86_OP_IMM:
                calls.append(ins.operands[0].imm)
            if (
                ins.mnemonic == "mov"
                and len(ins.operands) == 2
                and ins.operands[0].reg == X86_REG_R8D
                and ins.operands[1].type == X86_OP_IMM
            ):
                r8_immediates.add(ins.operands[1].imm)
            for op in ins.operands:
                if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                    continue
                target = ins.address + ins.size + op.mem.disp
                value = pe.get_data(target - base, 128).split(b"\0", 1)[0]
                if (
                    value
                    and len(value) < 128
                    and all(32 <= byte < 127 for byte in value)
                ):
                    strings.add(value.decode("ascii"))
        assert required_strings.get(address, set()) <= strings
        if address == 0x140F28810:
            assert {1, 1024} <= r8_immediates
        if address == 0x140F28BA0:
            assert 8 in r8_immediates and 0x1420FFA30 in calls
        functions.append(
            dict(
                va=address,
                candidate_alias=name,
                target_bytes_sha256=hashlib.sha256(code).hexdigest(),
                exported_size=size,
                direct_calls=calls,
                literal_strings=sorted(strings),
                r8d_immediates=sorted(r8_immediates),
            )
        )
assert database.stat().st_mtime_ns == snapshot.st_mtime_ns
receipt = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    target_image_sha256=hashlib.sha256(raw).hexdigest(),
    functions=functions,
    native_engine_capacities=dict(
        enrollments=8, client_treatments_per_enrollment=1, modifier_buffer_bytes=1024
    ),
    engine_modifier_application="Immediate at successful enrollment; filter future and expired treatments before publication",
    wire_fields=dict(
        response=["expiresIn", "ABToken", "enrollments"],
        enrollment=["testID", "cohortID", "clientTreatments"],
        treatment=["startsIn", "endsIn", "modifiers"],
    ),
    native_runtime_verified=False,
)
output = ROOT / "validation/20261006-abtesting-target-layout.json"
output.write_text(json.dumps(receipt, indent=2) + "\n")
print("PASS: original Replay AB readers and engine allocation capacities")
