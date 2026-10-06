"""Verify original Replay AB REST routing, reader binding and legacy body capacity."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_RIP,
    X86_REG_EBP,
    X86_REG_BPL,
)
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
)

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
database = image.with_suffix(".exe.sqlite")
before = database.stat()
raw = image.read_bytes()
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
functions, instructions = [], {}
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address in (
        0x1420FC2C0,
        0x1420FC910,
        0x1420FFE50,
        0x1420FF640,
        0x1420FF850,
        0x142157970,
        0x142169540,
        0x1421690E0,
        0x140F28A60,
    ):
        name, size = db.execute(
            "select name,size from functions where address=?", (str(address),)
        ).fetchone()
        code = pe.get_data(address - base, size)
        decoded = list(decoder.disasm(code, address))
        instructions[address] = decoded
        calls, strings, refs, immediate = [], set(), set(), set()
        for ins in decoded:
            if ins.mnemonic == "call" and ins.operands[0].type == X86_OP_IMM:
                calls.append(ins.operands[0].imm)
            for operand in ins.operands:
                if operand.type == X86_OP_IMM:
                    immediate.add(operand.imm)
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    pointer = ins.address + ins.size + operand.mem.disp
                    refs.add(pointer)
                    text = pe.get_data(pointer - base, 128).split(b"\0", 1)[0]
                    if (
                        text
                        and len(text) < 128
                        and all(32 <= byte < 127 for byte in text)
                    ):
                        strings.add(text.decode("ascii"))
        functions.append(
            dict(
                va=address,
                candidate_alias=name,
                exported_size=size,
                target_bytes_sha256=hashlib.sha256(code).hexdigest(),
                direct_calls=calls,
                literal_strings=sorted(strings),
                rip_references=sorted(refs),
                immediates=sorted(immediate),
            )
        )

indexed = {f["va"]: f for f in functions}
writer = indexed[0x1420FFE50]
assert {
    "abtesting/v2/users/{account_type}-{user_id}/enrollments/",
    "abtesting",
    "enroll",
} <= set(writer["literal_strings"])
assert 0x504F5354 in writer["immediates"]
assert 0x1420FCA50 not in writer["direct_calls"]  # No setServiceName.
assert 8096 in indexed[0x1420FF640]["immediates"]
assert {"expiresIn", "ABToken", "enrollments"} <= set(
    indexed[0x1420FF850]["literal_strings"]
)
table = 0x1423F0028
assert struct.unpack("<Q", pe.get_data(table + 8 - base, 8))[0] == 0x1420FF850
assert table in indexed[0x140F28A60]["rip_references"]
assert any(
    ins.mnemonic == "xor"
    and len(ins.operands) == 2
    and all(op.type == X86_OP_REG and op.reg == X86_REG_EBP for op in ins.operands)
    for ins in instructions[0x1420FC2C0]
)
assert any(
    ins.mnemonic == "mov"
    and len(ins.operands) == 2
    and ins.operands[0].type == X86_OP_MEM
    and ins.operands[0].mem.disp == 24416
    and ins.operands[1].type == X86_OP_REG
    and ins.operands[1].reg == X86_REG_BPL
    for ins in instructions[0x1420FC2C0]
)


def preflight(
    service,
    uri="abtesting/v2/users/uno-123/enrollments/",
    resource="abtesting",
    operation="enroll",
):
    """Run original validator instructions; external utility calls are VM boundaries."""
    address = 0x142169540
    decoded = instructions[address]
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    page = address & ~0xFFF
    uc.mem_map(page, 0x2000)
    uc.mem_write(
        address, pe.get_data(address - base, indexed[address]["exported_size"])
    )
    heap, stack, stop = 0x1000000, 0x2000000, 0x3000000
    uc.mem_map(heap, 0x4000)
    uc.mem_map(stack, 0x4000)
    uc.mem_map(stop, 0x1000)
    params, request = heap + 0x1000, heap
    uc.mem_write(request, struct.pack("<Q", params))
    uc.mem_write(request + 8, struct.pack("<II", 1, 0x504F5354))
    uc.mem_write(request + 16, struct.pack("<QQ", heap + 0x2000, heap + 0x2100))
    uc.mem_write(request + 32, struct.pack("<I", 1))
    uc.mem_write(request + 44, struct.pack("<I", 1))
    uc.mem_write(request + 56, struct.pack("<Q", heap + 0x3000))
    for pointer, value in (
        (heap + 0x2000, service),
        (heap + 0x2100, uri),
        (params + 268, resource),
        (params + 332, operation),
    ):
        uc.mem_write(pointer, value.encode() + b"\0")
    rsp = stack + 0x3F08
    uc.mem_write(rsp, struct.pack("<Q", stop))
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RCX, request)
    calls = {ins.address: ins for ins in decoded if ins.mnemonic == "call"}
    expected = {0x1421F7C70, 0x1421529B0, 0x142152A50, 0x142152C90}
    assert {ins.operands[0].imm for ins in calls.values()} == expected

    def hook(vm, pc, size, _):
        if pc == stop:
            vm.emu_stop()
        elif pc in calls:
            target = calls[pc].operands[0].imm
            if target == 0x1421F7C70:  # Bounded memchr, including the empty string.
                pointer = vm.reg_read(UC_X86_REG_RCX)
                value = vm.reg_read(UC_X86_REG_RDX) & 255
                count = vm.reg_read(UC_X86_REG_R8)
                data = bytes(vm.mem_read(pointer, count))
                index = data.find(bytes([value]))
                result = 0 if index < 0 else pointer + index
            elif target == 0x142152C90:  # Empty native header map: no forbidden key.
                result = 0
            else:  # Valid native POST/MIME utility boundaries.
                result = 1
            vm.reg_write(UC_X86_REG_RAX, result)
            vm.reg_write(UC_X86_REG_RIP, pc + size)

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(address, stop + 1, count=1000)
    assert uc.reg_read(UC_X86_REG_RIP) == stop
    return uc.reg_read(UC_X86_REG_RAX) & 255


cases = [
    dict(case="original unset service", accepted=preflight(""), expected=0),
    dict(case="explicit service", accepted=preflight("abtesting"), expected=1),
    dict(case="empty URI", accepted=preflight("abtesting", uri=""), expected=0),
    dict(
        case="empty resource", accepted=preflight("abtesting", resource=""), expected=0
    ),
    dict(
        case="empty operation",
        accepted=preflight("abtesting", operation=""),
        expected=0,
    ),
]
assert all(case["accepted"] == case["expected"] for case in cases)
assert database.stat().st_mtime_ns == before.st_mtime_ns
receipt = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    target_image_sha256=hashlib.sha256(raw).hexdigest(),
    functions=functions,
    rest_request=dict(
        service="abtesting",
        resource="abtesting",
        operation="enroll",
        method="POST",
        body=False,
        content_type=0,
        accept=1,
        native_uri="abtesting/v2/users/{account_type}-{user_id}/enrollments/",
    ),
    response_vtable=dict(table=table, slot=1, handler=0x1420FF850),
    legacy_body_capacity_bytes=8096,
    maximum_json_bytes=8095,
    original_rest_writer_requires_service_correction=True,
    original_validator_vm=dict(
        passed=True, cases=cases, external_utility_calls_stubbed=True
    ),
    native_game_rest_callback_verified=False,
)
output = ROOT / "validation/20261006-abtesting-rest-target-layout.json"
output.write_text(json.dumps(receipt, indent=2) + "\n", newline="\n")
print(
    "PASS: original AB REST writer/reader binding, body capacity and SDK service validator"
)
