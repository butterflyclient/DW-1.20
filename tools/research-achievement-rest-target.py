"""Bind shared Replay event writers and execute both original success readers."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
)

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
database = image.with_suffix(".exe.sqlite")
before = database.stat()
raw = image.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
addresses = (
    0x142102A60,
    0x14216A100,
    0x142155570,
    0x142103410,
    0x142169B70,
    0x142157FF0,
    0x1421696C0,
    0x142158070,
    0x142169760,
    0x1421CCF60,
    0x1420FF530,
    0x1420DE7C0,
)
functions, code = {}, {}
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address in addresses:
        name, size = db.execute(
            "select name,size from functions where address=?", (str(address),)
        ).fetchone()
        original = pe.get_data(address - base, size)
        code[address] = original
        calls, references, literals, constants = set(), set(), set(), set()
        for instruction in decoder.disasm(original, address):
            if (
                instruction.mnemonic == "call"
                and instruction.operands[0].type == X86_OP_IMM
            ):
                calls.add(instruction.operands[0].imm)
            for operand in instruction.operands:
                if operand.type == X86_OP_IMM:
                    constants.add(operand.imm)
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    pointer = instruction.address + instruction.size + operand.mem.disp
                    references.add(pointer)
                    value = pe.get_data(pointer - base, 128).split(b"\0", 1)[0]
                    if value and len(value) < 128 and all(32 <= b < 127 for b in value):
                        literals.add(value.decode("ascii"))
        functions[address] = dict(
            va=address,
            candidate_alias=name,
            size=size,
            bytes_sha256=hashlib.sha256(original).hexdigest(),
            direct_calls=sorted(calls),
            rip_references=sorted(references),
            literal_strings=sorted(literals),
            immediates=sorted(constants),
        )

for writer in (0x142102A60, 0x14216A100):
    row = functions[writer]
    assert 0x142155570 in row["direct_calls"] and 0x504F5354 in row["immediates"]
    assert {
        "user_events",
        "report_user_events_batch",
        "/v2/user-events/$batch/",
        "titleID",
        "idempotentRequestID",
        "userEvents",
    } <= set(row["literal_strings"])
assert {"ae.demonware.net", "context", "client", "titleID", "DW-ABToken"} <= set(
    functions[0x142155570]["literal_strings"]
)
assert {"name", "timestamp", "values"} <= set(functions[0x142103410]["literal_strings"])
assert {
    "accountType",
    "userID",
    "firstPartyAccountType",
    "firstPartyUserID",
    "platform",
    "events",
} <= set(functions[0x142169B70]["literal_strings"])
bindings = (
    (0x142157FF0, 0x1426A59C0, 0x142158070),
    (0x1421696C0, 0x1426A7E78, 0x142169760),
)
for constructor, table, success in bindings:
    assert table in functions[constructor]["rip_references"]
    assert struct.unpack("<Q", pe.get_data(table + 8 - base, 8))[0] == success
    assert "allSucceeded" in functions[success]["literal_strings"]


def execute(constructor, reader, document):
    """Execute original constructor/callback; model only JSON/OS boundaries."""
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped = set()

    def map_image(address):
        page = address & ~4095
        if page not in mapped:
            vm.mem_map(page, 4096)
            mapped.add(page)
            if base <= page < base + pe.OPTIONAL_HEADER.SizeOfImage:
                vm.mem_write(page, pe.get_data(page - base, 4096))

    for address in (constructor, reader):
        for offset in range(0, len(code[address]) + 4095, 4096):
            map_image(address + offset)
        for reference in functions[address]["rip_references"]:
            map_image(reference)
    targets = set(functions[reader]["direct_calls"]) | set(
        functions[constructor]["direct_calls"]
    )
    for target in targets:
        map_image(target)
    scratch, stack, stop = 0x10000000, 0x11000000, 0x12000000
    vm.mem_map(scratch, 4096)
    vm.mem_map(stack, 0x10000)
    vm.mem_map(stop, 4096)
    contexts, visited = {}, set()
    error_codes = []

    def cstring(address):
        return bytes(vm.mem_read(address, 128)).split(b"\0", 1)[0].decode("ascii")

    def boundary(machine, address, size, user):
        if address not in targets:
            return
        if address == 0x1421CCF60:
            return  # Execute the real cookie check with the actual VM frame.
        rcx, rdx, r8, r9 = [
            machine.reg_read(reg)
            for reg in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)
        ]
        result = 0
        visited.add(address)
        if address == 0x1420E4290:  # native JSON object constructor
            contexts[rcx] = None
            machine.mem_write(rcx, bytes(32))
        elif address == 0x1421536C0:  # REST message -> JSON deserializer
            contexts[rdx] = document
            result = int(isinstance(document, dict))
        elif address == 0x1420E4600:  # getBoolean, with the actual native key
            value = contexts.get(rcx)
            field = value.get(cstring(rdx)) if isinstance(value, dict) else None
            result = int(type(field) is bool)
            if result:
                machine.mem_write(r8, bytes([field]))
        elif address in (0x1420E4440, 0x1420E52F0):
            value = contexts.get(rcx)
            field = value.get(cstring(rdx)) if isinstance(value, dict) else None
            expected = list if address == 0x1420E4440 else dict
            result = int(isinstance(field, expected))
            if result:
                contexts[r8] = field
                if expected is list:
                    machine.mem_write(r8 + 28, struct.pack("<I", len(field)))
        elif address == 0x1420E4920:
            value = contexts.get(rcx)
            result = int(isinstance(value, list) and rdx < len(value))
            if result:
                contexts[r8] = value[rdx]
        elif address == 0x1420E5AC0:
            value = contexts.get(rcx)
            result = int(isinstance(value, dict) and cstring(rdx) in value)
        elif address == 0x1420E5480:
            value = contexts.get(rcx)
            field = value.get(cstring(rdx)) if isinstance(value, dict) else None
            result = int(isinstance(field, str) and len(field.encode()) < r9)
            if result:
                machine.mem_write(r8, field.encode() + b"\0")
        elif address == 0x1421541A0:
            # Missing/unknown error name fails lookup; no success is invented.
            result = 0
        elif address == 0x1420FF620:
            error_codes.append(rdx & 0xFFFFFFFF)
        elif address in (0x1420E42B0, 0x142118020):
            pass  # JSON destructor / error-map getter
        else:
            # Only the base constructor and diagnostic
            # logger may be no-op boundaries. Names are recorded, not trusted.
            if address not in noops:
                raise RuntimeError(f"Unexpected native boundary {address:x}")
        machine.reg_write(UC_X86_REG_RAX, result)
        rsp = machine.reg_read(UC_X86_REG_RSP)
        returned = struct.unpack("<Q", machine.mem_read(rsp, 8))[0]
        machine.reg_write(UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(UC_X86_REG_RIP, returned)

    vm.hook_add(UC_HOOK_CODE, boundary)
    for entry in (constructor, reader):
        rsp = stack + 0xFFC8
        vm.mem_write(rsp, struct.pack("<Q", stop))
        vm.reg_write(UC_X86_REG_RSP, rsp)
        vm.reg_write(UC_X86_REG_RCX, scratch)
        vm.reg_write(UC_X86_REG_RDX, scratch + 1024)
        vm.emu_start(entry, stop, count=20000)
        assert vm.reg_read(UC_X86_REG_RIP) == stop
    return dict(
        returned=vm.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF,
        original_constructor_executed=True,
        native_error_codes=error_codes,
        boundary_calls=sorted(visited),
    )


# Exactly two modeled non-JSON boundaries. Their target bytes are retained;
# candidate SQLite labels do not select a successful stub or response layout.
assert functions[0x142157FF0]["direct_calls"] == [0x1420FF530]
assert functions[0x1421696C0]["direct_calls"] == [0x1420FF530]
assert all(
    0x1420DE7C0 in functions[a]["direct_calls"] for a in (0x142158070, 0x142169760)
)
noops = {0x1420FF530, 0x1420DE7C0}

cases = []
for constructor, table, reader in bindings:
    for label, body, expected in (
        ("published-success", {"allSucceeded": True}, 1),
        ("old-empty-204", None, 0),
        ("missing-success-field", {}, 0),
        ("numeric-success-field", {"allSucceeded": 1}, 0),
        ("false-without-results", {"allSucceeded": False}, 0),
    ):
        result = execute(constructor, reader, body)
        assert result["returned"] == expected
        cases.append(dict(reader=reader, case=label, expected=expected, **result))
assert database.stat().st_mtime_ns == before.st_mtime_ns
output = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    target_image_sha256=digest,
    functions=list(functions.values()),
    bindings=[dict(constructor=c, vtable=t, success=s) for c, t, s in bindings],
    response=dict(status=200, body={"allSucceeded": True}),
    callback_vm=dict(
        passed=True,
        cases=cases,
        boundaries="JSON deserializer operations, base constructor and diagnostics are modeled; original constructors, callbacks and security-cookie check execute unchanged",
    ),
    native_game_event_callback_verified=False,
    full_backend_complete=False,
)
destination = ROOT / "validation/20261006-achievement-rest-layout.json"
destination.write_text(json.dumps(output, indent=2) + "\n")
print(
    f"Verified both shared writers and {len(cases)} original callback cases; empty 204 rejected."
)
