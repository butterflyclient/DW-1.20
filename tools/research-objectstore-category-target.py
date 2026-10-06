"""Verify Replay's category-list writer binding from original bytes and getter VM."""

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
    UC_X86_REG_RSP,
)

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
assert (
    hashlib.sha256(raw).hexdigest()
    == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
)
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
database = image.with_suffix(".exe.sqlite")
before = database.stat()
functions = {}
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address in (
        0x1421443E0,
        0x142144CF0,
        0x142144F50,
        0x142143690,
        0x142143720,
        0x14212A960,
    ):
        size = db.execute(
            "select size from functions where address=?", (str(address),)
        ).fetchone()[0]
        code = pe.get_data(address - base, size)
        instructions, references, literals = [], set(), set()
        for i in decoder.disasm(code, address):
            instructions.append(
                dict(va=i.address, mnemonic=i.mnemonic, operands=i.op_str)
            )
            for operand in i.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    pointer = i.address + i.size + operand.mem.disp
                    references.add(pointer)
                    text = pe.get_data(pointer - base, 128).split(b"\0", 1)[0]
                    if text and len(text) < 128 and all(32 <= c < 127 for c in text):
                        literals.add(text.decode())
        functions[address] = dict(
            va=address,
            bytes_sha256=hashlib.sha256(code).hexdigest(),
            size=size,
            instructions=instructions,
            references=sorted(references),
            literals=sorted(literals),
        )

writer = functions[0x142144CF0]
sequence = [(i["mnemonic"], i["operands"]) for i in writer["instructions"]]
index = sequence.index(("call", "0x1421443e0"))
assert sequence[index - 1] == ("lea", "rcx, [rdi - 0x1e0]")
assert sequence[index + 1 : index + 4] == [
    ("mov", "rdx, rax"),
    ("mov", "rcx, rbx"),
    ("call", "0x1420fca50"),
]
assert {
    "ObjectsResourcePublishers",
    "get_metadata",
    "/v2/core/publishers/{publisher}/objects/",
    "client",
    "context",
    "category",
    "limit",
    "pageToken",
} <= set(writer["literals"])
assert ("mov", "edx, 0x474554") in sequence
constructor = [
    (i["mnemonic"], i["operands"]) for i in functions[0x14212A960]["instructions"]
]
assert ("mov", "r8b, 0xc1") in constructor and ("mov", "r9b, 9") in constructor
assert ("lea", "r10, [rbx + 8]") in constructor
assert ("call", "0x142117c10") in constructor

tables = (0x145A532C0, 0x145A532C8, 0x145A532D0)
hosts = []
for pointer in tables:
    target = struct.unpack("<Q", pe.get_data(pointer - base, 8))[0]
    host = pe.get_data(target - base, 128).split(b"\0", 1)[0].decode()
    assert host.startswith("https://objectstore.")
    hosts.append((target, host[8:]))


def getter_case(environment):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    pages = set()

    def original_page(address):
        page = address & ~4095
        if page in pages:
            return
        vm.mem_map(page, 4096)
        vm.mem_write(page, pe.get_data(page - base, 4096))
        pages.add(page)

    for address in (
        0x1421443E0,
        0x14220F730,
        *tables,
        *(p for p, _ in hosts),
        *functions[0x1421443E0]["references"],
    ):
        original_page(address)
    stack, record, halt = 0x10000000, 0x11000000, 0x12000000
    for page in (stack, record, halt):
        vm.mem_map(page, 4096)
    vm.mem_write(record + 8, struct.pack("<I", environment))
    vm.mem_write(stack + 4080, struct.pack("<Q", halt))
    vm.reg_write(UC_X86_REG_RCX, record)
    vm.reg_write(UC_X86_REG_RSP, stack + 4080)

    def boundary(machine, address, size, _):
        if address == halt:
            machine.emu_stop()
        elif address == 0x14220F730:
            count = machine.reg_read(UC_X86_REG_R8)
            assert count == 8
            a = bytes(machine.mem_read(machine.reg_read(UC_X86_REG_RCX), count))
            b = bytes(machine.mem_read(machine.reg_read(UC_X86_REG_RDX), count))
            machine.reg_write(UC_X86_REG_RAX, 0 if a == b else 1)
            sp = machine.reg_read(UC_X86_REG_RSP)
            target = struct.unpack("<Q", machine.mem_read(sp, 8))[0]
            machine.reg_write(UC_X86_REG_RSP, sp + 8)
            # This is only the original strncmp boundary, not the host getter.
            from unicorn.x86_const import UC_X86_REG_RIP

            machine.reg_write(UC_X86_REG_RIP, target)

    vm.hook_add(UC_HOOK_CODE, boundary)
    vm.emu_start(0x1421443E0, halt, count=100)
    result = vm.reg_read(UC_X86_REG_RAX)
    selected = 0 if environment == 0 else 1 if environment == 1 else 2
    assert result == hosts[selected][0] + 8
    return dict(environment=environment, service=hosts[selected][1], passed=True)


cases = [getter_case(value) for value in (0, 1, 2, 42)]
after = database.stat()
assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
receipt = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    target_image_sha256=hashlib.sha256(raw).hexdigest(),
    audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    functions=list(functions.values()),
    environment_services=[host for _, host in hosts],
    getter_vm=dict(
        passed=True,
        cases=cases,
        modeled_boundary="Original strncmp with actual 8-byte memory arguments",
    ),
    request=dict(
        va=0x142144CF0,
        service=193,
        task=9,
        constructor=0x14212A960,
        resource="ObjectsResourcePublishers",
        operation="get_metadata",
        method="GET",
        path="/v2/core/publishers/{publisher}/objects/",
        query=["client", "context", "category", "limit", "optional pageToken"],
        struct_writer=0x142144F50,
        response_base_offset=8,
    ),
    native_response_reader_verified=False,
    native_runtime_verified=False,
    full_category_domain_implemented=False,
    scope="Original request service getter, setter dataflow and task constructor. Response body/parser remains unresolved; no category handler claimed.",
)
destination = ROOT / "validation/20261006-objectstore-category-target.json"
destination.write_text(json.dumps(receipt, indent=2) + "\n")
print(
    "Verified category REST binding, 193/9 request constructor and four original environment-getter cases; response reader remains unresolved."
)
