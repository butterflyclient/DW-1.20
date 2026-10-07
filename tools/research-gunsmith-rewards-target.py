"""Execute the original Replay reward reader and inventory cache writer."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP,
)

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = IMAGE.read_bytes()
image_hash = hashlib.sha256(raw).hexdigest()
assert image_hash == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
reader, writer, quantity, getter = 0x141B3B6D0, 0x141B3E0A0, 0x141B3C230, 0x141B3C030
cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True
functions = {}
with sqlite3.connect(IMAGE.with_suffix(".exe.sqlite").as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address in (reader, writer, quantity, getter, 0x1421CCF60, 0x1420E4290, 0x1420E42B0):
        size = db.execute("select size from functions where address=?", (str(address),)).fetchone()[0]
        code = pe.get_data(address - base, size)
        functions[address] = dict(size=size, code=code)
assert functions[reader]["size"] == 1268 and functions[writer]["size"] == 194
assert functions[quantity]["size"] == 140 and functions[getter]["size"] == 8
assert list(cs.disasm(functions[getter]["code"], getter))[0].mnemonic == "lea"
assert pe.get_data(0x23EFF20, 32).split(b"\0", 1)[0] == b"GRANT_PRODUCT"
assert pe.get_data(0x25BE720, 32).split(b"\0", 1)[0] == b"GRANT_CURRENCY"
assert pe.get_data(0x23FAA08, 32).split(b"\0", 1)[0] == b"ACTIVATE_ACHIEVEMENT"
calls = {i.operands[0].imm for a, f in functions.items() for i in cs.disasm(f["code"], a)
         if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM}


def execute(events=None, initial=(), direct_updates=None, prefilled=0):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped = set()
    stack, scratch, halt = 0x10000000, 0x11000000, 0x12000000
    vm.mem_map(stack, 0x20000)
    vm.mem_map(scratch, 0x10000)
    vm.mem_map(halt, 4096)
    def page(address):
        location = address & ~4095
        if location in mapped:
            return
        assert base <= location < base + pe.OPTIONAL_HEADER.SizeOfImage
        vm.mem_map(location, 4096)
        content = pe.get_data(location - base, 4096)
        if content:
            vm.mem_write(location, content)
        mapped.add(location)
    def missing(machine, access, address, size, value, context):
        page(address)
        page(address + size - 1)
        return True
    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    def invoke(address, rcx=0, rdx=0, r8=0, r9=0, fifth=0):
        rsp = stack + 0x1FF88
        vm.mem_write(rsp, struct.pack("<Q", halt))
        vm.mem_write(rsp + 40, struct.pack("<Q", fifth))
        for register, value in ((UC_X86_REG_RSP, rsp), (UC_X86_REG_RCX, rcx),
                                (UC_X86_REG_RDX, rdx), (UC_X86_REG_R8, r8), (UC_X86_REG_R9, r9)):
            vm.reg_write(register, value & (2**64 - 1))
        vm.emu_start(address, halt, count=2500000)
        assert vm.reg_read(UC_X86_REG_RIP) == halt
        return vm.reg_read(UC_X86_REG_RAX)
    state = invoke(getter)
    assert state == 0x1459E05C0
    slots, count_address = state + 64, state + 120064
    for address in range(state & ~4095, count_address + 4096, 4096):
        page(address)
    initial_rows = list(initial) if not prefilled else [(3000000+i, 1) for i in range(prefilled)]
    for i, (item, amount) in enumerate(initial_rows):
        vm.mem_write(slots + i*8, struct.pack("<II", item, amount))
    vm.mem_write(count_address, struct.pack("<I", len(initial_rows)))
    document = scratch + 0x100
    contexts, boundaries, writer_flags = {}, set(), []
    def cstring(address):
        data = bytearray()
        for offset in range(128):
            if base <= address + offset < base + pe.OPTIONAL_HEADER.SizeOfImage:
                page(address + offset)
            byte = bytes(vm.mem_read(address + offset, 1))
            if byte == b"\0":
                return data.decode()
            data += byte
        raise AssertionError("Unterminated native key")
    def returned(machine, value=0):
        rsp = machine.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", machine.mem_read(rsp, 8))[0]
        machine.reg_write(UC_X86_REG_RAX, value)
        machine.reg_write(UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(UC_X86_REG_RIP, target)
    def boundary(machine, address, size, context):
        if address == writer:
            rsp = machine.reg_read(UC_X86_REG_RSP)
            writer_flags.append(bytes(machine.mem_read(rsp + 40, 1))[0])
            return # Execute the real cache writes, search and capacity checks.
        if address == 0x1420E4290:
            contexts[machine.reg_read(UC_X86_REG_RCX)] = None
            return # Execute the real 32-byte JSON descriptor initialization.
        if address not in calls or address in functions:
            return
        rcx, rdx, r8, r9 = [machine.reg_read(reg) for reg in
                            (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
        boundaries.add(address)
        value = 0
        source = contexts.get(rcx)
        if address == 0x140D66C20:
            assert rcx == 0
        elif address == 0x1420E5AC0:
            value = int(isinstance(source, dict) and cstring(rdx) in source)
        elif address in (0x1420E4440, 0x1420E52F0):
            child = source.get(cstring(rdx)) if isinstance(source, dict) else None
            expected_type = list if address == 0x1420E4440 else dict
            value = int(isinstance(child, expected_type))
            if value:
                contexts[r8] = child
                machine.mem_write(r8, bytes(32))
                machine.mem_write(r8 + 28, struct.pack("<I", len(child)))
        elif address == 0x1420E4920:
            value = int(isinstance(source, list) and rdx < len(source))
            if value:
                contexts[r8] = source[rdx]
                machine.mem_write(r8, bytes(32))
        elif address == 0x1420E5480:
            child = source.get(cstring(rdx)) if isinstance(source, dict) else None
            value = int(isinstance(child, str) and len(child.encode()) < r9)
            if value:
                machine.mem_write(r8, child.encode() + b"\0")
        elif address == 0x1420E4F90:
            child = source.get(cstring(rdx)) if isinstance(source, dict) else None
            value = int(type(child) is int and -(2**31) <= child < 2**31)
            if value:
                machine.mem_write(r8, struct.pack("<i", child))
        elif address in (0x1412B0820, 0x141B3B440):
            pass # Diagnostic printing and the external last-drops history.
        elif address == 0x1419BCC30:
            pass # No real Lua VM in this isolated execution.
        else:
            raise AssertionError(f"Unexpected boundary {address:x}")
        returned(machine, value)
    vm.hook_add(UC_HOOK_CODE, boundary)
    snapshots = []
    operations = direct_updates if direct_updates is not None else events
    for operation in operations:
        if direct_updates is not None:
            item, amount, absolute = operation
            invoke(writer, state, 0, item, amount, absolute)
        else:
            contexts[document] = operation
            invoke(reader, state, 0, document, 5)
        count = struct.unpack("<I", vm.mem_read(count_address, 4))[0]
        cache = bytes(vm.mem_read(slots, count*8))
        snapshots.append(dict(count=count, rows=[struct.unpack_from("<II", cache, i*8)
                                                 for i in range(min(count, 32))],
                              cache_sha256=hashlib.sha256(cache).hexdigest()))
    return dict(snapshots=snapshots, writer_flags=writer_flags, modeled_boundaries=sorted(boundaries))


def grant(items, product=None):
    trigger = dict(type="GRANT_PRODUCT", inventory=dict(granted_items=[dict(id=i, quantity=q) for i, q in items]))
    if product is not None:
        trigger["productID"] = product
    return dict(triggers=[trigger])


cases = []
wrong = grant([(1001124, 1)])
wrong["triggers"][0]["type"] = "grantProduct"
result = execute(events=[wrong])
assert result["snapshots"][0]["count"] == 0 and not result["writer_flags"]
cases.append(dict(case="lowercase camel-case trigger is ignored by the original reader", **result))
result = execute(events=[grant([(1001124, 1)])]*2 + [grant([(1001124, 4)])])
assert [s["rows"] for s in result["snapshots"]] == [[(1001124, 1)], [(1001124, 1)], [(1001124, 4)]]
assert result["writer_flags"] == [1, 1, 1]
cases.append(dict(case="native reader uses absolute quantities, including retry and omitted productID", **result))
result = execute(events=[grant([(1001124, 1)], product=100001)])
assert result["snapshots"][0]["rows"] == [(1001124, 1)] and result["writer_flags"] == [1]
cases.append(dict(case="explicit productID special branch preserves the same cache semantics", **result))
result = execute(events=[grant([(1001124+i, 1) for i in range(20)])])
assert result["snapshots"][0]["count"] == 20 and result["writer_flags"] == [1]*20
cases.append(dict(case="20 item cache writes succeed independently of the native 16-item UI summary", **result))
result = execute(direct_updates=[(1001124, 7, 0), (1001124, 3, 1)], initial=[(1001124, 2)])
assert [s["rows"] for s in result["snapshots"]] == [[(1001124, 9)], [(1001124, 3)]]
cases.append(dict(case="relative and absolute primitive writes are distinct", **result))
result = execute(direct_updates=[(1001124, -1, 1)])
assert result["snapshots"][0]["count"] == 0
cases.append(dict(case="negative quantity cannot create a cache entry", **result))
result = execute(direct_updates=[(1001124, -1, 1)], initial=[(1001124, 0)])
assert result["snapshots"][0]["rows"] == [(1001124, 0)]
cases.append(dict(case="negative quantity cannot replace a zero entry", **result))
result = execute(direct_updates=[(1001124, 1, 1)], prefilled=15000)
assert result["snapshots"][0]["count"] == 15000
cases.append(dict(case="full native cache cannot append another item", **result))
receipt = dict(schema=1, passed=True, generated_utc=datetime.now(timezone.utc).isoformat(),
               target_image_sha256=image_hash, tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               functions={hex(a): dict(size=f["size"], bytes_sha256=hashlib.sha256(f["code"]).hexdigest())
                          for a, f in functions.items()}, cases=cases,
               native_controller=0, native_cache_capacity=15000,
               parser_descriptor_count_offset=28, reward_quantity_semantics="absolute snapshot, flag 1",
               verified_trigger_types=["GRANT_PRODUCT", "GRANT_CURRENCY", "ACTIVATE_ACHIEVEMENT"],
               modeled_boundaries=["JSON field reads", "controller mapping", "diagnostics", "last-drops history", "Lua begin-event unavailable"],
               original_reward_reader_executed=True, original_inventory_writer_executed=True,
               original_inventory_quantity_getter_executed=True,
               native_game_verified=False, backend_grants_implemented=False, game_runs_performed=False)
(ROOT / "validation/20261007-gunsmith-rewards-target.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(f"PASS: {len(cases)} original reward/cache execution cases, no game runs")
