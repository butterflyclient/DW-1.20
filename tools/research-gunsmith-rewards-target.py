"""Execute the original Replay reward reader and inventory cache writer."""

from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86_REG_R15
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
completion = 0x140F34CA0
envelope = 0x140F33650
version_reader, reward_message = 0x1420EFB80, 0x142125410
cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True
functions = {}
with sqlite3.connect(IMAGE.with_suffix(".exe.sqlite").as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address in (reader, writer, quantity, getter, completion, envelope, version_reader, reward_message, 0x1421CCF60, 0x1420E4290, 0x1420E42B0):
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
envelope_instructions = list(cs.disasm(functions[envelope]["code"], envelope))
envelope_literals = set()
assert any(i.mnemonic == "lea" and i.operands[0].reg == X86_REG_R15
           and i.operands[1].type == X86_OP_MEM and i.operands[1].mem.base == X86_REG_RIP
           and i.address + i.size + i.operands[1].mem.disp == base for i in envelope_instructions)
for instruction in envelope_instructions:
    for operand in instruction.operands:
        if operand.type == X86_OP_MEM:
            address = (instruction.address + instruction.size + operand.mem.disp
                       if operand.mem.base == X86_REG_RIP else operand.mem.disp)
            if operand.mem.base == X86_REG_R15 or operand.mem.index == X86_REG_R15:
                address = base + operand.mem.disp
            if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
                continue
            value = pe.get_data(address - base, 128).split(b"\0", 1)[0]
            if value and all(32 <= byte < 127 for byte in value):
                envelope_literals.add(value.decode())
assert {"type", "name", "reason", "ACHIEVEMENT", "completed", "inProgress"} <= envelope_literals
assert completion in {i.operands[0].imm for i in envelope_instructions
                      if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM}


def execute(events=None, initial=(), direct_updates=None, prefilled=0, through_completion=False, version_packet=None):
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
    # Isolate the optional upload-current-stats branch. No live engine dvars,
    # player progression state, AAR manager or Lua VM exist in this execution.
    if through_completion:
        page(0x14EE565D8)
        vm.mem_write(0x14EE565D8, struct.pack("<Q", scratch + 0x8000))
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
        elif through_completion and address == 0x1413FD570:
            assert rcx == 0
            value = 0 # Modeled controller mapping for the known local user.
        elif through_completion and address == 0x140F27A30:
            value = scratch + 0x4000 # External AAR manager, not progression.
        elif through_completion and address == 0x140F27DD0:
            assert rdx == 0 and r8 == 18 and contexts[r9]["kind"] == 18
            # AAR summary is external to this cache test; assert its exact kind.
        elif version_packet is not None and address == 0x1420EF570:
            assert rdx == 3 # Original readUByte8 requests tag 3, not UInt64's 10.
            current = struct.unpack("<Q", machine.mem_read(rcx + 32, 8))[0]
            value = int(bytes(machine.mem_read(current, 1))[0] == rdx)
            if value:
                machine.mem_write(rcx + 32, struct.pack("<Q", current + 1))
        elif version_packet is not None and address == 0x1420F23C0:
            rsp = machine.reg_read(UC_X86_REG_RSP)
            output = struct.unpack("<Q", machine.mem_read(rsp + 40, 8))[0]
            length = struct.unpack("<I", machine.mem_read(rsp + 48, 4))[0]
            assert length == 1 and rdx >= 1 and r8 == 0
            machine.mem_write(output, bytes(machine.mem_read(rcx, 1)))
            machine.mem_write(r9, struct.pack("<I", 1))
            value = 1
        else:
            raise AssertionError(f"Unexpected boundary {address:x}")
        returned(machine, value)
    vm.hook_add(UC_HOOK_CODE, boundary)
    if version_packet is not None:
        wire_data = scratch + 0x1000
        vm.mem_write(wire_data, version_packet)
        vm.mem_write(document + 16, struct.pack("<I", wire_data))
        vm.mem_write(document + 24, struct.pack("<I", len(version_packet)))
        vm.mem_write(document + 32, struct.pack("<Q", wire_data))
        output = scratch + 0x2000
        vm.mem_write(output, b"\xff" * 8)
        accepted = invoke(version_reader, document, output) & 255
        return dict(accepted=accepted, output=bytes(vm.mem_read(output, 8)).hex(),
                    consumed=struct.unpack("<Q", vm.mem_read(document + 32, 8))[0] - wire_data,
                    modeled_boundaries=sorted(boundaries))
    snapshots = []
    operations = direct_updates if direct_updates is not None else events
    for operation in operations:
        if direct_updates is not None:
            item, amount, absolute = operation
            invoke(writer, state, 0, item, amount, absolute)
        else:
            contexts[document] = operation
            invoke(completion, 0, 0, document) if through_completion else invoke(reader, state, 0, document, 5)
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
for packet, accepted, consumed in ((b"\x03\x01", 1, 2),
                                   (b"\x0a\x01" + bytes(7), 0, 0)):
    result = execute(version_packet=packet)
    assert result["accepted"] == accepted and result["consumed"] == consumed
    assert result["output"] == ("01" + "ff" * 7 if accepted else "ff" * 8)
    cases.append(dict(case="original version reader accepts tag-3 byte and rejects tag-10 UInt64",
                      packet_hex=packet.hex(), **result))
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
event = dict(type="ACHIEVEMENT", name="marketplace_inventory", reason="completed",
             kind=18, **grant([(400063, 1), (1001124, 3)]))
result = execute(events=[grant([(400063, 1)])], through_completion=True)
assert result["snapshots"][0]["count"] == 0 and not result["writer_flags"]
cases.append(dict(case="original completion rejects a grant body with no kind", **result))
result = execute(events=[event, event], through_completion=True)
assert [s["rows"] for s in result["snapshots"]] == [[(400063, 1), (1001124, 3)]] * 2
assert result["writer_flags"] == [1] * 4
cases.append(dict(case="kind-18 original completion dispatcher reaches absolute loot grants without XP or weapon handlers", **result))
receipt = dict(schema=1, passed=True, generated_utc=datetime.now(timezone.utc).isoformat(),
               target_image_sha256=image_hash, tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               functions={hex(a): dict(size=f["size"], bytes_sha256=hashlib.sha256(f["code"]).hexdigest())
                          for a, f in functions.items()}, cases=cases,
               native_controller=0, native_cache_capacity=15000,
               envelope_gate=dict(address=hex(envelope), required_literals=sorted(envelope_literals),
                                  completion_target=hex(completion), method="original instruction/literal validation; not VM executed"),
               original_completion_dispatcher_executed=True,
               reward_version=dict(reader=hex(version_reader), consumer=hex(reward_message),
                                   tag=3, width_bytes=1, original_reader_executed=True,
                                   sqlite_name_is_not_wire_type_proof=True),
               parser_descriptor_count_offset=28, reward_quantity_semantics="absolute snapshot, flag 1",
               verified_trigger_types=["GRANT_PRODUCT", "GRANT_CURRENCY", "ACTIVATE_ACHIEVEMENT"],
               modeled_boundaries=["JSON field reads", "controller mapping", "diagnostics", "last-drops history", "Lua begin-event unavailable", "AAR manager summary"],
               original_reward_reader_executed=True, original_inventory_writer_executed=True,
               original_inventory_quantity_getter_executed=True,
               native_game_verified=False, backend_grants_implemented=False, game_runs_performed=False)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, default=ROOT / "validation/20261007-gunsmith-rewards-target.json")
args = parser.parse_args()
args.output.write_text(json.dumps(receipt, indent=2) + "\n", newline="\n")
print(f"PASS: {len(cases)} original reward/cache execution cases, no game runs")
