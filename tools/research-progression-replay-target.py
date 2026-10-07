"""Execute Replay's absolute progression consumer with retry-safe notifications."""

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
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP,
)

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
consumer, cookie = 0x141060490, 0x1421CCF60
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
with sqlite3.connect(image.with_suffix(".exe.sqlite").as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    functions = {}
    for address in (consumer, cookie):
        size = db.execute("select size from functions where address=?", (str(address),)).fetchone()[0]
        code = pe.get_data(address - base, size)
        instructions = list(decoder.disasm(code, address))
        calls = {i.operands[0].imm for i in instructions
                 if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM}
        references = {i.address + i.size + o.mem.disp for i in instructions
                      for o in i.operands if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP}
        functions[address] = dict(size=size, code=code, calls=calls, references=references)
assert functions[consumer]["size"] == 1552


def execute(updates, controller=0, initial=(17, 0)):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped = set()
    def map_image(address):
        page = address & ~4095
        if page in mapped:
            return
        vm.mem_map(page, 4096)
        mapped.add(page)
        if base <= page < base + pe.OPTIONAL_HEADER.SizeOfImage:
            vm.mem_write(page, pe.get_data(page - base, 4096))
    for address, f in functions.items():
        for offset in range(0, f["size"] + 4095, 4096):
            map_image(address + offset)
        for reference in f["references"] | f["calls"]:
            map_image(reference)
    scratch, stack, stop = 0x10000000, 0x11000000, 0x12000000
    vm.mem_map(scratch, 0x10000)
    vm.mem_map(stack, 0x10000)
    vm.mem_map(stop, 4096)
    state, document = scratch, scratch + 0x8000
    slot = state + 64 + 16 * controller
    vm.mem_write(state + 64, bytes([0xA5]) * 128)
    vm.mem_write(slot, struct.pack("<QQ", *initial))
    contexts, calls = {}, set()
    def cstring(address):
        assert base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage
        map_image(address)
        map_image(address + 127)
        return bytes(vm.mem_read(address, 128)).split(b"\0", 1)[0].decode("ascii")
    def boundary(machine, address, size, user):
        if address not in functions[consumer]["calls"] or address == cookie:
            return
        rcx, rdx, r8, r9 = [machine.reg_read(reg) for reg in
                            (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
        result = 0
        calls.add(address)
        if address == 0x1420E4290:
            contexts[rcx] = None
            machine.mem_write(rcx, bytes(32))
        elif address == 0x1420E52F0:
            value = contexts.get(rcx)
            field = value.get(cstring(rdx)) if isinstance(value, dict) else None
            result = int(isinstance(field, dict))
            if result:
                contexts[r8] = field
        elif address == 0x1420E5A60:
            value = contexts.get(rcx)
            field = value.get(cstring(rdx)) if isinstance(value, dict) else None
            result = int(type(field) is int and 0 <= field < 2**64)
            if result:
                machine.mem_write(r8, struct.pack("<Q", field))
        elif address in (0x1420E42B0, 0x1412B0820):
            pass  # JSON destruction and diagnostic output only.
        else:
            raise AssertionError(f"Unexpected consumer boundary {address:x}; UI/stat calls are forbidden")
        machine.reg_write(UC_X86_REG_RAX, result)
        rsp = machine.reg_read(UC_X86_REG_RSP)
        returned = struct.unpack("<Q", machine.mem_read(rsp, 8))[0]
        machine.reg_write(UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(UC_X86_REG_RIP, returned)
    vm.hook_add(UC_HOOK_CODE, boundary)
    outcomes = []
    for update in updates:
        contexts[document] = update
        rsp = stack + 0xFFC8
        vm.mem_write(rsp, struct.pack("<Q", stop))
        for register, value in ((UC_X86_REG_RSP, rsp), (UC_X86_REG_RCX, state),
                                (UC_X86_REG_RDX, controller), (UC_X86_REG_R8, document),
                                (UC_X86_REG_R9, 0)):
            vm.reg_write(register, value)
        vm.emu_start(consumer, stop, count=20000)
        assert vm.reg_read(UC_X86_REG_RIP) == stop
        outcomes.append(dict(accepted=bool(vm.reg_read(UC_X86_REG_RAX) & 0xFF),
                             xp=struct.unpack("<Q", vm.mem_read(slot, 8))[0],
                             rank=struct.unpack("<Q", vm.mem_read(slot + 8, 8))[0]))
    untouched = bytes(vm.mem_read(state + 64, 16 * controller))
    untouched += bytes(vm.mem_read(slot + 16, 16 * (7 - controller)))
    assert untouched == bytes([0xA5]) * (7 * 16)
    return dict(outcomes=outcomes, boundary_calls=sorted(calls),
                original_consumer_executed=True, rank_up_flag=False,
                other_controllers_unchanged=True, ui_or_stats_calls=0)


def snapshot(xp, rank):
    return dict(id_=1000000, multiProgress=dict(xp=dict(value=xp), rank=dict(value=rank)))


cases = []
for controller in (0, 2, 7):
    result = execute([snapshot(3500, 1)] * 3 + [snapshot(17500, 4)], controller)
    assert result["outcomes"] == [dict(accepted=True, xp=3500, rank=1)] * 3 + [
        dict(accepted=True, xp=17500, rank=4)]
    cases.append(dict(case="repeated absolute snapshots", controller=controller, **result))
for xp in (0, 2**31 + 1500, 2**64 - 1):
    result = execute([snapshot(xp, 54)] * 2)
    assert result["outcomes"] == [dict(accepted=True, xp=xp, rank=54)] * 2
    cases.append(dict(case="unsigned absolute XP boundary", xp=xp, **result))
for update in ({}, {"id_": 1000000}, {"id_": "1000000"}):
    result = execute([update])
    assert result["outcomes"] == [dict(accepted=False, xp=17, rank=0)]
    cases.append(dict(case="missing/invalid player progression", **result))
output = dict(
    schema=1, passed=True, generated_utc=datetime.now(timezone.utc).isoformat(),
    audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    target_image_sha256=digest, consumer=consumer,
    functions={hex(a): dict(size=f["size"], bytes_sha256=hashlib.sha256(f["code"]).hexdigest(),
                             direct_calls=sorted(f["calls"])) for a, f in functions.items()},
    cases=cases, sqlite_access="read-only/query-only",
    modeled_boundaries="JSON constructor/object/UInt64 access/destructor and diagnostics; original consumer control flow, state stores and cookie check execute unchanged",
    native_game_callback_verified=False, full_backend_complete=False,
)
(ROOT / "validation/20261007-progression-replay-target.json").write_text(
    json.dumps(output, indent=2) + "\n")
print(f"PASS: {len(cases)} original progression-consumer cases; retries assign absolute XP with no rank-up UI")
