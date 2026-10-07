"""Check generated progression envelopes at Replay's original JSON dispatcher."""

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
entry = 0x140F33650
cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True
functions = {}
with sqlite3.connect(IMAGE.with_suffix(".exe.sqlite").as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address in (entry, 0x1420E4250, 0x14107E890, 0x142103DC0, 0x1421CCF60):
        size = db.execute("select size from functions where address=?", (str(address),)).fetchone()[0]
        code = pe.get_data(address - base, size)
        functions[address] = dict(size=size, code=code)
assert functions[entry]["size"] == 944
assert pe.get_data(0x23F3258, 32).split(b"\0", 1)[0] == b"ACHIEVEMENT"
parse_calls = [i.operands[0].imm for i in cs.disasm(functions[0x1420E4250]["code"], 0x1420E4250)
               if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM]
assert len(parse_calls) == 1
parse = parse_calls[0]
calls = {i.operands[0].imm for a, f in functions.items() for i in cs.disasm(f["code"], a)
         if i.mnemonic in ("call", "jmp") and i.operands[0].type == X86_OP_IMM}


def execute(event):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped = set()
    stack, scratch, halt = 0x10000000, 0x11000000, 0x12000000
    for address, size in ((stack, 0x20000), (scratch, 0x10000), (halt, 4096)):
        vm.mem_map(address, size)
    def page(address):
        location = address & ~4095
        if location in mapped:
            return
        assert base <= location < base + pe.OPTIONAL_HEADER.SizeOfImage
        vm.mem_map(location, 4096)
        data = pe.get_data(location - base, 4096)
        if data:
            vm.mem_write(location, data)
        mapped.add(location)
    def missing(machine, access, address, size, value, context):
        page(address)
        page(address + size - 1)
        return True
    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    manager, account, reward, message = scratch, scratch + 0x1000, scratch + 0x2000, scratch + 0x3000
    owner = 42
    vm.mem_write(account + 48, struct.pack("<Q", owner))
    vm.mem_write(message, json.dumps(event, separators=(",", ":")).encode() + b"\0")
    contexts, dispatches, diagnostics, boundaries = {}, [], [], set()
    def cstring(address):
        out = bytearray()
        for offset in range(1024):
            if base <= address + offset < base + pe.OPTIONAL_HEADER.SizeOfImage:
                page(address + offset)
            byte = bytes(vm.mem_read(address + offset, 1))
            if byte == b"\0":
                return out.decode()
            out += byte
        raise AssertionError("Unterminated dispatcher key/message")
    def returned(machine, value=0):
        rsp = machine.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", machine.mem_read(rsp, 8))[0]
        machine.reg_write(UC_X86_REG_RAX, value)
        machine.reg_write(UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(UC_X86_REG_RIP, target)
    def boundary(machine, address, size, context):
        if address not in calls or any(a <= address < a + f["size"] for a, f in functions.items()):
            return
        rcx, rdx, r8, r9 = [machine.reg_read(register) for register in
                            (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
        boundaries.add(address)
        value = 0
        if address == 0x1420ED9E0:
            assert rcx == reward + 40
            value = message # External bdString access; original reward getter runs.
        elif address == parse:
            contexts[rdx] = json.loads(cstring(rcx))
            value = 1 # Original JSON constructor writes its valid flag itself.
        elif address == 0x1420E5480:
            source = contexts.get(rcx)
            child = source.get(cstring(rdx)) if isinstance(source, dict) else None
            value = int(isinstance(child, str) and len(child.encode()) < r9)
            if value:
                machine.mem_write(r8, child.encode() + b"\0")
        elif address == 0x1421F6CC0:
            machine.mem_write(rcx, bytes([rdx & 255])*r8)
            value = rcx
        elif address in (0x140F34CA0, 0x140F34F40):
            assert rcx == manager and rdx == owner
            dispatches.append(dict(handler="completion" if address == 0x140F34CA0 else "update",
                                   owner=rdx, event=contexts[r8]))
            value = 1 # Record the native handler boundary, not a game callback claim.
        elif address == 0x1412B0570:
            diagnostics.append(cstring(rdx))
        elif address in (0x1412B0820, 0x1420E42B0, 0x1420F64A0, 0x1420EBB50):
            pass # Diagnostics and external JSON/account-context retirement.
        else:
            raise AssertionError(f"Unexpected dispatcher boundary {address:x}")
        returned(machine, value)
    vm.hook_add(UC_HOOK_CODE, boundary)
    rsp = stack + 0x1FF88
    vm.mem_write(rsp, struct.pack("<Q", halt))
    for register, value in ((UC_X86_REG_RSP, rsp), (UC_X86_REG_RCX, manager),
                            (UC_X86_REG_RDX, account), (UC_X86_REG_R8, 0), (UC_X86_REG_R9, reward)):
        vm.reg_write(register, value)
    vm.emu_start(entry, halt, count=200000)
    assert vm.reg_read(UC_X86_REG_RIP) == halt
    return dict(dispatches=dispatches, diagnostics=diagnostics, boundaries=sorted(boundaries))


cases = []
for kind, identity, name in ((0, 1000000, "player_xp"), (5, 2000001, "iw8_pi_golf21")):
    for reason, handler in (("inProgress", "update"), ("completed", "completion")):
        event = dict(type="ACHIEVEMENT", name=name, reason=reason, kind=kind, id_=identity,
                     multiProgress=dict(xp=dict(value=750), rank=dict(value=1)))
        result = execute(event)
        assert result["dispatches"] == [dict(handler=handler, owner=42, event=event)] and not result["diagnostics"]
        cases.append(dict(case="corrected generated progression envelope", kind=kind, reason=reason, **result))
for alteration, expected in ((dict(type="achievement"), "bad type"),
                              (dict(name=None), "bad name"),
                              (dict(reason=None), "missing reason"),
                              (dict(reason="IN_PROGRESS"), "missing reason")):
    event = dict(type="ACHIEVEMENT", name="player_xp", reason="inProgress")
    event.update(alteration)
    result = execute(event)
    assert not result["dispatches"] and any(expected in line for line in result["diagnostics"])
    cases.append(dict(case="native rejection control", alteration=alteration, **result))
receipt = dict(schema=1, passed=True, generated_utc=datetime.now(timezone.utc).isoformat(),
               target_image_sha256=image_hash, tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               functions={hex(a): dict(size=f["size"], bytes_sha256=hashlib.sha256(f["code"]).hexdigest())
                          for a, f in functions.items()}, cases=cases,
               confirmed_previous_notification_rejected=True, required_type="ACHIEVEMENT",
               original_dispatcher_executed=True,
               modeled_boundaries=["bdString access", "JSON parse/field access", "memset", "diagnostics", "handler entry", "account/JSON retirement"],
               native_game_verified=False, game_runs_performed=False)
(ROOT / "validation/20261007-achievement-dispatch-target.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(f"PASS: {len(cases)} original achievement dispatcher cases; lowercase baseline rejected")
