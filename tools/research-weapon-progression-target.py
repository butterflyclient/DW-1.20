"""Execute Replay's original absolute weapon-XP notification consumer."""

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
assets = json.loads((ROOT / "validation/20261007-weapon-progression-assets.json").read_bytes())
weapons = {row["id"]: row for row in assets["canonical_weapons"]}
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
consumer, cookie = 0x140F594D0, 0x1421CCF60
cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True
functions = {}
with sqlite3.connect(image.with_suffix(".exe.sqlite").as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address in (consumer, cookie, 0x140F57D10, 0x140F345C0):
        size = db.execute("select size from functions where address=?", (str(address),)).fetchone()[0]
        code = pe.get_data(address - base, size)
        instructions = list(cs.disasm(code, address))
        calls = {i.operands[0].imm for i in instructions
                 if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM}
        refs = {i.address + i.size + o.mem.disp for i in instructions for o in i.operands
                if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP}
        functions[address] = dict(size=size, code=code, calls=calls, references=refs)
assert functions[consumer]["size"] == 1999


def execute(updates, local=0, prefilled=0):
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
    for address in (consumer, cookie):
        f = functions[address]
        for offset in range(0, f["size"] + 4095, 4096):
            map_image(address + offset)
        for reference in f["references"] | f["calls"]:
            map_image(reference)
    scratch, stack, stop = 0x10000000, 0x11000000, 0x12000000
    vm.mem_map(scratch, 0x20000)
    vm.mem_map(stack, 0x10000)
    vm.mem_map(stop, 4096)
    state, document, table, buffer = scratch, scratch + 0x18000, scratch + 0x18100, scratch + 0x18200
    slots = state + 64 + 2056 * local
    count_address = slots + 2048
    vm.mem_write(count_address, struct.pack("<I", prefilled))
    for i in range(prefilled):
        vm.mem_write(slots + 32 * i + 8, struct.pack("<Q", 3000000 + i))
    contexts, calls = {}, set()
    def cstring(address):
        if base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
            map_image(address)
            map_image(address + 127)
        return bytes(vm.mem_read(address, 128)).split(b"\0", 1)[0].decode()
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
            source = contexts.get(rcx)
            value = source.get(cstring(rdx)) if isinstance(source, dict) else None
            result = int(isinstance(value, dict))
            if result:
                contexts[r8] = value
        elif address == 0x1420E5A60:
            source = contexts.get(rcx)
            value = source.get(cstring(rdx)) if isinstance(source, dict) else None
            result = int(type(value) is int and 0 <= value < 2**64)
            if result:
                machine.mem_write(r8, struct.pack("<Q", value))
        elif address == 0x1420E4440:
            # Generated weapon XP updates contain no unproven unlock triggers.
            assert cstring(rdx) == "triggers"
        elif address == 0x140D66C20:
            result = local  # External controller -> local-client mapping.
        elif address == 0x1413E2B00:
            assert cstring(rcx) == "loot/weapon_ids.csv"
            machine.mem_write(rdx, struct.pack("<Q", table))
        elif address == 0x1413F3010:
            assert cstring(rcx) == "%ld"
            machine.mem_write(buffer, str(rdx & 0xFFFFFFFF).encode() + b"\0")
            result = buffer
        elif address == 0x1413E2BA0:
            assert rcx == table and rdx == 0 and r9 == 1
            row = weapons[int(cstring(r8))]
            machine.mem_write(buffer + 128, row["ref"].encode() + b"\0")
            result = buffer + 128
        elif address in (0x1420E42B0, 0x1412B0820):
            pass
        else:
            raise AssertionError(f"Unexpected boundary {address:x}; UI/stat calls must stay absent")
        machine.reg_write(UC_X86_REG_RAX, result)
        rsp = machine.reg_read(UC_X86_REG_RSP)
        returned = struct.unpack("<Q", machine.mem_read(rsp, 8))[0]
        machine.reg_write(UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(UC_X86_REG_RIP, returned)
    vm.hook_add(UC_HOOK_CODE, boundary)
    results = []
    for update in updates:
        contexts[document] = update
        rsp = stack + 0xFFC8
        vm.mem_write(rsp, struct.pack("<Q", stop))
        vm.mem_write(rsp + 40, bytes(8))  # Fifth parameter: rank-up flag false.
        for reg, value in ((UC_X86_REG_RSP, rsp), (UC_X86_REG_RCX, state),
                           (UC_X86_REG_RDX, 0), (UC_X86_REG_R8, document), (UC_X86_REG_R9, 5)):
            vm.reg_write(reg, value)
        vm.emu_start(consumer, stop, count=30000)
        assert vm.reg_read(UC_X86_REG_RIP) == stop
        count = struct.unpack("<I", vm.mem_read(count_address, 4))[0]
        rows = [struct.unpack("<QQQ", vm.mem_read(slots + 32 * i + 8, 24))
                for i in range(count)]
        results.append(dict(accepted=bool(vm.reg_read(UC_X86_REG_RAX) & 0xFF), count=count, rows=rows))
    return dict(results=results, original_consumer_executed=True, boundary_calls=sorted(calls))


def event(weapon, xp, rank):
    return dict(id_=2000000 + weapon, multiProgress=dict(xp=dict(value=xp), rank=dict(value=rank)))


cases = []
for local in (0, 1):
    for weapon in (1, 15, 626):
        rank = min(2, weapons[weapon]["maximum_rank"])
        r = execute([event(weapon, 1000, rank)] * 2 + [event(weapon, 1500, rank)], local)
        assert [v["count"] for v in r["results"]] == [1, 1, 1]
        assert [v["rows"][0] for v in r["results"]] == [
            (2000000 + weapon, 1000, rank)] * 2 + [(2000000 + weapon, 1500, rank)]
        cases.append(dict(case="absolute insert/retry/update", local_client=local, weapon=weapon, **r))
for xp in (0, 2**31 + 99, 2**32 - 1):
    r = execute([event(15, xp, 70)])
    assert r["results"][0]["rows"] == [(2000015, xp, 70)]
    cases.append(dict(case="UInt32 profile transport boundary", xp=xp, **r))
r = execute([event(15, 1000, 2)], prefilled=64)
assert r["results"][0]["count"] == 64 and all(v[0] >= 3000000 for v in r["results"][0]["rows"])
cases.append(dict(case="native 64-row insertion bound", **r))
output = dict(schema=1, passed=True, generated_utc=datetime.now(timezone.utc).isoformat(),
    target_image_sha256=digest, consumer=consumer, cases=cases,
    functions={hex(a): dict(size=f["size"], bytes_sha256=hashlib.sha256(f["code"]).hexdigest())
               for a, f in functions.items()},
    asset_receipt_sha256=hashlib.sha256((ROOT / "validation/20261007-weapon-progression-assets.json").read_bytes()).hexdigest(),
    modeled_boundaries="JSON operations, diagnostics, controller mapping and retained loot StringTable lookup; original consumer/record writes/count limits/cookie check execute unchanged",
    native_game_verified=False, full_backend_complete=False)
(ROOT / "validation/20261007-weapon-progression-target.json").write_text(json.dumps(output, indent=2) + "\n")
print(f"PASS: {len(cases)} original weapon progression consumer cases")
