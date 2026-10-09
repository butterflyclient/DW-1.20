"""Verify Replay's cached player/weapon/Battle Pass XP event fields from original code."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn import x86_const as reg

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
assert (
    sha256(raw).hexdigest()
    == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
)
pe = pefile.PE(data=raw, fast_load=True)
base, entry = pe.OPTIONAL_HEADER.ImageBase, 0x140F345C0
database = image.with_suffix(".exe.sqlite")
before = database.stat()
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
    connection.execute("pragma query_only=on")
    size = connection.execute(
        "select size from functions where address=?", (str(entry),)
    ).fetchone()[0]
code = pe.get_data(entry - base, size)
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
calls = {
    i.operands[0].imm
    for i in decoder.disasm(code, entry)
    if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
}
assert size == 1361 and {0x1421031D0, 0x140F766D0, 0x140F3A2B0} <= calls


def execute(player_xp, battlepass_xp, weapons):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, manager, halt = 0x10000000, 0x11000000, 0x12000000
    vm.mem_map(stack, 0x20000)
    vm.mem_map(manager, 0x20000)
    vm.mem_map(halt, 4096)
    pages = set()

    def page(address):
        current = address & ~4095
        if current not in pages:
            assert base <= current < base + pe.OPTIONAL_HEADER.SizeOfImage
            vm.mem_map(current, 4096)
            content = pe.get_data(current - base, 4096)
            if content:
                vm.mem_write(current, content)
            pages.add(current)

    def missing(machine, access, address, length, value, context):
        page(address)
        page(address + length - 1)
        return True

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    cache = manager + 0xDC20

    def put32(address, value):
        vm.mem_write(address, struct.pack("<I", value))

    def secure(address, value):
        # Replay has a 16-byte secure integer, unlike the oracle's 24-byte
        # variant. The original XOR/multiply reader executes, not a mock getter.
        key = 0xA537126C
        put32(address + 8, key)
        for offset in (0, 4):
            mixed = ((address + offset) & 0xFFFFFFFF) ^ key
            mask = mixed * (mixed + 2) & 0xFFFFFFFF
            put32(address + offset, (value >> (offset * 8)) & 0xFFFFFFFF ^ mask)

    put32(manager + 0x1CE20, 1)
    vm.mem_write(cache, b"\x01")
    put32(cache + 152, 6)
    secure(cache + 160, player_xp)
    secure(cache + 176, battlepass_xp)
    put32(cache + 960, len(weapons))
    for index, (identity, xp) in enumerate(weapons):
        put32(cache + 192 + index * 24, identity)
        secure(cache + 200 + index * 24, xp)
    active, emitted = {}, []

    def returned(machine, value=0):
        sp = machine.reg_read(reg.UC_X86_REG_RSP)
        destination = struct.unpack("<Q", machine.mem_read(sp, 8))[0]
        machine.reg_write(reg.UC_X86_REG_RAX, value)
        machine.reg_write(reg.UC_X86_REG_RSP, sp + 8)
        machine.reg_write(reg.UC_X86_REG_RIP, destination)

    def cstring(address):
        for current in (address, address + 99):
            if base <= current < base + pe.OPTIONAL_HEADER.SizeOfImage:
                page(current)
        return bytes(vm.mem_read(address, 100)).split(b"\0", 1)[0].decode()

    def boundary(machine, address, length, context):
        if address not in calls or address == 0x1421CCF60:
            return
        rcx, rdx, r8 = [
            machine.reg_read(r)
            for r in (reg.UC_X86_REG_RCX, reg.UC_X86_REG_RDX, reg.UC_X86_REG_R8)
        ]
        value = 0
        if address == 0x1421033F0:
            active.clear()
        elif address == 0x1421036C0:
            assert cstring(rdx) == "mp_addxp"
        elif address == 0x1421031D0:
            active[cstring(rdx)] = r8
        elif address == 0x140F766D0:
            assert rdx == cache + 8 and r8 == cache + 80
            assert machine.reg_read(reg.UC_X86_REG_R9) == 6
            emitted.append(active.copy())
        elif address == 0x1410C86E0:
            value = 2
        elif address in (0x140E89820, 0x140F6B490, 0x140F6B120):
            value = manager
        returned(machine, value)

    vm.hook_add(UC_HOOK_CODE, boundary)
    sp = stack + 0x1F008
    vm.mem_write(sp, struct.pack("<Q", halt))
    vm.reg_write(reg.UC_X86_REG_RSP, sp)
    vm.reg_write(reg.UC_X86_REG_RCX, manager)
    vm.emu_start(entry, halt, count=10000)
    assert vm.reg_read(reg.UC_X86_REG_RIP) == halt
    assert struct.unpack("<I", vm.mem_read(manager + 0x1CE20, 4))[0] == 0
    assert len(emitted) == max(1, len(weapons))
    for index, row in enumerate(emitted):
        assert row["Param0"] == (0 if index else player_xp)
        assert row["Param4"] == (0 if index else battlepass_xp)
        assert row["Param2"] == (weapons[index][0] if weapons else 0)
        assert row["Param3"] == (weapons[index][1] if weapons else 0)
    return dict(
        player_xp=player_xp,
        battlepass_xp=battlepass_xp,
        weapons=weapons,
        emitted=emitted,
        passed=True,
    )


cases = [
    execute(500, 37, []),
    execute(500, 37, [(18, 11), (8, 13)]),
    execute(0, (1 << 32) + 7, []),
]
after = database.stat()
assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
proof = dict(
    schema=1,
    passed=True,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    target_image_sha256=sha256(raw).hexdigest(),
    tool_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
    producer=dict(va=entry, size=size, bytes_sha256=sha256(code).hexdigest()),
    target_cache_layout=dict(
        manager_offset=0xDC20,
        record_stride=968,
        game_mode=0,
        account=8,
        first_party_account=80,
        platform=152,
        player_xp=160,
        battlepass_xp=176,
        secure_integer_size=16,
        weapons=192,
        weapon_stride=24,
        weapon_capacity=32,
        weapon_count=960,
    ),
    cases=cases,
    original_producer_executed=True,
    scope="Original cache reads, secure integer decode, event selection and first-weapon gating. SDK setters/report calls, game context and cleanup are modeled boundaries; native game callback completion is not claimed.",
)
(ROOT / "validation/20261009-battlepass-earned-xp-target.json").write_text(
    json.dumps(proof, indent=2) + "\n"
)
print(
    "PASS: original producer emits independent 64-bit Battle Pass XP in Param4 once per player cache entry"
)
