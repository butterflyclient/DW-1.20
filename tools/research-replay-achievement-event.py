"""Execute Replay's original achievement event construction and key capacity.

This uses original instructions and original vtables. It does not send an event,
model a backend allocation, or claim native gameplay callback completion.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_RSP, UC_X86_REG_RIP,
)

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
CONSTRUCT, APPEND, RESET, STAMP, NAME = 0x142102F90, 0x1421031D0, 0x1421033F0, 0x142103710, 0x1421036C0
LOBBY = 0x141042510


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.is_relative_to(ROOT)
    raw = IMAGE.read_bytes()
    image_hash = hashlib.sha256(raw).hexdigest()
    assert image_hash == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    pe = pefile.PE(data=raw, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    arena, stack, halt = 0x60000000, 0x70000000, 0x71000000
    for address, size in ((arena, 0x10000), (stack, 0x10000), (halt, 4096)):
        vm.mem_map(address, size)
    pages = set()
    executed = set()

    def missing(machine, access, address, size, value, context):
        assert base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage, (
            hex(address), hex(machine.reg_read(UC_X86_REG_RIP)))
        for page in (address & ~4095, (address + size - 1) & ~4095):
            if page not in pages:
                machine.mem_map(page, 4096)
                content = pe.get_data(page - base, 4096)
                if content:
                    machine.mem_write(page, content)
                pages.add(page)
        return True

    def observe(machine, address, size, context):
        executed.add(address)
        if address == halt:
            machine.emu_stop()

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    vm.hook_add(UC_HOOK_CODE, observe)
    event = arena + 0x1000
    before, after = event - 32, event + 800
    vm.mem_write(before, b"\xA5" * 32)
    vm.mem_write(after, b"\x5A" * 32)

    def call(address, rcx, rdx=0, r8=0):
        rsp = stack + 0xF008
        vm.mem_write(rsp, struct.pack("<Q", halt))
        for register, value in ((UC_X86_REG_RSP, rsp), (UC_X86_REG_RCX, rcx),
                                (UC_X86_REG_RDX, rdx), (UC_X86_REG_R8, r8)):
            vm.reg_write(register, value)
        vm.emu_start(address, 0, count=100000)
        assert vm.reg_read(UC_X86_REG_RIP) == halt
        assert bytes(vm.mem_read(before, 32)) == b"\xA5" * 32
        assert bytes(vm.mem_read(after, 32)) == b"\x5A" * 32
        return vm.reg_read(UC_X86_REG_RAX)

    def number(offset, size=8):
        return int.from_bytes(vm.mem_read(event + offset, size), "little")

    def pairs():
        count = number(776, 4)
        assert count <= 10
        result = []
        for index in range(count):
            pointer = event + 136 + index * 64
            key = bytes(vm.mem_read(pointer + 16, 21)).split(b"\0", 1)[0].decode()
            value = int.from_bytes(vm.mem_read(pointer + 40, 8), "little")
            result.append(dict(key=key, value=value))
        return result

    assert call(CONSTRUCT, event, 1) == event
    assert number(16) == number(128) == number(776, 4) == 0
    assert bytes(vm.mem_read(event + 24, 1)) == b"\0"
    cases = [dict(name="original-construction", passed=True, pairs=pairs())]
    for index in range(11):
        name = "Param" + str(index)
        vm.mem_write(arena, name.encode() + b"\0")
        assert call(APPEND, event, arena, index + 100) == event
        observed = pairs()
        assert len(observed) == min(index + 1, 10)
        assert observed == [dict(key="Param" + str(i), value=i + 100)
                            for i in range(min(index + 1, 10))]
        cases.append(dict(name="append-" + str(index + 1), passed=True, pairs=observed))
    snapshot = bytes(vm.mem_read(event, 800))
    call(STAMP, event, 0x123456789ABCDEF0)
    stamped = bytes(vm.mem_read(event, 800))
    assert stamped[:128] == snapshot[:128] and stamped[136:] == snapshot[136:]
    assert number(128) == 0x123456789ABCDEF0
    cases.append(dict(name="timestamp-isolated-store", passed=True))
    call(RESET, event)
    assert number(16) == number(128) == number(776, 4) == 0
    assert bytes(vm.mem_read(event + 24, 1)) == b"\0"
    cases.append(dict(name="reset-clears-active-fields", passed=True, pairs=pairs()))
    for key, value in (("version", 1), ("gamemode", 2), ("Param0", 99), ("Param0", 100)):
        vm.mem_write(arena, key.encode() + b"\0")
        call(APPEND, event, arena, value)
    assert pairs() == [dict(key=k, value=v) for k, v in
                       (("version", 1), ("gamemode", 2), ("Param0", 99), ("Param0", 100))]
    cases.append(dict(name="duplicate-key-is-appended-not-replaced", passed=True, pairs=pairs()))
    for length in (1, 100, 130):
        content = "n" * length
        vm.mem_write(arena, content.encode() + b"\0")
        call(NAME, event, arena)
        assert bytes(vm.mem_read(event + 24, 101)).split(b"\0", 1)[0] == content[:100].encode()
        assert number(128) == 0 and len(pairs()) == 4
        cases.append(dict(name="name-capacity-" + str(length), passed=True, retained_length=min(length, 100)))
    call(RESET, event)
    for length in (20, 25):
        content = "k" * length
        vm.mem_write(arena, content.encode() + b"\0")
        call(APPEND, event, arena, length)
        assert pairs()[-1] == dict(key=content[:20], value=length)
        cases.append(dict(name="key-capacity-" + str(length), passed=True, pairs=pairs()))
    manager = 0x72000000
    vm.mem_map(manager, 0x20000)
    for value in (0, 0x123456789ABCDEF0, 0xFEDCBA9876543210):
        vm.mem_write(manager + 0x13728, struct.pack("<Q", value))
        assert call(LOBBY, manager) == value
        cases.append(dict(name="native-lobby-getter-" + str(value), passed=True, value=value))
    methods = [(CONSTRUCT, 204), (APPEND, 335), (RESET, 31), (STAMP, 8), (NAME, 74), (LOBBY, 8)]
    proof = dict(passed=True, target_image_sha256=image_hash,
                 tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 methods=[dict(address=a, size=s, sha256=hashlib.sha256(pe.get_data(a - base, s)).hexdigest())
                          for a, s in methods],
                 layout=dict(event_size=800, numeric_name=16, string_name=24, string_capacity=101,
                             timestamp=128, pairs=136, pair_stride=64, pair_key=16,
                             pair_key_capacity=21, pair_value=40, pair_capacity=10, pair_count=776,
                             virtual_referencable=784, reference_count=792),
                 cases=cases, executed_original_instructions=len(executed), modeled_boundaries=[],
                 lobby_getter=dict(instance_offset=0x13728, width=8, transition_lifetime_verified=False),
                 cache_lifetime_verified=False, allocation_ownership_verified=False,
                 game_runs_performed=False, native_runtime_verified=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(proof, indent=2) + "\n")
    print("PASS:", len(cases), "original event construction/capacity cases; no modeled callees")


if __name__ == "__main__":
    main()
