"""Verify original Replay's stat-write IDs and namespaced UI read IDs in x64."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
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
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
functions = {}
for va, size in ((0x1419B43C0, 270), (0x1419B4AF0, 434), (0x1419B5690, 1241)):
    code = pe.get_data(va - base, size)
    functions[hex(va)] = {"size": size, "sha256": hashlib.sha256(code).hexdigest(),
                         "instructions": [(i.mnemonic, i.op_str) for i in decoder.disasm(code, va)]}
assert ("mov", "edx, 0x249f0") in functions["0x1419b43c0"]["instructions"]
assert ("mov", "ecx, 0x222e0") in functions["0x1419b43c0"]["instructions"]
assert ("cmovne", "edx, ecx") in functions["0x1419b43c0"]["instructions"]
assert ("add", "edx, dword ptr [rcx + 8]") in functions["0x1419b43c0"]["instructions"]
assert ("mov", "ecx, dword ptr [r14 + 8]") in functions["0x1419b4af0"]["instructions"]
assert ("mov", "dword ptr [rdi + 0x20], ecx") in functions["0x1419b4af0"]["instructions"]


def case(board, platform_view=None):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, records, halt = 0x10000000, 0x11000000, 0x12000000
    vm.mem_map(stack, 0x10000)
    vm.mem_map(records, 0x20000)
    vm.mem_map(halt, 4096)
    pages = set()

    def original_page(address):
        page = address & ~4095
        if page not in pages:
            assert base <= page < base + pe.OPTIONAL_HEADER.SizeOfImage
            vm.mem_map(page, 4096)
            data = pe.get_data(page - base, 4096)
            if data:
                vm.mem_write(page, data)
            pages.add(page)

    def missing(machine, access, address, size, value, _):
        original_page(address)
        original_page(address + size - 1)
        return True

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    put32 = lambda address, value: vm.mem_write(address, struct.pack("<I", value))
    put64 = lambda address, value: vm.mem_write(address, struct.pack("<Q", value))
    get64 = lambda address: struct.unpack("<Q", vm.mem_read(address, 8))[0]
    asset, viewer, slot, dvar, row = (records + n for n in (0, 4096, 0xD000, 0xE000, 0xF000))
    put32(asset + 8, board)
    put32(asset + 20, 0)  # The ID proof does not invent player stat getter values.
    put64(stack + 0xF008, halt)
    vm.reg_write(UC_X86_REG_RSP, stack + 0xF008)
    captured, boundaries = [], []

    def returned(machine, value):
        sp = machine.reg_read(UC_X86_REG_RSP)
        machine.reg_write(UC_X86_REG_RAX, value)
        machine.reg_write(UC_X86_REG_RSP, sp + 8)
        machine.reg_write(UC_X86_REG_RIP, get64(sp))

    def boundary(machine, address, size, _):
        if address == halt:
            machine.emu_stop()
        elif address == 0x141505120:
            captured.append(machine.reg_read(UC_X86_REG_RDX) & 0xFFFFFFFF)
            machine.emu_stop()  # Stop before creating a remote task.
        elif address in (0x140D66C50, 0x141528490, 0x1412AA020,
                         0x1412AA890, 0x1419B5070):
            boundaries.append(hex(address))
            returned(machine, {0x140D66C50: 0, 0x141528490: 1,
                               0x1412AA020: slot, 0x1412AA890: 0,
                               0x1419B5070: 0}[address])

    vm.hook_add(UC_HOOK_CODE, boundary)
    if platform_view is None:
        # Original row producer: RCX controller, RDX asset, R8 destination,
        # R9 stats group and fifth argument owner on the native stack.
        vm.reg_write(UC_X86_REG_RCX, 0)
        vm.reg_write(UC_X86_REG_RDX, asset)
        vm.reg_write(UC_X86_REG_R8, row)
        vm.reg_write(UC_X86_REG_R9, 0)
        put64(stack + 0xF008 + 40, 123)
        vm.emu_start(0x1419B4AF0, halt, count=2000)
        actual = struct.unpack("<I", vm.mem_read(row + 32, 4))[0]
        assert actual == board and vm.reg_read(UC_X86_REG_RIP) == halt
        return {"base_board": board, "native_write_board": actual,
                "passed": True, "modeled_boundaries": [], "columns_populated": False}
    original_page(0x151868140)
    original_page(0x15185D9A8)
    put64(0x151868140, asset)
    vm.mem_write(0x15186815C, bytes([int(platform_view)]))
    put64(0x15185D9A8, dvar)
    put32(dvar + 40, 20)
    put64(viewer + 41832, asset)
    vm.reg_write(UC_X86_REG_RCX, viewer)
    vm.reg_write(UC_X86_REG_RDX, 0)
    vm.reg_write(UC_X86_REG_R8, 1)
    vm.emu_start(0x1419B43C0, halt, count=2000)
    expected = board + (140000 if platform_view else 150000)
    assert captured == [expected]
    return {"base_board": board, "platform_view": platform_view,
            "native_read_board": captured[0], "passed": True,
            "modeled_boundaries": boundaries,
            "remote_task_created": False}


cases = [case(board, view) for board in (0, 1003, 1603) for view in (None, False, True)]
result = {"schema": 1, "generated_utc": datetime.now(timezone.utc).isoformat(),
          "target_image_sha256": image_hash,
          "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "functions": functions, "cases": cases,
          "scope": "Original write-ID production and UI namespace addition. Local backend alias publication is an implementation choice; retail server internals and virtual score aggregation are not proven.",
          "game_runs_performed": False, "native_runtime_verified": False}
destination = ROOT / "validation/20261007-replay-leaderboard-namespaces.json"
destination.write_text(json.dumps(result, indent=2) + "\n")
print("PASS: three original write IDs and six original UI namespace selections")
