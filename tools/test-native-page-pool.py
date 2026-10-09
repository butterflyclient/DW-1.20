"""Execute original Replay and production COFF/linked page initialization.

Only Windows allocation/status, memset, logging and the fatal boundary are
modeled. The real machine instructions construct every native free-tree bit.
"""

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import sys

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
)

sys.path.insert(0, "E:/replay-compiler/tools")
from coff import read as read_coff

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--object", type=Path, required=True)
parser.add_argument("--build", type=Path)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
original = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
catalog = json.loads(
    Path("E:/replay-compiler/generated/function-catalog.json").read_text()
)
assert hashlib.sha256(original.read_bytes()).hexdigest() == catalog["image_sha256"]
native = json.loads(
    Path("E:/replay-compiler/generated/native-symbols.json").read_text()
)
original_pe = pefile.PE(str(original), fast_load=True)
obj = read_coff(args.object)
base = original_pe.OPTIONAL_HEADER.ImageBase
report = linked_pe = None
if args.build:
    report = json.loads((args.build / "build-report.json").read_text())
    image = args.build / report["executable"]
    with image.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == report["sha256"]
    assert report["unresolved_symbols"] == 0
    linked_pe = pefile.PE(str(image), fast_load=True)
    ranges = report["rva_map"]["ranges"]
    starts = [r["begin"] for r in ranges]


def run(edited, total, available, failed_alloc=0, failed_status=False):
    pe = linked_pe if edited and linked_pe else original_pe
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped = set()
    arena, table = 0x40000000, 0x50000000
    vm.mem_map(arena, 0x20000)
    vm.mem_map(table, 0x400000)
    stack, stop = arena + 0x1D008, arena + 0x1F000

    def location(rva):
        if not (edited and report):
            return base + rva
        row = ranges[bisect.bisect_right(starts, rva) - 1]
        assert row["begin"] <= rva < row["end"]
        return base + row["mapped_begin"] + rva - row["begin"]

    def symbol(name):
        if edited and report and name in report["symbols"]:
            return base + report["symbols"][name]
        if name.startswith(("gl_", "func_")):
            return location(int(name.split("_")[1], 16) - base)
        return location(native[name])

    def page(address):
        address &= ~4095
        if (
            arena <= address < arena + 0x20000
            or table <= address < table + 0x400000
            or address in mapped
        ):
            return
        assert base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage, hex(address)
        vm.mem_map(address, 4096)
        data = pe.get_data(address - base, 4096)
        if data:
            vm.mem_write(address, data)
        mapped.add(address)

    def write(address, data):
        for offset in range(
            address & ~4095, (address + len(data) + 4095) & ~4095, 4096
        ):
            page(offset)
        vm.mem_write(address, data)

    def missing(machine, access, address, size, value, context):
        page(address)
        page(address + size - 1)
        return True

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    state = location(0xB493780)
    initial = bytearray(0x11518)
    initial[:0xE0] = bytes(range(0xE0))
    struct.pack_into("<Q", initial, 0xE0, 0x120000)
    write(state, bytes(initial))
    imported = {
        "__imp_VirtualAlloc": arena + 0x1000,
        "__imp_GlobalMemoryStatusEx": arena + 0x2000,
    }
    for name, address in imported.items():
        write(symbol(name), struct.pack("<Q", address))

    if edited and not report:
        section_addresses = {
            i + 1: 0x180000000 + i * 0x10000 for i in range(len(obj["sections"]))
        }
        symbols = {}
        for index, row in obj["symbols"].items():
            if row["section"] > 0:
                symbols[index] = section_addresses[row["section"]] + row["value"]
            elif row["name"] == "_fltused":
                symbols[index] = arena + 0x4000
            elif row["section"] == 0:
                symbols[index] = symbol(row["name"])
            else:
                symbols[index] = row["value"]
        for section in obj["sections"]:
            address = section_addresses[section["number"]]
            data = bytearray(section["data"])
            for offset, index, kind in section["relocations"]:
                target = symbols[index]
                if 4 <= kind <= 9:
                    value = (
                        struct.unpack_from("<i", data, offset)[0]
                        + target
                        - address
                        - offset
                        - 4
                        - (kind - 4)
                    )
                    struct.pack_into("<i", data, offset, value)
                elif kind == 1:
                    struct.pack_into(
                        "<Q",
                        data,
                        offset,
                        struct.unpack_from("<Q", data, offset)[0] + target,
                    )
                elif kind == 3:
                    struct.pack_into(
                        "<I", data, offset, (target - 0x180000000) & 0xFFFFFFFF
                    )
                else:
                    raise AssertionError(kind)
            vm.mem_map(address, (max(1, len(data)) + 4095) & ~4095)
            if data:
                vm.mem_write(address, bytes(data))
        entry = next(
            symbols[i]
            for i, row in obj["symbols"].items()
            if row["name"] == "func_140F12E20"
        )
    else:
        entry = symbol("func_140F12E20")

    allocations, errors, logs = [], [], []

    def returned(value=0):
        sp = vm.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", vm.mem_read(sp, 8))[0]
        vm.reg_write(UC_X86_REG_RAX, value)
        vm.reg_write(UC_X86_REG_RSP, sp + 8)
        vm.reg_write(UC_X86_REG_RIP, target)

    def hook(machine, address, size, context):
        a, b, c, d = [
            vm.reg_read(r)
            for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)
        ]
        if address == imported["__imp_VirtualAlloc"]:
            allocations.append((a, b, c, d))
            returned(0 if len(allocations) == failed_alloc else table)
        elif address == imported["__imp_GlobalMemoryStatusEx"]:
            assert struct.unpack("<I", vm.mem_read(a, 4))[0] == 64
            if not failed_status:
                vm.mem_write(
                    a,
                    struct.pack(
                        "<II7Q", 64, 0, total, available, 2 * total, total, 0, 0, 0
                    ),
                )
            returned(0 if failed_status else 1)
        elif address == symbol("memset"):
            write(a, bytes([b & 255]) * c)
            returned(a)
        elif address == symbol("func_1412B0820"):
            logs.append((a, c, d))
            returned(0x1234)
        elif address == symbol("Mem_Error_CannotAlloc_Dev"):
            errors.append(a)
            returned()
        else:
            returned(vm.reg_read(UC_X86_REG_RAX))  # original security-cookie check

    boundaries = list(imported.values()) + [
        symbol(name)
        for name in ["memset", "func_1412B0820", "Mem_Error_CannotAlloc_Dev"]
    ]
    if not edited:
        # The original body retains its stack-cookie check.
        boundaries.append(location(0x21CCF60))
    for address in boundaries:
        page(address)
        vm.hook_add(UC_HOOK_CODE, hook, begin=address, end=address)
    vm.mem_write(stack, struct.pack("<Q", stop))
    vm.reg_write(UC_X86_REG_RSP, stack)
    vm.emu_start(entry, stop, count=50000000)
    assert vm.reg_read(UC_X86_REG_RIP) == stop
    raw = bytes(vm.mem_read(state, len(initial)))
    assert raw[:0xE0] == initial[:0xE0]
    assert allocations == [(0, 0x400000, 0x2000, 4)] + (
        [] if failed_alloc == 1 else [(table, 0x400000, 0x1000, 4)]
    )
    if failed_alloc:
        assert errors == [0] and not logs
        return {"allocation_failure_handled": True}
    expected = max(
        81920,
        min(524288, (0 if failed_status else total if edited else available) // 98304),
    )
    assert struct.unpack_from("<II", raw, 0xE8) == (expected, 524288)
    assert struct.unpack_from("<I", raw, 0x10510)[0] == expected
    assert bytes(vm.mem_read(table, 0x400000)) == b"\xff" * 0x400000
    assert raw[0x10518:] == struct.pack("<I", 0x7FFFF) * 1024
    assert logs == [(16, expected, expected * 65536)] and not errors
    assert vm.reg_read(UC_X86_REG_RAX) == 0x1234
    return {"state": raw, "page_count": expected, "allocations": allocations}


cases = []
for total, available in [
    (4 << 30, 1 << 30),
    (16 << 30, 8 << 30),
    (32 << 30, 4 << 30),
    (64 << 30, 64 << 30),
    (16958246912, 8742371328),
]:
    edited = run(True, total, available)
    oracle = run(False, total, total)
    assert edited["state"] == oracle["state"], (total, available)
    old_pages = max(81920, min(524288, available // 98304))
    cases.append(
        {
            "total_physical": total,
            "available_physical": available,
            "original_page_count": old_pages,
            "new_page_count": edited["page_count"],
            "entire_native_state_matches": True,
        }
    )
    print(
        "Native page-tree comparison passed:",
        total,
        available,
        edited["page_count"],
        flush=True,
    )
assert (
    run(True, 0, 0, failed_status=True)["state"]
    == run(False, 0, 0, failed_status=True)["state"]
)
for failed in (1, 2):
    run(True, 16 << 30, 8 << 30, failed_alloc=failed)
result = {
    "passed": True,
    "original_sha256": catalog["image_sha256"],
    "object_sha256": hashlib.sha256(args.object.read_bytes()).hexdigest(),
    "linked_sha256": report["sha256"] if report else None,
    "cases": cases,
    "memory_status_failure_preserves_native_floor": True,
    "reserve_and_commit_failure_cases": 2,
    "game_launched": False,
    "stubbed_boundaries": [
        "VirtualAlloc",
        "GlobalMemoryStatusEx",
        "memset",
        "logging",
        "fatal error",
        "security cookie",
    ],
}
args.output.write_text(json.dumps(result, indent=2) + "\n")
print("PASS:", args.output, flush=True)
