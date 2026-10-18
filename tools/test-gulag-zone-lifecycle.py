"""Offline instruction checks of Replay NavMesh owning-release lifecycle.

Executes original target instructions in Unicorn. Critical-section and BFX
destruction leaves are modeled; this does not certify live navigation behavior.
"""

import argparse
import hashlib
import json
import sqlite3
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
)

IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
ENTRY = 0x140F60530
REMOVE = 0x1410EB490
DETACH = 5385525824


def run_case(pe, leaves, initialized, owner, count, ordinal):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped = set()
    events = []

    def map_page(address):
        page = address & ~4095
        if page in mapped:
            return
        mapped.add(page)
        vm.mem_map(page, 4096)
        if (
            pe.OPTIONAL_HEADER.ImageBase
            <= page
            < pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.SizeOfImage
        ):
            vm.mem_write(page, pe.get_data(page - pe.OPTIONAL_HEADER.ImageBase, 4096))

    def unmapped(uc, access, address, size, value, data):
        for at in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            map_page(at)
        return True

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped)

    def write(address, fmt, *values):
        raw = struct.pack(fmt, *values)
        for at in range(address & ~4095, (address + len(raw) + 4095) & ~4095, 4096):
            map_page(at)
        vm.mem_write(address, raw)

    def read(address, fmt):
        return struct.unpack(fmt, vm.mem_read(address, struct.calcsize(fmt)))[0]

    root = 0x50000000
    resource = 0x51000000
    stock = [0x52000000 + i * 112 for i in range(16)]
    write(root, "168s", bytes(168))
    write(root + 16, "I", count)
    write(root + 24, "Q", resource)
    pending = [[0x60001000, root, root, 0x60002000], [root, 0x60003000, root]]
    for bank, rows in enumerate(pending):
        write(0x14C618030 + bank * 32, "4Q", *(rows + [0] * (4 - len(rows))))
        write(0x14C618070 + bank * 4, "I", len(rows))
    write(0x14C618018, "B", int(initialized))
    world_bounds = struct.pack(
        "<6f",
        9213.92578125,
        10745.3828125,
        1552.754638671875,
        52208.57421875,
        55987.875,
        2611.747314453125,
    )
    write(0x14C617FFC, "24s", world_bounds)
    ours = [resource + i * 112 for i in range(count)]
    registered = stock[:7] + ours + stock[7:] if initialized else []
    write(0x14C5CF9B8, "128Q", *(registered + [0] * (128 - len(registered))))
    write(0x14C5CFDB8, "I", len(registered))
    for i, address in enumerate(ours):
        space = 0x54000000 + i * 4096
        prev = 0x55000000 + i * 4096
        following = prev + 128
        write(address, "112s", bytes(112))
        write(address + 16, "Q", space)
        write(address + 64, "QQ", prev, following)
        write(address + 96, "Q", 0x56000000 + i * 4096)
        write(prev + 72, "Q", address)
        write(following + 64, "Q", address)
        write(space + 632, "I", 1)
    stop = 0x73000000
    stack = 0x72008008
    write(stack, "Q", stop)
    map_page(stop)

    def code(uc, address, size, data):
        if address == stop:
            uc.emu_stop()
            return
        if address in leaves:
            name = leaves[address]
            events.append(
                (name, uc.reg_read(UC_X86_REG_RCX), uc.reg_read(UC_X86_REG_RDX))
            )
            rsp = uc.reg_read(UC_X86_REG_RSP)
            uc.reg_write(UC_X86_REG_RIP, read(rsp, "Q"))
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)

    vm.hook_add(UC_HOOK_CODE, code)
    vm.reg_write(UC_X86_REG_RCX, root)
    vm.reg_write(UC_X86_REG_RDX, 0 if owner else 1)
    vm.reg_write(UC_X86_REG_RSP, stack)
    vm.emu_start(ENTRY, stop + 1, count=100000)
    assert vm.reg_read(UC_X86_REG_RIP) == stop
    assert bytes(vm.mem_read(0x14C617FFC, 24)) == world_bounds
    critical = [row for row in events if row[0] != "bfx::RemoveResource"]
    assert [(row[0], row[1]) for row in critical] == (
        [("Sys_EnterCriticalSection", 64), ("Sys_LeaveCriticalSection", 64)]
        if owner
        else []
    )
    for bank, rows in enumerate(pending):
        expected = [row for row in rows if row != root] if owner else rows
        assert read(0x14C618070 + bank * 4, "I") == len(expected)
        assert (
            list(
                struct.unpack(
                    "<" + "Q" * len(expected),
                    vm.mem_read(0x14C618030 + bank * 32, len(expected) * 8),
                )
            )
            == expected
        )
    expected = stock if initialized and owner else registered
    assert read(0x14C5CFDB8, "I") == len(expected)
    actual = list(
        struct.unpack(
            "<" + "Q" * len(expected), vm.mem_read(0x14C5CF9B8, len(expected) * 8)
        )
    )
    assert sorted(actual) == sorted(expected)
    destroys = [row for row in events if row[0] == "bfx::RemoveResource"]
    assert len(destroys) == (count if initialized and owner else 0)
    for i, address in enumerate(ours):
        if initialized and owner:
            assert (
                read(address + 16, "Q")
                == read(address + 64, "Q")
                == read(address + 72, "Q")
                == 0
            )
            assert read(0x54000000 + i * 4096 + 632, "I") == 0
            prev = 0x55000000 + i * 4096
            following = prev + 128
            assert (
                read(prev + 72, "Q") == following and read(following + 64, "Q") == prev
            )
            assert destroys[i][1:] == (0x54000000 + i * 4096, 0x56000000 + i * 4096)
    return dict(
        case=ordinal,
        initialized=initialized,
        owning_release=owner,
        resources=count,
        remaining_stock_resources=len(expected),
        modeled_bfx_calls=len(destroys),
        passed=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = IMAGE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA
    pe = pefile.PE(data=raw, fast_load=True)
    assert struct.unpack("<Q", pe.get_data(0x23FD3A0 + 27 * 8, 8))[0] == ENTRY
    db = sqlite3.connect("file:" + str(IMAGE) + ".sqlite?mode=ro", uri=True)
    names = (
        "Sys_EnterCriticalSection",
        "Sys_LeaveCriticalSection",
        "bfx::RemoveResource",
    )
    leaves = {
        int(address): name
        for name, address in db.execute(
            "select name,address from functions where name in (?,?,?)", names
        )
    }
    assert set(leaves.values()) == set(names)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    calls = {
        int(ins.op_str, 16)
        for ins in decoder.disasm(pe.get_data(DETACH - 0x140000000, 92), DETACH)
        if ins.mnemonic == "call"
    }
    assert (
        next(
            address for address, name in leaves.items() if name == "bfx::RemoveResource"
        )
        in calls
    )
    cases = [
        run_case(pe, leaves, initialized, owner, count, i)
        for i, (initialized, owner, count) in enumerate(
            [(True, True, 1)] * 10
            + [(True, True, 3), (True, False, 1), (False, True, 1), (False, False, 1)]
        )
    ]
    pins = [
        dict(
            address=hex(address),
            bytes=size,
            sha256=hashlib.sha256(pe.get_data(address - 0x140000000, size)).hexdigest(),
        )
        for address, size in ((ENTRY, 9), (REMOVE, 550), (DETACH, 92))
    ]
    result = dict(
        passed=True,
        original_image=str(IMAGE),
        original_image_sha256=SHA,
        code_pins=pins,
        cases=cases,
        executed_original_instructions=True,
        modeled_leaves=list(names),
        game_execution=False,
        qualification="Owning release removes both pending banks and registered resources; BFX destruction leaf modeled. No live reload proof.",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            dict(
                passed=True,
                scenarios=len(cases),
                output=str(args.output),
                game_execution=False,
            )
        )
    )


if __name__ == "__main__":
    main()
