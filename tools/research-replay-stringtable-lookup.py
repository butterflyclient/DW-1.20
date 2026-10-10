"""Execute Replay's real StringTable lookup and hash on retained native rows.

Only the CRT ASCII tolower boundary is modeled. The table's dimensions, cell
indices, hashes and string dictionary use the complete layout read by the
original lookup. No game launch or live state is involved.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX,
                              UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX,
                              UC_X86_REG_RIP)

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert args.output.resolve().is_relative_to(ROOT)
    raw = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe").read_bytes()
    image_sha = hashlib.sha256(raw).hexdigest()
    assert image_sha == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    pe = pefile.PE(data=raw, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    for section in pe.sections:
        size = (max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095) & ~4095
        if size:
            vm.mem_map(base + section.VirtualAddress, size)
            vm.mem_write(base + section.VirtualAddress, section.get_data())
    scratch, stack, stop = 0x60000000, 0x70000000, 0x71000000
    vm.mem_map(scratch, 0x200000)
    vm.mem_map(stack, 0x20000)
    vm.mem_map(stop, 4096)
    cursor = scratch
    calls = []

    def allocate(contents):
        nonlocal cursor
        start = cursor
        vm.mem_write(start, contents)
        cursor += (len(contents) + 15) & ~15
        assert cursor < scratch + 0x200000
        return start

    def text(pointer):
        result = bytearray()
        while byte := vm.mem_read(pointer + len(result), 1)[0]:
            result.append(byte)
            assert len(result) < 1024
        return result.decode("ascii")

    def hook(uc, address, size, unused):
        if address != 0x1422136BC:
            return
        calls.append(address)
        byte = uc.reg_read(UC_X86_REG_RCX)
        assert byte < 128
        uc.reg_write(UC_X86_REG_RAX, byte + 32 if 65 <= byte <= 90 else byte)
        sp = uc.reg_read(UC_X86_REG_RSP)
        uc.reg_write(UC_X86_REG_RIP, struct.unpack("<Q", uc.mem_read(sp, 8))[0])
        uc.reg_write(UC_X86_REG_RSP, sp + 8)

    vm.hook_add(UC_HOOK_CODE, hook)

    def execute(entry, *arguments):
        rsp = stack + 0x1F008
        vm.mem_write(rsp, struct.pack("<Q", stop))
        vm.reg_write(UC_X86_REG_RSP, rsp)
        for register, value in zip((UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9), arguments):
            vm.reg_write(register, value)
        vm.emu_start(entry, stop, count=500000)
        assert vm.reg_read(UC_X86_REG_RIP) == stop
        return vm.reg_read(UC_X86_REG_RAX)

    records = []

    def table(rows):
        columns = len(rows[0])
        assert all(len(row) == columns for row in rows)
        dictionary = list(dict.fromkeys(cell for row in rows for cell in row))
        hashes, pointers = [], []
        for cell in dictionary:
            pointer = allocate(cell.encode("ascii") + b"\0")
            pointers.append(pointer)
            hashes.append(execute(0x1413E3410, pointer))
        indices = [dictionary.index(cell) for row in rows for cell in row]
        cells_ptr = allocate(struct.pack("<" + "H" * len(indices), *indices))
        hashes_ptr = allocate(struct.pack("<" + "I" * len(hashes), *hashes))
        dictionary_ptr = allocate(struct.pack("<" + "Q" * len(pointers), *pointers))
        # name, columns, rows, dictionary count, padding, cell indices,
        # dictionary hashes, dictionary string pointers.
        return allocate(struct.pack("<QIIIIQQQ", 0, columns, len(rows), len(dictionary), 0,
                                    cells_ptr, hashes_ptr, dictionary_ptr))

    for name, requests in (
        ("replay120-achievementenginerefs.csv", [("fieldUpgrade", "4"), ("KILLSTREAK", "2"),
                                                ("teamrevive", "3"), ("unknown", "")]),
        ("replay120-brkioskpurchases.csv", [("UAV", "5"), ("supply_drop", "9"),
                                            ("super_AMMO_drop", "8"), ("unknown", "")]),
    ):
        path = ROOT / "validation/assets" / name
        rows = list(csv.reader(path.read_text().splitlines()))
        native_table = table(rows)
        column = 1 if "refs" in name else 2
        for selected, expected in requests:
            result = text(execute(0x1413E2BA0, native_table, column,
                                  allocate(selected.encode() + b"\0"), 0))
            assert result == expected, (selected, result, expected)
            records.append(dict(table=name, table_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                selected=selected, result=result))
    duplicate = table([["first", "same"], ["last", "SAME"]])
    result = text(execute(0x1413E2BA0, duplicate, 1, allocate(b"Same\0"), 0))
    assert result == "last"
    proof = dict(passed=True, target_image_sha256=image_sha,
                 tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 lookup_va=hex(0x1413E2BA0), hash_va=hex(0x1413E3410),
                 lookup_bytes_sha256=hashlib.sha256(pe.get_data(0x13E2BA0, 0x1BF)).hexdigest(),
                 hash_bytes_sha256=hashlib.sha256(pe.get_data(0x13E3410, 0x43)).hexdigest(),
                 native_table_layout={"bytes": 48, "columns": 8, "rows": 12, "dictionary_count": 16,
                                      "cell_indices": 24, "hashes": 32, "strings": 40},
                 cases=records, duplicate_lookup_result=result, ascii_case_insensitive=True,
                 last_matching_row_selected=True, modeled_boundaries=[hex(value) for value in sorted(set(calls))],
                 game_runs_performed=False)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print("Verified original native StringTable lookup: ASCII case folding and last matching row")


if __name__ == "__main__":
    main()
