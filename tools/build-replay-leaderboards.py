"""Build column publications and verify virtual requests with original x64 code."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP,
)


def native_columns(pe, definition, source):
    """Run Replay's original LB column builder; model only CRT output boundaries."""
    base = pe.OPTIONAL_HEADER.ImageBase
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, record, halt = 0x10000000, 0x11000000, 0x12000000
    vm.mem_map(stack, 0x10000)
    vm.mem_map(record, 0x10000)
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
    column_array = record + 4096
    put32(record + 16, source["width"])
    put32(record + 20, len(definition["columns"]))
    put64(record + 32, column_array)
    put32(record + 40, 3)
    for index, column in enumerate(definition["columns"]):
        put32(column_array + index * 56 + 8, column["id"])
    put64(stack + 0xF008, halt)
    vm.reg_write(UC_X86_REG_RCX, record)
    vm.reg_write(UC_X86_REG_RSP, stack + 0xF008)
    calls = []

    def returned(machine, value=0):
        sp = machine.reg_read(UC_X86_REG_RSP)
        machine.reg_write(UC_X86_REG_RAX, value)
        machine.reg_write(UC_X86_REG_RSP, sp + 8)
        machine.reg_write(UC_X86_REG_RIP, get64(sp))

    def boundary(machine, address, size, _):
        if address == halt:
            machine.emu_stop()
        elif address == 0x1421F6CC0:  # Original memset CRT boundary.
            dest, value, count = (machine.reg_read(r) for r in
                                  (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8))
            assert count <= 1024
            original_page(dest) if base <= dest < base + pe.OPTIONAL_HEADER.SizeOfImage else None
            machine.mem_write(dest, bytes([value & 255]) * count)
            calls.append("memset")
            returned(machine, dest)
        elif address == 0x1420365D0:  # Bounded Com_sprintf boundary.
            dest, capacity, fmt, number = (machine.reg_read(r) for r in
                                           (UC_X86_REG_RCX, UC_X86_REG_RDX,
                                            UC_X86_REG_R8, UC_X86_REG_R9))
            original_page(fmt)
            assert bytes(machine.mem_read(fmt, 7)) == b"col_%d\0"
            assert capacity == 64 and number < 240
            value = f"col_{number}".encode() + b"\0"
            original_page(dest)
            machine.mem_write(dest, value)
            calls.append("bounded-col-format")
            returned(machine, len(value) - 1)

    vm.hook_add(UC_HOOK_CODE, boundary)
    vm.emu_start(0x1419B5070, halt, count=20000)
    assert vm.reg_read(UC_X86_REG_RIP) == halt
    count = vm.reg_read(UC_X86_REG_RAX)
    assert count <= 10
    result = []
    for index in range(count):
        pointer = get64(0x15185D890 + index * 8)
        result.append(bytes(vm.mem_read(pointer, 64)).split(b"\0", 1)[0].decode())
    assert len(set(result)) == len(result)
    # Execute the original UI accessor against the packed result sequence.
    # Every physical display column must retrieve its own distinguishable value,
    # including nonascending IDs. Derived ratios retain the native UI path.
    row = record + 0x8000
    for index, name in enumerate(result):
        put32(row + 144 + index * 4, 1000 + int(name[4:]))
    original_page(0x151868140)
    put64(0x151868140, record)
    ui_reads = []
    for index, column in enumerate(definition["columns"]):
        if column["id"] >= 240:
            continue
        put64(stack + 0xF008, halt)
        vm.reg_write(UC_X86_REG_RSP, stack + 0xF008)
        vm.reg_write(UC_X86_REG_RCX, row)
        vm.reg_write(UC_X86_REG_RDX, column_array + index * 56)
        vm.emu_start(0x1419B5D80, halt, count=2000)
        actual = vm.reg_read(UC_X86_REG_RAX)
        expected = 1000 + column["id"]
        assert vm.reg_read(UC_X86_REG_RIP) == halt and actual == expected
        ui_reads.append({"column": column["id"], "expected": expected,
                         "actual": actual, "passed": True})
    unsigned_xp_reads = []
    if definition["name"] == "lb_vr_totalxp":
        index = next(i for i, column in enumerate(definition["columns"]) if column["id"] == 1)
        slot = result.index("col_1")
        for expected in (0x80000000, 0xFFFFFFFF):
            put32(row + 144 + slot * 4, expected)
            put64(stack + 0xF008, halt)
            vm.reg_write(UC_X86_REG_RSP, stack + 0xF008)
            vm.reg_write(UC_X86_REG_RCX, row)
            vm.reg_write(UC_X86_REG_RDX, column_array + index * 56)
            vm.emu_start(0x1419B5D80, halt, count=2000)
            actual = vm.reg_read(UC_X86_REG_RAX)
            assert actual == expected and vm.reg_read(UC_X86_REG_RIP) == halt
            unsigned_xp_reads.append({"expected": expected, "actual": actual, "passed": True})
    return {"name": definition["name"], "id": definition["id"],
            "columns": result, "passed": True, "modeled_calls": calls,
            "original_ui_column_reads": ui_reads, "unsigned_xp_reads": unsigned_xp_reads}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assets", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.assets.read_bytes()
    assets = json.loads(raw)
    contract = assets["target_contract"]
    image = Path(contract["original_image"]).read_bytes()
    assert hashlib.sha256(image).hexdigest() == contract["sha256"]
    pe = pefile.PE(data=image, fast_load=True)
    entry = contract["functions"]["0x1419b5070"]
    code = pe.get_data(0x19B5070, entry["size"])
    assert hashlib.sha256(code).hexdigest() == entry["sha256"]
    regular = {row["name"]: row for row in assets["leaderboards"]
               if row["name"].startswith("lb_")}
    definitions, cases = {}, []

    def add(board, storage_board, width, asset, origin):
        assert 0 < width <= 240 and 0 <= board < 2**32 - 1
        columns = [f"col_{i}" for i in range(width)]
        key = str(board)
        if key in definitions:
            assert definitions[key]["columns"] == columns and \
                definitions[key]["storage_board"] == storage_board, (key, asset)
            definitions[key]["assets"].append(asset)
        else:
            definitions[key] = {"schema": 2, "storage_board": storage_board,
                                "columns": columns, "assets": [asset],
                                "origin": origin}

    def source_width(source):
        ids = [column["id"] for column in source["columns"] if 0 <= column["id"] < 240]
        return max(source["width"], max(ids, default=-1) + 1)

    for row in regular.values():
        width = source_width(row)
        tracks = [0] + [100 * bit for bit in range(8) if row["track_mask"] & (1 << bit)]
        for track in set(tracks):
            for scope in (0, 140000, 150000):
                add(row["id"] + track + scope, row["id"] + track,
                    width, row["name"], "shipped-regular")
    for row in assets["virtual_leaderboards"]:
        if not row["name"].startswith("lb_"):
            continue
        source = regular[row["source_name"]]
        assert source["id"] == row["source_id"]
        case = native_columns(pe, row, source)
        cases.append(case)
        width = source_width(source)
        for scope in (0, 140000, 150000):
            add(row["id"] + scope, row["id"], width, row["name"], "shipped-virtual")
            if row["name"] == "lb_vr_totalxp":
                assert row["id"] == 3 and source["name"] == "lb_mr_mp"
                assert any(c["id"] == 1 and c["name"] == "Total XP" for c in row["columns"])
                definitions[str(row["id"] + scope)]["progression"] = {
                    "type": "player_xp", "context": "5800", "xp_column": 1}
    args.output.mkdir(parents=True, exist_ok=True)
    result = {"schema": 1, "title": 5800, "generated_utc": datetime.now(timezone.utc).isoformat(),
              "asset_export_sha256": hashlib.sha256(raw).hexdigest(),
              "original_image_sha256": contract["sha256"],
              "game_sha256": assets["game_sha256"], "definitions": definitions,
              "native_column_builder": {"original_instructions_executed": True,
                                        "modeled_boundaries": ["memset", "bounded Com_sprintf"],
                                        "cases": cases},
              "scope": "Column layouts and explicit native read-namespace aliases. No player statistics, ranks or progression are seeded."}
    (args.output / "catalog.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for board, definition in definitions.items():
        destination = args.output / "leaderboard-definitions/5800" / f"{board}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(definition, indent=2) + "\n", encoding="utf-8")
    print(f"Built {len(definitions)} column definitions; verified {len(cases)} native virtual requests")


if __name__ == "__main__":
    main()
