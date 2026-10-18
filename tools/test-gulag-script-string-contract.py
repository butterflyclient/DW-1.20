"""Exercise the original Replay script-string loaders on the package contract.

Original Load_ScriptStringList, its null-XString element loader, and
Load_ScriptStringCustom execute unchanged in Unicorn. Only archive I/O and
patch/stream bookkeeping callbacks are supplied by this offline harness.
The null-table negative control must fault at Custom+0xE, as R11 did.
"""

import argparse
import hashlib
import sqlite3
import struct
from pathlib import Path

import capstone
import pefile
import unicorn
from unicorn import x86_const as registers

IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA256 = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
DATABASE = IMAGE.with_suffix(".exe.sqlite")
IMAGE_BASE = 0x140000000
LIST_LOADER = 0x140DD1E90
ELEMENT_LOADER = 0x140DD28E0
CONVERTER = 0x1411B2CA0
LOAD_STREAM = 0x1411B2A20
PUSH_STREAM = 0x1411B2570
POP_STREAM = 0x1411B24C0
ALIGN_STREAM = 0x140D8D480
PUSH_ASSET = 0x140D8DA80
POP_ASSET = 0x140D8D850
ASSET_LIST_GLOBAL = 0x145D414C8
STRING_LIST_GLOBAL = 0x145D415C8
STREAM_POSITION_GLOBAL = 0x14D120C00
FOLLOW = 0xFFFFFFFFFFFFFFFE


def validate_serialized_contract(body, layout):
    count, padding, table, assets, asset_padding, asset_pointer = struct.unpack_from(
        "<IIQIIQ", body
    )
    if (count, padding, table, assets, asset_padding, asset_pointer) != (
        1,
        0,
        FOLLOW,
        1,
        0,
        FOLLOW,
    ):
        raise ValueError("Expected a real one-slot script-string table and one asset")
    table_at = layout["script_string_table_offset"]
    if table_at != 32 or struct.unpack_from("<Q", body, table_at)[0] != 0:
        raise ValueError("Script-string slot zero must contain the null XString")
    indices = []
    for index in range(layout["resource_count"]):
        value = struct.unpack_from("<I", body, layout["resource_offset"] + index * 112)[
            0
        ]
        if value >= count:
            raise ValueError("Nav resource name script-string index exceeds its table")
        indices.append(value)
    return dict(
        count=count,
        null_slot=0,
        resource_name_indices=indices,
        serialized_table_bytes=8,
        virtual_table_reservation=8,
    )


def native_case(
    table_present, code, image, serialized_list=None, serialized_table=None
):
    emulator = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    pages = set()

    def map_page(address):
        page = address & ~4095
        if page not in pages:
            emulator.mem_map(page, 4096)
            pages.add(page)
            if IMAGE_BASE <= page < IMAGE_BASE + image.OPTIONAL_HEADER.SizeOfImage:
                initial = image.get_data(page - IMAGE_BASE, 4096)
                if initial:
                    emulator.mem_write(page, initial)

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    for address, entry in code.items():
        data = entry["bytes"]
        for page in range(address & ~4095, (address + len(data) + 4095) & ~4095, 4096):
            map_page(page)
        emulator.mem_write(address, data)
        for instruction in decoder.disasm(data, address):
            for operand in instruction.operands:
                if (
                    operand.type == capstone.CS_OP_MEM
                    and operand.mem.base == capstone.x86.X86_REG_RIP
                ):
                    map_page(instruction.address + instruction.size + operand.mem.disp)

    callbacks = {
        LOAD_STREAM,
        PUSH_STREAM,
        POP_STREAM,
        ALIGN_STREAM,
        PUSH_ASSET,
        POP_ASSET,
    }
    for address in callbacks:
        map_page(address)
    header, virtual, stack, stop = 0x20000000, 0x30000000, 0x40000000, 0x50000000
    for address in (header, virtual, stack, stop):
        map_page(address)
    emulator.mem_write(stop, b"\xc3")
    list_header = (
        serialized_list
        if serialized_list is not None
        else struct.pack("<IIQ", int(table_present), 0, FOLLOW if table_present else 0)
    )
    emulator.mem_write(header, list_header)
    for address in (ASSET_LIST_GLOBAL, STRING_LIST_GLOBAL):
        map_page(address)
        emulator.mem_write(address, struct.pack("<Q", header))
    emulator.mem_write(STREAM_POSITION_GLOBAL, struct.pack("<Q", virtual))
    events = []
    fault = {}
    archive = (
        serialized_table
        if serialized_table is not None
        else (bytes(8) if table_present else b"")
    )
    cursor = 0

    def callback(machine, address, size, context):
        nonlocal cursor
        if address == stop:
            machine.emu_stop()
            return
        if address not in callbacks:
            return
        rcx = machine.reg_read(registers.UC_X86_REG_RCX)
        rdx = machine.reg_read(registers.UC_X86_REG_RDX)
        length = machine.reg_read(registers.UC_X86_REG_R8)
        if address == LOAD_STREAM:
            events.append(
                dict(callback="Load_Stream", not_at_start=bool(rcx), bytes=length)
            )
            if rcx == 0:
                if cursor + length > len(archive):
                    raise ValueError(
                        "Native loader consumed beyond the serialized table"
                    )
                machine.mem_write(rdx, archive[cursor : cursor + length])
                cursor += length
                machine.mem_write(
                    STREAM_POSITION_GLOBAL, struct.pack("<Q", rdx + length)
                )
        elif address == PUSH_STREAM:
            if rcx != 5:
                raise ValueError("Unexpected native script-string stream")
        elif address == ALIGN_STREAM:
            if rcx != 7:
                raise ValueError("Unexpected native XString alignment")
        # Other callbacks maintain no state observed by this loader branch.
        rsp = machine.reg_read(registers.UC_X86_REG_RSP)
        destination = struct.unpack("<Q", machine.mem_read(rsp, 8))[0]
        machine.reg_write(registers.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(registers.UC_X86_REG_RIP, destination)

    def invalid(machine, access, address, size, value, context):
        fault.update(
            address=address, instruction=machine.reg_read(registers.UC_X86_REG_RIP)
        )
        return False

    emulator.hook_add(unicorn.UC_HOOK_CODE, callback)
    emulator.hook_add(unicorn.UC_HOOK_MEM_INVALID, invalid)

    def call(address, argument):
        rsp = stack + 0xF08
        emulator.mem_write(rsp, struct.pack("<Q", stop))
        emulator.reg_write(registers.UC_X86_REG_RSP, rsp)
        emulator.reg_write(registers.UC_X86_REG_RCX, argument)
        emulator.emu_start(address, stop, count=10000)

    call(LIST_LOADER, 1)
    resource_name = header + 0x100
    emulator.mem_write(resource_name, bytes(4))
    try:
        call(CONVERTER, resource_name)
    except unicorn.UcError:
        if table_present or fault.get("instruction") != CONVERTER + 0xE:
            raise
    if table_present:
        assert not fault and cursor == 8
        assert struct.unpack("<Q", emulator.mem_read(header + 8, 8))[0] == virtual
        assert struct.unpack("<I", emulator.mem_read(resource_name, 4))[0] == 0
    else:
        assert fault == dict(address=0, instruction=CONVERTER + 0xE)
    return dict(
        table_present=table_present,
        archive_bytes_consumed=cursor,
        load_events=events,
        native_fault=fault,
        converter_succeeded=table_present,
    )


def run_native_regression(serialized_list=None, serialized_table=None):
    with IMAGE.open("rb") as stream:
        image_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    if image_sha256 != IMAGE_SHA256:
        raise ValueError("Original Replay image SHA256 changed")
    image = pefile.PE(str(IMAGE), fast_load=True)
    code = {}
    with sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True) as database:
        for address in (LIST_LOADER, ELEMENT_LOADER, CONVERTER):
            size = database.execute(
                "select size from functions where address=?", (str(address),)
            ).fetchone()[0]
            data = image.get_data(address - IMAGE_BASE, size)
            code[address] = dict(
                bytes=data, size=size, sha256=hashlib.sha256(data).hexdigest()
            )
    cases = [
        native_case(False, code, image),
        native_case(True, code, image, serialized_list, serialized_table),
    ]
    return dict(
        passed=True,
        executed_original_script_string_list=True,
        original_image_sha256=image_sha256,
        helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        executed_original_null_xstring_loader=True,
        executed_original_script_string_converter=True,
        conversion_hooked=False,
        game_execution=False,
        callbacks="archive Load_Stream, stream/patch bookkeeping only",
        code_pins=[
            dict(address=hex(address), bytes=entry["size"], sha256=entry["sha256"])
            for address, entry in code.items()
        ],
        cases=cases,
    )


def verify_package_contract(body, layout):
    serialized = validate_serialized_contract(body, layout)
    rejected = []
    for name in ("null_table", "out_of_range_resource_name"):
        damaged = bytearray(body)
        if name == "null_table":
            struct.pack_into("<IIQ", damaged, 0, 0, 0, 0)
        else:
            struct.pack_into("<I", damaged, layout["resource_offset"], 1)
        try:
            validate_serialized_contract(damaged, layout)
        except ValueError:
            rejected.append(name)
    if len(rejected) != 2:
        raise ValueError("Script-string contract negative controls did not reject")
    return dict(
        serialized=serialized,
        rejected_serialized_cases=rejected,
        native_regression=run_native_regression(body[:16], body[32:40]),
    )


if __name__ == "__main__":
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = run_native_regression()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
