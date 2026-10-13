"""Execute the exact Replay focus binding against valid and retired UI handles.

Only its five Lua argument/result boundaries are modeled. Native slot bounds,
generation checks, pool indexing and focus-bit reads execute unmodified image
instructions. Invalid-handle cases deliberately reproduce the native AV; the
separate playlist UI regression must prove closed elements never reach it.
"""

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSP, UC_X86_REG_RIP


ORIGINAL = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
ORIGINAL_SHA256 = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
BASE = 0x140000000
ENTRY_RVA = 0x19CAC80
LENGTH = 212
FAULT_OFFSET = 0x9D
LUA_RVAS = {
    "lua_gettop": 0x20838B0,
    "lua_isuserdata": 0x2083A60,
    "lua_touserdata": 0x2084A70,
    "lua_pushboolean": 0x2083E80,
    "luaL_error": 0x2089FB0,
}
GENERATION_RVA = 0x58963F0 + 4000 * 320
FLAGS_RVA = 0x58963F0 + 0x50


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def execute(pe, location, case):
    entry = location(ENTRY_RVA)
    fault = entry + FAULT_OFFSET
    code = pe.get_data(entry - BASE, LENGTH)
    generation_table, flags = location(GENERATION_RVA), location(FLAGS_RVA)
    boundaries = {location(rva): name for name, rva in LUA_RVAS.items()}
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    pages = set()

    def map_memory(address, size):
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            if page not in pages:
                vm.mem_map(page, 4096)
                pages.add(page)

    map_memory(entry, LENGTH)
    vm.mem_write(entry, code)
    for address in boundaries:
        map_memory(address, 1)
        vm.mem_write(address, b"\xc3")
    arena = 0x70000000
    map_memory(arena, 0x20000)
    userdata, lua_state, stop, stack = arena + 0x10000, arena + 0x11000, arena + 0x12000, arena + 0xFF08
    map_memory(generation_table, 4000 * 2)
    map_memory(flags, 4000 * 320)
    slot, handle_generation = case.get("slot", 3), case.get("generation", 7)
    vm.mem_write(userdata, struct.pack("<HH", slot, handle_generation))
    if slot < 4000:
        vm.mem_write(generation_table + slot * 2, struct.pack("<H", case.get("native_generation", 7)))
        vm.mem_write(flags + slot * 320, struct.pack("<I", 4 if case.get("focused") else 0))
    vm.mem_write(stack, struct.pack("<Q", stop))
    vm.reg_write(UC_X86_REG_RSP, stack)
    vm.reg_write(UC_X86_REG_RCX, lua_state)
    result = {"name": case["name"], "calls": []}
    lua_top = case.get("argument_count", 1)

    def boundary(machine, address, size, context):
        nonlocal lua_top
        if address == stop:
            result["returned"] = machine.reg_read(UC_X86_REG_RAX)
            machine.emu_stop()
            return
        name = boundaries.get(address)
        if name is None:
            assert entry <= address < entry + LENGTH, hex(address)
            return
        assert machine.reg_read(UC_X86_REG_RCX) == lua_state, name
        result["calls"].append(name)
        if name == "lua_gettop":
            machine.reg_write(UC_X86_REG_RAX, lua_top)
        elif name in ("lua_isuserdata", "lua_touserdata"):
            assert machine.reg_read(UC_X86_REG_RDX) == 1, name
            value = int(case.get("is_userdata", True)) if name == "lua_isuserdata" else (0 if case.get("null") else userdata)
            machine.reg_write(UC_X86_REG_RAX, value)
        elif name == "lua_pushboolean":
            result["boolean"] = machine.reg_read(UC_X86_REG_RDX)
            lua_top += 1
        else:
            assert name == "luaL_error"
            message = machine.reg_read(UC_X86_REG_RDX)
            assert BASE <= message < BASE + pe.OPTIONAL_HEADER.SizeOfImage
            result["lua_error"] = True
            machine.emu_stop()

    def invalid_memory(machine, access, address, size, value, context):
        result["fault"] = {
            "rip": machine.reg_read(UC_X86_REG_RIP), "read_address": address,
            "read_size": size, "rax": machine.reg_read(UC_X86_REG_RAX),
        }
        return False

    vm.hook_add(UC_HOOK_CODE, boundary)
    vm.hook_add(UC_HOOK_MEM_UNMAPPED, invalid_memory)
    try:
        vm.emu_start(entry, stop + 1, count=1000)
    except UcError:
        assert "fault" in result, result
    if case.get("expected_fault"):
        assert result.get("fault") == {"rip": fault, "read_address": 0x50, "read_size": 4, "rax": 0x50}, result
        assert result["calls"] == ["lua_gettop", "lua_isuserdata", "lua_touserdata"]
    elif case.get("expected_error"):
        assert result.get("lua_error") and "fault" not in result, result
        expected_calls = ["lua_gettop"]
        if case.get("argument_count", 1) == 1:
            expected_calls.append("lua_isuserdata")
        assert result["calls"] == expected_calls + ["luaL_error"], result
    else:
        assert result.get("returned") == 1 and result.get("boolean") == int(case.get("focused", False)), result
        assert result["calls"] == ["lua_gettop", "lua_isuserdata", "lua_touserdata", "lua_pushboolean", "lua_gettop"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, help="Linked build directory or build-report.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert digest(ORIGINAL) == ORIGINAL_SHA256
    original_pe = pefile.PE(str(ORIGINAL), fast_load=True)
    assert original_pe.OPTIONAL_HEADER.ImageBase == BASE
    original_code = original_pe.get_data(ENTRY_RVA, LENGTH)
    images = [("original", ORIGINAL, ORIGINAL_SHA256, original_pe, lambda rva: BASE + rva)]
    provenance = None
    if args.build:
        report_path = args.build / "build-report.json" if args.build.is_dir() else args.build
        report = json.loads(report_path.read_bytes())
        assert report["input_sha256"] == ORIGINAL_SHA256
        assert report["unresolved_symbols"] == 0
        image = Path(report["executable"])
        if not image.is_absolute():
            image = report_path.parent / image
        assert digest(image) == report["sha256"]
        linked_pe = pefile.PE(str(image), fast_load=True)
        assert linked_pe.OPTIONAL_HEADER.ImageBase == BASE
        ranges = report["rva_map"]["ranges"]
        starts = [row["begin"] for row in ranges]

        def location(rva):
            index = bisect.bisect_right(starts, rva) - 1
            assert index >= 0
            row = ranges[index]
            assert row["begin"] <= rva < row["end"], hex(rva)
            return BASE + row["mapped_begin"] + rva - row["begin"]

        # Reconstruct every original PC-relative reference using this build's
        # RVA map. The assembler may choose an equivalent direction opcode
        # for register/register MOV, CMP and ADD, so compare complete decoded
        # instructions rather than requiring identical opcode bytes.
        relocated = bytearray(original_code)
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        instructions = list(decoder.disasm(original_code, BASE + ENTRY_RVA))
        assert sum(i.size for i in instructions) == LENGTH
        references = []
        for instruction in instructions:
            for operand in instruction.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    original_target = instruction.address + instruction.size + operand.mem.disp
                    offset, size = instruction.disp_offset, instruction.disp_size
                elif operand.type == X86_OP_IMM and (instruction.group(capstone.CS_GRP_CALL) or instruction.group(capstone.CS_GRP_JUMP)):
                    original_target = operand.imm
                    offset, size = instruction.imm_offset, instruction.imm_size
                else:
                    continue
                target = location(original_target - BASE)
                value = target - location(instruction.address - BASE) - instruction.size
                begin = instruction.address - BASE - ENTRY_RVA + offset
                relocated[begin:begin + size] = value.to_bytes(size, "little", signed=True)
                references.append({"original_rva": original_target - BASE, "linked_rva": target - BASE})
        linked_code = linked_pe.get_data(location(ENTRY_RVA) - BASE, LENGTH)
        expected_instructions = [(i.mnemonic, i.op_str, i.size) for i in decoder.disasm(bytes(relocated), location(ENTRY_RVA))]
        linked_instructions = [(i.mnemonic, i.op_str, i.size) for i in decoder.disasm(linked_code, location(ENTRY_RVA))]
        assert expected_instructions == linked_instructions, "Linked focus binding differs from original instructions after RVA relocation"
        provenance = {"build_report": str(report_path), "build_report_sha256": digest(report_path),
                      "native_binding_relocation_verified": True, "relative_references": references}
        images.append(("linked", image, report["sha256"], linked_pe, location))
    cases = [
        {"name": "valid_first_unfocused", "slot": 0},
        {"name": "valid_focused", "focused": True},
        {"name": "valid_last_focused", "slot": 3999, "focused": True},
        {"name": "stale_generation", "generation": 6, "expected_fault": True},
        {"name": "out_of_range_4000", "slot": 4000, "expected_fault": True},
        {"name": "out_of_range_65535", "slot": 65535, "expected_fault": True},
        {"name": "null_userdata", "null": True, "expected_fault": True},
        {"name": "argument_count_rejected", "argument_count": 0, "expected_error": True},
        {"name": "receiver_type_rejected", "is_userdata": False, "expected_error": True},
    ]
    results = []
    for kind, path, sha256, pe, location in images:
        code = pe.get_data(location(ENTRY_RVA) - BASE, LENGTH)
        results.append({"kind": kind, "image": str(path), "image_sha256": sha256,
                        "entry_rva": location(ENTRY_RVA) - BASE,
                        "fault_rva": location(ENTRY_RVA) - BASE + FAULT_OFFSET,
                        "binding_size": LENGTH, "binding_sha256": hashlib.sha256(code).hexdigest(),
                        "generation_table_rva": location(GENERATION_RVA) - BASE,
                        "element_flags_rva": location(FLAGS_RVA) - BASE,
                        "cases": [execute(pe, location, case) for case in cases]})
    receipt = {"passed": True, "function": "LUI_LuaCall_LUIElement_isInFocus_1",
               "original_entry_rva": ENTRY_RVA, "lua_receiver_index": 1,
               "native_pool": {"slot_count": 4000, "element_size": 320, "handle_size": 4,
                               "slot_offset": 0, "generation_offset": 2, "focus_flag": 4},
               "modeled_boundaries": list(LUA_RVAS), "linked_provenance": provenance,
               "images": results, "case_count": len(cases) * len(images),
               "scope": "Offline exact native binding execution; UI close lifecycle and live game are separate gates."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "case_count": receipt["case_count"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
