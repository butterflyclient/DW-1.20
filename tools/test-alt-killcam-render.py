"""Execute compiled capture policy and compare the complete native final task."""

import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
import unicorn.x86_const as reg

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path("C:/Program Files/LLVM/bin")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_clone_unwind(obj, records):
    text = next(section for section in obj["sections"] if section["name"] == ".text")
    xdata = next(section for section in obj["sections"] if section["name"] == ".xdata")
    pdata = next(section for section in obj["sections"] if section["name"] == ".pdata")
    offsets, cursor = [], 0
    for record in records:
        offsets.append(cursor)
        cursor += len(bytes.fromhex(record["bytes"]))
    assert len(xdata["data"]) == cursor and len(pdata["data"]) == 12 * len(records)
    expected = bytearray(b"".join(bytes.fromhex(record["bytes"]) for record in records))
    actual = bytearray(xdata["data"])
    relocations = {
        offset: (obj["symbols"][index], kind)
        for offset, index, kind in xdata["relocations"]
    }
    fields = set()

    def relocated(section, table, offset, expected_section, expected_value):
        symbol, kind = table[offset]
        addend = struct.unpack_from("<I", section["data"], offset)[0]
        assert kind == 3 and symbol["section"] == expected_section
        assert symbol["value"] + addend == expected_value

    for index, record in enumerate(records):
        blob = bytes.fromhex(record["bytes"])
        size = 4 + ((blob[2] + 1) & ~1) * 2
        flags = blob[0] >> 3
        at = offsets[index] + size
        if flags == 3:
            symbol, kind = relocations[at]
            assert kind == 3 and symbol["section"] == 0
            assert symbol["name"] == "fn_3da1e16560231243"
            assert struct.unpack_from("<I", actual, at)[0] == 0
            fields.add(at)
        elif flags == 4:
            chain = struct.unpack_from("<III", blob, size)
            parent = next(
                i
                for i, row in enumerate(records[:index])
                if chain == (row["begin"], row["end"], row["unwind_rva"])
            )
            values = (
                records[parent]["begin"] - records[0]["begin"],
                records[parent]["end"] - records[0]["begin"],
                offsets[parent],
            )
            for ordinal, value in enumerate(values):
                site = at + ordinal * 4
                relocated(
                    xdata,
                    relocations,
                    site,
                    text["number"] if ordinal < 2 else xdata["number"],
                    value,
                )
                fields.add(site)
        else:
            assert flags == 0
    assert set(relocations) == fields
    for site in fields:
        expected[site : site + 4] = actual[site : site + 4] = bytes(4)
    assert expected == actual, "Native unwind codes or GS cookie changed"
    table = {
        offset: (obj["symbols"][symbol], kind)
        for offset, symbol, kind in pdata["relocations"]
    }
    assert len(table) == 3 * len(records)
    for index, record in enumerate(records):
        for ordinal, value in enumerate(
            (
                record["begin"] - records[0]["begin"],
                record["end"] - records[0]["begin"],
                offsets[index],
            )
        ):
            relocated(
                pdata,
                table,
                index * 12 + ordinal * 4,
                text["number"] if ordinal < 2 else xdata["number"],
                value,
            )
    return len(records)


def verify_linked_clones(receipt, pe, report):
    original = pefile.PE(
        r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe", fast_load=True
    )
    pe.parse_data_directories(directories=[3])
    symbols = report["symbols"]
    count = 0
    for clone in receipt["clones"]:
        start = symbols[clone["helper"]]
        records = clone["gs_unwind"]
        original_start = records[0]["begin"]
        expected = bytearray(original.get_data(original_start, clone["bytes"]))
        actual = bytearray(pe.get_data(start, clone["bytes"]))
        for fixup in clone["external_fixups"]:
            if fixup.get("section") == ".xdata":
                continue
            at = fixup["offset"]
            value = struct.unpack_from("<i", actual, at)[0]
            target = symbols[fixup["stable_id"]]
            assert (
                value
                if fixup["kind"] == 3
                else value + start + at + 4 + fixup["trailing_instruction_bytes"]
            ) == target
            expected[at : at + 4] = actual[at : at + 4] = bytes(4)
        assert expected == actual
        entries = []
        for record in records:
            begin = start + record["begin"] - original_start
            end = start + record["end"] - original_start
            matches = [
                entry
                for entry in pe.DIRECTORY_ENTRY_EXCEPTION
                if entry.struct.BeginAddress == begin and entry.struct.EndAddress == end
            ]
            assert len(matches) == 1
            entries.append(matches[0])
        for index, record in enumerate(records):
            expected = bytearray.fromhex(record["bytes"])
            actual = bytearray(
                pe.get_data(entries[index].struct.UnwindData, len(expected))
            )
            header = 4 + ((expected[2] + 1) & ~1) * 2
            flags = expected[0] >> 3
            if flags == 3:
                assert (
                    struct.unpack_from("<I", actual, header)[0]
                    == symbols["fn_3da1e16560231243"]
                )
                expected[header : header + 4] = actual[header : header + 4] = bytes(4)
            elif flags == 4:
                chain = struct.unpack_from("<III", expected, header)
                parent = next(
                    i
                    for i, row in enumerate(records[:index])
                    if chain == (row["begin"], row["end"], row["unwind_rva"])
                )
                assert struct.unpack_from("<III", actual, header) == (
                    entries[parent].struct.BeginAddress,
                    entries[parent].struct.EndAddress,
                    entries[parent].struct.UnwindData,
                )
                expected[header : header + 12] = actual[header : header + 12] = bytes(
                    12
                )
            assert expected == actual
            count += 1
    for alias, identity in receipt["imports"].items():
        assert symbols[alias] == symbols[identity], alias
    registry = receipt["native"]["taskRegistration"]
    code = pe.get_data(symbols[registry["id"]], registry["bytes"])
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    callback = (
        pe.OPTIONAL_HEADER.ImageBase + symbols["DW_AltKillcamRender_FinalComposite"]
    )
    references = [
        instruction
        for instruction in decoder.disasm(
            code, pe.OPTIONAL_HEADER.ImageBase + symbols[registry["id"]]
        )
        if instruction.mnemonic == "lea"
        and any(
            operand.type == X86_OP_MEM
            and operand.mem.base == X86_REG_RIP
            and instruction.address + instruction.size + operand.mem.disp == callback
            for operand in instruction.operands
        )
    ]
    assert (
        len(references) == 1
    ), "Native task registry does not install the linked callback"
    return count


def original_case(
    proof,
    pe,
    source_width,
    source_height,
    output_width,
    output_height,
    scale,
    mask,
    linked=None,
    active=False,
):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    base = pe.OPTIONAL_HEADER.ImageBase
    arena = 0x100000000
    vm.mem_map(arena, 0x400000)
    pages = set()

    def page(address):
        address &= ~4095
        if address not in pages:
            vm.mem_map(address, 4096)
            vm.mem_write(address, pe.get_data(address - base, 4096))
            pages.add(address)

    def write(address, value, fmt):
        vm.mem_write(address, struct.pack(fmt, value))

    def read(address, fmt):
        return struct.unpack(fmt, vm.mem_read(address, struct.calcsize(fmt)))[0]

    target = dict(proof["native"]["final"])
    if linked:
        target["rva"] = linked["symbols"]["DW_AltKillcamRender_FinalComposite"]
        if not hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION"):
            pe.parse_data_directories(directories=[3])
        target["bytes"] = next(
            entry.struct.EndAddress - entry.struct.BeginAddress
            for entry in pe.DIRECTORY_ENTRY_EXCEPTION
            if entry.struct.BeginAddress == target["rva"]
        )
    code = pe.get_data(target["rva"], target["bytes"])
    if not linked:
        assert hashlib.sha256(code).hexdigest() == target["sha256"]
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, base + target["rva"]))
    for instruction in instructions:
        page(instruction.address)
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                page(instruction.address + instruction.size + operand.mem.disp)
    hooks = {
        base
        + (linked["symbols"][name] if linked else proof["native"][name]["rva"]): name
        for name in (
            "AKR_ResolutionScale",
            "AKR_ClearTargets",
            "AKR_PostfxConstants",
            "AKR_PostfxApply",
        )
    }
    cookie = (
        0
        if linked
        else int(
            [
                instruction.op_str
                for instruction in instructions
                if instruction.mnemonic == "call"
            ][-1],
            16,
        )
    )
    if linked:
        clone = next(
            clone
            for clone in proof["clones"]
            if clone["helper"] == "AKR_FinalCompositeNative"
        )
        identity = max(
            (
                row
                for row in clone["external_fixups"]
                if row["stable_id"].startswith("fn_") and row.get("section") != ".xdata"
            ),
            key=lambda row: row["offset"],
        )["stable_id"]
        cookie = base + linked["symbols"][identity]
    hooks[cookie] = "cookie"
    if active:
        assert linked
        for name in (
            "AKR_Create",
            "AKR_Transition",
            "AKR_FlushTransitions",
            "AKR_CopyBoundColor",
            "AKR_DrawRectangle",
            "AKR_SetViewportScissor",
        ):
            hooks[base + linked["symbols"][name]] = name
    for address in hooks:
        page(address)
    pool, context, task, view, backend, attachments = (
        arena + offset for offset in (0x10000, 0x2000, 0x2100, 0x3000, 0x4000, 0x5000)
    )
    global_pool = base + (
        linked["symbols"]["AKR_SurfacePool"]
        if linked
        else proof["derived_globals"]["AKR_SurfacePool"]["rva"]
    )
    page(global_pool)
    write(global_pool, pool, "<Q")
    write(pool + 60, output_width, "<H")
    write(pool + 62, output_height, "<H")
    write(pool + 504 + 60, source_width, "<H")
    write(pool + 504 + 62, source_height, "<H")
    write(task + 48, 1, "<B")
    write(task + 50, 1, "<H")
    write(task + 80, attachments, "<Q")
    values = [
        2,
        7,
        8 if mask & 1 else 0,
        9 if mask & 2 else 0,
        10 if mask & 4 else 0,
        11 if mask & 8 else 0,
    ]
    vm.mem_write(attachments, struct.pack("<6H", *values))
    vm.mem_write(context, struct.pack("<QQ", arena + 0x6000, arena + 0x9000))
    source, state = arena + 0x6000, arena + 0x9000
    inset = arena + 0x700
    if active:
        graph_global = base + linked["symbols"]["AKR_GraphScriptDvar"]
        page(graph_global)
        write(graph_global, arena + 0x800, "<Q")
        write(arena + 0x800 + 40, 1, "<I")
        write(pool + 44, 7, "<I")
        write(view + 11592, backend, "<Q")
        write(view + 11600, 0, "<I")
        write(view + 11604, 0, "<I")
        vm.mem_write(view + 1200, struct.pack("<4i", 0, 0, output_width, output_height))
        vm.mem_write(
            inset, struct.pack("<4i", output_width - 320, output_height - 180, 320, 180)
        )
        write(backend + 33256, 123, "<I")
        write(backend + 33264, 0, "<I")
        write(backend + 33288, view, "<Q")
    stack, stop = arena + 0x3FF008, arena + 0x3FE000
    write(stack, stop, "<Q")
    vm.reg_write(reg.UC_X86_REG_RSP, stack)
    for register, value in (
        (reg.UC_X86_REG_RCX, context),
        (reg.UC_X86_REG_RDX, task),
        (reg.UC_X86_REG_R8, view),
        (reg.UC_X86_REG_R9, backend),
    ):
        vm.reg_write(register, value)
    results = [0] * 16
    gpu_trace = []

    def returned(value=0):
        rsp = vm.reg_read(reg.UC_X86_REG_RSP)
        ret = read(rsp, "<Q")
        vm.reg_write(reg.UC_X86_REG_RAX, value)
        vm.reg_write(reg.UC_X86_REG_RSP, rsp + 8)
        vm.reg_write(reg.UC_X86_REG_RIP, ret)

    def hook(vm, address, size, unused):
        if address == stop:
            vm.emu_stop()
            return
        name = hooks.get(address)
        rsp = vm.reg_read(reg.UC_X86_REG_RSP)
        if name == "AKR_ResolutionScale":
            vm.reg_write(
                reg.UC_X86_REG_XMM0, struct.unpack("<I", struct.pack("<f", scale))[0]
            )
            returned()
        elif name == "AKR_ClearTargets":
            results[:2] = [
                vm.reg_read(reg.UC_X86_REG_RDX) & 255,
                vm.reg_read(reg.UC_X86_REG_R8) & 255,
            ]
            returned()
        elif name == "AKR_PostfxConstants":
            results[2:6] = [
                vm.reg_read(reg.UC_X86_REG_R9) & 255,
                read(rsp + 0x28, "<B"),
                read(rsp + 0x30, "<B"),
                read(rsp + 0x38, "<B"),
            ]
            returned()
        elif name == "AKR_PostfxApply":
            results[6:10] = struct.unpack(
                "<4i", vm.mem_read(vm.reg_read(reg.UC_X86_REG_R8), 16)
            )
            results[10] = vm.reg_read(reg.UC_X86_REG_R9) & 65535
            results[11] = read(rsp + 0x28, "<H")
            depth = read(rsp + 0x30, "<Q")
            results[12:14] = struct.unpack("<2H", vm.mem_read(depth, 4))
            results[14:16] = [read(rsp + 0x38, "<H"), read(rsp + 0x40, "<H")]
            if active:
                pixels = struct.pack("<4i", *results[6:10])
                vm.mem_write(state + 4348, pixels)
                vm.mem_write(state + 4364, pixels)
                vm.mem_write(source + 11444, pixels)
                vm.mem_write(state + 4380, struct.pack("<7H", 1, 1, 0, 0, 0, 0, 0))
                write(source + 7920, pool + 504 + 24, "<Q")
            returned()
        elif name == "AKR_Create":
            created = pool + 1008
            write(vm.reg_read(reg.UC_X86_REG_RCX), 3, "<H")
            write(created + 16, 0x1003, "<I")
            write(created + 24, read(rsp + 0x70, "<Q"), "<Q")
            write(created + 40, 99, "<I")
            write(created + 44, read(rsp + 0x48, "<I"), "<I")
            write(created + 60, vm.reg_read(reg.UC_X86_REG_RDX), "<H")
            write(created + 62, vm.reg_read(reg.UC_X86_REG_R8), "<H")
            gpu_trace.append("create")
            returned()
        elif name == "AKR_Transition":
            gpu_trace.append(
                (
                    "transition",
                    vm.reg_read(reg.UC_X86_REG_RDX),
                    vm.reg_read(reg.UC_X86_REG_R9),
                    read(rsp + 0x28, "<I"),
                )
            )
            returned()
        elif name == "AKR_FlushTransitions":
            gpu_trace.append("barriers")
            returned()
        elif name == "AKR_CopyBoundColor":
            assert vm.reg_read(reg.UC_X86_REG_RDX) == pool + 1008 + 24
            gpu_trace.append("copy")
            returned()
        elif name == "AKR_DrawRectangle":
            assert read(source + 7920, "<Q") == pool + 1008 + 24
            uv = [read(rsp + offset, "<f") for offset in (0x48, 0x50, 0x58, 0x60)]
            x, y, width, height = results[6:10]
            expected = (
                max(0, x) / output_width,
                max(0, y) / output_height,
                min(output_width, x + width) / output_width,
                min(output_height, y + height) / output_height,
            )
            assert all(abs(a - b) < 1e-5 for a, b in zip(uv, expected)), (uv, expected)
            gpu_trace.append("rectangle")
            returned()
        elif name == "AKR_SetViewportScissor":
            vm.mem_write(
                state + 4348, bytes(vm.mem_read(vm.reg_read(reg.UC_X86_REG_RDX), 16))
            )
            vm.mem_write(
                state + 4364, bytes(vm.mem_read(vm.reg_read(reg.UC_X86_REG_R8), 16))
            )
            returned()
        elif name == "cookie":
            returned()

    registered_hooks = [vm.hook_add(UC_HOOK_CODE, hook)]
    if linked:

        def missing(machine, access, address, size, value, unused):
            if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
                return False
            for at in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
                page(at)
            return True

        registered_hooks.append(vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing))

    def call(symbol, values, extra=None):
        write(stack, stop, "<Q")
        vm.reg_write(reg.UC_X86_REG_RSP, stack)
        for register, value in zip(
            (
                reg.UC_X86_REG_RCX,
                reg.UC_X86_REG_RDX,
                reg.UC_X86_REG_R8,
                reg.UC_X86_REG_R9,
            ),
            values,
        ):
            vm.reg_write(register, value)
        if extra is not None:
            write(stack + 0x28, extra, "<Q")
        vm.emu_start(base + symbol, stop, count=100000)
        return vm.reg_read(reg.UC_X86_REG_RAX)

    if active:
        stamp = linked["symbols"]["DW_AltKillcamRender_Stamp"]
        assert call(stamp, (backend, 0, 1, 77), inset) & 255 == 1
        call(target["rva"], (context, task, view, backend))
        assert "copy" in gpu_trace and "rectangle" not in gpu_trace
        second_backend = arena + 0x30000
        write(second_backend + 33256, 123, "<I")
        write(second_backend + 33264, 0, "<I")
        write(second_backend + 33288, view, "<Q")
        write(view + 11592, second_backend, "<Q")
        assert call(stamp, (second_backend, 0, 2, 77), inset) & 255 == 1
        call(target["rva"], (context, task, view, second_backend))
        assert (
            gpu_trace.count("create")
            == gpu_trace.count("copy")
            == gpu_trace.count("rectangle")
            == 1
        )
        assert read(source + 7920, "<Q") == pool + 504 + 24
    else:
        call(target["rva"], (context, task, view, backend))
    # Each callback closes over this VM. Remove native hook references before
    # returning so completed cases release their emulator and translation cache.
    for handle in registered_hooks:
        vm.hook_del(handle)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve()
    spec = importlib.util.spec_from_file_location(
        "render_prepare", ROOT / "tools/prepare-alt-killcam-render.py"
    )
    prepare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prepare)
    _, _, native, _, derived = prepare.inspect_native(snapshot)
    receipt = json.loads(
        (snapshot / "generated/alt-killcam-render-integration.json").read_bytes()
    )
    assert (
        receipt["passed"]
        and receipt["native"] == native
        and receipt["derived_globals"] == derived
    )
    for name, digest in receipt["dependencies"].items():
        assert sha(snapshot / name) == digest, name
    assert receipt["generator_sha256"] == sha(
        ROOT / "tools/prepare-alt-killcam-render.py"
    )
    assert receipt["clone_tool_sha256"] == sha(ROOT / "tools/replay_owned_clone.py")
    assert receipt["binding_table_sha256"] == sha(
        ROOT / "tools/alt_killcam_render_native.json"
    )
    linked = None
    linked_pe = linked_report = None
    linked_unwind = linked_comparisons = linked_active = 0
    assert receipt["reference_sha256"] == sha(
        ROOT / "tools/alt_killcam_render_reference.cpp"
    )
    sys.path.insert(0, str(snapshot / "tools"))
    from coff import read as read_coff

    unwind_records = 0
    for clone in receipt["clones"]:
        obj = read_coff(
            snapshot / "generated/alt-killcam-render" / (clone["helper"] + ".obj")
        )
        assert clone["gs_unwind"]
        unwind_records += verify_clone_unwind(obj, clone["gs_unwind"])
    if args.build:
        report = json.loads((args.build / "build-report.json").read_bytes())
        assert Path(report["source_root"]).resolve() == snapshot
        assert Path(report["executable"]).resolve().is_relative_to(args.build.resolve())
        assert (
            sha(report["executable"]) == report["sha256"]
            and report["unresolved_symbols"] == 0
        )
        for name in (
            "DW_AltKillcamRender.cpp",
            "DW_AltKillcamRender_Native.cpp",
        ):
            rows = [row for row in report["cpp"] if Path(row["source"]).name == name]
            assert len(rows) == 1 and rows[0]["source_sha256"] == sha(
                snapshot / "src" / name
            )
            assert sha(rows[0]["object"]) == rows[0]["object_sha256"]
            dependencies = {
                Path(row["path"]).name: row["sha256"] for row in rows[0]["dependencies"]
            }
            for dependency, digest in receipt["dependencies"].items():
                if Path(dependency).name == name or (
                    name == "DW_AltKillcamRender.cpp"
                    and Path(dependency).suffix == ".h"
                ):
                    assert dependencies[Path(dependency).name] == digest
        assert all(
            symbol in report["symbols"]
            for symbol in (
                "DW_AltKillcamRender_FinalComposite",
                "DW_AltKillcamRender_DestroyGlobalTargets",
                "DW_AltKillcamRender_Stamp",
                "DW_AltKillcamRender_SupportsCurrentGraph",
                "AKR_FinalCompositeNative",
                "AKR_DestroyGlobalTargetsNative",
            )
        )
        linked = report["sha256"]
        linked_report = report
        linked_pe = pefile.PE(str(report["executable"]), fast_load=True)
        linked_unwind = verify_linked_clones(receipt, linked_pe, report)
        for role, symbol in (
            ("final", "DW_AltKillcamRender_FinalComposite"),
            ("reset", "DW_AltKillcamRender_DestroyGlobalTargets"),
        ):
            identity = receipt["native"][role]["id"]
            assert report["symbols"][identity] == report["symbols"][symbol]
            assert (
                dict(
                    source="src/DW_AltKillcamRender.cpp",
                    symbol=symbol,
                    function_id=identity,
                )
                in report["source_units"]
            )
    pe = pefile.PE(str(prepare.IMAGE), fast_load=True)
    policy_cases = comparisons = 0
    with tempfile.TemporaryDirectory(
        prefix="alt-render-", dir=ROOT / "data"
    ) as temporary:
        for fallback in (False, True):
            dll = Path(temporary) / ("fallback.dll" if fallback else "policy.dll")
            command = [
                str(LLVM / "clang++.exe"),
                "-std=c++20",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-shared",
                "-I" + str(snapshot / "src"),
                str(snapshot / "src/DW_AltKillcamRender.cpp"),
                str(ROOT / "tools/alt_killcam_render_harness.cpp"),
                "-o",
                str(dll),
            ]
            if fallback:
                command += [
                    "-DDW_ALT_KILLCAM_FALLBACK_TEST",
                    str(ROOT / "tools/alt_killcam_render_reference.cpp"),
                ]
            run = subprocess.run(command, capture_output=True, text=True)
            assert run.returncode == 0, run.stdout + run.stderr
            library = ctypes.CDLL(str(dll))
            try:
                if not fallback:
                    library.Test_Case.argtypes = [ctypes.c_uint]
                    for scenario in range(29):
                        assert library.Test_Case(scenario) == 0, scenario
                        policy_cases += 1
                else:
                    library.Test_FallbackCase.argtypes = [ctypes.c_uint] * 4 + [
                        ctypes.c_float,
                        ctypes.c_uint,
                    ]
                    library.Test_FallbackResult.argtypes = [ctypes.c_uint]
                    sizes = [
                        (1920, 1080, 1920, 1080),
                        (1280, 720, 1920, 1080),
                        (3840, 2160, 1920, 1080),
                        (1111, 777, 1920, 1080),
                    ]
                    for dimensions in sizes:
                        for scale in (0.5, 1.0, 1.25):
                            for mask in range(16):
                                expected = original_case(
                                    receipt, pe, *dimensions, scale, mask
                                )
                                if linked_pe:
                                    mapped = original_case(
                                        receipt,
                                        linked_pe,
                                        *dimensions,
                                        scale,
                                        mask,
                                        linked=linked_report,
                                    )
                                    assert mapped == expected, (
                                        dimensions,
                                        scale,
                                        mask,
                                        expected,
                                        mapped,
                                    )
                                    linked_comparisons += 1
                                    if mask == 0:
                                        paired = original_case(
                                            receipt,
                                            linked_pe,
                                            *dimensions,
                                            scale,
                                            mask,
                                            linked=linked_report,
                                            active=True,
                                        )
                                        assert paired == expected
                                        linked_active += 1
                                library.Test_FallbackCase(*dimensions, scale, mask)
                                actual = [
                                    library.Test_FallbackResult(index)
                                    for index in range(16)
                                ]
                                assert actual == expected, (
                                    dimensions,
                                    scale,
                                    mask,
                                    expected,
                                    actual,
                                )
                                comparisons += 1
            finally:
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(library._handle))
    output = dict(
        passed=True,
        policy_cases=policy_cases,
        original_instruction_comparisons=comparisons,
        exact_native_unwind_records=unwind_records,
        linked_native_unwind_records=linked_unwind,
        linked_default_callback_comparisons=linked_comparisons,
        linked_active_capture_composite_pairs=linked_active,
        linked_image_sha256=linked,
        source_sha256=receipt["source_sha256"],
        image_sha256=receipt["image_sha256"],
        native_clone_preserved=all(
            clone["preserved_outside_fixups"] for clone in receipt["clones"]
        ),
        game_run_performed=False,
        full_engine_build_performed=False,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output))


if __name__ == "__main__":
    main()
