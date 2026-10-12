"""Check native camera compatibility and execute the authored secondary-scene owner.

The CPU fixtures model native renderer boundaries; they do not exercise a GPU.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile
from unicorn import (
    Uc,
    UC_ARCH_X86,
    UC_MODE_64,
    UC_HOOK_CODE,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
)
import unicorn.x86_const as reg

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path("C:/Program Files/LLVM/bin")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def original_case(
    pe,
    receipt,
    role,
    local,
    active=0,
    type_=0,
    first=0,
    flag=0,
    pip=0,
    draw=3,
    linked=None,
):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    base = pe.OPTIONAL_HEADER.ImageBase
    arena, mapped = 0x100000000, set()
    vm.mem_map(arena, 0x400000)
    # Execute the actual Win64 __chkstk prologue against the mapped fixture
    # stack. Windows stores StackBase/StackLimit at TEB+8/+16; the native
    # probe reads GS:[16] and preserves RAX (the requested allocation).
    teb = arena + 0x300100
    vm.mem_write(teb + 8, struct.pack("<QQ", arena + 0x400000, arena + 0x380000))
    vm.reg_write(reg.UC_X86_REG_GS_BASE, teb)

    def page(address):
        start = address & ~4095
        if start not in mapped:
            vm.mem_map(start, 4096)
            vm.mem_write(start, pe.get_data(start - base, 4096).ljust(4096, b"\0"))
            mapped.add(start)

    target = receipt["native"][role]
    start = (
        target["rva"]
        if linked is None
        else linked["symbols"][
            {
                "entity": "DW_AltKillcam_EntityView",
                "fov": "DW_AltKillcam_EntityFov",
                "render": "DW_AltKillcam_RenderScene",
            }[role]
        ]
    )
    for a in range((base + start) & ~4095, base + start + target["bytes"], 4096):
        page(a)
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    instructions = list(cs.disasm(pe.get_data(start, target["bytes"]), base + start))
    calls = [
        i.operands[0].imm
        for i in instructions
        if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
    ]
    for i in instructions:
        for o in i.operands:
            if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP:
                page(i.address + i.size + o.mem.disp)
    for a in calls:
        page(a)
    cg = arena + 0x1000
    slot = base + (
        receipt["derived_globals"]["AK_CgGlobals"]["rva"]
        if linked is None
        else linked["symbols"]["AK_CgGlobals"]
    )
    page(slot)
    vm.mem_write(slot, struct.pack("<QQ", cg, cg))
    vm.mem_write(cg + 533720, struct.pack("<ii", active, type_))
    vm.mem_write(cg + 168533, bytes([flag]))
    if role == "render":
        slot = base + (
            receipt["derived_globals"]["AK_FirstClient"]["rva"]
            if linked is None
            else linked["symbols"]["AK_FirstClient"]
        )
        page(slot)
        vm.mem_write(slot, struct.pack("<i", first))
    refdef, stop, stack = arena + 0x200000, arena + 0x300000, arena + 0x3FFF08
    vm.mem_write(stack, struct.pack("<Q", stop))
    vm.reg_write(reg.UC_X86_REG_RSP, stack)
    vm.reg_write(reg.UC_X86_REG_RCX, local)
    vm.reg_write(reg.UC_X86_REG_RDX, refdef)
    vm.reg_write(reg.UC_X86_REG_R8, draw)
    observed, sequence = None, []
    names = [
        "AK_NextView",
        "AK_RealTime",
        "AK_TextureAtlasTime",
        "AK_DefaultFeatures",
        "AK_IsPipView",
        "AK_Exposure",
        "AK_SceneFrame",
        "AK_RenderNative",
        "security",
    ]
    boundaries = dict(zip(calls, names)) if role == "render" and linked is None else {}
    if linked is not None:
        boundaries = {base + linked["symbols"][name]: name for name in names[:-1]}
        boundaries[base + linked["symbols"]["fn_c84fea47f33a39ca"]] = "security"
        boundaries[base + linked["symbols"]["AK_IsMainThread"]] = "main_thread"
        boundaries[base + linked["symbols"]["DW_AltKillcamRender_Disarm"]] = "disarm"

        def missing(vm, access, address, size, value, unused):
            if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
                return False
            page(address)
            return True

        vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)

    def returned(value=0):
        rsp = vm.reg_read(reg.UC_X86_REG_RSP)
        ret = struct.unpack("<Q", vm.mem_read(rsp, 8))[0]
        vm.reg_write(reg.UC_X86_REG_RAX, value)
        vm.reg_write(reg.UC_X86_REG_RSP, rsp + 8)
        vm.reg_write(reg.UC_X86_REG_RIP, ret)

    def hook(vm, address, size, unused):
        nonlocal observed
        if address == stop:
            vm.emu_stop()
            return
        name = boundaries.get(address)
        if name is None:
            return
        if name == "main_thread":
            returned(1)
            return
        if name == "disarm":
            returned()
            return
        sequence.append(name)
        pointer = vm.reg_read(reg.UC_X86_REG_RCX)
        if name == "AK_NextView":
            vm.mem_write(pointer, struct.pack("<i", 0))
            returned()
        elif name == "AK_RealTime":
            returned(321)
        elif name == "AK_TextureAtlasTime":
            assert pointer == 321
            returned()
        elif name == "AK_DefaultFeatures":
            vm.mem_write(pointer, bytes(48))
            returned()
        elif name == "AK_IsPipView":
            returned(pip)
        elif name == "AK_Exposure":
            assert bytes(vm.mem_read(pointer, 48)) == bytes(48)
            returned()
        elif name == "AK_SceneFrame":
            returned(42)
        elif name == "AK_RenderNative":
            assert pointer == refdef and vm.reg_read(reg.UC_X86_REG_R8) == draw
            assert vm.reg_read(reg.UC_X86_REG_XMM1) & 0xFFFFFFFF == 0x3F800000
            observed = bytes(vm.mem_read(vm.reg_read(reg.UC_X86_REG_R9), 48))
            returned()
        else:
            returned()

    vm.hook_add(UC_HOOK_CODE, hook)
    vm.emu_start(base + start, stop, count=10000)
    if role == "render":
        assert sequence == names
        assert bytes(vm.mem_read(cg + 167080, 4)) == bytes(4)
        return observed
    return bool(vm.reg_read(reg.UC_X86_REG_RAX) & 255)


def streaming_chain(pe, receipt, fixed, linked=None):
    """Execute the native producer/end/static/append chain; model platform leaves.

    Without a linked image the compiled scope policy is checked by the C++
    harness, and this function executes its one-update effect. With a linked
    image it also executes the actual authored scope guard and native clone.
    """
    base = pe.OPTIONAL_HEADER.ImageBase
    arena, mapped = 0x100000000, set()
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    vm.mem_map(arena, 0x1000000)
    glob, view, output = arena + 0x1000, arena + 0xB00000, arena + 0xB10000
    backend, stack, stop, teb = (
        arena + 0xB20000,
        arena + 0xFFF000,
        arena + 0xD00000,
        arena + 0xD01000,
    )
    vm.mem_write(teb + 8, struct.pack("<QQ", arena + 0x1000000, arena + 0xE00000))
    vm.reg_write(reg.UC_X86_REG_GS_BASE, teb)

    def page(address):
        start = address & ~4095
        if start not in mapped:
            vm.mem_map(start, 4096)
            vm.mem_write(start, pe.get_data(start - base, 4096).ljust(4096, b"\0"))
            mapped.add(start)

    def missing(vm, access, address, size, value, unused):
        if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
            return False
        page(address)
        return True

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    bodies, calls = {}, {}
    for role in (
        "streaming",
        "stream_end_frame",
        "stream_static_view",
        "stream_append_view",
    ):
        binding = receipt["native"][role]
        rva = binding["rva"] if linked is None else linked["symbols"][binding["id"]]
        if role == "streaming" and linked is not None:
            rva = linked["symbols"]["AK_OriginalUpdateStreaming"]
        bodies[role] = list(
            decoder.disasm(pe.get_data(rva, binding["bytes"]), base + rva)
        )
        calls[role] = [
            i.operands[0].imm
            for i in bodies[role]
            if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
        ]
    pointer_refs = [
        i.address + i.size + o.mem.disp
        for i in bodies["streaming"]
        for o in i.operands
        if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP
    ]
    stream_slot = pointer_refs[0]
    page(stream_slot)
    vm.mem_write(stream_slot, struct.pack("<Q", glob))
    append_refs = [
        i.address + i.size + o.mem.disp
        for i in bodies["stream_append_view"]
        for o in i.operands
        if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP
    ]
    assert append_refs[1] == stream_slot
    # Both saved counts precede the first position (a 780-byte native record).
    saved = glob + 0x98B138
    vm.mem_write(saved, struct.pack("<III", 1, 0, 1))
    vm.mem_write(saved + 12, struct.pack("<I", 0xC4515C7F))
    # Deterministic data beyond the valid one-client record exposes the native
    # unchecked phantom-client append, without depending on unrelated heap data.
    vm.mem_write(saved + 780, struct.pack("<I", 9) * 32)
    vm.mem_write(glob + 10006824, b"\1")
    vm.mem_write(glob + 2501704 * 4, struct.pack("<i", 0))
    vm.mem_write(view + 328, struct.pack("<f", 1.0))
    vm.mem_write(view + 11592, struct.pack("<Qii", backend, 0, 0))
    boundaries = {
        a: ("platform", 0)
        for role in ("streaming", "stream_end_frame", "stream_append_view")
        for a in calls[role]
    }
    boundaries[calls["streaming"][0]] = ("wait89", 0)
    boundaries[calls["streaming"][2]] = ("enabled", 1)
    boundaries[calls["streaming"][3]] = ("cached_views", 1)
    deduplicate = next(
        i.operands[0].imm
        for i in reversed(bodies["stream_static_view"])
        if i.mnemonic == "jmp" and i.operands[0].type == X86_OP_IMM
    )
    boundaries[deduplicate] = ("deduplicate", 0)
    scope_address = None
    if linked is not None:
        wrapper = linked["symbols"]["DW_AltKillcam_UpdateStreaming"]
        instructions = list(decoder.disasm(pe.get_data(wrapper, 256), base + wrapper))
        active = next(
            i
            for i in instructions
            if i.mnemonic == "cmp"
            and any(
                o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP and o.size == 1
                for o in i.operands
            )
        )
        operand = next(o for o in active.operands if o.type == X86_OP_MEM)
        scope_address = active.address + active.size + operand.mem.disp - 20
        page(scope_address)
        backend_slot = base + linked["symbols"]["AK_Backend"]
        page(backend_slot)
        vm.mem_write(backend_slot, struct.pack("<Q", backend))
        boundaries[base + linked["symbols"]["AK_IsMainThread"]] = ("main_thread", 1)
        boundaries[base + linked["symbols"]["AK_WaitWorkerType"]] = ("wait89", 0)
    waits, overflow = 0, None

    def returned(value):
        rsp = vm.reg_read(reg.UC_X86_REG_RSP)
        ret = struct.unpack("<Q", vm.mem_read(rsp, 8))[0]
        vm.reg_write(reg.UC_X86_REG_RAX, value)
        vm.reg_write(reg.UC_X86_REG_RSP, rsp + 8)
        vm.reg_write(reg.UC_X86_REG_RIP, ret)

    def hook(vm, address, size, unused):
        nonlocal waits
        if address == stop:
            vm.emu_stop()
        elif address in boundaries:
            name, value = boundaries[address]
            if name == "wait89":
                assert vm.reg_read(reg.UC_X86_REG_RCX) == 89
                waits += 1
            returned(value)

    def write(vm, access, address, size, value, unused):
        nonlocal overflow
        if output + 548 <= address < output + 4096:
            overflow = dict(
                address_offset=address - output,
                bytes=size,
                instruction_rva=vm.reg_read(reg.UC_X86_REG_RIP) - base,
            )
            vm.emu_stop()

    vm.hook_add(UC_HOOK_CODE, hook)
    vm.hook_add(UC_HOOK_MEM_WRITE, write)

    def run(address, rcx, rdx=0):
        vm.reg_write(reg.UC_X86_REG_RSP, stack)
        vm.mem_write(stack, struct.pack("<Q", stop))
        vm.reg_write(reg.UC_X86_REG_RCX, rcx)
        vm.reg_write(reg.UC_X86_REG_RDX, rdx)
        vm.emu_start(address, stop, count=100000)
        assert overflow is not None or vm.reg_read(reg.UC_X86_REG_RIP) == stop

    native_update = bodies["streaming"][0].address
    if fixed and linked is not None:
        vm.mem_write(scope_address, struct.pack("<QiiIB3x", backend, 0, 0, 0, 1))
        run(base + linked["symbols"]["DW_AltKillcam_UpdateStreaming"], view)
        assert (
            struct.unpack("<i", vm.mem_read(glob + 2501704 * 4, 4))[0] == 0
            and waits == 1
        )
        vm.mem_write(scope_address, bytes(24))
        run(base + linked["symbols"]["DW_AltKillcam_UpdateStreaming"], view)
    else:
        for _ in range(1 if fixed else 2):
            run(native_update, view)
    updates = struct.unpack("<i", vm.mem_read(glob + 2501704 * 4, 4))[0]
    assert updates == (1 if fixed else 2)
    run(bodies["stream_end_frame"][0].address, 0)
    assert struct.unpack("<i", vm.mem_read(glob + 2501705 * 4, 4))[0] == updates
    run(bodies["stream_static_view"][0].address, output)
    assert (overflow is None) == fixed
    if fixed:
        assert struct.unpack("<I", vm.mem_read(output + 544, 4))[0] == 1
    return dict(
        fixed=fixed,
        native_updates=updates,
        saved_clients=updates,
        overflow=overflow,
        native_wait_calls=waits,
        linked_scope_executed=bool(fixed and linked is not None),
        platform_and_view_cache_leaves_modeled=True,
    )


def verify_linked(snapshot, receipt, build, owners):
    import sys

    sys.path.insert(0, str(snapshot / "tools"))
    from coff import read

    report = json.loads((build / "build-report.json").read_bytes())
    assert Path(report["source_root"]).resolve() == snapshot
    assert (
        report["input_sha256"] == receipt["image_sha256"]
        and report["unresolved_symbols"] == 0
    )
    executable = Path(report["executable"]).resolve()
    assert (
        executable.is_relative_to(build.resolve())
        and sha(executable) == report["sha256"]
    )
    pe = pefile.PE(str(executable))
    associations = json.loads((snapshot / "source-units.json").read_bytes())
    symbols = report["symbols"]
    for role, symbol, _ in owners:
        identity = receipt["native"][role]["id"]
        assert symbols[identity] == symbols[symbol]
        expected = dict(
            source="src/DW_AltKillcam.cpp", symbol=symbol, function_id=identity
        )
        assert [u for u in associations["units"] if u["function_id"] == identity] == [
            expected
        ]
    for alias, identity in receipt["imports"].items():
        assert symbols[alias] == symbols[identity], alias
        assert [r for r in associations["imports"] if r["symbol"] == alias] == [
            dict(symbol=alias, symbol_id=identity)
        ]
    objects = {}
    for name in (
        "DW_AltKillcam.cpp",
        "DW_AltKillcam_Native.cpp",
        "ScrPlace_EndFrame.cpp",
    ):
        rows = [
            r for r in report["cpp"] if Path(r["source"]).as_posix() == "src/" + name
        ]
        assert len(rows) == 1, name
        row = rows[0]
        assert row["source_sha256"] == sha(snapshot / "src" / name)
        objpath = Path(row["object"]).resolve()
        assert (
            objpath.is_relative_to(build.resolve())
            and sha(objpath) == row["object_sha256"]
        )
        dependencies = {
            Path(r["path"]).resolve(): r["sha256"] for r in row["dependencies"]
        }
        assert len(dependencies) == len(row["dependencies"])
        for path, expected in dependencies.items():
            assert sha(path) == expected, path
        required = (
            {
                r: d
                for r, d in receipt["dependencies"].items()
                if not r.endswith("DW_AltKillcam_Native.cpp")
            }
            if name == "DW_AltKillcam.cpp"
            else {"src/" + name: sha(snapshot / "src" / name)}
        )
        for relative, expected in required.items():
            assert dependencies[(snapshot / relative).resolve()] == expected, relative
        objects[name] = read(objpath)

    def callback(obj, name):
        rows = [
            s for s in obj["symbols"].values() if s["name"] == name and s["section"] > 0
        ]
        assert len(rows) == 1
        symbol = rows[0]
        section = obj["sections"][symbol["section"] - 1]
        finish = min(
            [
                s["value"]
                for s in obj["symbols"].values()
                if s["section"] == symbol["section"]
                and s["kind"] == 32
                and s["value"] > symbol["value"]
            ]
            or [len(section["data"])]
        )
        original = bytearray(section["data"][symbol["value"] : finish])
        actual = bytearray(pe.get_data(symbols[name], len(original)))
        references = []
        for offset, index, kind in section["relocations"]:
            if not symbol["value"] <= offset < finish:
                continue
            at = offset - symbol["value"]
            target = obj["symbols"][index]
            assert 4 <= kind <= 9
            if target["name"] in symbols:
                resolved = (
                    symbols[name]
                    + at
                    + 4
                    + kind
                    - 4
                    + struct.unpack_from("<i", actual, at)[0]
                )
                assert (
                    resolved
                    == symbols[target["name"]]
                    + struct.unpack_from("<i", original, at)[0]
                )
            references.append(target["name"])
            original[at : at + 4] = actual[at : at + 4] = bytes(4)
        assert original == actual, name
        return references, len(actual)

    lengths = {}
    for _, name, _ in owners:
        _, lengths[name] = callback(objects["DW_AltKillcam.cpp"], name)
    _, lengths["DW_AltKillcam_Init"] = callback(
        objects["DW_AltKillcam.cpp"], "DW_AltKillcam_Init"
    )
    frames = [
        u for u in associations["units"] if u["source"] == "src/ScrPlace_EndFrame.cpp"
    ]
    assert len(frames) == 1
    refs, _ = callback(objects["ScrPlace_EndFrame.cpp"], frames[0]["symbol"])
    assert refs.count("DW_AltKillcam_Init") == 1
    runtime_count = 0
    for clone in receipt["clones"]:
        start = symbols[clone["helper"]]
        original = bytearray(
            module_image().get_data(
                receipt["native"][
                    next(r for r, _, h in owners if h == clone["helper"])
                ]["rva"],
                clone["bytes"],
            )
        )
        actual = bytearray(pe.get_data(start, len(original)))
        for fixup in clone["external_fixups"]:
            if fixup.get("section"):
                continue
            at = fixup["offset"]
            if fixup["kind"] == 3:
                target = struct.unpack_from("<I", actual, at)[0]
            else:
                target = (
                    start
                    + at
                    + 4
                    + fixup["trailing_instruction_bytes"]
                    + struct.unpack_from("<i", actual, at)[0]
                )
            assert target == symbols[fixup["stable_id"]], fixup
            original[at : at + 4] = actual[at : at + 4] = bytes(4)
        assert original == actual, clone["helper"]
        records = clone["gs_unwind"]
        first = records[0]["begin"]
        entries = [
            e.struct
            for e in pe.DIRECTORY_ENTRY_EXCEPTION
            if start <= e.struct.BeginAddress < start + clone["bytes"]
        ]
        entries.sort(key=lambda e: e.BeginAddress)
        assert len(entries) == len(records)
        for index, (record, entry) in enumerate(zip(records, entries)):
            assert (entry.BeginAddress - start, entry.EndAddress - start) == (
                record["begin"] - first,
                record["end"] - first,
            )
            source = bytes.fromhex(record["bytes"])
            header = 4 + ((source[2] + 1) & ~1) * 2
            flags = source[0] >> 3
            raw = pe.get_data(entry.UnwindData, len(source))
            assert raw[:header] == source[:header]
            if flags == 3:
                assert struct.unpack_from("<II", raw, header) == (
                    symbols["fn_3da1e16560231243"],
                    struct.unpack_from("<I", source, header + 4)[0],
                )
            elif flags == 4:
                chain = struct.unpack_from("<III", source, header)
                parent = next(
                    j
                    for j, r in enumerate(records[:index])
                    if chain == (r["begin"], r["end"], r["unwind_rva"])
                )
                expected = entries[parent]
                assert struct.unpack_from("<III", raw, header) == (
                    expected.BeginAddress,
                    expected.EndAddress,
                    expected.UnwindData,
                )
            else:
                assert flags == 0 and raw == source
        runtime_count += len(entries)
    return (
        pe,
        report,
        dict(
            sha256=report["sha256"],
            callback_bytes=lengths,
            native_clone_bytes=sum(c["bytes"] for c in receipt["clones"]),
            native_runtime_records=runtime_count,
            compiled_objects_verified=3,
            actual_boot_call_verified=True,
        ),
    )


_ORIGINAL_IMAGE = None


def module_image():
    global _ORIGINAL_IMAGE
    if _ORIGINAL_IMAGE is None:
        _ORIGINAL_IMAGE = pefile.PE(
            "E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe"
        )
    return _ORIGINAL_IMAGE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve()
    spec = importlib.util.spec_from_file_location(
        "alt_prepare", ROOT / "tools/prepare-alt-killcam-integration.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pe, catalog, native, imports, declarations, globals_ = module.inspect_native(
        snapshot
    )
    receipt = json.loads(
        (snapshot / "generated/alt-killcam-integration.json").read_bytes()
    )
    assert (
        receipt["passed"]
        and receipt["native"] == json.loads(json.dumps(native))
        and receipt["derived_globals"] == globals_
    )
    assert receipt["generator_sha256"] == sha(
        ROOT / "tools/prepare-alt-killcam-integration.py"
    )
    assert receipt["clone_tool_sha256"] == sha(ROOT / "tools/replay_owned_clone.py")
    assert receipt["binding_table_sha256"] == sha(
        ROOT / "tools/alt_killcam_native.json"
    )
    for relative, expected in receipt["dependencies"].items():
        assert sha(snapshot / relative) == expected, relative
    linked = None
    linked_pe = linked_report = None
    if args.build:
        linked_pe, linked_report, linked = verify_linked(
            snapshot, receipt, args.build.resolve(), module.OWNERS
        )
    with tempfile.TemporaryDirectory(
        prefix="alt-killcam-", dir=ROOT / "data"
    ) as directory:
        executable = Path(directory) / "camera-test.exe"
        result = subprocess.run(
            [
                str(LLVM / "clang++.exe"),
                "-std=c++20",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I" + str(snapshot / "src"),
                str(ROOT / "tools/alt_killcam_harness.cpp"),
                "-o",
                str(executable),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr + result.stdout
        runs = [
            subprocess.run([str(executable)], capture_output=True, text=True)
            for _ in range(2)
        ]
        for result in runs:
            assert result.returncode == 0, result.stderr + result.stdout
        assert runs[0].stdout == runs[1].stdout
    predicate_cases = submission_cases = linked_cases = 0
    for line in runs[0].stdout.splitlines():
        fields = line.split()
        if fields[0] == "PRED":
            local, active, type_, entity, fov = map(int, fields[1:])
            assert original_case(pe, receipt, "entity", local, active, type_) == bool(
                entity
            )
            assert original_case(pe, receipt, "fov", local, active, type_) == bool(fov)
            if linked_report:
                assert original_case(
                    linked_pe,
                    receipt,
                    "entity",
                    local,
                    active,
                    type_,
                    linked=linked_report,
                ) == bool(entity)
                assert original_case(
                    linked_pe,
                    receipt,
                    "fov",
                    local,
                    active,
                    type_,
                    linked=linked_report,
                ) == bool(fov)
                linked_cases += 2
            predicate_cases += 1
        elif fields[0] == "SUBMIT":
            local, first, flag, pip, draw = map(int, fields[1:6])
            assert original_case(
                pe, receipt, "render", local, first=first, flag=flag, pip=pip, draw=draw
            ) == bytes.fromhex(fields[6])
            if linked_report:
                assert original_case(
                    linked_pe,
                    receipt,
                    "render",
                    local,
                    first=first,
                    flag=flag,
                    pip=pip,
                    draw=draw,
                    linked=linked_report,
                ) == bytes.fromhex(fields[6])
                linked_cases += 1
            submission_cases += 1
    harness = json.loads(runs[0].stdout.splitlines()[-1])
    assert predicate_cases == 48 and submission_cases == 48
    expected_cpu = dict(cases=236, active_pair_cases=54, failure_cases=19, origin_cases=100,
                        streaming_scope_cases=8, third_person_cases=4, continuation_cases=10,
                        uncaptured_cases=2,
                        replay_boundary_cases=16, camera_cut_cases=12, inset_cases=6)
    assert harness == expected_cpu, harness
    assert len(receipt["clones"]) == 8
    assert receipt["native"]["third_person"]["bytes"] == 446
    assert receipt["native"]["third_person"]["sha256"] == (
        "e1ef7ba01d3ab473db9f89d02d95da69fbc0f21e2029db706c507d0601184160")
    assert "uint32_t AK_OriginalUpdateThirdPerson(uint32_t);" in (
        snapshot / "src/DW_AltKillcamBindings.h").read_text()
    streaming = [streaming_chain(pe, receipt, fixed) for fixed in (False, True)]
    if linked_report:
        streaming.extend(
            streaming_chain(linked_pe, receipt, fixed, linked_report)
            for fixed in (False, True)
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    proof = dict(
        schema=1,
        passed=True,
        image_sha256=receipt["image_sha256"],
        dependencies=receipt["dependencies"],
        focused_cpu_cases=harness,
        native_predicate_comparisons=predicate_cases * 2,
        complete_native_submission_comparisons=submission_cases,
        independent_process_runs=2,
        native_full_body_clones=len(receipt["clones"]),
        native_streaming_chain_regressions=streaming,
        fixture_sha256=sha(ROOT / "tools/alt_killcam_harness.cpp"),
        checker_sha256=sha(Path(__file__)),
        linked_build=linked,
        linked_image_sha256=linked["sha256"] if linked else None,
        linked_image_identity_verified=bool(linked),
        linked_frontend_instruction_cases=linked_cases,
        linked_frontend_execution_performed=bool(linked_cases),
        renderer_boundaries_modeled=True,
        gpu_rendering_tested=False,
        game_run_performed=False,
    )
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    main()
