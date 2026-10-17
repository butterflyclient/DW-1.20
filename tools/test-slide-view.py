"""Deferred slide-view gate. --self-test never compiles or assembles anything.

--build belongs to an approved future build verification: it checks linked
production ownership and compiles an isolated mocked behavior DLL, never a game.
"""

import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

import pefile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
OWNER_RVA, OWNER_SIZE = 0xD261B0, 243
OWNER_SHA = "19ad8df78554d570a1a991e90cb0e55131bf0dec29d090aee3d49ac2f5ed7df1"
SYMBOL, HELPER = "DW_SlideView_StartTransition", "DSV_OriginalStartTransition"


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def native_evidence():
    """Read original PE and execute the slide argument setup through its call."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
    from unicorn.x86_const import (
        UC_X86_REG_RSI,
        UC_X86_REG_RSP,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
    )

    assert sha(IMAGE) == IMAGE_SHA
    pe = pefile.PE(str(IMAGE))
    body = pe.get_data(OWNER_RVA, OWNER_SIZE)
    assert hashlib.sha256(body).hexdigest() == OWNER_SHA
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, OWNER_RVA))
    assert (
        sum(item.size for item in instructions) == OWNER_SIZE
        and instructions[-1].mnemonic == "ret"
    )
    assert not any(item.mnemonic in ("call", "push", "pop") for item in instructions)
    assert not any(
        entry.struct.BeginAddress <= OWNER_RVA < entry.struct.EndAddress
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION
    )
    base, arena, pages = pe.OPTIONAL_HEADER.ImageBase, 0x200000000, set()
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    vm.mem_map(arena, 0x10000)

    def page(address):
        start = address & ~4095
        if arena <= start < arena + 0x10000 or start in pages:
            return
        assert base <= start < base + pe.OPTIONAL_HEADER.SizeOfImage
        vm.mem_map(start, 4096)
        data = pe.get_data(start - base, 4096)
        if data:
            vm.mem_write(start, data)
        pages.add(start)

    def missing(machine, access, address, size, value, context):
        page(address)
        page(address + size - 1)
        return True

    pmove, player, stack = arena + 0x1000, arena + 0x2000, arena + 0x8000
    vm.mem_write(pmove, struct.pack("<QQ", 0, player))
    vm.mem_write(player + 460, struct.pack("<f", 30.0))
    vm.reg_write(UC_X86_REG_RSI, pmove)
    vm.reg_write(UC_X86_REG_RSP, stack)
    calls = []

    def hook(machine, address, size, context):
        if address != base + OWNER_RVA:
            return
        rsp = machine.reg_read(UC_X86_REG_RSP)
        goal = struct.unpack("<Q", machine.mem_read(rsp + 40, 8))[0]
        calls.append(
            dict(
                duration_ms=machine.reg_read(UC_X86_REG_RDX),
                ease_in=machine.reg_read(UC_X86_REG_R8),
                ease_out=machine.reg_read(UC_X86_REG_R9),
                goal_pitch=struct.unpack("<f", machine.mem_read(goal, 4))[0],
                goal_yaw=struct.unpack("<f", machine.mem_read(goal + 4, 4))[0],
                flags=struct.unpack("<I", machine.mem_read(rsp + 48, 4))[0],
            )
        )
        assert machine.reg_read(UC_X86_REG_RCX) == pmove
        machine.emu_stop()

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    vm.hook_add(UC_HOOK_CODE, hook)
    vm.emu_start(base + 0x112EB15, base + 0x112EB63, count=100)
    expected = dict(
        duration_ms=1100, ease_in=4, ease_out=4, goal_pitch=15.0, goal_yaw=0.0, flags=9
    )
    assert calls == [expected], calls
    result = dict(
        image_sha256=IMAGE_SHA,
        leaf_bytes=OWNER_SIZE,
        leaf_sha256=OWNER_SHA,
        original_has_unwind=False,
        transition=calls[0],
        argument_setup_rva=0x112EB15,
        argument_setup_sha256=hashlib.sha256(pe.get_data(0x112EB15, 0x4E)).hexdigest(),
        scope="Original native caller instructions, isolated CPU; target captured before transition execution",
    )
    pe.close()
    return result


def harness(snapshot, compiler):
    import _ctypes

    source = snapshot / "tools/slide_view_harness.cpp"
    source_sha = sha(source)
    linker = compiler.parent / "lld-link.exe"
    scratch = ROOT / "data/research/weapon-inspect-20261017"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="slide-view-", dir=scratch) as temporary:
        folder = Path(temporary)
        obj, dll = folder / "fixture.obj", folder / "fixture.dll"
        command = [
            str(compiler),
            "--target=x86_64-pc-windows-msvc",
            "-std=c++20",
            "-O2",
            "-ffreestanding",
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-stack-protector",
            "-mno-stack-arg-probe",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(snapshot / "src"),
            "-c",
            str(source),
            "-o",
            str(obj),
        ]
        subprocess.run(command, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(
            [
                str(linker),
                "/dll",
                "/noentry",
                "/nodefaultlib",
                "/out:" + str(dll),
                str(obj),
            ],
            check=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        library = ctypes.WinDLL(str(dll))
        try:
            library.SlideView_Run.restype = ctypes.c_int
            library.SlideView_Cases.restype = ctypes.c_uint
            result = library.SlideView_Run()
            assert result == 0, ("Slide behavior harness failed at source line", result)
            cases = library.SlideView_Cases()
            assert cases == 24, cases
        finally:
            _ctypes.FreeLibrary(library._handle)
        assert sha(source) == source_sha
        receipt = dict(
            passed=True,
            cases=cases,
            harness_sha256=source_sha,
            object_sha256=sha(obj),
            dll_sha256=sha(dll),
            compiler_sha256=sha(compiler),
            linker_sha256=sha(linker),
            mocked_boundaries=[
                "native transition",
                "Dvar APIs",
                "backend/main-thread checks",
            ],
        )
    return receipt


def verify(build):
    build = Path(build).resolve(strict=True)
    report = read(build / "build-report.json")
    snapshot = Path(report["source_root"]).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    image = Path(report["executable"])
    image = (image if image.is_absolute() else build / image).resolve(strict=True)
    assert (
        image.is_relative_to(build)
        and sha(image) == report["sha256"]
        and not report["unresolved_symbols"]
    )
    checked = read(build / "verification-report.json")
    assert checked["sha256"] == report["sha256"] and not checked["unresolved_symbols"]
    proof = read(snapshot / "generated/slide-view-integration.json")
    assert (
        proof["passed"]
        and proof["native_bodies_assembled"]
        and proof["leaf_unwind_synthesized"]
    )
    native = native_evidence()
    assert report["input_sha256"] == proof["image_sha256"] == native["image_sha256"]
    assert proof["transition"] == native["transition"]
    assert proof["dvar"]["name"] == "cg_useOldSlide" and proof["dvar"]["type"] == "bool"
    assert proof["dvar"]["default"] is False and proof["dvar"]["flags"] == 1
    assert proof["generator_sha256"] == sha(snapshot / "tools/prepare-slide-view.py")
    assert proof["clone_tool_sha256"] == sha(snapshot / "tools/replay_owned_clone.py")
    for relative, digest in proof["dependencies"].items():
        assert sha(snapshot / relative) == digest, (
            "Changed slide generated input",
            relative,
        )
    assert sha(snapshot / "src/DW_SlideView.cpp") == proof["source_sha256"]
    assert sha(snapshot / "src/DW_SlideView.h") == proof["source_header_sha256"]
    catalog = read(snapshot / "generated/function-catalog.json")
    assert catalog["image_sha256"] == IMAGE_SHA
    identity = next(
        row["id"] for row in catalog["functions"] if row["rva"] == OWNER_RVA
    )
    assert proof["owners"][SYMBOL] == dict(
        identity=identity,
        rva=OWNER_RVA,
        bytes=OWNER_SIZE,
        sha256=OWNER_SHA,
        native_leaf=True,
    )
    desired = dict(source="src/DW_SlideView.cpp", symbol=SYMBOL, function_id=identity)
    assert [
        row
        for row in read(snapshot / "source-units.json")["units"]
        if row["function_id"] == identity
    ] == [desired]
    revisions = [
        row
        for row in read(snapshot / "source-workstation/units.json")["units"]
        if row["function_id"] == identity
    ]
    assert (
        len(revisions) == 1
        and revisions[0]["source"] == desired["source"]
        and revisions[0]["symbol"] == SYMBOL
    )
    assert revisions[0]["sha256"] == proof["source_sha256"]
    coff = module(snapshot / "tools/coff.py", "slide_coff")
    helper = module(snapshot / "tools/test-weapon-inspect.py", "slide_link_checker")
    symbols, objects, receipts, compiler = report["symbols"], {}, {}, None
    assert symbols[identity] == symbols[SYMBOL] != symbols[HELPER]
    main_thread = next(
        row["id"] for row in catalog["functions"] if row["rva"] == 0x12CF280
    )
    assert proof["imports"]["DSV_IsMainThread"] == main_thread
    for name in ("DW_SlideView.cpp", "DW_SlideView_Native.cpp"):
        rows = [
            row
            for row in report["cpp"]
            if Path(row["source"]).as_posix() == "src/" + name
        ]
        assert len(rows) == 1 and rows[0]["source_sha256"] == sha(
            snapshot / "src" / name
        )
        row = rows[0]
        objpath = Path(row["object"]).resolve(strict=True)
        assert objpath.is_relative_to(build) and sha(objpath) == row["object_sha256"]
        dependencies = {
            Path(item["path"]).resolve(): item["sha256"] for item in row["dependencies"]
        }
        assert len(dependencies) == len(row["dependencies"])
        for path, digest in dependencies.items():
            assert sha(path) == digest
        required = [name] + (
            ["DW_SlideView.h", "DW_SlideViewBindings.h", "replay_dvar.h"]
            if name == "DW_SlideView.cpp"
            else []
        )
        for item in required:
            path = (snapshot / "src" / item).resolve()
            assert dependencies[path] == sha(path)
        objects[name] = coff.read(objpath)
        receipts[name] = dict(
            source_sha256=row["source_sha256"], object_sha256=row["object_sha256"]
        )
        compiler = Path(row["compiler"]["path"])
        assert sha(compiler) == row["compiler"]["sha256"]
    for alias, stable in proof["imports"].items():
        assert symbols[alias] == symbols[stable], ("Wrong slide native binding", alias)
    graph = helper.linked_object(
        pefile.PE(str(image), fast_load=True),
        objects["DW_SlideView.cpp"],
        symbols,
        [SYMBOL, "DW_SlideView_Init"],
        report["rva_map"]["ranges"],
    )
    assert helper.branch_to(objects["DW_SlideView.cpp"], SYMBOL, HELPER)
    clone = proof["clones"][0]
    assert (
        len(proof["clones"]) == 1
        and clone["identity"] == identity
        and clone["helper"] == HELPER
    )
    assert (
        clone["bytes"] == OWNER_SIZE
        and clone["preserved_outside_fixups"]
        and clone["unwind_records"] == 1
    )
    package = snapshot / "generated/slide-view"
    assert sha(package / (HELPER + ".cpp")) == clone["source_sha256"]
    assert sha(package / (HELPER + ".obj")) == clone["object_sha256"]
    original = pefile.PE(str(IMAGE), fast_load=True)
    for evidence in proof["native_proofs"].values():
        assert (
            hashlib.sha256(
                original.get_data(evidence["rva"], evidence["bytes"])
            ).hexdigest()
            == evidence["sha256"]
        )
    assert {row["rva"] for row in proof["direct_callers"]} == {
        0x1107895,
        0x11287C3,
        0x112EB5E,
    }
    for caller in proof["direct_callers"]:
        raw = original.get_data(caller["rva"], 5)
        assert (
            raw[0] == 0xE8
            and caller["rva"] + 5 + struct.unpack_from("<i", raw, 1)[0] == OWNER_RVA
        )
    linked = pefile.PE(str(image))
    expected, actual = bytearray(original.get_data(OWNER_RVA, OWNER_SIZE)), bytearray(
        linked.get_data(symbols[HELPER], OWNER_SIZE)
    )
    for fixup in clone["external_fixups"]:
        assert fixup.get("section", ".text") == ".text"
        offset = fixup["offset"]
        target = (
            struct.unpack_from("<I", actual, offset)[0]
            if fixup["kind"] == 3
            else symbols[HELPER]
            + offset
            + 4
            + fixup["trailing_instruction_bytes"]
            + struct.unpack_from("<i", actual, offset)[0]
        )
        assert target == symbols[fixup["stable_id"]]
        actual[offset : offset + 4] = expected[offset : offset + 4] = bytes(4)
    assert actual == expected
    runtime = [
        entry.struct
        for entry in linked.DIRECTORY_ENTRY_EXCEPTION
        if entry.struct.BeginAddress == symbols[HELPER]
    ]
    assert len(runtime) == 1 and runtime[0].EndAddress == symbols[HELPER] + OWNER_SIZE
    assert linked.get_data(runtime[0].UnwindData, 4) == bytes([1, 0, 0, 0])
    behavior = harness(snapshot, compiler)
    return dict(
        passed=True,
        executable_sha256=report["sha256"],
        native=native,
        objects=receipts,
        linked_graph=graph,
        behavior_harness=behavior,
        compiled_image_verified=True,
        game_modified=False,
        game_launched=False,
        generated_fastfiles=False,
        scope="Native evidence, linked ownership and isolated production-owner behavior; live slide camera remains untested",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert bool(args.build) != args.self_test
    result = (
        dict(
            passed=True,
            self_test_only=True,
            native=native_evidence(),
            compiled_cpp=False,
            behavior_harness_executed=False,
            compiled_image_verified=False,
            game_modified=False,
            game_launched=False,
            generated_fastfiles=False,
        )
        if args.self_test
        else verify(args.build)
    )
    result["checker_sha256"] = sha(Path(__file__))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        "PASS original Replay slide tuple and 243-byte native leaf"
        if args.self_test
        else "PASS linked slide-view owner and mocked behavior cases"
    )
