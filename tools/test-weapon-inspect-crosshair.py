"""Check inspection crosshair ownership without launching or compiling a game.

--source-only validates the original target and the source contract. --build
executes the final linked adapter in an isolated CPU with three explicit API
boundaries modeled. Neither mode invokes a compiler or assembler.
"""

import argparse
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct

import pefile

ROOT = Path(__file__).resolve().parents[1]
SYMBOL = "DW_WeaponInspectCrosshair_Allowed"
HELPER = "WIC_OriginalAllowed"
IDENTITY = "fn_f964a37b43ace2fa"
SOURCE = "src/DW_WeaponInspectCrosshair.cpp"


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


def source_contract(snapshot):
    preparer = module(ROOT / "tools/prepare-weapon-inspect-crosshair.py", "crosshair_prepare")
    evidence = preparer.inspect(snapshot)[3]
    source = (ROOT / "integration/replay/DW_WeaponInspectCrosshair.cpp").read_text()
    assert "const bool allowed = WIC_OriginalAllowed(localClient, viewedPlayerState);" in source
    assert "if (!allowed || !DW_LocalBackend_IsEnabled() || !viewedPlayerState)" in source
    assert "DW_WeaponInspect_IsActive(viewedPlayerState) &&" in source
    assert "viewedPlayerState->hands[0].weaponTime > 800" in source
    assert source.index("WIC_OriginalAllowed(localClient") < source.index("if (!allowed")
    assert source.count("WIC_OriginalAllowed(localClient") == 1
    assert source.count("DW_WeaponInspect_IsActive(viewedPlayerState)") == 1
    layout = (ROOT / "integration/replay/DW_WeaponInspect.h").read_text()
    assert "int32_t weaponTime;" in layout
    assert "static_assert(offsetof(DWInspectWeaponHand, weaponTime) == 24);" in layout
    assert "static_assert(offsetof(DWInspectPlayerState, hands) == 1288);" in layout
    return dict(passed=True, native=evidence, production_behavior_executed=False,
                scope="Exact native owner/callers/unwind and source contract; no C++ compilation or execution")


def behavior(pe, symbols):
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
    from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                                   UC_X86_REG_RIP, UC_X86_REG_RSP)

    base, arena = pe.OPTIONAL_HEADER.ImageBase, 0x200000000
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    vm.mem_map(arena, 0x10000)
    pages, events, state = set(), [], {}
    stop, stack = arena + 0xFFF0, arena + 0xF008
    pointers = (arena + 0x1000, arena + 0x3000)
    boundaries = {base + symbols[name]: name for name in
                  (HELPER, "DW_LocalBackend_IsEnabled", "DW_WeaponInspect_IsActive")}
    assert len(boundaries) == 3

    def page(address):
        start = address & ~4095
        if arena <= start < arena + 0x10000 or start in pages:
            return
        assert base <= start < base + pe.OPTIONAL_HEADER.SizeOfImage, hex(address)
        vm.mem_map(start, 4096)
        data = pe.get_data(start - base, 4096)
        if data:
            vm.mem_write(start, data)
        pages.add(start)

    def missing(machine, access, address, size, value, context):
        page(address)
        page(address + size - 1)
        return True

    def step(machine, address, size, context):
        if address == stop:
            machine.emu_stop()
            return
        if address not in boundaries:
            return
        name = boundaries[address]
        events.append(name)
        if name == HELPER:
            assert machine.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF == state["local"]
            assert machine.reg_read(UC_X86_REG_RDX) == state["player"]
            result = state["native"]
        elif name == "DW_WeaponInspect_IsActive":
            assert machine.reg_read(UC_X86_REG_RCX) == state["player"]
            result = state["active"]
        else:
            result = state["enabled"]
        rsp = machine.reg_read(UC_X86_REG_RSP)
        machine.reg_write(UC_X86_REG_RAX, int(result))
        machine.reg_write(UC_X86_REG_RIP, struct.unpack("<Q", machine.mem_read(rsp, 8))[0])
        machine.reg_write(UC_X86_REG_RSP, rsp + 8)

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    vm.hook_add(UC_HOOK_CODE, step)
    cases = []
    # Two distinct viewed states and nonzero local index deliberately avoid a
    # hidden assumption that clientNumber, localClient and viewed player match.
    matrix = itertools.product((False, True), (False, True), (False, True),
                               (-1, 0, 799, 800, 801, 6000), (0, 1), (0, 1, 2))
    for native, enabled, active, time, local, viewed in matrix:
        player = 0 if viewed == 0 else pointers[viewed - 1]
        state.update(native=native, enabled=enabled, active=active, local=local, player=player)
        events.clear()
        before = bytes([0x5A]) * 1808
        if player:
            vm.mem_write(player, before)
            vm.mem_write(player + 1312, struct.pack("<i", time))
            before = bytes(vm.mem_read(player, 1808))
        vm.mem_write(stack, struct.pack("<Q", stop) + bytes(64))
        vm.reg_write(UC_X86_REG_RSP, stack)
        vm.reg_write(UC_X86_REG_RCX, local)
        vm.reg_write(UC_X86_REG_RDX, player)
        vm.emu_start(base + symbols[SYMBOL], stop + 1, count=1000)
        expected = native and not (enabled and player and active and time > 800)
        assert bool(vm.reg_read(UC_X86_REG_RAX) & 0xFF) == bool(expected), state
        assert vm.reg_read(UC_X86_REG_RIP) == stop
        assert vm.reg_read(UC_X86_REG_RSP) == stack + 8
        expected_calls = [HELPER]
        if native:
            expected_calls.append("DW_LocalBackend_IsEnabled")
            if enabled and player:
                expected_calls.append("DW_WeaponInspect_IsActive")
        assert events == expected_calls, (state, events)
        if player:
            assert bytes(vm.mem_read(player, 1808)) == before
        cases.append(dict(native=native, enabled=enabled, active=active,
                          time=time, local=local, viewed=viewed, result=bool(expected)))
    assert len(cases) == 288
    return dict(passed=True, cases=len(cases), unchanged_viewed_state=True,
                native_original_first=True, modeled_boundaries=list(boundaries.values()),
                scope="Actual final linked adapter instructions; native predicate and runtime ownership are API boundaries")


def verify(build):
    build = build.resolve(strict=True)
    report = read(build / "build-report.json")
    snapshot = Path(report["source_root"]).resolve(strict=True)
    image = Path(report["executable"])
    image = (image if image.is_absolute() else build / image).resolve(strict=True)
    assert image.is_relative_to(build) and sha(image) == report["sha256"]
    assert not report["unresolved_symbols"]
    verified = read(build / "verification-report.json")
    assert verified["sha256"] == report["sha256"] and not verified["unresolved_symbols"]
    proof = read(snapshot / "generated/weapon-inspect-crosshair-integration.json")
    assert proof["passed"] and proof["original_bodies_assembled"]
    assert proof["image_sha256"] == report["input_sha256"]
    assert proof["generator_sha256"] == sha(snapshot / "tools/prepare-weapon-inspect-crosshair.py")
    assert proof["clone_tool_sha256"] == sha(snapshot / "tools/replay_owned_clone.py")
    for relative, digest in proof["dependencies"].items():
        path = (snapshot / relative).resolve(strict=True)
        assert path.is_relative_to(snapshot) and sha(path) == digest
    assert sha(snapshot / SOURCE) == proof["source_sha256"]
    symbols = report["symbols"]
    assert symbols[IDENTITY] == symbols[SYMBOL] != symbols[HELPER]
    for alias, identity in proof["imports"].items():
        assert symbols[alias] == symbols[identity]
    rows = [row for row in report["cpp"] if Path(row["source"]).as_posix() == SOURCE]
    assert len(rows) == 1 and rows[0]["source_sha256"] == proof["source_sha256"]
    row = rows[0]
    objpath = Path(row["object"])
    objpath = (objpath if objpath.is_absolute() else build / objpath).resolve(strict=True)
    assert objpath.is_relative_to(build) and sha(objpath) == row["object_sha256"]
    for dependency in row["dependencies"]:
        assert sha(dependency["path"]) == dependency["sha256"]
    coff = module(snapshot / "tools/coff.py", "crosshair_coff")
    checker = module(snapshot / "tools/test-weapon-inspect.py", "crosshair_link")
    obj = coff.read(objpath)
    pe = pefile.PE(str(image))
    graph = checker.linked_object(pe, obj, symbols, [SYMBOL], report["rva_map"]["ranges"])
    for target in (HELPER, "DW_LocalBackend_IsEnabled", "DW_WeaponInspect_IsActive"):
        assert checker.branch_to(obj, SYMBOL, target), ("Missing boundary relocation", target)
    assert len(proof["clones"]) == 1
    clone = proof["clones"][0]
    assert clone["identity"] == IDENTITY and clone["helper"] == HELPER
    assert clone["bytes"] == 435 and clone["unwind_records"] == 1
    original_path = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
    assert sha(original_path) == report["input_sha256"]
    original = pefile.PE(str(original_path), fast_load=True)
    expected = bytearray(original.get_data(0x1698A70, 435))
    actual = bytearray(pe.get_data(symbols[HELPER], 435))
    assert hashlib.sha256(expected).hexdigest() == proof["owners"][SYMBOL]["sha256"]
    for fixup in clone["external_fixups"]:
        assert fixup.get("section", ".text") == ".text"
        offset = fixup["offset"]
        target = (struct.unpack_from("<I", actual, offset)[0] if fixup["kind"] == 3 else
                  symbols[HELPER] + offset + 4 + fixup["trailing_instruction_bytes"] +
                  struct.unpack_from("<i", actual, offset)[0])
        assert target == symbols[fixup["stable_id"]]
        actual[offset:offset + 4] = expected[offset:offset + 4] = bytes(4)
    assert actual == expected
    unwind = [entry.struct for entry in pe.DIRECTORY_ENTRY_EXCEPTION
              if entry.struct.BeginAddress == symbols[HELPER]]
    assert len(unwind) == 1 and unwind[0].EndAddress == symbols[HELPER] + 435
    assert pe.get_data(unwind[0].UnwindData, 24).hex() == proof["owners"][SYMBOL]["unwind"]
    return dict(passed=True, executable_sha256=report["sha256"],
                production_source_sha256=proof["source_sha256"],
                production_object_sha256=row["object_sha256"], linked_graph=graph,
                preserved_original_bytes=435, behavior=behavior(pe, symbols),
                cpp_compiled_by_checker=False, game_launched=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source-only", action="store_true")
    mode.add_argument("--build", type=Path)
    parser.add_argument("--snapshot", type=Path, default=ROOT / "data/dw-client/compiler-base")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = source_contract(args.snapshot.resolve(strict=True)) if args.source_only else verify(args.build)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")
