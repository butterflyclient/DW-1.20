"""Exercise the native controller hold path without starting the game."""
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
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_cases(snapshot, proof, package):
    sys.path.insert(0, str(snapshot / "tools"))
    from coff import read
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    by_id = {r["id"]: r for r in catalog["functions"] + catalog["symbols"]}
    original = pefile.PE("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe", fast_load=True)
    base = original.OPTIONAL_HEADER.ImageBase
    result = []

    def run(name, *, br=True, elapsed=200, gamepad=True, forward=True,
            native_enabled=False, active=True, pressed=False, apply_all=False,
            equipment=False, alt=False, nvg=False, consumed=False, repeat=False):
        vm = Uc(UC_ARCH_X86, UC_MODE_64)
        arena, code = 0x180000000, base + proof["owner_rva"]
        vm.mem_map(arena, 0x50000)
        pages = set()

        def page(address):
            start = address & ~4095
            if arena <= start < arena + 0x50000 or start in pages:
                return
            assert base <= start < base + original.OPTIONAL_HEADER.SizeOfImage, hex(address)
            vm.mem_map(start, 4096)
            data = original.get_data(start - base, 4096)
            if data:
                vm.mem_write(start, data)
            pages.add(start)

        def write(address, data):
            for p in range(address & ~4095, (address + len(data) + 4095) & ~4095, 4096):
                page(p)
            vm.mem_write(address, data)

        def missing(machine, access, address, size, value, context):
            page(address)
            page(address + size - 1)
            return True

        vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
        local, client, cg = 1, arena + 0x1000, arena + 0x10000
        button, command, stack, stop = arena + 0x200, arena + 0x300, arena + 0x4F008, arena + 0x400
        native_dvar, br_dvar, private_pointer = arena + 0x500, arena + 0x600, arena + 0x700
        write(base + 0xEE854F8 + local * 8, struct.pack("<Q", client))
        write(base + 0xF26F940 + local * 8, struct.pack("<Q", cg))
        write(base + 0xD38654C, struct.pack("<I", 1000 + elapsed))
        write(native_dvar + 40, bytes([native_enabled]))
        write(br_dvar + 40, b"\1")
        write(private_pointer, struct.pack("<Q", br_dvar))
        write(base + 0xC6E20F8, struct.pack("<Q", native_dvar))
        # Full native dvar records for the underbarrel, NVG and hybrid branches.
        for offset, value in ((0xC6E20E8, alt), (0xC6E2088, alt),
                              (0xC6E20F0, True), (0xC6E2100, False)):
            pointer = arena + 0x800 + (offset & 255) * 128
            write(pointer + 40, bytes([value]))
            write(base + offset, struct.pack("<Q", pointer))
        write(cg + 32, struct.pack("<I", 0x2000000 if nvg else 0))
        write(button, struct.pack("<iiiiBBHBBH", 71, 0, 1000, 0,
                                  active, pressed, 0, 1, 0, 0))
        helper = "DCA_CycleWeaponBR" if br else "DCA_CycleWeaponNative"
        obj = read(package / (helper + ".obj"))
        section = next(s for s in obj["sections"] if s["name"] == ".text")
        body = bytearray(section["data"])
        clone = next(c for c in proof["clones"] if c["helper"] == helper)
        fixups = {r["offset"]: r for r in clone["external_fixups"] if r.get("section", ".text") == ".text"}
        for off, idx, kind in section["relocations"]:
            symbol = obj["symbols"][idx]["name"]
            target = private_pointer if symbol == "DCA_ArmorInput" else base + by_id[symbol]["rva"]
            assert kind in (3, 4)
            if kind == 3:
                struct.pack_into("<I", body, off, target - base)
            else:
                struct.pack_into("<i", body, off, target - (code + off + 4 + fixups[off]["trailing_instruction_bytes"]))
        write(code, bytes(body))
        calls = []
        returns = {0xEFD1A0: consumed, 0xD66C50: 3, 0x15D6F70: gamepad,
                   0x15D7910: equipment, 0x10C86E0: 2 if not alt else 1,
                   0x173DB20: alt, 0x17319D0: False, 0x15D6AB0: apply_all,
                   0x15D6AE0: False, 0x173C700: nvg, 0x172C5E0: True,
                   0x172F4F0: 0, 0x1745E30: 0, 0x1746090: 0,
                   0x172D750: 0, 0x16EB7C0: 0}

        def hook(machine, address, size, context):
            if address == stop:
                machine.emu_stop()
                return
            rva = address - base
            if code <= address < code + len(body):
                return
            assert rva in returns, ("Unexpected native call", hex(rva))
            args = tuple(machine.reg_read(reg) for reg in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8))
            calls.append((rva, args))
            machine.reg_write(UC_X86_REG_RAX, int(returns[rva]))
            rsp = machine.reg_read(UC_X86_REG_RSP)
            machine.reg_write(UC_X86_REG_RIP, struct.unpack("<Q", machine.mem_read(rsp, 8))[0])
            machine.reg_write(UC_X86_REG_RSP, rsp + 8)

        vm.hook_add(UC_HOOK_CODE, hook)
        for _ in range(2 if repeat else 1):
            write(stack, struct.pack("<Q", stop))
            for reg, value in ((UC_X86_REG_RCX, local), (UC_X86_REG_RDX, button),
                               (UC_X86_REG_R8, command), (UC_X86_REG_R9, forward),
                               (UC_X86_REG_RSP, stack)):
                vm.reg_write(reg, int(value))
            vm.emu_start(code, stop, count=1000)
            assert vm.reg_read(UC_X86_REG_RIP) == stop
        notifications = [args for rva, args in calls if rva == 0x16EB7C0]
        for controller, event, all_plates in notifications:
            assert controller == local and all_plates == apply_all
            page(event)
            page(event + 17)
            assert bytes(vm.mem_read(event, 18)) == b"try_use_heal_slot\0\0"[:18]
        assert bytes(vm.mem_read(native_dvar + 40, 1)) == bytes([native_enabled])
        result.append(dict(name=name, armor_events=len(notifications),
                           weapon_cycles=sum(rva == 0x172D750 for rva, _ in calls),
                           equipment_events=sum(rva == 0x1745E30 for rva, _ in calls),
                           alt_events=sum(rva == 0x1746090 for rva, _ in calls)))
        return result[-1]

    assert run("original remote BR failure", br=False)["armor_events"] == 0
    assert run("remote BR hold")["armor_events"] == 1
    assert run("remote BR apply all", apply_all=True)["armor_events"] == 1
    assert run("host BR hold", native_enabled=True)["armor_events"] == 1
    assert run("199 ms hold", elapsed=199)["armor_events"] == 0
    assert run("short tap", elapsed=100, active=False, pressed=True)["weapon_cycles"] == 1
    assert run("released long hold", active=False, pressed=True)["armor_events"] == 1
    assert run("consumed hold not repeated", repeat=True)["armor_events"] == 1
    assert run("inactive button", active=False)["armor_events"] == 0
    assert run("keyboard cycle", gamepad=False)["weapon_cycles"] == 1
    assert run("reverse cycle", forward=False)["weapon_cycles"] == 1
    assert run("equipment priority", equipment=True)["equipment_events"] == 1
    assert run("underbarrel priority", alt=True)["alt_events"] == 1
    assert run("early native consumer", consumed=True)["armor_events"] == 0
    assert run("non-BR weapon cycle", br=False)["weapon_cycles"] == 1
    assert run("non-BR NVG", br=False, nvg=True)["armor_events"] == 0
    assert run("explicit native armor setting", br=False, native_enabled=True)["armor_events"] == 1
    return result


def wrapper_cases(snapshot, production_source):
    with tempfile.TemporaryDirectory(prefix="dw-controller-armor-") as temporary:
        folder = Path(temporary)
        harness = folder / "harness.cpp"
        harness.write_text('''#include "replay_dvar.h"
extern "C" uint64_t DW_ControllerArmor_CycleWeapon(unsigned, void *, void *, bool);
extern "C" const dvar_t *const DCA_ArmorInput;
static bool br;
extern "C" bool DCA_PlayingBR() { return br; }
static uint64_t check(unsigned local, void *button, void *command, bool forward) {
    return local == 1 && button == (void*)0x1234 && command == (void*)0x5678 && forward;
}
extern "C" uint64_t DCA_CycleWeaponNative(unsigned l, void *b, void *c, bool f) { return check(l,b,c,f) + 10; }
extern "C" uint64_t DCA_CycleWeaponBR(unsigned l, void *b, void *c, bool f) { return check(l,b,c,f) + 20; }
extern "C" __declspec(dllexport) uint64_t Run(bool mode) {
    br = mode;
    if (!DCA_ArmorInput || !DCA_ArmorInput->current.enabled) return 0;
    return DW_ControllerArmor_CycleWeapon(1, (void*)0x1234, (void*)0x5678, true);
}
''')
        dll = folder / "test.dll"
        subprocess.run(["C:/Program Files/LLVM/bin/clang++.exe", "--target=x86_64-pc-windows-msvc",
            "-shared", "-fuse-ld=lld", "-O2", "-std=c++20", "-ffreestanding", "-fno-stack-protector",
            "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra", "-Werror",
            "-I" + str(snapshot / "src"), str(production_source), str(harness),
            "-o", str(dll), "-nostdlib", "-Wl,/noentry"], check=True)
        library = ctypes.CDLL(str(dll))
        library.Run.argtypes = [ctypes.c_bool]
        library.Run.restype = ctypes.c_uint64
        try:
            for mode in (False, True, True, False):
                assert library.Run(mode) == (21 if mode else 11)
        finally:
            import _ctypes
            _ctypes.FreeLibrary(library._handle)
        return dict(passed=True, mode_transitions=4, arguments_preserved=True)


def verify_build(build):
    report = json.loads((build / "build-report.json").read_bytes())
    snapshot = Path(report["source_root"])
    proof = json.loads((snapshot / "generated/controller-armor-integration.json").read_bytes())
    assert proof["passed"] and proof["owner_sha256"] == "5efcd86011b2c0cdfa7ba3f56031a788a37919ccf548c001ae016cb218f0fea7"
    image = Path(report["executable"])
    image = image if image.is_absolute() else build / image
    assert sha(image) == report["sha256"] and not report["unresolved_symbols"]
    verification = json.loads((build / "verification-report.json").read_bytes())
    assert verification["sha256"] == report["sha256"] and not verification["unresolved_symbols"]
    assert proof["generator_sha256"] == sha(snapshot / "tools/prepare-controller-armor.py")
    assert proof["clone_tool_sha256"] == sha(snapshot / "tools/replay_owned_clone.py")
    for relative, digest in proof["dependencies"].items():
        assert sha(snapshot / relative) == digest
    symbols = report["symbols"]
    assert symbols[proof["owner"]] == symbols["DW_ControllerArmor_CycleWeapon"]
    for alias, identity in proof["imports"].items():
        assert symbols[alias] == symbols[identity]
    sys.path.insert(0, str(snapshot / "tools"))
    from coff import read
    checker = load(snapshot / "tools/test-weapon-inspect.py", "armor_link_check")
    pe = pefile.PE(str(image))
    for name in ("DW_ControllerArmor.cpp", "DW_ControllerArmor_Native.cpp"):
        records = [r for r in report["cpp"] if Path(r["source"]).as_posix() == "src/" + name]
        assert len(records) == 1
        row = records[0]
        obj = Path(row["object"])
        assert obj.resolve().is_relative_to(build.resolve())
        assert sha(obj) == row["object_sha256"]
        assert row["source_sha256"] == sha(snapshot / "src" / name)
        for dependency in row["dependencies"]:
            assert sha(Path(dependency["path"])) == dependency["sha256"]
        roots = ["DW_ControllerArmor_CycleWeapon", "DCA_ArmorInput"] if name == "DW_ControllerArmor.cpp" else [c["helper"] for c in proof["clones"]]
        checker.linked_object(pe, read(obj), symbols, roots, report["rva_map"]["ranges"])
    for clone in proof["clones"]:
        address = symbols[clone["helper"]]
        assert address != symbols[proof["owner"]]
        raw = pe.get_data(address, proof["owner_bytes"])
        for fixup in clone["external_fixups"]:
            if fixup.get("section", ".text") != ".text":
                continue
            off = fixup["offset"]
            target = (struct.unpack_from("<I", raw, off)[0] if fixup["kind"] == 3 else
                      address + off + 4 + fixup["trailing_instruction_bytes"] + struct.unpack_from("<i", raw, off)[0])
            alias = clone.get("redirects", {}).get(fixup["stable_id"], fixup["stable_id"])
            assert target == symbols[alias]
        records = sorted([e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION if address <= e.struct.BeginAddress < address + len(raw)], key=lambda r: r.BeginAddress)
        assert len(records) == len(proof["native_unwind"]) == 5
        for index, (actual, native) in enumerate(zip(records, proof["native_unwind"])):
            assert actual.BeginAddress == address + native["begin"] - proof["owner_rva"]
            assert actual.EndAddress == address + native["end"] - proof["owner_rva"]
            expected = bytes.fromhex(native["bytes"])
            header = 4 + ((expected[2] + 1) & ~1) * 2
            assert pe.get_data(actual.UnwindData, header) == expected[:header]
            if index == 0:
                assert expected[0] >> 3 == 0 and len(expected) == header
            else:
                assert expected[0] >> 3 == 4
                chain = struct.unpack_from("<III", expected, header)
                parent = [i for i, r in enumerate(proof["native_unwind"][:index])
                          if chain == (r["begin"], r["end"], r["unwind_rva"])]
                assert len(parent) == 1
                record = records[parent[0]]
                assert pe.get_data(actual.UnwindData + header, 12) == struct.pack(
                    "<III", record.BeginAddress, record.EndAddress, record.UnwindData)
    return snapshot, proof, dict(passed=True, executable_sha256=report["sha256"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert bool(args.snapshot) != bool(args.build)
    if args.build:
        snapshot, proof, linked = verify_build(args.build.resolve())
        package = snapshot / "generated/controller-armor"
        production_source = snapshot / "src/DW_ControllerArmor.cpp"
    else:
        snapshot = args.snapshot.resolve(strict=True)
        package = args.output.resolve().parent / "isolated"
        preparer = load(ROOT / "tools/prepare-controller-armor.py", "armor_preparer")
        native, proof = preparer.generate(snapshot, package)
        (package / "proof.json").write_text(json.dumps(proof, indent=2) + "\n")
        production_source = ROOT / "integration/replay/DW_ControllerArmor.cpp"
        linked = dict(passed=False, reason="No new game EXE built")
    result = dict(passed=True, native_cases=native_cases(snapshot, proof, package),
                  wrapper=wrapper_cases(snapshot, production_source), linked=linked,
                  source_sha256=sha(production_source), game_launched=False,
                  live_remote_controller_verified=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS controller armor: native hold cases and compiled mode routing")
