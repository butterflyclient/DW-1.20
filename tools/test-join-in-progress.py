"""Compare native reservation instructions with the compiled complete replacement."""

import argparse
import ctypes
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
import unicorn.x86_const as reg

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path("C:/Program Files/LLVM/bin")


def original_case(native, pe, scenario, mask, capacity, maximum, private):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    arena = 0x100000000
    vm.mem_map(arena, 0x100000)
    base = pe.OPTIONAL_HEADER.ImageBase
    mapped = set()

    def page(address):
        address &= ~4095
        if address not in mapped:
            vm.mem_map(address, 4096)
            vm.mem_write(address, pe.get_data(address - base, 4096))
            mapped.add(address)

    target = native["target"]
    page(base + target["rva"])
    vm.mem_write(base + target["rva"], bytes.fromhex(target["complete_body_hex"]))
    functions = {}
    for name, binding in native["imports"].items():
        address = base + binding["rva"]
        page(address)
        if binding["kind"] == "function":
            functions[address] = name
    party, challenge, output = arena + 0x1000, arena + 0x60000, arena + 0x61000
    vm.mem_write(party + 311056, struct.pack("<Q", arena + 0x62000))
    members = bytearray(488 * 200)
    for index in range(200):
        members[index * 488 + 402] = 5
    oldest = {}
    if scenario in (0, 5, 6):
        members[402] = 0
        if scenario != 5:
            members[4 * 488 + 402] = 0
        if scenario == 6:
            members[402] = 2
    elif 1 <= scenario <= 3:
        oldest[scenario + 1] = 7
        members[7 * 488 + 402] = scenario + 1
    vm.mem_write(party + 2192, bytes(members))
    vm.mem_write(party + 311164, bytes([255]) * 28)
    vm.mem_write(challenge, bytes.fromhex("616263646500"))
    vm.mem_write(output, struct.pack("<i", -99))
    for index, name in enumerate(
        (
            "DWJIP_PrivateMatch",
            "DWJIP_Playlist",
            "DWJIP_AnonymousDuration",
            "DWJIP_ZombieDuration",
            "DWJIP_ConnectingDuration",
        )
    ):
        address = arena + 0x70000 + index * 4096
        vm.mem_write(base + native["imports"][name]["rva"], struct.pack("<Q", address))
        vm.mem_write(
            address + 40,
            struct.pack(
                "<I", private if index == 0 else (1 if index == 1 else 9 + index)
            ),
        )
    stack, stop = arena + 0xEF008, arena + 0xEE000
    vm.mem_write(stack, struct.pack("<Q", stop))
    vm.reg_write(reg.UC_X86_REG_RSP, stack)
    vm.reg_write(reg.UC_X86_REG_RCX, party)
    vm.reg_write(reg.UC_X86_REG_RDX, 0x1122334455667788)
    vm.reg_write(reg.UC_X86_REG_R8, challenge)
    vm.reg_write(reg.UC_X86_REG_R9, output)
    counts = [0, 0]

    def returned(value):
        rsp = vm.reg_read(reg.UC_X86_REG_RSP)
        ret = struct.unpack("<Q", vm.mem_read(rsp, 8))[0]
        vm.reg_write(reg.UC_X86_REG_RAX, value)
        vm.reg_write(reg.UC_X86_REG_RSP, rsp + 8)
        vm.reg_write(reg.UC_X86_REG_RIP, ret)

    def hook(vm, address, size, unused):
        if address == stop:
            vm.emu_stop()
            return
        name = functions.get(address)
        if not name:
            return
        rcx, rdx, r8 = [
            vm.reg_read(register)
            for register in (reg.UC_X86_REG_RCX, reg.UC_X86_REG_RDX, reg.UC_X86_REG_R8)
        ]
        value = 0
        if name == "DWJIP_GameSlots":
            value = capacity
        elif name == "DWJIP_GameLobby":
            value = int(bool(mask & 2))
        elif name == "DWJIP_PlaylistId":
            value = 7
        elif name == "DWJIP_MaxHumanPlayers":
            value = maximum
        elif name == "DWJIP_LocalServerRunning":
            value = int(bool(mask & 4))
        elif name == "DWJIP_OldestSlot":
            value = oldest.get(rdx, -1) & 0xFFFFFFFF
        elif name == "DWJIP_Print":
            counts[0] += 1
        elif name == "DWJIP_RemoveMember":
            counts[1] += 1
        elif name == "DWJIP_XuidString":
            value = arena + 0x62000
        elif name == "DWJIP_Zero":
            vm.mem_write(rcx, bytes(r8))
            value = rcx
        elif name == "DWJIP_XuidAssign":
            vm.mem_write(rcx, bytes(vm.mem_read(rdx, 8)))
            value = rcx
        elif name == "DWJIP_Milliseconds":
            value = 777
        else:
            raise AssertionError(name)
        returned(value)

    vm.hook_add(UC_HOOK_CODE, hook)
    vm.emu_start(base + target["rva"], stop, count=100000)
    digest = 14695981039346656037
    for byte in bytes(vm.mem_read(party + 2192, 488 * 200)) + bytes(
        vm.mem_read(party + 311164, 28)
    ):
        digest = ((digest ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return [
        vm.reg_read(reg.UC_X86_REG_RAX) & 0xFFFFFFFF,
        struct.unpack("<I", vm.mem_read(output, 4))[0],
        *counts,
        digest,
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve()
    spec = importlib.util.spec_from_file_location(
        "join_prepare", ROOT / "tools/prepare-join-in-progress.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    native = module.inspect_native(snapshot)
    receipt = json.loads(
        (snapshot / "generated/join-in-progress-integration.json").read_bytes()
    )
    for key in native:
        assert native[key] == receipt[key]
    assert receipt["generator_sha256"] == module.sha(
        (ROOT / "tools/prepare-join-in-progress.py").read_bytes()
    )
    assert receipt["source_sha256"] == module.sha(
        (ROOT / "integration/replay/DW_JoinInProgress.cpp").read_bytes()
    )
    for name, digest in receipt["dependencies"].items():
        assert module.sha((snapshot / name).read_bytes()) == digest
    if args.build:
        report = json.loads((args.build / "build-report.json").read_bytes())
        assert not report["unresolved_symbols"]
        assert Path(report["source_root"]).resolve() == snapshot
        assert module.sha(Path(report["executable"]).read_bytes()) == report["sha256"]
        owner = next(row for row in report["cpp"] if row["source"] == receipt["source"])
        assert owner["source_sha256"] == receipt["source_sha256"]
        assert module.sha(Path(owner["object"]).read_bytes()) == owner["object_sha256"]
        dependencies = {
            Path(row["path"]).resolve(): row["sha256"] for row in owner["dependencies"]
        }
        for name, digest in receipt["dependencies"].items():
            assert dependencies[(snapshot / name).resolve()] == digest
        receipt["compiled_image_sha256"] = report["sha256"]
    pe = pefile.PE(str(module.IMAGE), fast_load=True)
    cases = 0
    with tempfile.TemporaryDirectory(
        prefix="join-in-progress-", dir=ROOT / "build"
    ) as temporary:
        folder = Path(temporary)
        flags = [
            "--target=x86_64-pc-windows-msvc",
            "-std=c++20",
            "-O2",
            "-ffreestanding",
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-stack-protector",
            "-mno-stack-arg-probe",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(snapshot / "src"),
        ]
        for name, source in [
            ("production", "integration/replay/DW_JoinInProgress.cpp"),
            ("harness", "tools/join_in_progress_harness.cpp"),
        ]:
            subprocess.run(
                [
                    str(LLVM / "clang++.exe"),
                    *flags,
                    "-c",
                    str(ROOT / source),
                    "-o",
                    str(folder / (name + ".obj")),
                ],
                check=True,
            )
        subprocess.run(
            [
                str(LLVM / "lld-link.exe"),
                "/dll",
                "/noentry",
                "/nodefaultlib",
                "/opt:ref",
                "/out:" + str(folder / "test.dll"),
                str(folder / "harness.obj"),
            ],
            check=True,
        )
        library = ctypes.CDLL(str(folder / "test.dll"))
        library.Test_Case.argtypes = [ctypes.c_uint] * 5
        library.Test_Result.argtypes = [ctypes.c_uint]
        library.Test_Result.restype = ctypes.c_uint64
        try:
            for scenario in range(7):
                for mask in (0, 2, 4, 6, 254):
                    for capacity, maximum, private in (
                        (10, 0, 0),
                        (10, 3, 0),
                        (10, 3, 1),
                    ):
                        original = original_case(
                            native, pe, scenario, mask, capacity, maximum, private
                        )
                        library.Test_Case(scenario, mask, capacity, maximum, private)
                        actual = [library.Test_Result(index) for index in range(5)]
                        assert actual == original, (
                            scenario,
                            mask,
                            capacity,
                            maximum,
                            private,
                            actual,
                            original,
                        )
                        cases += 1
            for omitted in (0, 1, 2, 4, 8, 16, 32, 64, 128):
                mask = 255 & ~omitted
                library.Test_Case(0, mask, 10, 0, 0)
                selected = library.Test_Result(1)
                assert selected == (4 if omitted == 0 else 0), (mask, selected)
            library.Test_Case(0, 255, 10, 3, 0)
            assert library.Test_Result(1) == 0
            library.Test_Case(0, 255, 10, 3, 1)
            assert library.Test_Result(1) == 0
            library.Test_Case(5, 255, 10, 0, 0)
            assert library.Test_Result(1) == 0
            assert library.Test_Reservation() == 0
            assert library.Test_ServerBounds() == 0
        finally:
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(library._handle)
    receipt.update(
        original_instruction_comparison_passed=True,
        compiled_harness_passed=True,
        original_cases=cases,
        bot_preference_scope_passed=True,
        native_cap_fallback_passed=True,
        reservation_no_premature_drop_passed=True,
        test_sha256=module.sha(Path(__file__).read_bytes()),
        harness_sha256=module.sha(
            (ROOT / "tools/join_in_progress_harness.cpp").read_bytes()
        ),
        game_run_performed=False,
        no_game_writes=True,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        f"PASS {cases} original/compiled cases plus bot preference, native caps, and reservation isolation"
    )


if __name__ == "__main__":
    main()
