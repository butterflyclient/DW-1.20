"""Compare full original Replay setrank instructions with the compiled replacement."""

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


def native_case(proof, pe, cls, client, argc, rank, prestige):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    base = pe.OPTIONAL_HEADER.ImageBase
    arena = 0x100000000
    vm.mem_map(arena, 0x10000)
    mapped = set()

    def page(address):
        start = address & ~4095
        if start not in mapped:
            vm.mem_map(start, 4096)
            vm.mem_write(start, pe.get_data(start - base, 4096))
            mapped.add(start)

    target = proof["target"]
    for address in range(
        (base + target["rva"]) & ~4095, base + target["rva"] + target["bytes"], 4096
    ):
        page(address)
    functions = {
        base + row["rva"]: name
        for name, row in proof["imports"].items()
        if row["kind"] == "function"
    }
    for address in functions:
        page(address)
    slot = base + proof["imports"]["RK_Entities"]["rva"]
    page(slot)
    entities, state = arena + 0x100, arena + 0x4000
    vm.mem_write(slot, struct.pack("<Q", entities))
    vm.mem_write(entities + 7 * 1440 + 336, struct.pack("<Q", state if client else 0))
    vm.mem_write(state + 22168, struct.pack("<HH", 91, 9))
    stop, stack = arena + 0xF000, arena + 0xFF08
    vm.mem_write(stack, struct.pack("<Q", stop))
    vm.reg_write(reg.UC_X86_REG_RSP, stack)
    vm.reg_write(reg.UC_X86_REG_RCX, arena)
    vm.reg_write(reg.UC_X86_REG_RDX, 7 | (cls << 32))
    error, trace = 0, 0

    def returned(value):
        rsp = vm.reg_read(reg.UC_X86_REG_RSP)
        ret = struct.unpack("<Q", vm.mem_read(rsp, 8))[0]
        vm.reg_write(reg.UC_X86_REG_RAX, value & 0xFFFFFFFFFFFFFFFF)
        vm.reg_write(reg.UC_X86_REG_RSP, rsp + 8)
        vm.reg_write(reg.UC_X86_REG_RIP, ret)

    def hook(vm, address, size, unused):
        nonlocal error, trace
        if address == stop:
            vm.emu_stop()
            return
        name = functions.get(address)
        if name == "RK_GetInt":
            index = vm.reg_read(reg.UC_X86_REG_RDX)
            trace = trace * 10 + (6 if index else 3)
            returned((prestige if index else rank) & 0xFFFFFFFF)
        elif name == "RK_GetNumParam":
            trace = trace * 10 + 4
            returned(argc)
        elif name == "RK_Format":
            trace = trace * 10 + 1
            returned(arena + 0x40)
        elif name in ("RK_Error", "RK_ObjectError"):
            error = vm.reg_read(reg.UC_X86_REG_RCX)
            trace = trace * 10 + (2 if name == "RK_ObjectError" else 5)
            if name == "RK_ObjectError":
                vm.reg_write(reg.UC_X86_REG_RAX, 0)
                vm.emu_stop()
            else:
                returned(0xABC)

    vm.hook_add(UC_HOOK_CODE, hook)
    vm.emu_start(base + target["rva"], stop, count=10000)
    rank_value, prestige_value = struct.unpack("<HH", vm.mem_read(state + 22168, 4))
    return [rank_value, prestige_value, vm.reg_read(reg.UC_X86_REG_RAX), error, trace]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location(
        "rank_prepare", ROOT / "tools/prepare-bot-rank-integration.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    snapshot = args.snapshot.resolve()
    proof = module.inspect_native(snapshot)
    receipt = json.loads(
        (snapshot / "generated/bot-rank-integration.json").read_bytes()
    )
    assert receipt["passed"] and receipt["target"] == proof["target"]
    for name, expected in receipt["dependencies"].items():
        assert module.sha((snapshot / "src" / name).read_bytes()) == expected, name
    linked = None
    if args.build:
        report = json.loads((args.build / "build-report.json").read_bytes())
        assert module.sha(Path(report["executable"]).read_bytes()) == report["sha256"]
        assert report["unresolved_symbols"] == 0
        rows = [r for r in report["cpp"] if Path(r["source"]).name == "DW_BotRank.cpp"]
        assert len(rows) == 1 and rows[0]["source_sha256"] == receipt["source_sha256"]
        dependencies = {
            Path(r["path"]).name: r["sha256"] for r in rows[0]["dependencies"]
        }
        for name, expected in receipt["dependencies"].items():
            assert dependencies[name] == expected, name
        assert all(
            name in report["symbols"]
            for name in ("DW_BotRank_SetRank", "DW_BotRank_Apply")
        )
        linked = report["sha256"]
    pe = pefile.PE(str(module.IMAGE), fast_load=True)
    cases = 0
    with tempfile.TemporaryDirectory(
        prefix="bot-rank-", dir=ROOT / "data"
    ) as temporary:
        library_path = Path(temporary) / "rank.dll"
        command = [
            r"C:\Program Files\LLVM\bin\clang++.exe",
            "-std=c++20",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-shared",
            "-I" + str(snapshot / "src"),
            str(snapshot / "src/DW_BotRank.cpp"),
            str(ROOT / "tools/bot_rank_harness.cpp"),
            "-o",
            str(library_path),
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr + result.stdout
        library = ctypes.CDLL(str(library_path))
        library.Test_Case.argtypes = (
            [ctypes.c_uint] * 4 + [ctypes.c_int] * 2 + [ctypes.c_uint64]
        )
        library.Test_Result.argtypes = [ctypes.c_uint]
        library.Test_Result.restype = ctypes.c_uint64
        library.Test_PreScript.argtypes = [ctypes.c_uint64]
        try:
            inputs = [
                (0, 1, count, rank, prestige)
                for count in (1, 2, 3)
                for rank in (-1, 0, 1023, 1024)
                for prestige in (-1, 0, 255, 256)
            ]
            inputs += [(1, 1, 2, 0, 0), (0, 0, 2, 0, 0)]
            for cls, has_client, argc, rank, prestige in inputs:
                original = native_case(proof, pe, cls, has_client, argc, rank, prestige)
                for custom in (0, 1):
                    library.Test_Case(
                        cls, has_client, custom, argc, rank, prestige, 12345
                    )
                    actual = [library.Test_Result(i) for i in range(5)]
                    expected = original.copy()
                    if custom and not original[3]:
                        expected[0] = library.Test_Result(5)
                        expected[1] = 0
                    assert actual == expected, (
                        cls,
                        has_client,
                        custom,
                        argc,
                        rank,
                        prestige,
                        actual,
                        expected,
                    )
                    cases += 1
            library.Test_Ownership.argtypes = [ctypes.c_uint]
            for scenario in range(10):
                assert library.Test_Ownership(scenario) == 0, scenario
            for seed in range(200):
                assert library.Test_PreScript(seed) == 0
        finally:
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(library._handle)
    output = dict(
        schema=1,
        passed=True,
        image_sha256=proof["image_sha256"],
        target=proof["target"],
        original_instruction_comparison_cases=cases,
        pre_script_profile_cases=200,
        current_owner_cases=10,
        only_rank_prestige_fields_written=True,
        client_begin=proof["client_begin"],
        pre_script_call=proof["pre_script_call"],
        source_sha256=receipt["source_sha256"],
        dependencies=receipt["dependencies"],
        fixture_sha256=module.sha((ROOT / "tools/bot_rank_harness.cpp").read_bytes()),
        test_sha256=module.sha(Path(__file__).read_bytes()),
        linked_image_sha256=linked,
        linked_image_identity_verified=bool(linked),
        harness_executes_linked_image=False,
        boundaries_modeled=[
            "Native VM argument/error APIs",
            "Mapped native bot profile lookup",
        ],
        game_run_performed=False,
        no_game_writes=True,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(
        f"PASS {cases} original/compiled setrank cases; 200 pre-script stable profiles"
    )


if __name__ == "__main__":
    main()
