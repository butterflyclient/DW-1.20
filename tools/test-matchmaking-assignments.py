"""Compare complete original Replay instructions against compiled assignment updates."""

import argparse
import ctypes
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
import unicorn.x86_const as reg

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path("C:/Program Files/LLVM/bin")


def original_case(native, pe, target, squad, enabled, found, cached, desired, member):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    arena = 0x100000000
    vm.mem_map(arena, 0x30000)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    mapped = set()

    def map_page(address):
        page = address & ~4095
        if page not in mapped:
            vm.mem_map(page, 4096)
            if image_base <= page < image_base + pe.OPTIONAL_HEADER.SizeOfImage:
                vm.mem_write(page, pe.get_data(page - image_base, 4096))
            mapped.add(page)

    for page in range(
        (image_base + target["rva"]) & ~4095,
        image_base + target["rva"] + target["bytes"],
        4096,
    ):
        map_page(page)
    vm.mem_write(image_base + target["rva"], bytes.fromhex(target["complete_body_hex"]))
    imports = native["imports"]
    functions = {
        image_base + row["rva"]: name
        for name, row in imports.items()
        if row["kind"] == "function"
    }
    for address in functions:
        map_page(address)
    dvar_slot = image_base + imports["DWMA_UpdateAssignments"]["rva"]
    map_page(dvar_slot)
    context, players, assignment_list, assignment, dvar, party = (
        arena + x for x in (0x100, 0xD000, 0xE000, 0x10000, 0x11000, 0x12000)
    )
    player_head = context + 46424
    assignment_head = assignment_list + 6408
    vm.mem_write(
        player_head,
        struct.pack(
            "<QQ", players if found else player_head, players if found else player_head
        ),
    )
    vm.mem_write(players, struct.pack("<QQ", player_head, player_head))
    vm.mem_write(players + 104, struct.pack("<Q", 1001))
    vm.mem_write(players + 192, struct.pack("<ii", cached, cached))
    vm.mem_write(assignment_head, struct.pack("<QQ", assignment, assignment))
    vm.mem_write(
        assignment,
        struct.pack("<QQQiI", assignment_head, assignment_head, 1001, desired, 0),
    )
    vm.mem_write(dvar_slot, struct.pack("<Q", dvar))
    vm.mem_write(dvar + 40, bytes([enabled]))
    stack, stop = arena + 0x2F008, arena + 0x2E000
    vm.mem_write(stack, struct.pack("<Q", stop))
    vm.reg_write(reg.UC_X86_REG_RSP, stack)
    vm.reg_write(reg.UC_X86_REG_RCX, context)
    vm.reg_write(reg.UC_X86_REG_RDX, assignment_list)
    counts = dict(
        setters=0,
        applied=0,
        prints=0,
        warnings=0,
        party_team=0xFFFFFFF6,
        party_squad=0xFFFFFFF6,
    )

    def returned(value):
        rsp = vm.reg_read(reg.UC_X86_REG_RSP)
        ret = struct.unpack("<Q", vm.mem_read(rsp, 8))[0]
        vm.reg_write(reg.UC_X86_REG_RAX, value)
        vm.reg_write(reg.UC_X86_REG_RSP, rsp + 8)
        vm.reg_write(reg.UC_X86_REG_RIP, ret)

    def boundary(vm, address, size, unused):
        if address == stop:
            vm.emu_stop()
            return
        name = functions.get(address)
        if not name:
            return
        if name == "DWMA_LobbyParty":
            returned(party)
        elif name == "DWMA_XuidEqual":
            a = vm.reg_read(reg.UC_X86_REG_RCX)
            b = vm.reg_read(reg.UC_X86_REG_RDX)
            returned(int(bytes(vm.mem_read(a, 8)) == bytes(vm.mem_read(b, 8))))
        elif name == "DWMA_XuidString":
            returned(arena + 0x13000)
        elif name in ("DWMA_Print", "DWMA_Warning"):
            assert vm.reg_read(reg.UC_X86_REG_RCX) == 25
            counts["prints" if name == "DWMA_Print" else "warnings"] += 1
            returned(0)
        elif name in ("DWMA_SetTeam", "DWMA_SetSquad"):
            assert vm.reg_read(reg.UC_X86_REG_RCX) == party
            assert vm.reg_read(reg.UC_X86_REG_RDX) == 1001
            counts["setters"] += 1
            if member:
                counts["applied"] += 1
                counts["party_team" if name == "DWMA_SetTeam" else "party_squad"] = (
                    vm.reg_read(reg.UC_X86_REG_R8) & 0xFFFFFFFF
                )
            returned(0)

    vm.hook_add(UC_HOOK_CODE, boundary)
    vm.emu_start(image_base + target["rva"], stop, count=100000)
    team, squad_value = struct.unpack("<II", vm.mem_read(players + 192, 8))
    return [
        team,
        squad_value,
        counts["setters"],
        counts["applied"],
        counts["party_team"],
        counts["party_squad"],
        counts["prints"],
        counts["warnings"],
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve()
    spec = importlib.util.spec_from_file_location(
        "assignment_prepare", ROOT / "tools/prepare-matchmaking-assignments.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    native = module.inspect_native(snapshot)
    receipt = json.loads(
        (snapshot / "generated/matchmaking-assignments-integration.json").read_bytes()
    )
    assert receipt["source_sha256"] == module.sha(
        (ROOT / "integration/replay/DW_MatchmakingAssignments.cpp").read_bytes()
    )
    assert (
        native["targets"] == receipt["targets"]
        and native["imports"] == receipt["imports"]
    )
    assert native["cache_binding"] == receipt["cache_binding"]
    assert native["setter_guards"] == receipt["setter_guards"]
    assert (
        module.sha((ROOT / "tools/prepare-matchmaking-assignments.py").read_bytes())
        == receipt["generator_sha256"]
    )
    for name, digest in receipt["dependencies"].items():
        assert module.sha((snapshot / name).read_bytes()) == digest, name
    build_evidence = None
    if args.build:
        report_path = args.build / "build-report.json"
        build = json.loads(report_path.read_bytes())
        assert not build["unresolved_symbols"]
        assert module.sha(Path(build["executable"]).read_bytes()) == build["sha256"]
        assert Path(build["source_root"]).resolve() == snapshot
        owners = [row for row in build["cpp"] if row["source"] == receipt["source"]]
        assert len(owners) == 1
        owner = owners[0]
        assert owner["source_sha256"] == receipt["source_sha256"]
        assert module.sha(Path(owner["object"]).read_bytes()) == owner["object_sha256"]
        dependency_paths = {
            Path(row["path"]).resolve(): row["sha256"] for row in owner["dependencies"]
        }
        for name, digest in receipt["dependencies"].items():
            assert dependency_paths[(snapshot / name).resolve()] == digest
        for target in receipt["targets"]:
            assert any(
                row["function_id"] == target["identity"]
                and row["symbol"] == target["symbol"]
                and row["source"] == receipt["source"]
                for row in build["source_units"]
            )
        build_evidence = dict(
            report_sha256=module.sha(report_path.read_bytes()),
            executable_sha256=build["sha256"],
            object_sha256=owner["object_sha256"],
        )
    pe = pefile.PE(str(module.IMAGE), fast_load=True)
    cases = 0
    with tempfile.TemporaryDirectory(
        prefix="matchmaking-assignment-", dir=ROOT / "build"
    ) as temporary:
        folder = Path(temporary)
        obj, dll = folder / "test.obj", folder / "test.dll"
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
        subprocess.run(
            [
                str(LLVM / "clang++.exe"),
                *flags,
                "-c",
                str(ROOT / "integration/replay/DW_MatchmakingAssignments.cpp"),
                "-o",
                str(folder / "production.obj"),
            ],
            check=True,
        )
        symbols = subprocess.check_output(
            [
                str(LLVM / "llvm-nm.exe"),
                "--defined-only",
                str(folder / "production.obj"),
            ],
            text=True,
        )
        assert " T DW_MatchmakingAssignments_PrepareLaunch" in symbols
        subprocess.run(
            [
                str(LLVM / "clang++.exe"),
                *flags,
                "-c",
                str(ROOT / "tools/matchmaking_assignments_harness.cpp"),
                "-o",
                str(obj),
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
                "/out:" + str(dll),
                str(obj),
            ],
            check=True,
        )
        library = ctypes.CDLL(str(dll))
        library.Test_Case.argtypes = [
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        library.Test_Result.argtypes = [ctypes.c_uint]
        library.Test_Result.restype = ctypes.c_uint64
        try:
            for squad in (0, 1):
                target = native["targets"][0 if squad else 1]
                for enabled in (0, 1):
                    for found in (0, 1):
                        for cached, desired in ((0, 0), (0, 1), (3, 1), (-1, 0)):
                            for member in (0, 1):
                                original = original_case(
                                    native,
                                    pe,
                                    target,
                                    squad,
                                    enabled,
                                    found,
                                    cached,
                                    desired,
                                    member,
                                )
                                library.Test_Case(
                                    squad, enabled, 0, found, cached, desired, member
                                )
                                actual = [library.Test_Result(i) for i in range(8)]
                                assert actual == original, (
                                    squad,
                                    enabled,
                                    found,
                                    cached,
                                    desired,
                                    member,
                                    original,
                                    actual,
                                )
                                cases += 1
                                library.Test_Case(
                                    squad, enabled, 1, found, cached, desired, member
                                )
                                desired_result = original.copy()
                                desired_result[2] = int(bool(enabled))
                                desired_result[3] = int(bool(enabled and member))
                                if enabled and member:
                                    desired_result[5 if squad else 4] = (
                                        desired if squad else desired + 1
                                    ) & 0xFFFFFFFF
                                assert [
                                    library.Test_Result(i) for i in range(8)
                                ] == desired_result
                                cases += 1
            assert library.Test_Retry() == 0
            cache_result = library.Test_LaunchCache()
            assert (
                cache_result == 0
            ), f"Launch cache failed at harness line {cache_result}"
            assert library.Test_CallbackRevision() == 0
            library.Test_StressInit()
            library.Test_StressWriter.argtypes = [ctypes.c_uint]
            library.Test_StressReader.argtypes = [ctypes.c_uint]
            barrier = threading.Barrier(2)

            def stress(function):
                barrier.wait()
                return function(40000)

            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [
                    pool.submit(stress, function)
                    for function in (
                        library.Test_StressWriter,
                        library.Test_StressReader,
                    )
                ]
                assert all(future.result() == 0 for future in futures)
        finally:
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(library._handle)
    receipt.update(
        original_native_instruction_comparison_passed=True,
        compiled_harness_passed=True,
        compiled_cases=cases,
        pending_member_retry_passed=True,
        missing_cache_assignment_passed=True,
        unchanged_cached_assignment_reapplied=True,
        lobby_scoped_launch_cache_passed=True,
        cache_capacity_and_replacement_passed=True,
        concurrent_cache_snapshot_stress_passed=True,
        concurrent_iterations_per_thread=40000,
        callbacks_run_without_cache_lock=True,
        new_revision_stops_old_replay=True,
        build_evidence=build_evidence,
        harness_sha256=module.sha(
            (ROOT / "tools/matchmaking_assignments_harness.cpp").read_bytes()
        ),
        test_sha256=module.sha(Path(__file__).read_bytes()),
        launch_helper_export_verified=True,
        no_game_writes=True,
        game_run_performed=False,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        f"PASS {cases} original/compiled native assignment cases and pending-member retry"
    )


if __name__ == "__main__":
    main()
