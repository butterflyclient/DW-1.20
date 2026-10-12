"""Verify bot queue ownership with compiled native owners; no game is launched."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
import unicorn.x86_const as reg

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path("C:/Program Files/LLVM/bin")
OWNERS = (
    "SV_BotApplyCommands.cpp",
    "SV_UserMoveWorkersMP_TryQueueClientThinkCmd.cpp",
    "SV_UserMoveWorkersMP_ExecuteClientThinkCmd.cpp",
)


def original_worker_case(proof, count):
    """Run the pinned complete worker body with the same engine boundaries."""
    pe = pefile.PE(
        r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe", fast_load=True
    )
    base = pe.OPTIONAL_HEADER.ImageBase
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    pages = set()

    def page(address):
        address &= ~4095
        if address not in pages:
            vm.mem_map(address, 4096)
            if base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
                vm.mem_write(address, pe.get_data(address - base, 4096))
            pages.add(address)

    def put(address, value, fmt=None):
        value = struct.pack(fmt, value) if fmt else value
        for at in range(address & ~4095, (address + len(value) + 4095) & ~4095, 4096):
            page(at)
        vm.mem_write(address, value)

    def get(address, fmt):
        return struct.unpack(fmt, vm.mem_read(address, struct.calcsize(fmt)))[0]

    imports = {row["name"]: base + row["original_rva"] for row in proof["bindings"]}
    target = next(
        row
        for row in proof["replacements"]
        if row["symbol"] == "SV_UserMoveWorkersMP_ExecuteClientThinkCmd"
    )
    code = pe.get_data(target["original_rva"], target["original_bytes"])
    assert hashlib.sha256(code).hexdigest() == target["original_sha256"]
    entry = base + target["original_rva"]
    put(entry, code)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    cookie = int(
        [row.op_str for row in decoder.disasm(code, entry) if row.mnemonic == "call"][
            -1
        ],
        16,
    )
    hooks = {
        imports[name]: name
        for name in (
            "SVHS_TimingStartWorker",
            "SVHS_CurrentThreadContext",
            "SVHS_ClientThinkInternal",
            "SVHS_AddWorker",
            "SVHS_TimingEndWorker",
        )
    }
    hooks[cookie] = "cookie"
    for address in hooks:
        page(address)
    arena = 0x100000000
    queue, client, info, tlsSlots, tls, stack, stop = (
        arena + offset
        for offset in (0x1000, 0x10000, 0x80000, 0x81000, 0x82000, 0xF0008, 0xFF000)
    )
    put(queue, bytes(1600))
    buttons = 0x123456789ABC
    for index in range(count):
        buttons += index
        command = bytearray(264)
        struct.pack_into("<Q", command, 0, buttons)
        struct.pack_into("<ii", command, 12, 1000, 999)
        put(queue + index * 264, bytes(command))
    put(queue + 1584, count % 6, "<I")
    put(queue + 1592, count, "<i")
    put(imports["SVHS_ThinkQueues"], queue, "<Q")
    put(imports["SVHS_Clients"], client, "<Q")
    put(imports["SVHS_InWorkerContext"], bytes(28 * 4))
    put(imports["SVHS_BotTlsIndex"], 1, "<I")
    put(0x58, tlsSlots, "<Q")
    put(tlsSlots + 8, tls, "<Q")
    put(tls, bytes(32))
    put(tls + 16, 0xABCDEF0123456789, "<Q")
    put(info, 0, "<I")
    put(stop, bytes(1))
    stats = [0, 0, 1, 0, 0]
    observed = 0

    def returned(value=0):
        rsp = vm.reg_read(reg.UC_X86_REG_RSP)
        vm.reg_write(reg.UC_X86_REG_RAX, value)
        vm.reg_write(reg.UC_X86_REG_RSP, rsp + 8)
        vm.reg_write(reg.UC_X86_REG_RIP, get(rsp, "<Q"))

    def boundary(machine, address, size, context):
        nonlocal observed
        if address == stop:
            machine.emu_stop()
            return
        name = hooks.get(address)
        if name is None:
            return
        if name == "SVHS_CurrentThreadContext":
            returned(3)
            return
        if name == "SVHS_TimingStartWorker":
            stats[3] += 1
        elif name == "SVHS_TimingEndWorker":
            stats[4] += 1
        elif name == "SVHS_AddWorker":
            assert vm.reg_read(reg.UC_X86_REG_RCX) == 128
            stats[2] += 1
        elif name == "SVHS_ClientThinkInternal":
            assert vm.reg_read(reg.UC_X86_REG_RCX) == client
            assert get(tls + 16, "<Q") == 0
            assert get(imports["SVHS_InWorkerContext"] + 12, "<I") == 1
            observed = get(vm.reg_read(reg.UC_X86_REG_RDX), "<Q")
            stats[0] += 1
        returned()

    def missing(machine, access, address, size, value, context):
        page(address)
        page(address + size - 1)
        return True

    vm.hook_add(UC_HOOK_CODE, boundary)
    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    for index in range(count):
        put(stack, stop, "<Q")
        vm.reg_write(reg.UC_X86_REG_RSP, stack)
        vm.reg_write(reg.UC_X86_REG_RCX, info)
        vm.emu_start(entry, stop + 1, count=10000)
    assert get(tls + 16, "<Q") == 0xABCDEF0123456789
    return [
        stats[0],
        count,
        stats[2],
        stats[3],
        stats[4],
        get(queue + 1592, "<i"),
        get(queue + 1588, "<I"),
        get(queue + 1584, "<I"),
        get(imports["SVHS_InWorkerContext"] + 12, "<I"),
        observed & 0xFFFFFFFF,
        observed >> 32,
        0,
        1,
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve(strict=True)
    proof = json.loads(
        (snapshot / "generated/host-scale-integration.json").read_bytes()
    )
    assert (
        proof["image_sha256"]
        == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    )
    for name in OWNERS:
        source = ROOT / "integration/host-scale" / name
        frozen = snapshot / "src" / name
        assert source.read_bytes() == frozen.read_bytes(), name
    header = ROOT / "integration/host-scale/sv_bot_command_ownership.h"
    assert header.read_bytes() == (snapshot / "src" / header.name).read_bytes()
    linked = None
    if args.build:
        report = json.loads((args.build / "build-report.json").read_bytes())
        assert not report["unresolved_symbols"]
        assert Path(report["source_root"]).resolve() == snapshot
        executable = Path(report["executable"])
        assert hashlib.sha256(executable.read_bytes()).hexdigest() == report["sha256"]
        for name in OWNERS:
            row = next(
                row for row in report["cpp"] if row.get("source") == "src/" + name
            )
            assert (
                row["source_sha256"]
                == hashlib.sha256((snapshot / "src" / name).read_bytes()).hexdigest()
            )
            assert (
                hashlib.sha256(Path(row["object"]).read_bytes()).hexdigest()
                == row["object_sha256"]
            )
            dependencies = {
                Path(item["path"]).resolve(): item["sha256"]
                for item in row["dependencies"]
            }
            for dependency in (
                "sv_bot_command_ownership.h",
                "sv_host_scale.h",
                "SV_HostScaleBindings.h",
            ):
                path = snapshot / "src" / dependency
                assert (
                    dependencies[path.resolve()]
                    == hashlib.sha256(path.read_bytes()).hexdigest()
                )
        linked = report["sha256"]
    flags = [
        "--target=x86_64-pc-windows-msvc",
        "-std=c++20",
        "-O2",
        "-ffreestanding",
        "-fno-exceptions",
        "-fno-rtti",
        "-fno-stack-protector",
        "-mno-stack-arg-probe",
        "-fno-builtin",
        "-ffunction-sections",
        "-fdata-sections",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I" + str(snapshot / "src"),
    ]
    cases = []
    original = {count: original_worker_case(proof, count) for count in (1, 2, 6)}
    with tempfile.TemporaryDirectory(
        prefix="command-ownership-", dir=ROOT / "build"
    ) as temporary:
        folder = Path(temporary)
        objects = []
        for name in (*OWNERS, "host_command_ownership_harness.cpp"):
            source = (
                ROOT
                / (
                    "tools"
                    if name.endswith("harness.cpp")
                    else "integration/host-scale"
                )
                / name
            )
            obj = folder / (name + ".obj")
            subprocess.run(
                [str(LLVM / "clang++.exe"), *flags, "-c", str(source), "-o", str(obj)],
                check=True,
            )
            objects.append(str(obj))
        dll = folder / "ownership.dll"
        subprocess.run(
            [
                str(LLVM / "lld-link.exe"),
                "/dll",
                "/noentry",
                "/nodefaultlib",
                "/opt:ref",
                "/out:" + str(dll),
                *objects,
            ],
            check=True,
        )
        loaded = ctypes.WinDLL(str(dll))
        loaded.OwnershipTest.argtypes = [ctypes.c_uint] * 4
        loaded.OwnershipTest.restype = ctypes.POINTER(ctypes.c_uint)
        index = 0
        try:
            for scenario in (0, 1, 2, 6):
                for count in (1, 2, 6):
                    values = list(loaded.OwnershipTest(scenario, 0, count, index)[:14])
                    expected = 1 if scenario == 6 else count
                    assert values[0] == expected, (scenario, count, values)
                    if scenario != 6:
                        assert values[:13] == original[count], (
                            scenario,
                            count,
                            values,
                            original[count],
                        )
                    assert values[3:6] == [expected, expected, 0]
                    assert values[8] == 0
                    assert values[12] == 1
                    cases.append(dict(scenario=scenario, count=count, result=values))
            for scenario in (3, 4, 5):
                for change in range(1, 13):
                    count = 6 if scenario == 3 else 1
                    values = list(
                        loaded.OwnershipTest(scenario, change, count, index)[:14]
                    )
                    assert values[0] == 0, (scenario, change, values)
                    assert (
                        values[13] == 1
                    ), "Rejected bot command wrote current client input"
                    assert values[5] == 0 and values[8] == 0
                    if scenario == 3:
                        assert values[3:5] == [6, 6] and values[6] == 0
                    assert values[12] == 1
                    cases.append(
                        dict(
                            scenario=scenario, change=change, count=count, result=values
                        )
                    )
        finally:
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
            kernel.FreeLibrary(loaded._handle)
    receipt = dict(
        passed=True,
        cases=len(cases),
        scenarios=cases,
        linked_executable_sha256=linked,
        native_worker_sha256=next(
            row["original_sha256"]
            for row in proof["replacements"]
            if row["symbol"] == "SV_UserMoveWorkersMP_ExecuteClientThinkCmd"
        ),
        source_sha256={
            name: hashlib.sha256(
                (ROOT / "integration/host-scale" / name).read_bytes()
            ).hexdigest()
            for name in OWNERS
        },
        header_sha256=hashlib.sha256(header.read_bytes()).hexdigest(),
        harness_sha256=hashlib.sha256(
            (ROOT / "tools/host_command_ownership_harness.cpp").read_bytes()
        ).hexdigest(),
        human_commands_preserved=True,
        stale_bot_to_human_no_movement=True,
        native_queue_drained=True,
        tls_restored=True,
        original_worker_comparisons=9,
        game_run_performed=False,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        "PASS",
        len(cases),
        "compiled bot ownership and worker lifecycle cases; no game launched",
    )


if __name__ == "__main__":
    main()
