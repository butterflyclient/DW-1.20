"""Check compiled C++ metadata emission against original SDK instructions."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
import unicorn.x86_const as x

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--build-report",
        type=Path,
        help="Execute the final linked EXE instead of a component DLL; does not launch the game",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.is_relative_to(ROOT)
    folder = ROOT / "data/remaining-client-match-events-20261010/component"
    spec = importlib.util.spec_from_file_location(
        "match_event_preparation", ROOT / "tools/prepare-match-event-integration.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    prepared = module.prepare(folder, False)
    variables = Path(
        r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
    )
    listing = subprocess.check_output(
        f'cmd /d /s /c "call "{variables}" >nul && set"', text=True
    )
    environment = dict(os.environ)
    for line in listing.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.upper() in ("PATH", "INCLUDE", "LIB", "LIBPATH"):
            environment[key.upper()] = value
    compiler = shutil.which("cl.exe", path=environment["PATH"])
    assert compiler
    boundaries = folder / "boundaries.cpp"
    boundaries.write_text("""#include "src/DW_AchievementEventBindings.h"
extern "C" {
uint8_t DW_Achievement_Matchmaker[131072]{};
bool DW_LocalBackend_IsEnabled() { return false; }
uint64_t DW_Achievement_GetLobbyId(const void *) { return 0; }
uint64_t DW_Achievement_GetMatchId() { return 0; }
void *DW_Achievement_AddKeyValue(void *event, const char *, uint64_t) { return event; }
}
""")
    dll = folder / "match-events.dll"
    names = [
        "bdAchievementEvent_SetTimeStamp",
        "DW_Achievement_Matchmaker",
        "DW_LocalBackend_IsEnabled",
        "DW_Achievement_GetLobbyId",
        "DW_Achievement_GetMatchId",
        "DW_Achievement_AddKeyValue",
    ]
    report = None
    if args.build_report:
        report_path = args.build_report.resolve()
        assert report_path.is_relative_to(ROOT / "data")
        report = json.loads(report_path.read_bytes())
        dll = Path(report["executable"]).resolve()
        assert dll.is_relative_to(ROOT / "data")
        assert hashlib.sha256(dll.read_bytes()).hexdigest() == report["sha256"]
        source_rows = [
            row
            for row in report["cpp"]
            if Path(row["source"]).name == "DW_AchievementEvent.cpp"
        ]
        assert len(source_rows) == 1
        assert source_rows[0]["source_sha256"] == prepared["source_sha256"]
        compiled = pefile.PE(str(dll), fast_load=True)
        symbols = {
            name: compiled.OPTIONAL_HEADER.ImageBase + report["symbols"][name]
            for name in names
        }
        spec = importlib.util.spec_from_file_location(
            "private_linked_layout", Path(report["source_root"]) / "tools/layout.py"
        )
        sys.path.insert(0, str(Path(report["source_root"]) / "tools"))
        layout_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(layout_module)
    else:
        subprocess.run(
            [
                compiler,
                "/nologo",
                "/LD",
                "/std:c++20",
                "/O2",
                "/GS-",
                "/MD",
                str(folder / "src/DW_AchievementEvent.cpp"),
                str(boundaries),
                "/Fe" + str(dll),
                "/Fo" + str(folder) + "\\",
                "/link",
                "/OPT:NOICF",
                *["/export:" + name for name in names],
            ],
            cwd=folder,
            env=environment,
            check=True,
        )
        compiled = pefile.PE(str(dll))
        symbols = {
            row.name.decode(): compiled.OPTIONAL_HEADER.ImageBase + row.address
            for row in compiled.DIRECTORY_ENTRY_EXPORT.symbols
            if row.name
        }
    original_path = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    raw = original_path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == prepared["image_sha256"]
    original = pefile.PE(data=raw, fast_load=True)
    base = original.OPTIONAL_HEADER.ImageBase
    proof = json.loads(
        (
            ROOT / "data/remaining-event-ownership-20261010/native-event-capacity.json"
        ).read_bytes()
    )
    constructor, append, reset, stamp, name_setter, lobby = [
        row["address"] for row in proof["methods"]
    ]
    accessors = json.loads(
        (
            ROOT / "data/remaining-event-ownership-20261010/native-match-functions.json"
        ).read_bytes()
    )
    match_getter = int(
        next(
            r["address"] for r in accessors if r["name"] == "OnlineMatchId::GetMatchId"
        )
    )
    runtime = original
    if report:
        assert report["input_sha256"] == prepared["image_sha256"]

        def remap(address):
            return compiled.OPTIONAL_HEADER.ImageBase + layout_module.from_report(
                address - base, report
            )

        constructor, append, reset, stamp, name_setter, lobby = map(
            remap, (constructor, append, reset, stamp, name_setter, lobby)
        )
        match_getter = symbols["DW_Achievement_GetMatchId"]
        runtime = compiled
        base = compiled.OPTIONAL_HEADER.ImageBase
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(
        decoder.disasm(runtime.get_data(match_getter - base, 8), match_getter)
    )
    assert len(instructions) == 2 and instructions[-1].mnemonic == "ret"
    match_global = (
        instructions[0].address
        + instructions[0].size
        + instructions[0].operands[1].mem.disp
    )
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    for section in (() if report else compiled.sections):
        size = (max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095) & ~4095
        if size:
            vm.mem_map(
                compiled.OPTIONAL_HEADER.ImageBase + section.VirtualAddress, size
            )
            vm.mem_write(
                compiled.OPTIONAL_HEADER.ImageBase + section.VirtualAddress,
                section.get_data(),
            )
    arena, stack, halt = 0x60000000, 0x70000000, 0x71000000
    for address, size in ((arena, 0x10000), (stack, 0x10000), (halt, 4096)):
        vm.mem_map(address, size)
    pages, calls = set(), []
    enabled = False

    def missing(machine, access, address, size, value, context):
        assert base <= address < base + runtime.OPTIONAL_HEADER.SizeOfImage
        for page in (address & ~4095, (address + size - 1) & ~4095):
            if page not in pages:
                machine.mem_map(page, 4096)
                content = runtime.get_data(page - base, 4096)
                if content:
                    machine.mem_write(page, content)
                pages.add(page)
        return True

    def returned(machine, value):
        position = machine.reg_read(x.UC_X86_REG_RSP)
        target = int.from_bytes(machine.mem_read(position, 8), "little")
        machine.reg_write(x.UC_X86_REG_RAX, value)
        machine.reg_write(x.UC_X86_REG_RSP, position + 8)
        machine.reg_write(x.UC_X86_REG_RIP, target)

    redirects = {
        symbols["DW_Achievement_GetLobbyId"]: lobby,
        symbols["DW_Achievement_GetMatchId"]: match_getter,
        symbols["DW_Achievement_AddKeyValue"]: append,
    }
    # VM redirects require distinct stub entry points. The shipping build binds
    # these names directly to distinct original functions rather than these stubs.
    assert len(redirects) == 3
    if report:
        # Linked imports already target the relocated native SDK functions.
        # Execute those instructions rather than redirecting the real image.
        assert symbols["DW_Achievement_AddKeyValue"] == append
        assert symbols["DW_Achievement_GetLobbyId"] == lobby
        redirects = {}

    def observe(machine, address, size, context):
        if address == halt:
            machine.emu_stop()
        elif address == symbols["DW_LocalBackend_IsEnabled"]:
            returned(machine, int(enabled))
        elif address in redirects:
            calls.append(dict(boundary=address, original=redirects[address]))
            machine.reg_write(x.UC_X86_REG_RIP, redirects[address])

    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    vm.hook_add(UC_HOOK_CODE, observe)
    event = arena + 0x1000
    vm.mem_write(event - 32, b"\xa5" * 32)
    vm.mem_write(event + prepared["derived_layout"]["event_size"], b"\x5a" * 32)
    missing(vm, 0, match_global, 8, 0, None)

    def call(entry, rcx, rdx=0, r8=0):
        rsp = stack + 0xF008
        vm.mem_write(rsp, struct.pack("<Q", halt))
        preserved = {}
        for index, register in enumerate(
            (
                x.UC_X86_REG_RBX,
                x.UC_X86_REG_RBP,
                x.UC_X86_REG_RSI,
                x.UC_X86_REG_RDI,
                x.UC_X86_REG_R12,
                x.UC_X86_REG_R13,
                x.UC_X86_REG_R14,
                x.UC_X86_REG_R15,
            )
        ):
            preserved[register] = 0x12340000 + index * 0x1000
        for index in range(6, 16):
            preserved[getattr(x, "UC_X86_REG_XMM" + str(index))] = (1 << 120) | index
        for register, value in preserved.items():
            vm.reg_write(register, value)
        for register, value in (
            (x.UC_X86_REG_RSP, rsp),
            (x.UC_X86_REG_RCX, rcx),
            (x.UC_X86_REG_RDX, rdx),
            (x.UC_X86_REG_R8, r8),
        ):
            vm.reg_write(register, value)
        vm.emu_start(entry, 0, count=200000)
        assert vm.reg_read(x.UC_X86_REG_RIP) == halt
        assert vm.reg_read(x.UC_X86_REG_RSP) == rsp + 8
        assert all(
            vm.reg_read(register) == value for register, value in preserved.items()
        )
        assert bytes(vm.mem_read(event - 32, 32)) == b"\xa5" * 32
        assert (
            bytes(vm.mem_read(event + prepared["derived_layout"]["event_size"], 32))
            == b"\x5a" * 32
        )

    def append_value(key, value):
        vm.mem_write(arena, key.encode() + b"\0")
        call(append, event, arena, value)

    layout = prepared["derived_layout"]

    def pairs():
        count = int.from_bytes(vm.mem_read(event + layout["pair_count"], 4), "little")
        assert count <= layout["pair_capacity"]
        rows = []
        for index in range(count):
            pointer = event + layout["pairs"] + index * layout["pair_stride"]
            key = (
                bytes(
                    vm.mem_read(
                        pointer + layout["pair_key"], layout["pair_key_capacity"]
                    )
                )
                .split(b"\0", 1)[0]
                .decode()
            )
            value = int.from_bytes(
                vm.mem_read(pointer + layout["pair_value"], 8), "little"
            )
            rows.append(dict(key=key, value=value))
        return rows

    call(constructor, event, 1)
    cases = []
    for label, active, count, mode, mid, lid, numeric in (
        ("ordinary-replay", False, 7, "kill", 101, 202, 0),
        ("largest-kill-before-params", True, 0, "kill", 101, 202, 0),
        ("largest-kill-after-params", True, 7, "kill", 101, 202, 0),
        ("start-distinct-ids", True, 2, "start_match", 101, 202, 0),
        ("start-no-allocation", True, 2, "start_match", 101, 0, 0),
        ("no-native-match", True, 2, "driving", 0, 202, 0),
        ("cached-duration", True, 2, "driving", 0x123456789ABCDEF0, 202, 0),
        ("full-event", True, 8, "kill", 101, 202, 0),
        ("unrelated-event", True, 2, "unrelated_sdk_event", 101, 202, 0),
        ("numeric-event", True, 2, "kill", 101, 202, 333),
    ):
        call(reset, event)
        vm.mem_write(arena, mode.encode() + b"\0")
        call(name_setter, event, arena)
        vm.mem_write(event + 16, struct.pack("<Q", numeric))
        enabled = active
        vm.mem_write(match_global, struct.pack("<Q", mid))
        lobby_field = (
            symbols["DW_Achievement_Matchmaker"]
            + proof["lobby_getter"]["instance_offset"]
        )
        if report:
            missing(vm, 0, lobby_field, 8, 0, None)
        vm.mem_write(lobby_field, struct.pack("<Q", lid))
        append_value("version", 1)
        append_value("gamemode", 2)
        for index in range(count):
            value = mid if mode == "start_match" and index == 0 else index + 10
            append_value("Param" + str(index), value)
        before = pairs()
        call(symbols["bdAchievementEvent_SetTimeStamp"], event, 1000)
        result = pairs()
        assert result[: len(before)] == before
        should_tag = (
            active
            and not numeric
            and count < 8
            and (
                (mode == "start_match" and lid) or (mode in ("kill", "driving") and mid)
            )
        )
        if should_tag:
            key, value = (
                ("dw_lobby_id", lid) if mode == "start_match" else ("dw_match_id", mid)
            )
            assert result == before + [dict(key=key, value=value)], {
                "case": label,
                "before": before,
                "after": result,
                "expected_key": key,
                "expected_value": value,
                "calls": calls[-4:],
            }
        else:
            assert result == before
        if label == "largest-kill-before-params":
            for index in range(7):
                append_value("Param" + str(index), index + 10)
            assert len(pairs()) == 10 and pairs()[-1] == dict(key="Param6", value=16)
        first = pairs()
        vm.mem_write(match_global, struct.pack("<Q", mid + 1))
        call(symbols["bdAchievementEvent_SetTimeStamp"], event, 1001)
        # A previously zero ID can legitimately become available on restamp.
        if label == "no-native-match":
            assert pairs() == first + [dict(key="dw_match_id", value=1)]
        else:
            assert pairs() == first
        assert (
            int.from_bytes(vm.mem_read(event + layout["timestamp"], 8), "little")
            == 1001
        )
        cases.append(dict(name=label, passed=True, pairs=pairs()))
    for name, key in (("start_match", "dw_lobby_id"), ("kill", "dw_match_id")):
        call(reset, event)
        vm.mem_write(arena, name.encode() + b"\0")
        call(name_setter, event, arena)
        vm.mem_write(event + 16, struct.pack("<Q", 0))
        enabled = True
        append_value(key, 777)
        before = pairs()
        call(symbols["bdAchievementEvent_SetTimeStamp"], event, 1002)
        assert pairs() == before
        cases.append(dict(name="retain-existing-" + key, passed=True, pairs=pairs()))
    receipt = dict(
        passed=True,
        checks=len(cases),
        cases=cases,
        compiled_image_sha256=hashlib.sha256(dll.read_bytes()).hexdigest(),
        source_sha256=prepared["source_sha256"],
        header_sha256=prepared["header_sha256"],
        original_image_sha256=prepared["image_sha256"],
        original_sdk_redirects=calls,
        modeled_boundary="DW enabled/ordinary executable selection only",
        sdk_append_and_getters_executed_original=True,
        game_runs_performed=False,
        win64_nonvolatile_registers_and_stack_preserved=True,
        linked_executable_instructions_verified=report is not None,
        cache_transition_lifetime_verified=False,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS:", len(cases), "compiled metadata cases with original SDK methods")


if __name__ == "__main__":
    main()
