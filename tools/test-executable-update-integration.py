"""Run linked Replay patch getters and platform restart routing in an ABI VM."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import re
import collections
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import capstone as cs
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
import unicorn.x86_const as reg


def check_initial_update(pe, base, symbols, updater_state):
    """Execute the first frame with image-initialized state and mocked OS threads."""
    cases = []
    for enabled, thread_succeeds, bypass in (
        (False, True, False), (True, True, False), (True, False, False),
        (True, True, True), (True, False, True),
    ):
        vm = Uc(UC_ARCH_X86, UC_MODE_64)
        arena = 0x100000000
        vm.mem_map(arena, 0x10000)
        mapped, calls, stages = set(), [], []
        worker_callback = None

        def page(address):
            start = address & ~4095
            if start in mapped:
                return
            assert base <= start < base + pe.OPTIONAL_HEADER.SizeOfImage
            vm.mem_map(start, 4096)
            data = pe.get_data(start - base, 4096)
            if data:
                vm.mem_write(start, data)
            mapped.add(start)

        def missing(vm, access, address, size, value, context):
            page(address)
            page(address + size - 1)
            return True

        vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
        page(updater_state)
        initial = struct.unpack("<I", vm.mem_read(updater_state, 4))[0]
        assert initial == 0, ("Compiled updater must start unstarted", initial)
        for name, address in (("__imp_CreateThread", arena + 0x1000), ("__imp_CloseHandle", arena + 0x1100)):
            page(symbols[name])
            vm.mem_write(symbols[name], struct.pack("<Q", address))

        def returned(value):
            stack = vm.reg_read(reg.UC_X86_REG_RSP)
            target = struct.unpack("<Q", vm.mem_read(stack, 8))[0]
            vm.reg_write(reg.UC_X86_REG_RAX, value)
            vm.reg_write(reg.UC_X86_REG_RSP, stack + 8)
            vm.reg_write(reg.UC_X86_REG_RIP, target)

        def boundary(vm, address, size, context):
            nonlocal worker_callback
            if address == symbols["DW_LocalBackend_IsEnabled"]:
                returned(int(enabled))
            elif address == symbols["DW_LocalConfig_BypassUpdateRestart"]:
                returned(int(bypass))
            elif address == arena + 0x1000:
                callback = vm.reg_read(reg.UC_X86_REG_R8)
                worker_callback = callback
                assert base <= callback < base + pe.OPTIONAL_HEADER.SizeOfImage
                assert vm.reg_read(reg.UC_X86_REG_RCX) == vm.reg_read(reg.UC_X86_REG_RDX) == vm.reg_read(reg.UC_X86_REG_R9) == 0
                stack = vm.reg_read(reg.UC_X86_REG_RSP)
                assert bytes(vm.mem_read(stack + 40, 16)) == bytes(16)
                calls.append("thread")
                returned(0x1234 if thread_succeeds else 0)
            elif address == arena + 0x1100:
                assert vm.reg_read(reg.UC_X86_REG_RCX) == 0x1234
                calls.append("close")
                returned(1)
            elif address == symbols["DW_LocalPlatform_RecordStage"]:
                pointer = vm.reg_read(reg.UC_X86_REG_RCX)
                data = bytearray()
                while True:
                    page(pointer + len(data))
                    value = bytes(vm.mem_read(pointer + len(data), 1))[0]
                    if not value:
                        break
                    data.append(value)
                    assert len(data) < 512
                stages.append(data.decode())
                returned(0)

        vm.hook_add(UC_HOOK_CODE, boundary)
        for _ in range(2):
            stack, stop = arena + 0xEF88, arena + 0xF000
            vm.mem_write(stack, struct.pack("<Q", stop))
            vm.reg_write(reg.UC_X86_REG_RSP, stack)
            vm.emu_start(symbols["DW_ExecutableUpdate_Frame"], stop, count=10000)
            assert vm.reg_read(reg.UC_X86_REG_RIP) == stop
        # bypass_update_restart=1 never starts the worker: no helper, no
        # update check and no download of any executable, asset or map.
        expected = [] if not enabled or bypass else ["thread", "close"] if thread_succeeds else ["thread"]
        assert calls == expected, (enabled, thread_succeeds, bypass, calls)
        state = struct.unpack("<I", vm.mem_read(updater_state, 4))[0]
        assert state == (50 if enabled and bypass else 1 if enabled and thread_succeeds else 40 if enabled else 0)
        assert any("bypass_update_restart=1" in stage for stage in stages) == (enabled and bypass), stages
        cases.append({"enabled": enabled, "thread_creation_succeeds": thread_succeeds,
                      "bypass_update_restart": bypass, "bypass_logged": any("bypass_update_restart=1" in stage for stage in stages),
                      "compiled_initial_state": initial, "frames": 2, "worker_starts": calls.count("thread"), "final_state": state,
                      "worker_callback": worker_callback})
    return cases


def check_worker(pe, base, symbols, updater_state, initial_checks, helper):
    """Execute the native worker; model only Win32 file/process boundaries."""
    results = []
    # Only installations without the bypass ever run the worker.
    for bypass in (False,):
        callback = next(row["worker_callback"] for row in initial_checks
                        if row["enabled"] and row["thread_creation_succeeds"] and row["bypass_update_restart"] == bypass)
        for existing in ("exact", "older", "trailing"):
            for helper_exit in ((10, 20, 40) if existing == "older" else (10,)):
                vm = Uc(UC_ARCH_X86, UC_MODE_64)
                arena = 0x100000000
                vm.mem_map(arena, 0x20000)
                pages, calls = set(), []
                read_at = 0
                api_names = ("GetModuleFileNameW", "CreateFileW", "WriteFile", "ReadFile",
                             "GetExitCodeProcess", "CreateProcessW")
                api = {name: arena + 0x1000 + index * 0x100 for index, name in enumerate(api_names)}
                imported = {"LoadLibraryA": arena + 0x2000, "GetProcAddress": arena + 0x2100,
                            "CloseHandle": arena + 0x2200, "WaitForSingleObject": arena + 0x2300}

                def page(address):
                    start = address & ~4095
                    if start in pages or arena <= start < arena + 0x20000:
                        return
                    assert base <= start < base + pe.OPTIONAL_HEADER.SizeOfImage
                    vm.mem_map(start, 4096)
                    raw = pe.get_data(start - base, 4096)
                    if raw:
                        vm.mem_write(start, raw)
                    pages.add(start)

                def read(address, size):
                    for at in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
                        page(at)
                    return bytes(vm.mem_read(address, size))

                def text(address, wide=False):
                    result = bytearray()
                    width = 2 if wide else 1
                    for index in range(2400):
                        value = read(address + index * width, width)
                        if value == bytes(width):
                            return result.decode("utf-16-le" if wide else "ascii")
                        result.extend(value)
                    raise AssertionError("Unbounded worker string")

                def returned(value):
                    rsp = vm.reg_read(reg.UC_X86_REG_RSP)
                    vm.reg_write(reg.UC_X86_REG_RAX, value)
                    vm.reg_write(reg.UC_X86_REG_RIP, struct.unpack("<Q", read(rsp, 8))[0])
                    vm.reg_write(reg.UC_X86_REG_RSP, rsp + 8)

                def missing(machine, access, address, size, value, context):
                    page(address); page(address + size - 1)
                    return True

                vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
                for name, address in imported.items():
                    page(symbols["__imp_" + name])
                    vm.mem_write(symbols["__imp_" + name], struct.pack("<Q", address))
                vm.mem_write(arena + 0x8000, "fixture-host\0".encode("utf-16-le"))

                def boundary(machine, address, size, context):
                    nonlocal read_at
                    a, b, c, d = [machine.reg_read(r) for r in (reg.UC_X86_REG_RCX, reg.UC_X86_REG_RDX,
                                                               reg.UC_X86_REG_R8, reg.UC_X86_REG_R9)]
                    if address == symbols.get("__chkstk"):
                        returned(machine.reg_read(reg.UC_X86_REG_RAX))
                    elif address == symbols["DW_LocalConfig_BypassUpdateRestart"]:
                        returned(int(bypass))
                    elif address == symbols["DW_LocalConfig_WideHost"]:
                        returned(arena + 0x8000)
                    elif address == imported["LoadLibraryA"]:
                        assert text(a) == "kernel32.dll"; returned(0x111)
                    elif address == imported["GetProcAddress"]:
                        assert a == 0x111; returned(api[text(b)])
                    elif address == api["GetModuleFileNameW"]:
                        assert a == 0 and c == 1024
                        value = "E:\\fixture\\game.exe"
                        vm.mem_write(b, (value + "\0").encode("utf-16-le")); returned(len(value))
                    elif address == api["CreateFileW"]:
                        assert text(a, True) == "E:\\fixture\\game.exe.updater.exe"
                        calls.append("open-existing" if b == 0x80000000 else "rewrite-helper")
                        returned(0x201 if b == 0x80000000 else 0x202)
                    elif address == api["ReadFile"]:
                        assert a == 0x201
                        data = helper[read_at:read_at + c]
                        if existing == "older" and not read_at:
                            data = bytes([helper[0] ^ 1]) + data[1:]
                        if existing == "trailing" and read_at == len(helper):
                            data = b"x"
                        vm.mem_write(b, data); vm.mem_write(d, struct.pack("<I", len(data)))
                        read_at += len(data); returned(1)
                    elif address == api["WriteFile"]:
                        assert a == 0x202 and c == len(helper) and read(b, c) == helper
                        vm.mem_write(d, struct.pack("<I", c)); returned(1)
                    elif address == api["CreateProcessW"]:
                        assert text(a, True) == "E:\\fixture\\game.exe.updater.exe"
                        mode = "--prepare"
                        assert text(b, True) == '"E:\\fixture\\game.exe.updater.exe" ' + mode + ' "E:\\fixture\\game.exe" fixture-host'
                        rsp = machine.reg_read(reg.UC_X86_REG_RSP)
                        assert struct.unpack("<I", read(rsp + 48, 4))[0] == 0x08000000
                        working, startup, process = struct.unpack("<QQQ", read(rsp + 64, 24))
                        assert text(working, True) == "E:\\fixture\\"
                        assert struct.unpack("<I", read(startup, 4))[0] == 104
                        vm.mem_write(process, struct.pack("<QQII", 0x301, 0x302, 123, 456))
                        calls.append(mode); returned(1)
                    elif address == imported["WaitForSingleObject"]:
                        assert a == 0x301 and b == 90 * 60 * 1000
                        calls.append("bounded-map-wait"); returned(0)
                    elif address == api["GetExitCodeProcess"]:
                        assert a == 0x301
                        vm.mem_write(b, struct.pack("<I", helper_exit)); returned(1)
                    elif address == imported["CloseHandle"]:
                        assert a in (0x201, 0x202, 0x301, 0x302); returned(1)

                vm.hook_add(UC_HOOK_CODE, boundary)
                rsp, stop = arena + 0x1EF88, arena + 0x1F000
                vm.mem_write(rsp, struct.pack("<Q", stop)); vm.reg_write(reg.UC_X86_REG_RSP, rsp)
                vm.reg_write(reg.UC_X86_REG_RCX, 0)
                try:
                    vm.emu_start(callback, stop, count=max(100000, len(helper) * 16))
                except Exception as error:
                    raise AssertionError((bypass, existing, helper_exit, hex(vm.reg_read(reg.UC_X86_REG_RIP)),
                                          hex(vm.reg_read(reg.UC_X86_REG_RCX)), hex(vm.reg_read(reg.UC_X86_REG_RDX)), calls)) from error
                assert vm.reg_read(reg.UC_X86_REG_RIP) == stop
                final_state = struct.unpack("<I", read(updater_state, 4))[0]
                assert final_state == helper_exit
                assert calls.count("rewrite-helper") == int(existing != "exact")
                results.append({"bypass_update_restart": bypass, "existing_helper": existing,
                                "helper_exit": helper_exit, "state": final_state, "calls": calls})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--updater-source", type=Path, help="Compile this owner into an offline component overlay")
    parser.add_argument("--compiler-source", type=Path, help="Frozen compiler tools and native headers for --updater-source")
    args = parser.parse_args()
    report = json.loads((args.build / "build-report.json").read_bytes())
    image = Path(report["executable"])
    assert hashlib.sha256(image.read_bytes()).hexdigest() == report["sha256"]
    pe = pefile.PE(str(image), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    symbols = {name: base + rva for name, rva in report["symbols"].items()}
    owner_proof = None
    if args.updater_source:
        assert args.compiler_source
        sys.path.insert(0, str(args.compiler_source / "tools"))
        import coff
        import build as compiler_linker
        source_hash = hashlib.sha256(args.updater_source.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="update-owner-", dir=Path(__file__).resolve().parents[1] / "data") as folder:
            output = Path(folder) / "update.obj"
            subprocess.run([str(compiler_linker.LLVM / "clang++.exe"),
                "--target=x86_64-pc-windows-msvc", "-std=c++20", "-O2", "-ffreestanding",
                "-fno-stack-protector", "-fno-exceptions", "-fno-rtti", "-funwind-tables",
                "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Werror",
                "-I" + str(args.compiler_source / "src"), "-c", str(args.updater_source),
                "-o", str(output)], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            obj = coff.read(output)
            owner_proof = {"source_sha256": source_hash, "object_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}
        assert hashlib.sha256(args.updater_source.read_bytes()).hexdigest() == source_hash
        original_symbols = dict(symbols)
        rvas = {name: address - base for name, address in symbols.items()}
        at = (pe.OPTIONAL_HEADER.SizeOfImage + 65535) & -65536
        for section in obj["sections"]:
            section["rva"] = at
            at = coff.align(at + len(section["data"]), 16)
        for symbol in obj["symbols"].values():
            if symbol["section"] > 0 and symbol["storage"] == 2:
                rvas[symbol["name"]] = obj["sections"][symbol["section"] - 1]["rva"] + symbol["value"]
        statistics = collections.Counter()
        manifest = dict(image_base=base, replacements=[], optional=dict(SizeOfImage=at))
        overlays = []
        for section in obj["sections"]:
            if section["data"]:
                data = bytes(compiler_linker.relocate(obj, section, rvas, manifest, statistics, set()))
                overlays.append((section["rva"], data))
        symbols = {name: base + rva for name, rva in rvas.items()}
        for name, address in symbols.items():
            if name in original_symbols and address != original_symbols[name]:
                overlays.append((original_symbols[name] - base, b"\x48\xb8" + struct.pack("<Q", address) + b"\xff\xe0"))
        original_pe = pe

        class ComponentPE:
            OPTIONAL_HEADER = SimpleNamespace(ImageBase=base, SizeOfImage=coff.align(at, 4096))

            def get_data(self, rva, size):
                data = bytearray(original_pe.get_data(rva, size)) if rva < original_pe.OPTIONAL_HEADER.SizeOfImage else bytearray()
                data.extend(bytes(size - len(data)))
                for begin, value in overlays:
                    left, right = max(rva, begin), min(rva + size, begin + len(value))
                    if left < right:
                        data[left - rva:right - rva] = value[left - begin:right - begin]
                return bytes(data)

        pe = ComponentPE()
        owner_proof.update(vm_only=True, full_game_compiled=False,
                           compiler_relocator_sha256=hashlib.sha256((args.compiler_source / "tools/build.py").read_bytes()).hexdigest(),
                           relocation_counts=dict(statistics))
    # The existing compiled-updater gate also executes the linked INI parser;
    # configuration defaults and field preservation belong to this feature.
    spec = importlib.util.spec_from_file_location("linked_local_config_tests", Path(__file__).with_name("test-local-config.py"))
    local_config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(local_config)
    local_config_checks = local_config.run_checks(pe, base, symbols)
    # Discover the compiled private state through its atomic instruction, rather
    # than assuming an RVA or depending on compiler-local symbol spelling.
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    decoder.detail = True
    address = symbols["func_141053520"]
    candidates = []
    for insn in decoder.disasm(pe.get_data(address - base, 256), address):
        if "cmpxchg" in insn.mnemonic:
            operand = insn.operands[0]
            assert operand.type == cs.x86.X86_OP_MEM and operand.mem.base == cs.x86.X86_REG_RIP
            candidates.append(insn.address + insn.size + operand.mem.disp)
    assert len(candidates) == 1
    updater_state = candidates[0]
    initial_checks = check_initial_update(pe, base, symbols, updater_state)
    updater = next(row for row in report["cpp"] if Path(row["source"]).name == "DW_ExecutableUpdate.cpp")
    helper_dependency = next(row for row in updater["dependencies"] if Path(row["path"]).name == "DW_UpdateHelper.h")
    helper_header = Path(helper_dependency["path"])
    assert hashlib.sha256(helper_header.read_bytes()).hexdigest() == helper_dependency["sha256"]
    helper = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})\b", helper_header.read_text()))
    assert helper.startswith(b"MZ") and len(helper) > 1024
    worker_checks = check_worker(pe, base, symbols, updater_state, initial_checks, helper)
    assert not any(
        row["symbol"] == "func_1410527B0" for row in report["replacements"]
    ), "Do not close the native prerequisite fence"
    checks = []

    for enabled in (False, True):
        for state, bypass in ((value, bypass) for value in (1, 10, 20, 30, 40, 50) for bypass in (False, True)):
            vm = Uc(UC_ARCH_X86, UC_MODE_64)
            arena = 0x100000000
            vm.mem_map(arena, 0x10000)
            mapped = set()

            def page(address):
                start = address & ~4095
                if start in mapped:
                    return
                assert base <= start < base + pe.OPTIONAL_HEADER.SizeOfImage
                vm.mem_map(start, 4096)
                data = pe.get_data(start - base, 4096)
                if data:
                    vm.mem_write(start, data)
                mapped.add(start)

            def missing(vm, access, address, size, value, context):
                page(address)
                page(address + size - 1)
                return True

            vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)

            def write(address, value):
                if not arena <= address < arena + 0x10000:
                    page(address)
                vm.mem_write(address, value)

            calls = []

            def returned(value):
                stack = vm.reg_read(reg.UC_X86_REG_RSP)
                target = struct.unpack("<Q", vm.mem_read(stack, 8))[0]
                vm.reg_write(reg.UC_X86_REG_RAX, value)
                vm.reg_write(reg.UC_X86_REG_RSP, stack + 8)
                vm.reg_write(reg.UC_X86_REG_RIP, target)

            def boundary(vm, address, size, context):
                if address == symbols["DW_LocalBackend_IsEnabled"]:
                    returned(int(enabled))
                elif address == symbols["DW_LocalConfig_BypassUpdateRestart"]:
                    returned(int(bypass))
                elif address == symbols["func_1420838B0"]:
                    returned(0)
                elif address == symbols["func_1413E9BE0"]:
                    calls.append("success-label")
                    returned(0)
                elif address == symbols["Dvar_SetBool_Internal"]:
                    assert vm.reg_read(reg.UC_X86_REG_RDX) & 255 == 1
                    calls.append("native-restart-dvar")
                    returned(0)
                elif address == symbols["func_1416702D0"]:
                    calls.append("service")
                    returned(arena + 0x5000)
                elif address == symbols["func_141660390"]:
                    calls.append("account")
                    returned(99)
                elif address == symbols["func_140C859F0"]:
                    assert [
                        vm.reg_read(r)
                        for r in (
                            reg.UC_X86_REG_RCX,
                            reg.UC_X86_REG_RDX,
                            reg.UC_X86_REG_R8,
                            reg.UC_X86_REG_R9,
                        )
                    ] == [arena + 0x5000, 99, symbols["func_14165E6D0"], 0]
                    calls.append("request")
                    returned(0)

            vm.hook_add(UC_HOOK_CODE, boundary)

            def call(name, *arguments):
                stack, stop = arena + 0xEF88, arena + 0xF000
                vm.mem_write(stack, struct.pack("<Q", stop))
                for target, value in zip(
                    (reg.UC_X86_REG_RCX, reg.UC_X86_REG_RDX, reg.UC_X86_REG_R8, reg.UC_X86_REG_R9),
                    arguments,
                ):
                    vm.reg_write(target, value)
                vm.reg_write(reg.UC_X86_REG_RSP, stack)
                vm.emu_start(symbols[name], stop, count=10000)
                assert vm.reg_read(reg.UC_X86_REG_RIP) == stop
                return vm.reg_read(reg.UC_X86_REG_RAX) & 255

            write(updater_state, struct.pack("<I", state))
            for kind in (0, 1):
                for native in range(5):
                    write(arena + 0x1000 + 165 + kind * 100, bytes([native]))
                    expected = native
                    if enabled and kind == 0 and native not in (3, 4):
                        if state == 1:
                            expected = 0
                        elif state == 20 and native in (1, 2):
                            expected = 2
                        elif state == 40:
                            expected = 3
                    assert call("func_141053520", arena + 0x1000, kind) == expected
            # Startup prerequisite remains passable while the UI owns the
            # restart-required state, preventing the observed sign-in deadlock.
            write(symbols["gl_14D386A08"], struct.pack("<Q", arena + 0x3000))
            write(arena + 0x3028, struct.pack("<Q", arena + 0x4000))
            write(arena + 0x1000 + 79, b"\x01")
            assert call("func_1410527B0", arena + 0x1000, 0) == 1
            call("func_141B117B0", arena + 0x2000)
            expected_lua = [] if enabled and state == 20 else ["success-label", "native-restart-dvar"]
            assert calls == expected_lua, (enabled, bypass, state, calls)
            calls.clear()
            write(symbols["gl_14F05AC00"], b"\0")
            call("func_14165E530")
            expected = [] if enabled and state == 20 else ["service", "account", "request"]
            assert calls == expected
            checks.append(
                {
                    "enabled": enabled,
                    "state": state,
                    "bypass_update_restart": bypass,
                    "getter_cases": 10,
                    "native_prerequisite_passes": True,
                    "restart_route_correct": True,
                    "native_data_restart_preserved": not (enabled and state == 20),
                    "asset_failure_fence": enabled and state == 40,
                }
            )
    args.output.write_text(
        json.dumps(
            {
                "schema": 1,
                "passed": True,
                "bypass_skips_updater": True,
                "game_sha256": report["sha256"],
                "focused_owner": owner_proof,
                "checks": checks,
                "initial_update_checks": initial_checks,
                "worker_checks": worker_checks,
                "embedded_helper_sha256": hashlib.sha256(helper).hexdigest(),
                "local_config_checks": local_config_checks,
                "native_game_verified": False,
                "modeled_boundaries": [
                    "DW filename selection",
                    "native platform request transport",
                    "OS thread creation and handle close",
                    "Worker Win32 file/process APIs and helper exit status; exact worker instructions executed",
                ],
            },
            indent=2,
        )
        + "\n"
    )
    print(
        "PASS: compiled updater scheduling (bypass starts nothing), 240 linked patch-state cases, asset failure/restart and native data restart routing"
    )


if __name__ == "__main__":
    main()
