"""Verify compiled native zone delivery and complete original clone offline."""

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path("C:/Program Files/LLVM/bin")


def native_path_matrix(policy):
    """Execute original classifiers/getters/path builder with modeled formatting."""
    import capstone
    import pefile
    import struct
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
    from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_RIP
    image = pefile.PE("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe", fast_load=True)
    base = image.OPTIONAL_HEADER.ImageBase
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    entries = {row["role"]: base + row["rva"] for row in policy["native"]}
    decoded = {row["role"]: list(decoder.disasm(image.get_data(row["rva"], row["bytes"]), base + row["rva"])) for row in policy["native"]}
    vm, mapped = Uc(UC_ARCH_X86, UC_MODE_64), set()

    def page(address):
        address &= -4096
        if address not in mapped:
            vm.mem_map(address, 4096)
            if base <= address < base + image.OPTIONAL_HEADER.SizeOfImage:
                data = image.get_data(address - base, 4096)
                if data: vm.mem_write(address, data)
            mapped.add(address)

    def put(address, data):
        for at in range(address & -4096, (address + len(data) + 4095) & -4096, 4096): page(at)
        vm.mem_write(address, data)

    def text(address):
        value = bytearray()
        while True:
            page(address)
            byte = vm.mem_read(address, 1)[0]
            if not byte: return value.decode()
            value.append(byte); address += 1

    def rip(row):
        operand = next(op for op in row.operands if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP)
        return row.address + row.size + operand.mem.disp

    language_global = rip(decoded["SEH_GetCurrentLanguageCode"][0])
    region_global = rip(decoded["RG_GetCurrentRegionCode"][0])
    folder_table = rip(next(row for row in decoded["DWBSZ_BuildAbsPath"] if row.mnemonic == "lea" and row.op_str.startswith("rax, [rip")))
    printf = [row.operands[0].imm for row in decoded["DWBSZ_IsLocalized"] if row.mnemonic == "call"][1]
    default_root = entries["Sys_DefaultInstallPath"]
    stack, stop, dvar, input_at, out_at, root_at = 0x72008000, 0x73000000, 0x74000000, 0x74001000, 0x74002000, 0x74003000
    put(stop, b"\xc3"); put(root_at, b"E:\\native-root\0"); put(language_global, struct.pack("<Q", dvar))

    def return_value(value):
        rsp = vm.reg_read(UC_X86_REG_RSP)
        vm.reg_write(UC_X86_REG_RAX, value)
        vm.reg_write(UC_X86_REG_RIP, struct.unpack("<Q", vm.mem_read(rsp, 8))[0])
        vm.reg_write(UC_X86_REG_RSP, rsp + 8)

    def boundary(vm, address, size, user):
        if address == default_root:
            return_value(root_at)
        elif address == printf:
            rsp = vm.reg_read(UC_X86_REG_RSP)
            fmt = text(vm.reg_read(UC_X86_REG_R8))
            first = vm.reg_read(UC_X86_REG_R9)
            if fmt == "%s_": value = text(first) + "_"
            elif fmt == "%s%c%s%s%s":
                extra = struct.unpack("<QQQQ", vm.mem_read(rsp + 40, 32))
                value = text(first) + chr(extra[0] & 255) + "".join(text(at) for at in extra[1:])
            else: raise AssertionError(("Unexpected native path format", fmt))
            assert len(value) + 1 <= vm.reg_read(UC_X86_REG_RDX)
            put(vm.reg_read(UC_X86_REG_RCX), value.encode() + b"\0")
            return_value(len(value))

    vm.hook_add(UC_HOOK_CODE, boundary)
    vm.hook_add(UC_HOOK_MEM_UNMAPPED, lambda vm, access, at, size, value, user: (page(at), True)[1])

    def call(role, args):
        put(stack - 8192, bytes(8192 + 128)); put(stack, struct.pack("<Q", stop))
        for reg, value in zip((UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9), args): vm.reg_write(reg, value)
        if len(args) > 4: put(stack + 40, struct.pack("<Q", args[4]))
        vm.reg_write(UC_X86_REG_RSP, stack)
        vm.emu_start(entries[role], stop, count=10000)
        return vm.reg_read(UC_X86_REG_RAX)

    codes = ["ww", "jp", "sa", "kr15", "cn", ""]
    languages = list(policy["language_directories"])
    cases = 0
    for region_index, region in enumerate(codes):
        put(region_global, struct.pack("<I", region_index))
        for language_index, language in enumerate(languages):
            put(dvar + 40, struct.pack("<I", language_index))
            for folder, directory in ((0, ""), (1, policy["language_directories"][language]), (7, policy["region_directories"][region])):
                value = "zone\\" + (directory + "\\" if directory else "")
                put(folder_table + folder * 256, value.encode() + b"\0")
            for rule in policy["native_folder_rules"]:
                name = rule["name_prefix"] + "dw_bot_styles_mp_0123456789abcdef.ff"
                for spelling in (name, name.upper()):
                    put(input_at, spelling.encode() + b"\0")
                    localized = bool(call("DWBSZ_IsLocalized", [input_at]) & 255)
                    regional = bool(call("DWBSZ_IsRegional", [input_at]) & 255)
                    assert localized == name.startswith(language + "_")
                    assert regional == name.startswith(region + "_")
                    folder = 1 if localized else 7 if regional else 0
                    put(root_at + 128, b"\0")
                    call("DWBSZ_BuildAbsPath", [out_at, 512, folder, input_at, root_at + 128])
                    directory = policy["language_directories"][language] if folder == 1 else policy["region_directories"][region] if folder == 7 else ""
                    assert text(out_at) == "E:\\native-root\\zone\\" + (directory + "\\" if directory else "") + spelling
                    if folder != 0 or not rule["directory"]:
                        assert rule["directory"] == directory
                    cases += 1
    return cases


def native_duplicate_matrix(proof):
    """Run the complete native link routine for same-group ScriptFile duplicates."""
    import capstone
    import pefile
    import struct
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
    from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_RIP
    image = pefile.PE("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe", fast_load=True)
    base = image.OPTIONAL_HEADER.ImageBase
    body = proof["native_duplicate_link"]
    assert hashlib.sha256(image.get_data(body["rva"], body["bytes"])).hexdigest() == body["sha256"]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    calls = {row.operands[0].imm for row in decoder.disasm(image.get_data(body["rva"], body["bytes"]), base + body["rva"])
             if row.mnemonic == "call" and row.operands[0].type == capstone.x86.X86_OP_IMM}
    hooks = {base + row["rva"]: row["role"] for row in proof["native_duplicate_boundaries"]}
    results = []
    for name in ("1827", "scripts/mp/bots/bots_gametype_br.gsc", "scripts/mp/gametypes/br_weapons.gsc"):
        for first in ("original", "patched"):
            vm, pages, events = Uc(UC_ARCH_X86, UC_MODE_64), set(), []
            stack, stop, name_at, existing, existing_header, incoming_header, argument = (
                0x71008000, 0x72000000, 0x73000000, 0x73001000, 0x73002000, 0x73003000, 0x73004000)

            def page(address):
                address &= -4096
                if address not in pages:
                    vm.mem_map(address, 4096)
                    if base <= address < base + image.OPTIONAL_HEADER.SizeOfImage:
                        data = image.get_data(address - base, 4096)
                        if data: vm.mem_write(address, data)
                    pages.add(address)

            def put(address, data):
                for at in range(address & -4096, (address + len(data) + 4095) & -4096, 4096): page(at)
                vm.mem_write(address, data)

            def returned(value=0):
                rsp = vm.reg_read(UC_X86_REG_RSP)
                vm.reg_write(UC_X86_REG_RAX, value)
                vm.reg_write(UC_X86_REG_RIP, struct.unpack("<Q", vm.mem_read(rsp, 8))[0])
                vm.reg_write(UC_X86_REG_RSP, rsp + 8)

            def boundary(vm, address, size, user):
                if address not in calls: return
                role = hooks.get(address)
                a, b, cc, d = (vm.reg_read(reg) for reg in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9))
                events.append(role)
                if role == "find":
                    assert b == name_at and cc == 52
                    returned(existing)
                elif role == "current-zone": returned(78)
                elif role == "zone-flags":
                    assert a in (74, 78)
                    returned(0x10)
                elif role == "duplicate":
                    rsp = vm.reg_read(UC_X86_REG_RSP)
                    assert a == 52 and b == name_at and cc == 74 and d == 78
                    assert vm.mem_read(rsp + 40, 1)[0] == 1
                    returned()
                elif role == "discard":
                    assert struct.unpack("<I", vm.mem_read(a, 4))[0] == 52
                    assert struct.unpack("<Q", vm.mem_read(a + 8, 8))[0] == incoming_header
                    returned()
                else: raise AssertionError(("Unexpected native duplicate boundary", hex(address), role))

            put(stack - 8192, bytes(8192 + 128)); put(stack, struct.pack("<Q", stop)); put(stop, b"\xc3")
            put(name_at, name.encode() + b"\0")
            put(existing_header, struct.pack("<QiiiIQQ", name_at, 1, 1, 26243 if first == "patched" else 26221, 0, 0, 0))
            put(incoming_header, struct.pack("<QiiiIQQ", name_at, 1, 1, 26221 if first == "patched" else 26243, 0, 0, 0))
            put(existing, struct.pack("<QIIBBH", existing_header, 0, 0, 13, 52, 74))
            put(argument, struct.pack("<Q", incoming_header))
            vm.hook_add(UC_HOOK_CODE, boundary)
            vm.hook_add(UC_HOOK_MEM_UNMAPPED, lambda vm, access, at, size, value, user: (page(at), True)[1])
            vm.reg_write(UC_X86_REG_RCX, 52); vm.reg_write(UC_X86_REG_RDX, argument); vm.reg_write(UC_X86_REG_RSP, stack)
            vm.emu_start(base + body["rva"], stop, count=100000)
            assert vm.reg_read(UC_X86_REG_RAX) == existing
            assert struct.unpack("<Q", vm.mem_read(argument, 8))[0] == 0
            assert struct.unpack("<Q", vm.mem_read(existing, 8))[0] == existing_header
            assert events.count("duplicate") == events.count("discard") == 1
            results.append(dict(name=name,first_owner=first,native_retained_owner=first,incoming_discarded=True))
    return results


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--build", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    snapshot = a.snapshot.resolve()
    if a.build:
        build = json.loads((a.build / "build-report.json").read_bytes())
        assert not build["unresolved_symbols"]
        assert sha(build["executable"]) == build["sha256"]
        compiled = {row["source_sha256"] for row in build["cpp"]}
        assert sha(snapshot / "src/DW_BotStyleZone.cpp") in compiled
        assert sha(snapshot / "src/DW_BotStyleZone_Native.cpp") in compiled
    receipt = json.loads(
        (snapshot / "generated/bot-style-zone-integration.json").read_bytes()
    )
    assert (
        receipt["passed"]
        and receipt["original_body_reconstructed"]
        and receipt["coff_unwind_records"] == 1
    )
    assert receipt["source_sha256"] == sha(
        ROOT / "integration/replay/DW_BotStyleZone.cpp"
    )
    assert receipt["native_clone_source_sha256"] == sha(receipt["native_clone_source"])
    assert receipt["clone_object_sha256"] == sha(receipt["clone_object"])
    assert receipt["generated_package_header_sha256"] == sha(
        snapshot / "src/DW_BotStyleScriptPackage.h"
    )
    assert (
        receipt["helper_has_no_original_mapping"]
        and receipt["native_queue_same_priority_fifo"]
        and receipt["overlay_precedes_common_base_mp"]
    )
    duplicate_cases = native_duplicate_matrix(receipt)
    package = json.loads((snapshot / "generated/bot-style-scripts/package-proof.json").read_bytes())
    header = (snapshot / "src/DW_BotStyleScriptPackage.h").read_text()
    names = [row["name"][:-3] for row in package["installation_manifest"] if row["name"].endswith(".ff")]
    assert len(names) == 10 and len(set(names)) == 10
    policy = package["native_locale_codes"]
    assert policy["supported_language_directories"] == {"eng": "english"}
    assert len(policy["language_directories"]) == 21
    native_path_cases = native_path_matrix(policy)
    assert package["native_folder_rules"] == policy["installation_folder_rules"]
    assert len(package["native_folder_rules"]) == 10
    assert receipt["native_path_policy"] == policy
    assert len({row["relative_path"] for row in package["installation_manifest"]}) == 20
    for row in package["installation_manifest"]:
        directory = row["relative_path"].rsplit("/", 1)[0] if "/" in row["relative_path"] else ""
        assert row["relative_path"] == (directory + "/" if directory else "") + row["name"]
        assert not directory or directory in {*policy["region_directories"].values(), *policy["supported_language_directories"].values()}
    assert all(header.count('"' + name + '"') == 1 + int(name == package["zone_name"]) for name in names)
    for name in ("prepare-bot-style-scripts.py", "prepare-bot-style-zone.py"):
        spec = importlib.util.spec_from_file_location(
            "private_write_test", ROOT / "tools" / name
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(
            prefix="bot-style-owner-", dir=ROOT / "data"
        ) as temporary:
            folder = Path(temporary)
            retained = folder / "retained.bin"
            inherited = folder / "inherited.bin"
            retained.write_bytes(b"sealed-original")
            os.link(retained, inherited)
            assert retained.stat().st_nlink == 2
            module.write_private(inherited, b"new-owned-output")
            assert retained.read_bytes() == b"sealed-original"
            assert inherited.read_bytes() == b"new-owned-output"
            assert retained.stat().st_nlink == inherited.stat().st_nlink == 1
    with tempfile.TemporaryDirectory(
        prefix="bot-style-zone-", dir=ROOT / "build"
    ) as temporary:
        folder = Path(temporary)
        obj = folder / "test.obj"
        dll = folder / "test.dll"
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
                str(ROOT / "integration/replay/DW_BotStyleZone.cpp"),
                "-o",
                str(folder / "production.obj"),
            ],
            check=True,
        )
        subprocess.run(
            [
                str(LLVM / "clang++.exe"),
                *flags,
                "-c",
                str(ROOT / "tools/bot_style_zone_harness.cpp"),
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
        try:
            result = library.Test_Run()
            assert result == 0, f"Compiled zone owner failed at source line {result}"
            library.Test_Locale.argtypes = [ctypes.c_char_p] * 4
            locale_cases = 0
            for region, region_directory in policy["region_directories"].items():
                for language, language_directory in policy["supported_language_directories"].items():
                    assert library.Test_Locale(*(value.encode() for value in
                        (region, language, region_directory, language_directory))) == 0, (region, language)
                    locale_cases += 1
        finally:
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(library._handle)
    receipt.update(
        production_object_compiled=True,
        compiled_wrapper_stager_harness_passed=True,
        modeled_native_lifecycle_states_checked=True,
        exact_resource_comparison_checked=True,
        stale_resource_repaired=True,
        partial_write_and_move_failures_checked=True,
        original_request_unchanged_on_failure=True,
        inherited_hardlink_outputs_remain_unchanged=True,
        all_owned_installation_files_staged=True,
        owned_installation_file_count=len(package["installation_manifest"]),
        supported_languages=policy["supported_languages"],
        embedded_names_match_updater_manifest=True,
        native_locale_folder_cases=locale_cases,
        native_locale_files_available_before_queueing=True,
        native_pending_load_performs_no_staging_reads=True,
        original_native_path_classification_cases=native_path_cases,
        original_native_duplicate_policy_cases=duplicate_cases,
        game_modified=False,
        game_run_performed=False,
    )
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        "PASS: complete 933-byte native clone and compiled native zone/resource delivery harness"
    )


if __name__ == "__main__":
    main()
