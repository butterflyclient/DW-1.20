"""Execute linked native INI parsing with in-memory Windows file boundaries."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
import unicorn.x86_const as reg


def check(pe, base, symbols, files):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    arena = 0x100000000
    vm.mem_map(arena, 0x20000)
    mapped, handles, imports = set(), {}, {}

    def page(address):
        if arena <= address < arena + 0x20000:
            return
        address &= -4096
        if address in mapped:
            return
        assert base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage
        vm.mem_map(address, 4096)
        data = pe.get_data(address - base, 4096)
        if data:
            vm.mem_write(address, data)
        mapped.add(address)

    def put(address, data):
        for at in range(address & -4096, (address + len(data) + 4095) & -4096, 4096):
            page(at)
        vm.mem_write(address, data)

    def string(address):
        value = bytearray()
        while len(value) < 2048:
            page(address + len(value))
            byte = bytes(vm.mem_read(address + len(value), 1))[0]
            if not byte:
                return value.decode()
            value.append(byte)
        raise AssertionError("Unterminated fixture string")

    def missing(machine, access, address, size, value, context):
        page(address); page(address + size - 1)
        return True
    vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    for index, name in enumerate(("GetModuleFileNameA", "CreateFileA", "ReadFile", "CloseHandle", "Sleep")):
        address = arena + 0x1000 + index * 16
        imports[address] = name
        put(symbols["__imp_" + name], struct.pack("<Q", address))

    def returned(value):
        stack = vm.reg_read(reg.UC_X86_REG_RSP)
        target = struct.unpack("<Q", vm.mem_read(stack, 8))[0]
        vm.reg_write(reg.UC_X86_REG_RAX, value & 0xffffffffffffffff)
        vm.reg_write(reg.UC_X86_REG_RSP, stack + 8)
        vm.reg_write(reg.UC_X86_REG_RIP, target)

    def boundary(machine, address, size, context):
        a = [vm.reg_read(register) for register in
             (reg.UC_X86_REG_RCX, reg.UC_X86_REG_RDX, reg.UC_X86_REG_R8, reg.UC_X86_REG_R9)]
        name = imports.get(address)
        if name == "GetModuleFileNameA":
            text = b"E:\\Fixture\\custom-game.exe\0"
            put(a[1], text); returned(len(text) - 1)
        elif name == "CreateFileA":
            path = string(a[0])
            if path not in files:
                returned(2**64 - 1)
            else:
                handle = 100 + len(handles)
                handles[handle] = [path, 0]
                returned(handle)
        elif name == "ReadFile":
            path, cursor = handles[a[0]]
            data = files[path][cursor:cursor + a[2]]
            put(a[1], data); put(a[3], struct.pack("<I", len(data)))
            handles[a[0]][1] += len(data)
            returned(1)
        elif name == "CloseHandle":
            assert a[0] in handles
            returned(1)
        elif name == "Sleep":
            raise AssertionError("Serial fixture must not wait on INI initialization")
        elif address == symbols.get("memset"):
            put(a[0], bytes([a[1] & 255]) * a[2]); returned(a[0])
        elif address == symbols.get("memcpy"):
            put(a[0], bytes(vm.mem_read(a[1], a[2]))); returned(a[0])
        elif address in (symbols.get("__chkstk"), symbols.get("sub_1421CCEF0")):
            returned(vm.reg_read(reg.UC_X86_REG_RAX))
        elif address in (symbols.get("__security_check_cookie"), symbols.get("sub_1421CCF60")):
            returned(0)
    vm.hook_add(UC_HOOK_CODE, boundary)

    def call(name):
        stack, stop = arena + 0x1EF88, arena + 0x1F000
        put(stack, struct.pack("<Q", stop))
        vm.reg_write(reg.UC_X86_REG_RSP, stack)
        vm.emu_start(symbols[name], stop, count=200000)
        assert vm.reg_read(reg.UC_X86_REG_RIP) == stop
        return vm.reg_read(reg.UC_X86_REG_RAX)
    bypass = call("DW_LocalConfig_BypassUpdateRestart") & 255
    return dict(bypass=bool(bypass), host=string(call("DW_LocalConfig_Host")),
                player_name=string(call("DW_LocalConfig_PlayerName")),
                unlock_all=bool(call("DW_LocalConfig_UnlockAll") & 255),
                rank=call("DW_LocalConfig_Rank") & 0xffffffff,
                test_command=string(call("DW_LocalConfig_TestCommand")),
                test_enabled=string(call("DW_LocalConfig_TestEnabled")),
                auth_url=string(call("DW_LocalConfig_AuthUrl")))


def run_checks(pe, base, symbols):
    primary = "E:\\Fixture\\custom-game.ini"
    existing = b"host=10.20.30.40\nplayer_name=Custom Test\nunlock_all=1\nrank=53\n"
    expected = dict(bypass=False, host="10.20.30.40", player_name="Custom Test", unlock_all=True,
                    rank=53, test_command="replay-dw-test.command", test_enabled="replay-dw-test.enabled",
                    auth_url="https://10.20.30.40:8443/auth/")
    cases = [("omitted", existing, False), ("zero", existing + b"bypass_update_restart=0\n", False),
             ("one", existing + b"bypass_update_restart=1\n", True),
             ("BOM", b"\xef\xbb\xbf" + existing + b"bypass_update_restart=1\r\n", True),
             ("last setting wins", existing + b"bypass_update_restart=1\nbypass_update_restart=0\n", False)]
    checks = []
    for label, contents, bypass in cases:
        actual = check(pe, base, symbols, {primary: contents})
        assert actual == dict(expected, bypass=bypass), (label, actual)
        checks.append(label)
    for value in (b"", b"2", b"-1", b"true", b"01", b"1 ", b"123456789"):
        actual = check(pe, base, symbols, {primary: existing + b"bypass_update_restart=" + value + b"\n"})
        assert not actual["bypass"] and actual["host"] == "", (value, actual)
        assert actual["unlock_all"] and actual["rank"] == 53 and actual["player_name"] == "Custom Test"
        checks.append("invalid:" + value.decode())
    actual = check(pe, base, symbols, {"replay-dw.ini": existing + b"bypass_update_restart=1\n"})
    assert actual == dict(expected, bypass=True)
    checks.append("fallback INI")
    actual = check(pe, base, symbols, {primary: existing + b"bypass_update_restart=0\n",
                                      "replay-dw.ini": existing + b"bypass_update_restart=1\n"})
    assert actual == expected
    checks.append("executable INI preference")
    actual = check(pe, base, symbols, {})
    assert not actual["bypass"] and actual["host"] == "127.0.0.1" and not actual["unlock_all"] and actual["rank"] == 0
    assert actual['auth_url'] == 'http://127.0.0.1:8085/auth/'
    checks.append("no INI defaults")
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads((args.build / "build-report.json").read_bytes())
    image = Path(report["executable"])
    assert hashlib.sha256(image.read_bytes()).hexdigest() == report["sha256"]
    assert report["unresolved_symbols"] == 0
    pe = pefile.PE(str(image), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    symbols = {name: base + rva for name, rva in report["symbols"].items()}
    checks = run_checks(pe, base, symbols)
    result = dict(schema=1, passed=True, game_sha256=report["sha256"], checks=checks,
                  native_game_verified=False, modeled_boundaries=["Windows module filename", "in-memory Windows file reads"])
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS: 15 linked native INI cases, strict bypass 0/1/default and unchanged existing fields")


if __name__ == "__main__":
    main()
