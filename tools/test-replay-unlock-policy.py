"""Execute the freshly linked ownership binding with native API boundaries.

The VM supplies Lua arguments and the controller/config getters. It executes
the actual compiled inventory lookup, policy branch, ABI and result conversion;
this is separate from the native menu test and never writes player data.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                              UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_XMM0, UC_X86_REG_XMM1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads((args.build / "build-report.json").read_bytes())
    verification = json.loads((args.build / "verification-report.json").read_bytes())
    images = [path for path in args.build.glob("*.exe") if hashlib.sha256(path.read_bytes()).hexdigest() == report["sha256"]]
    assert len(images) == 1 and verification["sha256"] == report["sha256"]
    assert verification["unresolved_symbols"] == 0
    pe = pefile.PE(str(images[0]), fast_load=True)
    base, limit = pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SizeOfImage
    symbols = report["symbols"]
    entry = base + symbols["LUI_CoD_LuaCall_IsOwned"]
    aliases = ("LUI_CoD_LuaCall_IsOwned", "func_141B39ED0", "sub_141B39ED0")
    assert all(base + symbols[name] == entry for name in aliases)
    registration = symbols["gl_1425BDE40"]
    registered_entry = struct.unpack("<Q", pe.get_data(registration + 24, 8))[0]
    assert registered_entry == entry, "Loot registration does not target the compiled ownership binding"
    inventory = base + symbols["gl_1459E05C0"]
    boundaries = {base + symbols[name]: name for name in (
        "func_1420838B0", "func_1420839E0", "func_142084A10", "func_142084100",
        "func_142089FB0", "func_140D66C20", "DW_LocalBackend_IsEnabled", "DW_LocalConfig_UnlockAll")}

    def case(enabled, item, expected, quantity=7, controller=0, mapped=0, argc=2, numeric=True):
        vm = Uc(UC_ARCH_X86, UC_MODE_64)
        stack, lua, halt = 0x10000000, 0x11000000, 0x12000000
        for address, size in ((stack, 65536), (lua, 4096), (halt, 4096)):
            vm.mem_map(address, size)
        pages = set()

        def page(address):
            address &= ~4095
            if address not in pages:
                assert base <= address < base + limit
                vm.mem_map(address, 4096)
                data = pe.get_data(address - base, 4096)
                if data:
                    vm.mem_write(address, data)
                pages.add(address)

        def missing(machine, access, address, size, value, context):
            page(address)
            page(address + size - 1)
            return True

        for address in (inventory + 64, inventory + 120064):
            page(address)
        vm.mem_write(inventory + 64, struct.pack("<II", 111, quantity))
        vm.mem_write(inventory + 120064, struct.pack("<i", 1))
        sp = stack + 0xF008
        vm.mem_write(sp, struct.pack("<Q", halt))
        vm.reg_write(UC_X86_REG_RSP, sp)
        vm.reg_write(UC_X86_REG_RCX, lua)
        pushed, calls, errors = [], [], []

        def returned(machine, value=0):
            position = machine.reg_read(UC_X86_REG_RSP)
            target = struct.unpack("<Q", machine.mem_read(position, 8))[0]
            machine.reg_write(UC_X86_REG_RAX, value)
            machine.reg_write(UC_X86_REG_RSP, position + 8)
            machine.reg_write(UC_X86_REG_RIP, target)

        def boundary(machine, address, size, context):
            if address == halt:
                machine.emu_stop()
                return
            name = boundaries.get(address)
            if not name:
                return
            calls.append(name)
            if name.startswith("func_14208"):
                assert machine.reg_read(UC_X86_REG_RCX) == lua
            if name == "func_1420838B0":
                returned(machine, argc + len(pushed))
            elif name == "func_1420839E0":
                returned(machine, int(numeric))
            elif name == "func_142084A10":
                value = controller if machine.reg_read(UC_X86_REG_RDX) == 1 else item
                machine.reg_write(UC_X86_REG_XMM0, int.from_bytes(struct.pack("<d", value), "little"))
                returned(machine)
            elif name == "func_142084100":
                value = machine.reg_read(UC_X86_REG_XMM1).to_bytes(16, "little")[:8]
                pushed.append(struct.unpack("<d", value)[0])
                returned(machine)
            elif name == "func_142089FB0":
                errors.append("native Lua argument error")
                machine.emu_stop()
            elif name == "func_140D66C20":
                assert machine.reg_read(UC_X86_REG_RCX) & 0xffffffff == controller & 0xffffffff
                returned(machine, mapped & 0xffffffff)
            elif name == "DW_LocalBackend_IsEnabled":
                returned(machine, 1)
            elif name == "DW_LocalConfig_UnlockAll":
                returned(machine, int(enabled))

        vm.hook_add(UC_HOOK_CODE, boundary)
        vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
        vm.emu_start(entry, halt, count=5000)
        if expected is None:
            assert errors and not pushed
        else:
            assert vm.reg_read(UC_X86_REG_RIP) == halt and not errors
            assert vm.reg_read(UC_X86_REG_RAX) == 1 and pushed == [float(expected)]
        assert struct.unpack("<II", vm.mem_read(inventory + 64, 8)) == (111, quantity)
        assert struct.unpack("<i", vm.mem_read(inventory + 120064, 4))[0] == 1
        return dict(enabled=enabled, item=item, expected=expected, controller=controller,
                    mapped=mapped, argc=argc, numeric=numeric, passed=True, inventory_unchanged=True)

    cases = [case(False, 111, 7), case(False, 222, 0), case(True, 111, 7), case(True, 222, 1),
             case(True, 0, 0), case(True, 0xffffffff, 0), case(True, 222, 0, mapped=-1),
             case(True, 222, 0, controller=-1), case(True, 222, None, argc=1),
             case(True, 222, None, numeric=False)]
    result = dict(schema=1, passed=True, generated_utc=datetime.now(timezone.utc).isoformat(),
                  game_sha256=report["sha256"], tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  lua_registration_target_verified=True, original_symbol_aliases_verified=list(aliases),
                  cases=cases, native_runtime_verified=False,
                  scope="Linked C++ ownership binding; modeled Lua/controller/config boundaries; actual inventory memory stays unchanged")
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS: {len(cases)} linked ownership policy/ABI cases")


if __name__ == "__main__":
    main()
