"""Run linked Replay patch getters and platform restart routing in an ABI VM."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import capstone as cs
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
import unicorn.x86_const as reg


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads((args.build / "build-report.json").read_bytes())
    image = Path(report["executable"])
    assert hashlib.sha256(image.read_bytes()).hexdigest() == report["sha256"]
    pe = pefile.PE(str(image), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    symbols = {name: base + rva for name, rva in report["symbols"].items()}
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
    assert not any(
        row["symbol"] == "func_1410527B0" for row in report["replacements"]
    ), "Do not close the native prerequisite fence"
    checks = []

    for enabled in (False, True):
        for state in (1, 10, 20, 30, 40):
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
                    assert call("func_141053520", arena + 0x1000, kind) == expected
            # Startup prerequisite remains passable while the UI owns the
            # restart-required state, preventing the observed sign-in deadlock.
            write(symbols["gl_14D386A08"], struct.pack("<Q", arena + 0x3000))
            write(arena + 0x3028, struct.pack("<Q", arena + 0x4000))
            write(arena + 0x1000 + 79, b"\x01")
            assert call("func_1410527B0", arena + 0x1000, 0) == 1
            write(symbols["gl_14F05AC00"], b"\0")
            call("func_14165E530")
            expected = [] if enabled and state == 20 else ["service", "account", "request"]
            assert calls == expected
            checks.append(
                {
                    "enabled": enabled,
                    "state": state,
                    "getter_cases": 10,
                    "native_prerequisite_passes": True,
                    "restart_route_correct": True,
                }
            )
    args.output.write_text(
        json.dumps(
            {
                "schema": 1,
                "passed": True,
                "game_sha256": report["sha256"],
                "checks": checks,
                "native_game_verified": False,
                "modeled_boundaries": [
                    "DW filename selection",
                    "native platform request transport",
                ],
            },
            indent=2,
        )
        + "\n"
    )
    print(
        "PASS: 100 linked patch-state cases, prerequisite fence and actual platform restart routing"
    )


if __name__ == "__main__":
    main()
