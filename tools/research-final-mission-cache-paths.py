"""Execute Replay's original four-event cache decision without running the game.

Only I_stricmp is modeled. Execution stops at the original cache/immediate
branch, before constructing or publishing any event. This proves the decision
window, not delivery, allocation ownership or gameplay callbacks.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_R12, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RIP, UC_X86_REG_RSP,
)

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
ENTRY, END = 0x1419EC377, 0x1419ECE5C
COMPARE = 0x140E60C20
BRANCHES = {
    0x1419EC38E: "pickup",
    0x1419EC665: "driving",
    0x1419EC90F: "alive_in_gas",
    0x1419ECBC2: "alive_not_downed",
    END: "immediate",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert args.output.resolve().is_relative_to(ROOT)
    raw = IMAGE.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    pe = pefile.PE(data=raw, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    results = []
    for name in ("pickup", "driving", "alive_in_gas", "alive_not_downed",
                 "revive", "gulag_end_match", "kill", "match_placement", "loadout", "REVIVE",
                 "death", "field_end", "killstreak_end", "start_match", "end_match"):
        vm = Uc(UC_ARCH_X86, UC_MODE_64)
        scratch, stack = 0x60000000, 0x70000000
        vm.mem_map(scratch, 4096)
        vm.mem_map(stack, 4096)
        vm.mem_write(scratch, name.encode() + b"\0")
        vm.reg_write(UC_X86_REG_R12, scratch)
        vm.reg_write(UC_X86_REG_RSP, stack + 2048)
        pages, comparisons, outcome = set(), [], []

        def missing(machine, access, address, size, value, context):
            assert base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage
            for page in (address & ~4095, (address + size - 1) & ~4095):
                if page not in pages:
                    machine.mem_map(page, 4096)
                    content = pe.get_data(page - base, 4096)
                    if content:
                        machine.mem_write(page, content)
                    pages.add(page)
            return True

        def string(machine, pointer):
            if base <= pointer < base + pe.OPTIONAL_HEADER.SizeOfImage:
                missing(machine, 0, pointer, 64, 0, None)
            return bytes(machine.mem_read(pointer, 64)).split(b"\0", 1)[0].decode("ascii")

        def boundary(machine, address, size, context):
            if address in BRANCHES:
                outcome.append(BRANCHES[address])
                machine.emu_stop()
            elif address == COMPARE:
                left = string(machine, machine.reg_read(UC_X86_REG_RCX))
                right = string(machine, machine.reg_read(UC_X86_REG_RDX))
                assert right == name
                comparisons.append(left)
                machine.reg_write(UC_X86_REG_RAX, 0 if left.lower() == right.lower() else 1)
                position = machine.reg_read(UC_X86_REG_RSP)
                target = struct.unpack("<Q", machine.mem_read(position, 8))[0]
                machine.reg_write(UC_X86_REG_RSP, position + 8)
                machine.reg_write(UC_X86_REG_RIP, target)

        vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
        vm.hook_add(UC_HOOK_CODE, boundary)
        vm.emu_start(ENTRY, 0, count=100)
        expected = name if name in BRANCHES.values() else "immediate"
        assert outcome == [expected], (name, outcome)
        results.append(dict(name=name, branch=outcome[0], comparisons=comparisons, passed=True))
    proof = dict(passed=True, target_image_sha256=digest, entry=ENTRY, end=END,
                 original_window_sha256=hashlib.sha256(pe.get_data(ENTRY-base, END-ENTRY)).hexdigest(),
                 tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), cases=results,
                 modeled_boundary="I_stricmp over actual original and input strings",
                 native_game_execution_verified=False,
                 scope="Original event-cache decision only; publishing and allocation ownership are separate")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print("PASS: 15 original event-cache decisions; death and mission terminal events use the immediate branch")


if __name__ == "__main__":
    main()
