"""Execute original category-task constructors and capture response subobjects.

The task-manager boundary records arguments and returns an empty task handle.
It does not model response serialization or imply native task completion.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP,
)

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
TASK_MANAGER = 0x142117C10
METHODS = ((0x14212A960, 9, 464, 8), (0x14212AA70, 10, 464, 432))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert args.output.resolve().is_relative_to(ROOT)
    raw = IMAGE.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    base = pe.OPTIONAL_HEADER.ImageBase
    bounds = {base+r.struct.BeginAddress: base+r.struct.EndAddress
              for r in pe.DIRECTORY_ENTRY_EXCEPTION}
    results, methods = [], []
    for entry, task, request_offset, response_offset in METHODS:
        end = bounds[entry]
        methods.append(dict(address=entry, end=end, task=task,
                            bytes_sha256=hashlib.sha256(pe.get_data(entry-base, end-entry)).hexdigest()))
        for environment, null_response in ((0, False), (2, False), (0, True), (2, True)):
            vm = Uc(UC_ARCH_X86, UC_MODE_64)
            scratch, stack, halt = 0x60000000, 0x70000000, 0x71000000
            vm.mem_map(scratch, 0x10000)
            vm.mem_map(stack, 0x10000)
            vm.mem_map(halt, 4096)
            owner, output, request, response = (scratch+i for i in (0, 0x1000, 0x2000, 0x4000))
            manager, lobby = scratch+0x6000, scratch+0x7000
            vm.mem_write(owner, struct.pack("<QI", manager, environment))
            vm.mem_write(owner+1272, struct.pack("<Q", lobby))
            vm.mem_write(stack+0xF008, struct.pack("<Q", halt))
            for register, value in ((UC_X86_REG_RCX, owner), (UC_X86_REG_RDX, output),
                                    (UC_X86_REG_R8, request),
                                    (UC_X86_REG_R9, 0 if null_response else response),
                                    (UC_X86_REG_RSP, stack+0xF008)):
                vm.reg_write(register, value)
            pages, captured, reached = set(), [], []

            def missing(machine, access, address, size, value, context):
                assert base <= address < base+pe.OPTIONAL_HEADER.SizeOfImage
                for page in (address & ~4095, (address+size-1) & ~4095):
                    if page not in pages:
                        machine.mem_map(page, 4096)
                        content = pe.get_data(page-base, 4096)
                        if content:
                            machine.mem_write(page, content)
                        pages.add(page)
                return True

            def qword(machine, address):
                return struct.unpack("<Q", machine.mem_read(address, 8))[0]

            def boundary(machine, address, size, context):
                if address == halt:
                    reached.append(True)
                    machine.emu_stop()
                elif address == TASK_MANAGER:
                    position = machine.reg_read(UC_X86_REG_RSP)
                    actual = dict(manager=machine.reg_read(UC_X86_REG_RCX),
                                  service=machine.reg_read(UC_X86_REG_R8) & 255,
                                  task=machine.reg_read(UC_X86_REG_R9) & 255,
                                  request=qword(machine, position+0x28),
                                  response=qword(machine, position+0x30),
                                  lobby=qword(machine, position+0x38))
                    expected = dict(manager=manager, service=193, task=task,
                                    request=request+request_offset,
                                    response=0 if null_response else response+response_offset,
                                    lobby=lobby)
                    assert actual == expected, (actual, expected)
                    captured.append(actual)
                    slot = machine.reg_read(UC_X86_REG_RDX)
                    machine.mem_write(slot, struct.pack("<Q", 0))
                    machine.reg_write(UC_X86_REG_RAX, slot)
                    target = qword(machine, position)
                    machine.reg_write(UC_X86_REG_RSP, position+8)
                    machine.reg_write(UC_X86_REG_RIP, target)

            vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
            vm.hook_add(UC_HOOK_CODE, boundary)
            vm.emu_start(entry, 0, count=1000)
            assert reached == [True] and len(captured) == 1
            assert vm.reg_read(UC_X86_REG_RAX) == output
            assert qword(vm, output) == 0
            assert struct.unpack("<I", vm.mem_read(request+8, 4))[0] == environment
            results.append(dict(method=entry, environment=environment, null_response=null_response,
                                request_offset=request_offset, response_offset=response_offset,
                                captured=captured[0], passed=True))
    proof = dict(passed=True, target_image_sha256=digest, methods=methods, cases=results,
                 tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 modeled_boundary="startStructTask arguments and empty task output only",
                 original_environment_setter_executed=True,
                 native_response_reader_verified=False, native_runtime_verified=False,
                 scope="Publisher 193/9 response base +8; user 193/10 response base +432. Concrete response readers remain unresolved")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2)+"\n")
    print("PASS: eight original category constructors; response offsets 8 and 432")


if __name__ == "__main__":
    main()
