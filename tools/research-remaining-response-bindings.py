"""Verify original live-result ownership boundaries without launching Replay.

The original-image reference receipt supplies candidate caller chunks. This
fixture executes their original argument setup; it does not model a metadata
reader or infer a response schema from SDK/source names.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP,
    UC_X86_REG_RIP,
)

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
EXPECTED = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
BOUNDARY = 0x142131E60
CASES = ((0x142133457, 0x14213348B), (0x142133583, 0x1421335B7),
         (0x1421340A0, 0x1421340FC), (0x142134210, 0x142134278),
         (0x142134380, 0x1421343F5))


def main():
    raw = IMAGE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED
    pe = pefile.PE(data=raw, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    receipt_path = ROOT / "validation/20261011-remaining-response-original-references.json"
    receipt = json.loads(receipt_path.read_bytes())
    assert receipt["target_image_sha256"] == EXPECTED
    actual_sites = {hit["address"] for row in receipt["matches"]
                    for hit in row["hits"] if hit["target"] == BOUNDARY}
    assert actual_sites == {call for _, call in CASES}
    results = []
    for start, call in CASES:
        vm = Uc(UC_ARCH_X86, UC_MODE_64)
        scratch, stack = 0x60000000, 0x70000000
        vm.mem_map(scratch, 0x40000)
        vm.mem_map(stack, 0x10000)
        # Poison the outgoing argument area so a missing initialization fails.
        vm.mem_write(stack, b"\xa5" * 0x10000)
        for reg, value in ((UC_X86_REG_RCX, scratch), (UC_X86_REG_RDX, scratch + 0x1000),
                           (UC_X86_REG_R8, scratch + 0x2000), (UC_X86_REG_R9, scratch + 0x3000),
                           (UC_X86_REG_RBX, scratch + 0x4000), (UC_X86_REG_RBP, scratch + 0x5000),
                           (UC_X86_REG_RSP, stack + 0xF008)):
            vm.reg_write(reg, value)
        pages, captured, executed = set(), [], []

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

        def step(machine, address, size, context):
            if address == BOUNDARY:
                position = machine.reg_read(UC_X86_REG_RSP)
                returned, = struct.unpack("<Q", machine.mem_read(position, 8))
                assert returned == call + 5
                response, = struct.unpack("<Q", machine.mem_read(position + 0x40, 8))
                assert response == 0
                captured.append(dict(call=hex(call), extended_response=response))
                machine.emu_stop()
            elif address == 0x14213DE70:
                # Ordinary summary metadata reset. Its body cannot affect the
                # nonvolatile RDI that supplies argument eight in this wrapper.
                position = machine.reg_read(UC_X86_REG_RSP)
                target, = struct.unpack("<Q", machine.mem_read(position, 8))
                machine.reg_write(UC_X86_REG_RAX, 0)
                machine.reg_write(UC_X86_REG_RSP, position + 8)
                machine.reg_write(UC_X86_REG_RIP, target)
            else:
                assert start <= address <= call, hex(address)
                executed.append(address)

        vm.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
        vm.hook_add(UC_HOOK_CODE, step)
        vm.emu_start(start, BOUNDARY + 1, count=500)
        assert len(captured) == 1
        code = pe.get_data(start - base, call + 5 - start)
        results.append(dict(start=hex(start), call=hex(call),
                            original_bytes_sha256=hashlib.sha256(code).hexdigest(),
                            executed_original_instructions=len(executed),
                            extended_response_argument=0, passed=True,
                            modeled_calls=[hex(0x14213DE70)] if start == 0x142134380 else []))
    proof = dict(schema=1, recorded_utc=datetime.now(timezone.utc).isoformat(), passed=True,
                 target_image_sha256=EXPECTED,
                 tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 reference_receipt_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                 cases=results, supported_routes_added=0,
                 response_deserializer_verified=False, native_task_completion_verified=False,
                 scope="All five decoded direct/one-relocated-pointer initDownload references supply null extended metadata. Indirect references and serializer ownership remain unresolved.")
    output = ROOT / "validation/20261011-remaining-response-live-ownership.json"
    output.write_text(json.dumps(proof, indent=2) + "\n")
    print("PASS: five original argument-setup cases supply null extended metadata; no response route enabled")


if __name__ == "__main__":
    main()
