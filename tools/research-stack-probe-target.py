"""Execute Replay's unchanged stack probe to verify its register/stack contract."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_WRITE
from unicorn import x86_const as registers

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", required=True, type=Path)
output = parser.parse_args().output.resolve()
if not any(output.is_relative_to(ROOT / name) for name in ("data", "validation")):
    raise ValueError("Keep research evidence in this repository")
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
assert (
    sha256(raw).hexdigest()
    == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
)
pe = pefile.PE(data=raw, fast_load=True)
entry, size = 0x1421CCEF0, 81
code = pe.get_data(entry - pe.OPTIONAL_HEADER.ImageBase, size)
assert (
    sha256(code).hexdigest()
    == "99d2cc1dbc125fe60aeb6230c1033e4ddda1e4488b7baf555c32ea70e50e79da"
)
gprs = (
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RBP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
)
cases = []
for allocation in (0, 32, 4095, 4096, 4097, 0x1AC0, 8192, 0x8400, 0x11000):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, tls, halt = 0x10000000, 0x11000000, 0x12000000
    vm.mem_map(stack, 0x20000)
    vm.mem_map(tls, 4096)
    vm.mem_map(halt, 4096)
    vm.mem_map(entry & ~4095, 4096)
    vm.mem_write(entry, code)
    sp = stack + 0x1F008
    # The probe reads the Windows TIB StackLimit, including a lower committed
    # boundary so the cases cross and touch real mapped page boundaries.
    vm.mem_write(tls + 0x10, struct.pack("<Q", stack + 0x1E000))
    vm.mem_write(sp, struct.pack("<Q", halt))
    vm.reg_write(registers.UC_X86_REG_GS_BASE, tls)
    vm.reg_write(registers.UC_X86_REG_RSP, sp)
    expected = {
        name: 0x7123400000000000 + index * 0x1357 for index, name in enumerate(gprs)
    }
    expected["RAX"] = allocation
    for name, value in expected.items():
        vm.reg_write(getattr(registers, "UC_X86_REG_" + name), value)
    writes = []
    vm.hook_add(
        UC_HOOK_MEM_WRITE,
        lambda machine, access, address, length, value, context: writes.append(
            (address, length)
        ),
    )
    vm.emu_start(entry, halt, count=1000)
    assert vm.reg_read(registers.UC_X86_REG_RIP) == halt
    assert vm.reg_read(registers.UC_X86_REG_RSP) == sp + 8
    assert all(
        vm.reg_read(getattr(registers, "UC_X86_REG_" + name)) == value
        for name, value in expected.items()
    )
    assert all(address + length <= sp for address, length in writes)
    assert struct.unpack("<Q", vm.mem_read(sp, 8))[0] == halt
    cases.append(
        dict(
            allocation=allocation,
            passed=True,
            preserved_gprs=len(expected),
            writes_below_entry_rsp=len(writes),
            probed_pages=sum(length == 1 for _, length in writes),
        )
    )
proof = dict(
    schema=1,
    passed=True,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    target_image_sha256=sha256(raw).hexdigest(),
    tool_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
    function=dict(va=entry, size=size, bytes_sha256=sha256(code).hexdigest()),
    original_instructions_executed=True,
    modeled_external_calls=False,
    scope="Nine valid frame allocations; actual GPR preservation, return and writes below entry RSP. Flags and Windows guard-page faults are not modeled.",
    cases=cases,
)
output.write_text(json.dumps(proof, indent=2) + "\n")
print(
    "PASS: nine unchanged stack-probe cases preserve all 15 GPRs and the caller frame"
)
