"""Execute original Replay's connected relay frame with expired cached tokens."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RSP

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw)
base = pe.OPTIONAL_HEADER.ImageBase
entry = 0x1412BFBB0
bound = next(
    item.struct
    for item in pe.DIRECTORY_ENTRY_EXCEPTION
    if base + item.struct.BeginAddress == entry
)
end = base + bound.EndAddress
code = pe.get_data(entry - base, end - entry)
instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(code, entry))
assert instructions[-1].address + instructions[-1].size == end
cases = []
for expiry in (0, 1, 0xFFFFFFFF):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    start_page = entry & ~4095
    size = ((end + 4095) & ~4095) - start_page
    vm.mem_map(start_page, size)
    vm.mem_write(start_page, pe.get_data(start_page - base, size))
    stack, record, halt = 0x10000000, 0x11000000, 0x12000000
    for page in (stack, record, halt):
        vm.mem_map(page, 4096)
    vm.mem_write(record + 20, struct.pack("<I", 6))
    vm.mem_write(record + 296, struct.pack("<II", 2, expiry))
    vm.mem_write(stack + 0xF08, struct.pack("<Q", halt))
    vm.reg_write(UC_X86_REG_RCX, record)
    vm.reg_write(UC_X86_REG_RSP, stack + 0xF08)
    visited = []

    def boundary(machine, address, size, context):
        if address == halt:
            machine.emu_stop()
            return
        assert entry <= address < end, f"Unexpected original call {address:#x}"
        visited.append(address)

    vm.hook_add(UC_HOOK_CODE, boundary)
    vm.emu_start(entry, halt, count=1000)
    assert struct.unpack("<I", vm.mem_read(record + 20, 4))[0] == 6
    assert struct.unpack("<II", vm.mem_read(record + 296, 8)) == (2, expiry)
    assert visited
    cases.append(
        dict(
            connected_state=6,
            cached_auth_state=2,
            expiry_clock_seconds=expiry,
            executed_instructions=len(visited),
            external_calls=0,
            passed=True,
        )
    )
proof = dict(
    schema=1,
    passed=True,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    original_image_sha256=digest,
    function_va=hex(entry),
    function_size=len(code),
    function_bytes_sha256=hashlib.sha256(code).hexdigest(),
    tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    cases=cases,
    method="Unchanged original PE instructions with original unwind bounds; no clock/API/function boundary modeled",
    scope="Connected state 6 performs no credential refresh, regardless of cached expiry. This is original-code execution, not a live game/network proof.",
    native_game_verified=False,
)
output = ROOT / "validation/20261008-relay-connected-expiry-target.json"
output.write_text(json.dumps(proof, indent=2) + "\n")
print("PASS: three original connected-frame cases; no auth refresh or external calls")
