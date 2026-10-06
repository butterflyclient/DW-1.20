"""Execute the untouched Replay x64 map selector in an isolated CPU emulator.

This proves the original selector's behavior, not native lobby callbacks or
playability. Only __security_check_cookie is replaced with a return; the map
selection and inline string comparisons execute original PE instructions.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED
from unicorn.x86_const import (
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
    UC_X86_REG_EAX,
)

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--image",
    type=Path,
    default=Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe"),
)
parser.add_argument(
    "--output",
    type=Path,
    default=ROOT / "data/native-tournament-map-reference-20261006.json",
)
parser.add_argument(
    "--compiled-selector",
    type=Path,
    help="Comparison driver built by build-tournament-map-check.ps1 from exact server Release objects",
)
args = parser.parse_args()
image = args.image.read_bytes()
pe = struct.unpack_from("<I", image, 0x3C)[0]
assert image[pe : pe + 4] == b"PE\0\0"
count, optional_size = struct.unpack_from("<H12xH", image, pe + 6)
optional = pe + 24
assert struct.unpack_from("<H", image, optional)[0] == 0x20B
base = struct.unpack_from("<Q", image, optional + 24)[0]
assert base == 0x140000000
sections = []
for index in range(count):
    entry = optional + optional_size + 40 * index
    virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", image, entry + 8)
    sections.append((rva, max(virtual_size, raw_size), raw_size, raw))


def original(address, size):
    rva = address - base
    for start, length, raw_size, raw in sections:
        if start <= rva and rva + size <= start + length:
            offset = rva - start
            present = max(0, min(size, raw_size - offset))
            return image[raw + offset : raw + offset + present] + bytes(size - present)
    raise ValueError(f"Unreviewed original memory range: {address:#x}+{size:#x}")


pdata_rva, pdata_size = struct.unpack_from("<II", image, optional + 112 + 3 * 8)
pdata = original(base + pdata_rva, pdata_size)


def bounds(address):
    def owner(start, unwind, depth=0):
        assert depth < 16
        header = original(base + unwind, 4)
        if header[0] >> 3 & 4:  # UNW_FLAG_CHAININFO: join actual unwind fragments.
            chain = (4 + 2 * header[2] + 3) & ~3
            parent, _, info = struct.unpack("<III", original(base + unwind + chain, 12))
            return owner(parent, info, depth + 1)
        return base + start

    fragments = []
    for offset in range(0, len(pdata), 12):
        start, end, unwind = struct.unpack_from("<III", pdata, offset)
        if (
            address - base <= start < address - base + 512
            and owner(start, unwind) == address
        ):
            fragments.append((base + start, base + end))
    assert fragments and fragments[0][0] == address
    assert all(left[1] == right[0] for left, right in zip(fragments, fragments[1:]))
    return address, fragments[-1][1]


selector, availability = 0x141070950, 0x141070840
functions = [bounds(selector), bounds(availability)]
disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
disassembler.detail = True
calls = set()
for start, end in functions:
    for instruction in disassembler.disasm(original(start, end - start), start):
        if instruction.mnemonic == "call":
            assert instruction.operands[0].type == CS_OP_IMM
            calls.add(instruction.operands[0].imm)
assert availability in calls and len(calls) == 2
cookie_check = (calls - {availability}).pop()
assert original(cookie_check, 3) == b"\x48\x3b\x0d", "Unexpected security-cookie callee"

POOL, STACK, EXIT, CHOSEN = 0x70000000, 0x60000000, 0x71000000, 0x14C3B0350


def choose(pools, tournament):
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped = set()

    def map_original(address):
        page = address & ~0xFFF
        if page not in mapped:
            data = original(page, 4096)
            machine.mem_map(page, 4096)
            machine.mem_write(page, data)
            mapped.add(page)

    for start, end in functions:
        for page in range(start & ~0xFFF, (end + 4095) & ~0xFFF, 4096):
            map_original(page)
    map_original(cookie_check)
    map_original(CHOSEN)
    machine.mem_map(POOL, 4096)
    machine.mem_map(STACK, 65536)
    machine.mem_map(EXIT, 4096)

    def read_missing(uc, access, address, size, value, context):
        for page in range(address & ~0xFFF, (address + size + 4095) & ~0xFFF, 4096):
            map_original(page)
        return True

    def execute(uc, address, size, context):
        if address == cookie_check:
            stack = uc.reg_read(UC_X86_REG_RSP)
            target = struct.unpack("<Q", uc.mem_read(stack, 8))[0]
            uc.reg_write(UC_X86_REG_RSP, stack + 8)
            uc.reg_write(UC_X86_REG_RIP, target)
        else:
            assert any(start <= address < end for start, end in functions), hex(address)

    machine.hook_add(UC_HOOK_MEM_READ_UNMAPPED, read_missing)
    machine.hook_add(UC_HOOK_CODE, execute)
    chosen = []
    machine.mem_write(CHOSEN, bytes(128))
    for round_index, pool in enumerate(pools):
        assert 1 <= len(pool) <= 8 and len(set(pool)) == len(pool)
        names = b"".join(name.encode().ljust(32, b"\0") for name in pool)
        machine.mem_write(
            POOL,
            struct.pack("<I", len(pool))
            + names.ljust(256, b"\0")
            + struct.pack("<I", round_index),
        )
        stack = STACK + 65536 - 40
        machine.mem_write(stack, struct.pack("<Q", EXIT))
        machine.reg_write(UC_X86_REG_RSP, stack)
        machine.reg_write(UC_X86_REG_RCX, POOL)
        machine.reg_write(UC_X86_REG_RDX, tournament)
        machine.emu_start(selector, EXIT, count=50000)
        assert (
            machine.reg_read(UC_X86_REG_RIP) == EXIT
        ), "Selector instruction budget exhausted"
        index = machine.reg_read(UC_X86_REG_EAX)
        assert index < len(pool)
        chosen.append(pool[index])
        machine.mem_write(
            CHOSEN + 32 * round_index, pool[index].encode().ljust(32, b"\0")
        )
    return chosen


profiles = [
    [["mp_rust", "mp_shipment"] for _ in range(4)],
    [["mp_shipment"] for _ in range(4)],
    [["mp_rust", "mp_shipment", "mp_hideout", "mp_backlot2"] for _ in range(4)],
    [
        ["mp_rust", "mp_shipment"],
        ["mp_shipment"],
        ["mp_shipment", "mp_hideout"],
        ["mp_rust", "mp_hideout", "mp_shipment"],
    ],
]
ids = [
    1,
    2,
    561,
    (1 << 62) + 561,
    0x0001000200030004,
    0x8000800080008000,
    0xFEDCBA9876543210,
    0xFFFFFFFFFFFFFFFF,
]
cases = [
    dict(tournament=tournament, pools=pools, chosen=choose(pools, tournament))
    for pools in profiles
    for tournament in ids
]
assert cases[3]["chosen"] == ["mp_shipment", "mp_rust", "mp_shipment", "mp_rust"]
receipt = {
    "image": str(args.image),
    "sha256": hashlib.sha256(image).hexdigest(),
    "functions": [
        dict(
            va=f"{start:#x}",
            end=f"{end:#x}",
            sha256=hashlib.sha256(original(start, end - start)).hexdigest(),
        )
        for start, end in functions
    ],
    "only_stub": f"__security_check_cookie at {cookie_check:#x}",
    "scope": "Original x64 selector instructions in isolated Unicorn CPU emulator; no game or lobby callback validation",
    "cases": cases,
}
if args.compiled_selector:
    completed = subprocess.run(
        [str(args.compiled_selector)],
        input=json.dumps(cases),
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert json.loads(completed.stdout) == [entry["chosen"] for entry in cases]
    files = [
        args.compiled_selector,
        ROOT / "build/Release/iw8-dw-server.exe",
        ROOT / "build/iw8-dw-server.dir/Release/tournament_map_policy.obj",
        ROOT / "build/iw8-dw-server.dir/Release/crypto.obj",
        ROOT / "src/tournament_map_policy.cpp",
        ROOT / "tools/tournament-map-check.cpp",
    ]
    receipt["compiled_backend_comparison"] = {
        "passed": True,
        "cases": len(cases),
        "sha256": {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files
        },
        "method": "Driver linked to exact backend Release selector/crypto objects, compared to original Replay x64 instructions",
    }
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(receipt, indent=2) + "\n")
print(f"PASS: {len(cases)} original Replay x64 selector cases; {args.output}")
