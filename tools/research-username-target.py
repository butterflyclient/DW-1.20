"""Record bulk username bindings from untouched Replay bytes, not display names."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
output = args.output.resolve()
if not any(output.is_relative_to(ROOT / name) for name in ("data", "validation")):
    raise ValueError("Keep target receipts in data or validation")
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
database = image.with_suffix(".exe.sqlite")
snapshot = database.stat()
raw = image.read_bytes()
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
bindings = ((0x1426A3CF8, 0x1421479B0), (0x1424256B0, 0x142147CC0))
for vtable, handler in bindings:
    actual = struct.unpack("<Q", pe.get_data(vtable + 8 - base, 8))[0]
    if actual != handler:
        raise ValueError("Unexpected target response/request vtable")
addresses = (
    0x142147870,
    0x1421479B0,
    0x142147CC0,
    0x142152290,
    0x14107E460,
    0x141B37DE0,
    0x141B375F0,
)
functions = []
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address in addresses:
        name, size = db.execute(
            "select name,size from functions where address=?", (str(address),)
        ).fetchone()
        code = pe.get_data(address - base, size)
        calls, strings = [], set()
        for instruction in decoder.disasm(code, address):
            if (
                instruction.mnemonic == "call"
                and instruction.operands[0].type == X86_OP_IMM
            ):
                calls.append(hex(instruction.operands[0].imm))
            if instruction.mnemonic != "lea":
                continue
            for operand in instruction.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    pointer = instruction.address + instruction.size + operand.mem.disp
                    value = pe.get_data(pointer - base, 128).split(b"\0", 1)[0]
                    if (
                        value
                        and len(value) < 128
                        and all(32 <= byte < 127 for byte in value)
                    ):
                        strings.add(value.decode("ascii"))
        functions.append(
            dict(
                va=address,
                candidate_alias=name,
                exported_size=size,
                target_bytes_sha256=hashlib.sha256(code).hexdigest(),
                direct_calls=calls,
                literal_strings=sorted(strings),
            )
        )
if database.stat().st_mtime_ns != snapshot.st_mtime_ns:
    raise ValueError("Target database changed during this audit; retry")
receipt = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    target_image_sha256=hashlib.sha256(raw).hexdigest(),
    native_runtime_verified=False,
    vtable_bindings=[
        dict(vtable=table, slot=1, handler=handler) for table, handler in bindings
    ],
    functions=functions,
    request=dict(
        service="social-service",
        resource="Users",
        operation="get_usernames",
        method="GET",
        path="/v1/users/",
        query=[
            "context (numeric title)",
            "client",
            "titleID",
            "users (accountType-ID CSV)",
        ],
        max_users=200,
        encoded_users_buffer=4096,
    ),
    response=dict(
        users_array="userID UInt64, accountType string capacity 10, username string capacity 97",
        capacity=200,
        first_record_offset=40,
        record_stride=144,
        count_offset=28840,
        object_size=28848,
    ),
    rejected_alias=dict(
        candidate="bdGetCrossPlatformUsernamesResponse::scalar deleting destructor",
        candidate_va=0x14217C2A0,
        reason="Uses vtable 0x1426AA938 and size 0x240; absent from the real engine resolver response table",
    ),
    scope="Target byte/vtable/request/reader/engine allocation research; live task completion is a separate gate",
)
output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
print("Verified Replay bulk-username vtables and recorded request/response bindings.")
