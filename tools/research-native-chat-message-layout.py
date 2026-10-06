"""Bind chat recipient/owner fields to instructions in the untouched Replay PE."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
pe = pefile.PE(data=raw, fast_load=True)
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
functions, decoded = [], {}
for address, length in (
    (0x141B316F0, 0x340),
    (0x140F3D950, 0x80),
    (0x140F3E160, 0x1A0),
    (0x140F3A9F0, 0x240),
):
    body = pe.get_data(address - pe.OPTIONAL_HEADER.ImageBase, length)
    assert len(body) == length
    instructions = list(decoder.disasm(body, address))
    decoded[address] = instructions
    functions.append(
        dict(
            address=hex(address),
            window_bytes=length,
            window_sha256=hashlib.sha256(body).hexdigest(),
        )
    )

writer = {(row.mnemonic, row.op_str) for row in decoded[0x141B316F0]}
assert ("mov", "r12, r8") in writer
assert ("mov", "rsi, rcx") in writer
assert ("mov", "qword ptr [rbx + 8], r12") in writer
assert ("mov", "qword ptr [rbx + 0x230], rsi") in writer
calls = []
for address in (0x140F3D950, 0x140F3E160, 0x140F3A9F0):
    instructions = decoded[address]
    selected = [
        index
        for index, row in enumerate(instructions)
        if row.mnemonic == "call" and row.op_str == "0x141b316f0"
    ]
    assert len(selected) == 1
    window = instructions[max(0, selected[0] - 8) : selected[0] + 1]
    expected = ("mov", "r8, rax") if address == 0x140F3A9F0 else ("xor", "r8d, r8d")
    assert expected in {(row.mnemonic, row.op_str) for row in window}
    calls.append(
        dict(
            caller=hex(address),
            recipient_argument=(
                "local XUID result" if address == 0x140F3A9F0 else "zero"
            ),
            instructions=[
                dict(
                    address=hex(row.address),
                    instruction=row.mnemonic + " " + row.op_str,
                )
                for row in window
            ],
        )
    )

proof = dict(
    schema=1,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    original_executable_sha256=hashlib.sha256(raw).hexdigest(),
    research_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    functions=functions,
    verified_fields=dict(message_recipient_offset=8, owning_chat_pointer_offset=560),
    exact_target_callers=calls,
    channel_id_equality_is_a_valid_message_invariant=False,
    source_oracle_addresses_used=False,
)
path = ROOT / "validation/20261006-native-chat-recipient-layout.json"
path.write_text(json.dumps(proof, indent=2) + "\n")
print("Untouched Replay instructions verify recipient +8 and owning-chat pointer +560.")
