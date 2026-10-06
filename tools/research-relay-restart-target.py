"""Read-only proof of Replay's relay shutdown/reset/request path from original bytes."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile

ROOT = Path(__file__).resolve().parents[1]
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
database = image.with_suffix(".exe.sqlite")
before = database.stat()
raw = image.read_bytes()
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
records = []
decoded = {}
with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
    db.execute("pragma query_only=on")
    for address in (
        0x1412C0140,
        0x1412BF930,
        0x1412C0090,
        0x1412BF9A0,
        0x1412BFBB0,
        0x1414EFC90,
        0x1414EFBA0,
        0x1414EFBB0,
        0x14218C910,
        0x14217A520,
        0x142196200,
        0x14219F1C0,
        0x1421A0AA0,
        0x1414EFAE0,
    ):
        name, size = db.execute(
            "select name,size from functions where address=?", (str(address),)
        ).fetchone()
        code = pe.get_data(address - base, size)
        instructions = list(decoder.disasm(code, address))
        decoded[address] = instructions
        calls, writes = [], []
        rsi_zero = False
        for ins in instructions:
            if ins.mnemonic in {"call", "jmp"} and ins.operands[0].type == X86_OP_IMM:
                calls.append(ins.operands[0].imm)
            if (
                ins.mnemonic == "mov"
                and len(ins.operands) == 2
                and ins.operands[0].type == X86_OP_MEM
                and (
                    ins.operands[1].type == X86_OP_IMM
                    or (
                        ins.operands[1].type == X86_OP_REG
                        and rsi_zero
                        and ins.reg_name(ins.operands[1].reg)
                        in {"rsi", "esi", "si", "sil"}
                    )
                )
            ):
                writes.append(
                    dict(
                        va=ins.address,
                        base=ins.reg_name(ins.operands[0].mem.base),
                        offset=ins.operands[0].mem.disp,
                        width=ins.operands[0].size,
                        value=(
                            ins.operands[1].imm
                            if ins.operands[1].type == X86_OP_IMM
                            else 0
                        ),
                        provenance=(
                            "immediate"
                            if ins.operands[1].type == X86_OP_IMM
                            else "XOR-zeroed nonvolatile RSI"
                        ),
                    )
                )
            if (
                ins.mnemonic == "xor"
                and len(ins.operands) == 2
                and all(op.type == X86_OP_REG for op in ins.operands)
                and ins.operands[0].reg == ins.operands[1].reg
                and ins.reg_name(ins.operands[0].reg) in {"rsi", "esi"}
            ):
                rsi_zero = True
            elif any(
                ins.reg_name(reg) in {"rsi", "esi", "si", "sil"}
                for reg in ins.regs_access()[1]
            ):
                rsi_zero = False
        records.append(
            dict(
                va=address,
                database_alias=name,
                size=size,
                original_code_sha256=hashlib.sha256(code).hexdigest(),
                direct_targets=calls,
                constant_stores=writes,
            )
        )
by_address = {row["va"]: row for row in records}
reset, callback, request, fetch, frame = records[:5]
assert any(
    row["offset"] == 20 and row["width"] == 4 and row["value"] == 0
    for row in reset["constant_stores"]
)
assert 0x1412C0090 in callback["direct_targets"]
assert 0x1412BF9A0 in request["direct_targets"]
assert any(
    row["offset"] == 20 and row["width"] == 4 and row["value"] == 2
    for row in request["constant_stores"]
)
assert 0x140F71C20 in fetch["direct_targets"]
assert 0x1412C0090 in frame["direct_targets"]
assert {0x1414EFBA0, 0x1414EFBB0} <= set(callback["direct_targets"])
stub = decoded[0x1414EFC90]
assert [(ins.mnemonic, ins.op_str) for ins in stub] == [
    ("xor", "al, al"),
    ("ret", ""),
]
for address, expected_status in ((0x1414EFBA0, 4), (0x1414EFBB0, 3)):
    ins = decoded[address][0]
    assert ins.mnemonic == "cmp"
    assert ins.operands[0].type == X86_OP_MEM
    assert ins.reg_name(ins.operands[0].mem.base) == "rip"
    assert ins.address + ins.size + ins.operands[0].mem.disp == 0x14E6BDA40
    assert ins.operands[1].imm == expected_status
bind = decoded[0x14218C910]
assert any(ins.mnemonic == "add" and ins.op_str == "rcx, 0xb8" for ins in bind)
assert 0x142195760 in by_address[0x14218C910]["direct_targets"]
getter = decoded[0x14217A520][0]
assert getter.mnemonic == "mov" and getter.op_str == "rax, qword ptr [rcx + 0x280]"
bound = decoded[0x142196200][0]
assert bound.mnemonic == "lea" and bound.op_str == "rax, [rcx + 0x20]"
assert 0x1421A0AA0 in by_address[0x14219F1C0]["direct_targets"]
disconnect_packet = by_address[0x1421A0AA0]
assert 0x1421A2760 in disconnect_packet["direct_targets"]
assert any(
    ins.mnemonic == "mov" and ins.op_str == "edx, 0xa" for ins in decoded[0x1421A0AA0]
)
assert any(
    row["base"] == "rip" and row["value"] == 2 and row["width"] == 4
    for row in by_address[0x1414EFAE0]["constant_stores"]
)
after = database.stat()
assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
receipt = dict(
    schema=1,
    passed=True,
    native_runtime_verified=False,
    target_image=str(image),
    target_image_sha256=hashlib.sha256(raw).hexdigest(),
    target_database=str(database),
    target_database_size=after.st_size,
    target_database_mtime_ns=after.st_mtime_ns,
    target_database_changed=False,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    functions=records,
    scope="Exact Replay dwRelayStop is a no-op; the dependency callback rejects DW status 3/4. Native socket-router/routing-layer getters lead to the bound SDK association, whose disconnect owns locking and sends packet type 10. The native completion callback returns DW status to 2. Reset clears the credential owner; the dependency callback then reaches the original SDK request. Database aliases alone are not ABI evidence.",
    sdk_socket_router_routing_layer_offset=184,
    sdk_bound_reference_getter_offset=32,
    original_dw_relay_stop_is_stub=True,
    network_status_values=dict(started=2, relay_starting=3, relay_started=4),
    native_fence_header=dict(controller_offset=8, dependencies_met_offset=12, size=16),
    native_relay_header=dict(
        net_init_offset=8, callback_registered_offset=16, state_offset=20, size=24
    ),
    layout_evidence="Original reset/request/frame instructions and existing linked read-only controller-zero fence observation; complete allocation sizes exceed these explicitly named headers.",
)
output = ROOT / "validation/20261006-relay-restart-target-layout.json"
output.write_text(json.dumps(receipt, indent=2) + "\n")
print(
    "PASS: original Replay relay disconnect/reset/request path; native runtime remains separate"
)
