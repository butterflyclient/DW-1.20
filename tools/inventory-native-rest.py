"""Inventory exact Replay REST builder calls without trusting display aliases.

Scan the untouched image for direct call targets, confirm instruction boundaries
inside exported functions, and follow bounded CFG/register facts to recover
literal service/resource/operation strings. Unknown paths stay explicit.
"""

from bisect import bisect_right
import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--output", type=Path, default=ROOT / "data/native-rest-callgraph.json"
)
args = parser.parse_args()
output = args.output.resolve()
if not any(output.is_relative_to(ROOT / folder) for folder in ("data", "validation")):
    raise ValueError(
        "Keep the inventory in this repository's data or validation folder"
    )
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
DATABASE = IMAGE.with_suffix(IMAGE.suffix + ".sqlite")
TARGETS = {0x1420FCA50: "service", 0x1420FC930: "resource_operation"}
VOLATILE = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
raw = IMAGE.read_bytes()
image = pefile.PE(data=raw, fast_load=True)
base = image.OPTIONAL_HEADER.ImageBase
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
stat = DATABASE.stat()
with sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True) as database:
    database.execute("pragma query_only=on")
    functions = sorted(
        (int(address), name, int(size))
        for name, address, size in database.execute(
            "select name,address,size from functions"
        )
    )
starts = [row[0] for row in functions]
candidates = {}
for section in image.sections:
    if not section.Characteristics & 0x20000000:
        continue
    code = section.get_data()
    offset = -1
    while True:
        offset = code.find(b"\xe8", offset + 1)
        if offset < 0 or offset + 5 > len(code):
            break
        address = base + section.VirtualAddress + offset
        target = (
            address
            + 5
            + int.from_bytes(code[offset + 1 : offset + 5], "little", signed=True)
        )
        if target in TARGETS:
            index = bisect_right(starts, address) - 1
            candidates.setdefault(index, set()).add(address)


def register(instruction, identifier):
    name = instruction.reg_name(identifier)
    if name in ("eax", "ax", "al", "ah"):
        return "rax"
    if name in ("ebx", "bx", "bl", "bh"):
        return "rbx"
    if name in ("ecx", "cx", "cl", "ch"):
        return "rcx"
    if name in ("edx", "dx", "dl", "dh"):
        return "rdx"
    if name in ("esi", "si", "sil"):
        return "rsi"
    if name in ("edi", "di", "dil"):
        return "rdi"
    return name[:-1] if name.startswith("r") and name[-1:] in ("d", "w", "b") else name


def literal(pointer):
    if (
        pointer is None
        or not base <= pointer < base + image.OPTIONAL_HEADER.SizeOfImage
    ):
        return None
    value = image.get_data(pointer - base, 128).split(b"\0", 1)[0]
    return (
        value.decode("ascii")
        if value and len(value) < 128 and all(32 <= c < 127 for c in value)
        else None
    )


calls, unresolved = [], []
for function_index, sites in candidates.items():
    if function_index < 0:
        unresolved.append({"sites": sorted(sites), "reason": "No exported owner"})
        continue
    start, name, size = functions[function_index]
    end = (
        starts[function_index + 1] if function_index + 1 < len(starts) else start + size
    )
    if not 0 < end - start <= 65536:
        unresolved.append(
            {
                "address": start,
                "sites": sorted(sites),
                "reason": "Owner span outside bound",
            }
        )
        continue
    instructions = {
        instruction.address: instruction
        for instruction in decoder.disasm(
            image.get_data(start - base, end - start), start
        )
    }
    confirmed = {
        site
        for site in sites
        if site in instructions and instructions[site].mnemonic == "call"
    }
    if confirmed != sites:
        unresolved.append(
            {
                "address": start,
                "sites": sorted(sites - confirmed),
                "reason": "Call bytes not on a confirmed instruction boundary",
            }
        )
    work, visited = deque([(start, {})]), set()
    while work and len(visited) < 8192:
        address, facts = work.popleft()
        state = (address, tuple(sorted(facts.items())))
        if state in visited or address not in instructions:
            continue
        visited.add(state)
        instruction = instructions[address]
        operands = instruction.operands
        following = address + instruction.size
        if instruction.mnemonic == "call":
            if address in confirmed:
                target = operands[0].imm
                arguments = ("rdx",) if TARGETS[target] == "service" else ("rdx", "r8")
                values = [literal(facts.get(argument)) for argument in arguments]
                calls.append(
                    {
                        "function": name,
                        "function_address": start,
                        "call_address": address,
                        "builder": TARGETS[target],
                        "target": target,
                        "arguments": values,
                        "literal_arguments_resolved": all(
                            value is not None for value in values
                        ),
                    }
                )
            facts = {key: value for key, value in facts.items() if key not in VOLATILE}
        else:
            # Implicit writes (mul/div/string instructions) invalidate facts too.
            # Partial writes cannot retain a recovered 64-bit image pointer.
            destination = (
                register(instruction, operands[0].reg)
                if operands and operands[0].type == X86_OP_REG
                else None
            )
            value = None
            if (
                instruction.mnemonic == "lea"
                and len(operands) == 2
                and operands[0].size == 8
                and operands[1].type == X86_OP_MEM
                and operands[1].mem.base == X86_REG_RIP
            ):
                value = following + operands[1].mem.disp
            elif (
                instruction.mnemonic in ("mov", "movabs")
                and len(operands) == 2
                and operands[0].size == 8
            ):
                if operands[1].type == X86_OP_REG and operands[1].size == 8:
                    value = facts.get(register(instruction, operands[1].reg))
                elif operands[1].type == X86_OP_IMM:
                    value = operands[1].imm
            written = {
                register(instruction, reg) for reg in instruction.regs_access()[1]
            }
            facts = {key: old for key, old in facts.items() if key not in written}
            if destination in written:
                if value is not None:
                    facts[destination] = value
        if instruction.mnemonic.startswith("ret") or instruction.mnemonic in (
            "int3",
            "ud2",
        ):
            continue
        if instruction.mnemonic.startswith("j"):
            if operands and operands[0].type == X86_OP_IMM:
                work.append((operands[0].imm, facts.copy()))
            else:
                unresolved.append({"address": address, "reason": "Indirect CFG branch"})
            if instruction.mnemonic == "jmp":
                continue
        work.append((following, facts.copy()))
    if work:
        unresolved.append({"address": start, "reason": "CFG state bound reached"})
    reached = {row["call_address"] for row in calls}
    for site in confirmed - reached:
        unresolved.append(
            {
                "address": site,
                "reason": "Exported entry CFG did not reach direct builder call",
            }
        )
calls = list({json.dumps(row, sort_keys=True): row for row in calls}.values())
requests = []
for address in sorted({row["function_address"] for row in calls}):
    owned = [row for row in calls if row["function_address"] == address]
    services = sorted(
        {
            row["arguments"][0]
            for row in owned
            if row["builder"] == "service" and row["literal_arguments_resolved"]
        }
    )
    operations = sorted(
        {
            tuple(row["arguments"])
            for row in owned
            if row["builder"] == "resource_operation"
            and row["literal_arguments_resolved"]
        }
    )
    requests.append(
        {
            "function": owned[0]["function"],
            "function_address": address,
            "services": services,
            "resource_operations": operations,
            "service_operation_binding_resolved": len(services) == 1
            and len(operations) == 1
            and all(row["literal_arguments_resolved"] for row in owned),
            "builder_calls": sorted({row["call_address"] for row in owned}),
            "native_response_verified": False,
        }
    )
result = {
    "schema": 1,
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "inventory_tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "target_image_sha256": hashlib.sha256(raw).hexdigest(),
    "target_database": str(DATABASE),
    "target_database_changed": DATABASE.stat().st_size != stat.st_size
    or DATABASE.stat().st_mtime_ns != stat.st_mtime_ns,
    "exported_functions": len(functions),
    "scope": "Direct compiled REST service/resource builder calls with bounded entry CFG; indirect/inlined builders and native consumption remain open",
    "full_rest_audit_complete": False,
    "calls": calls,
    "requests": requests,
    "unresolved": unresolved,
}
output.write_text(json.dumps(result, indent=2) + "\n")
print(
    json.dumps(
        {
            "calls": len(calls),
            "resolved": sum(row["literal_arguments_resolved"] for row in calls),
            "unresolved_paths": len(unresolved),
        }
    )
)
