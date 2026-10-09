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
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_WRITE
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
if (
    hashlib.sha256(raw).hexdigest()
    != "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
):
    raise ValueError("Unexpected original Replay image")
image = pefile.PE(data=raw, fast_load=True)
base = image.OPTIONAL_HEADER.ImageBase
STACK_PROBE = 0x1421CCEF0
STACK_PROBE_SIZE = 81
STACK_PROBE_SHA256 = "99d2cc1dbc125fe60aeb6230c1033e4ddda1e4488b7baf555c32ea70e50e79da"
if (
    hashlib.sha256(image.get_data(STACK_PROBE - base, STACK_PROBE_SIZE)).hexdigest()
    != STACK_PROBE_SHA256
):
    raise ValueError("Unexpected original register-preserving stack probe")
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
names = {start: name for start, name, _ in functions}
image.parse_data_directories(
    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
)
entries = {row.struct.BeginAddress: row for row in image.DIRECTORY_ENTRY_EXCEPTION}


def primary(entry):
    visited = set()
    while entry.unwindinfo and entry.unwindinfo.UNW_FLAG_CHAININFO:
        address = entry.struct.BeginAddress
        if address in visited:
            raise ValueError("Cyclic original unwind chain")
        visited.add(address)
        entry = entries[entry.unwindinfo.FunctionEntry]
    return base + entry.struct.BeginAddress


regions, owners = {}, {}
for entry in entries.values():
    begin, end = base + entry.struct.BeginAddress, base + entry.struct.EndAddress
    owner = primary(entry)
    regions.setdefault(owner, []).append((begin, end))
    owners[begin] = owner
for chunks in regions.values():
    chunks.sort()
unwind_ranges = sorted(
    (begin, end) for chunks in regions.values() for begin, end in chunks
)
unwind_starts = [begin for begin, _ in unwind_ranges]


def code_owner(address):
    position = bisect_right(unwind_starts, address) - 1
    if position >= 0:
        begin, end = unwind_ranges[position]
        if begin <= address < end:
            start = owners[begin]
            return start, "pe-unwind", tuple(regions[start])
    position = bisect_right(starts, address) - 1
    if position >= 0:
        start, _, size = functions[position]
        if 0 < size <= 65536 and start <= address < start + size:
            return start, "sqlite-fallback", ((start, start + size),)
    return None


candidates = {}
for section in image.sections:
    if not section.Characteristics & 0x20000000:
        continue
    code = section.get_data()
    for opcode in (b"\xe8", b"\xe9"):
        offset = -1
        while True:
            offset = code.find(opcode, offset + 1)
            if offset < 0 or offset + 5 > len(code):
                break
            address = base + section.VirtualAddress + offset
            target = address + 5 + struct.unpack_from("<i", code, offset + 1)[0]
            if target in TARGETS:
                candidates.setdefault(code_owner(address), set()).add(address)


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


def stack_address(instruction, operand, facts):
    if operand.type != X86_OP_MEM or operand.mem.index:
        return None
    name = instruction.reg_name(operand.mem.base)
    key = {"rsp": "stack-pointer", "rbp": "frame-pointer"}.get(name)
    offset = facts.get(key) if key else None
    return offset + operand.mem.disp if offset is not None else None


def forget_stack(facts, offset=None, size=0):
    for key in tuple(facts):
        if not key.startswith("stack:"):
            continue
        _, begin, width = key.split(":")
        begin, width = int(begin), int(width)
        if offset is None or (begin < offset + size and offset < begin + width):
            facts.pop(key)


calls, unresolved, shared_calls, inspected = [], [], [], []
# A negative sentinel cannot be confused with a PE literal address. Track the
# incoming writer's RDX builder only through complete 64-bit register copies.
BUILDER_ARGUMENT = -1
for owner, sites in candidates.items():
    if owner is None:
        unresolved.append({"sites": sorted(sites), "reason": "No original code owner"})
        continue
    start, boundary, chunks = owner
    name = names.get(start)
    if not 0 < sum(end - begin for begin, end in chunks) <= 65536:
        unresolved.append(
            {
                "address": start,
                "sites": sorted(sites),
                "reason": "Owned code size outside bound",
            }
        )
        continue
    instructions = {
        instruction.address: instruction
        for begin, end in chunks
        for instruction in decoder.disasm(
            image.get_data(begin - base, end - begin), begin
        )
    }
    inspected.append(
        dict(
            function_address=start,
            display_alias=name,
            boundary_source=boundary,
            chunks=[
                dict(
                    begin=begin,
                    end=end,
                    bytes_sha256=hashlib.sha256(
                        image.get_data(begin - base, end - begin)
                    ).hexdigest(),
                )
                for begin, end in chunks
            ],
        )
    )
    confirmed = {
        site
        for site in sites
        if site in instructions
        and instructions[site].mnemonic in ("call", "jmp")
        and instructions[site].operands[0].type == X86_OP_IMM
        and instructions[site].operands[0].imm in TARGETS
    }
    if confirmed != sites:
        unresolved.append(
            {
                "address": start,
                "sites": sorted(sites - confirmed),
                "reason": "Call bytes not on a confirmed instruction boundary",
            }
        )
    work, visited = (
        deque([(start, {"rdx": BUILDER_ARGUMENT, "stack-pointer": 0})]),
        set(),
    )
    while work and len(visited) < 8192:
        address, facts = work.popleft()
        state = (address, tuple(sorted(facts.items())))
        if state in visited or address not in instructions:
            continue
        visited.add(state)
        instruction = instructions[address]
        operands = instruction.operands
        following = address + instruction.size
        if instruction.mnemonic == "call" or (
            instruction.mnemonic == "jmp" and address in confirmed
        ):
            if (
                operands
                and operands[0].type == X86_OP_IMM
                and facts.get("rdx") == BUILDER_ARGUMENT
            ):
                shared_calls.append(
                    dict(
                        function_address=start,
                        call_address=address,
                        target=operands[0].imm,
                    )
                )
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
                        "incoming_builder_verified": facts.get("rcx")
                        == BUILDER_ARGUMENT,
                        "boundary_source": boundary,
                        "transfer": instruction.mnemonic,
                    }
                )
            target = (
                operands[0].imm if operands and operands[0].type == X86_OP_IMM else None
            )
            if target != STACK_PROBE:
                stack = facts.get("stack-pointer")
                if stack is not None:
                    forget_stack(facts, stack, 32)
                if "stack-escaped" in facts:
                    forget_stack(facts)
                facts = {
                    key: value for key, value in facts.items() if key not in VOLATILE
                }
            # The pinned original probe saves/restores R10/R11, preserves the
            # other GPRs and touches only stack pages below the current frame.
            # It is not an ordinary Windows x64 call that clobbers RDX/RAX.
        else:
            # Implicit writes (mul/div/string instructions) invalidate facts too.
            # Partial writes cannot retain a recovered 64-bit image pointer.
            destination = (
                register(instruction, operands[0].reg)
                if operands and operands[0].type == X86_OP_REG
                else None
            )
            value = None
            pointer = None
            stack_updated = False
            if instruction.mnemonic in ("push", "pop") and operands:
                stack = facts.get("stack-pointer")
                if stack is not None:
                    if instruction.mnemonic == "push":
                        stack -= 8
                        pushed = (
                            facts.get(register(instruction, operands[0].reg))
                            if operands[0].type == X86_OP_REG
                            else (
                                operands[0].imm
                                if operands[0].type == X86_OP_IMM
                                else None
                            )
                        )
                        forget_stack(facts, stack, 8)
                        if pushed is not None:
                            facts[f"stack:{stack}:8"] = pushed
                    else:
                        value = facts.get(f"stack:{stack}:8")
                        forget_stack(facts, stack, 8)
                        stack += 8
                    facts["stack-pointer"] = stack
                    stack_updated = True
            elif (
                instruction.mnemonic in ("add", "sub")
                and len(operands) == 2
                and destination == "rsp"
            ):
                stack = facts.get("stack-pointer")
                delta = (
                    operands[1].imm
                    if operands[1].type == X86_OP_IMM
                    else (
                        facts.get(register(instruction, operands[1].reg))
                        if operands[1].type == X86_OP_REG
                        else None
                    )
                )
                if stack is not None and delta is not None and delta >= 0:
                    facts["stack-pointer"] = stack + (
                        delta if instruction.mnemonic == "add" else -delta
                    )
                    stack_updated = True
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
                    key = {"rsp": "stack-pointer", "rbp": "frame-pointer"}.get(
                        instruction.reg_name(operands[1].reg)
                    )
                    pointer = facts.get(key) if key else None
                elif operands[1].type == X86_OP_IMM:
                    value = operands[1].imm
                elif operands[1].type == X86_OP_MEM and operands[1].size == 8:
                    offset = stack_address(instruction, operands[1], facts)
                    if offset is not None:
                        value = facts.get(f"stack:{offset}:8")
            elif (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and operands[0].size == 4
                and operands[1].type == X86_OP_IMM
            ):
                value = operands[1].imm & 0xFFFFFFFF
            if (
                instruction.mnemonic == "lea"
                and len(operands) == 2
                and operands[0].size == 8
                and operands[1].type == X86_OP_MEM
            ):
                pointer = stack_address(instruction, operands[1], facts)
            for operand in operands:
                if operand.type != X86_OP_MEM or not operand.access & CS_AC_WRITE:
                    continue
                offset = stack_address(instruction, operand, facts)
                if offset is not None:
                    stored = None
                    if (
                        instruction.mnemonic in ("mov", "movabs")
                        and len(operands) == 2
                        and operand is operands[0]
                        and operand.size == 8
                    ):
                        if operands[1].type == X86_OP_REG and operands[1].size == 8:
                            stored = facts.get(register(instruction, operands[1].reg))
                        elif operands[1].type == X86_OP_IMM:
                            stored = operands[1].imm
                    forget_stack(facts, offset, operand.size)
                    if stored is not None:
                        facts[f"stack:{offset}:8"] = stored
                elif "stack-escaped" in facts:
                    forget_stack(facts)
            written = {
                register(instruction, reg) for reg in instruction.regs_access()[1]
            }
            facts = {key: old for key, old in facts.items() if key not in written}
            if "rsp" in written and not stack_updated:
                facts.pop("stack-pointer", None)
            if "rbp" in written:
                facts.pop("frame-pointer", None)
            if pointer is not None:
                if destination == "rsp":
                    facts["stack-pointer"] = pointer
                elif destination == "rbp":
                    facts["frame-pointer"] = pointer
                else:
                    # An unknown callee can modify saved locals after any local
                    # address escapes. Never join a route using those stale facts.
                    facts["stack-escaped"] = 1
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
                "reason": "Owned entry CFG did not reach direct builder transfer",
            }
        )
calls = list({json.dumps(row, sort_keys=True): row for row in calls}.values())
shared_calls = list(
    {json.dumps(row, sort_keys=True): row for row in shared_calls}.values()
)
by_owner = {
    owner: [row for row in calls if row["function_address"] == owner]
    for owner in {row["function_address"] for row in calls}
}


def shared_service_paths(owner, visited=()):
    if owner in visited or len(visited) >= 4:
        return []
    paths = []
    for edge in shared_calls:
        if edge["function_address"] != owner or edge["target"] not in by_owner:
            continue
        for row in by_owner[edge["target"]]:
            if (
                row["builder"] == "service"
                and row["literal_arguments_resolved"]
                and row["incoming_builder_verified"]
            ):
                paths.append(
                    dict(
                        service=row["arguments"][0],
                        call_sites=[edge["call_address"], row["call_address"]],
                        functions=[owner, edge["target"]],
                    )
                )
        for inherited in shared_service_paths(edge["target"], visited + (owner,)):
            paths.append(
                dict(
                    inherited,
                    call_sites=[edge["call_address"]] + inherited["call_sites"],
                    functions=[owner] + inherited["functions"],
                )
            )
    return paths


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
    inherited = shared_service_paths(address) if operations and not services else []
    if inherited:
        services = sorted({row["service"] for row in inherited})
    requests.append(
        {
            "function": owned[0]["function"],
            "function_address": address,
            "services": services,
            "resource_operations": operations,
            "service_operation_binding_resolved": len(services) == 1
            and len(operations) == 1
            and all(
                row["literal_arguments_resolved"] and row["incoming_builder_verified"]
                for row in owned
            ),
            "builder_calls": sorted({row["call_address"] for row in owned}),
            "shared_service_paths": inherited,
            "native_response_verified": False,
        }
    )
helper_owners = {
    owner
    for row in requests
    for path in row["shared_service_paths"]
    for owner in path["functions"][1:]
}
for row in requests:
    row["shared_service_helper_only"] = (
        row["function_address"] in helper_owners and not row["resource_operations"]
    )
result = {
    "schema": 2,
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "inventory_tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "target_image_sha256": hashlib.sha256(raw).hexdigest(),
    "target_database": str(DATABASE),
    "target_database_changed": DATABASE.stat().st_size != stat.st_size
    or DATABASE.stat().st_mtime_ns != stat.st_mtime_ns,
    "exported_functions": len(functions),
    "scope": "Original PE-unwind owned direct call/tail transfers, including chained chunks, with explicit bounded SQLite fallback and shared service setters preserving the incoming builder through full 64-bit register copies; indirect/inlined builders and native consumption remain open",
    "full_rest_audit_complete": False,
    "calls": calls,
    "requests": requests,
    "shared_builder_calls": shared_calls,
    "inspected_owners": inspected,
    "chained_unwind_ownership_resolved": True,
    "register_preserving_stack_probe": dict(
        target=STACK_PROBE,
        size=STACK_PROBE_SIZE,
        bytes_sha256=STACK_PROBE_SHA256,
        evidence="validation/20261009-native-stack-probe.json",
    ),
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
