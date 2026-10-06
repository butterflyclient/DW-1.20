"""Inventory Replay task routes from original instructions, independent of aliases.

Unwind boundaries are preferred. SQLite starts/sizes are fallback boundaries and
display labels only. Branches remain separate; unresolved values stay unresolved.
This is a bounded potential-call audit, not native completion or an exhaustive
recovery of indirect dispatch, stack arguments or condition feasibility.
"""

import argparse
from bisect import bisect_right
from collections import defaultdict, deque
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_WRITE
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
CONSTRUCTORS = {
    0x1421170B0: ("rdx", "r8"),
    0x142156330: ("rdx", "r8"),
    0x142117C10: ("r8", "r9"),
}
FULL = (1 << 64) - 1
VOLATILE = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")
REGISTERS = {}
for root, forms in {
    "rax": ("rax", "eax", "ax", "al", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "rbp": ("rbp", "ebp", "bp", "bpl"),
    "rsp": ("rsp", "esp", "sp", "spl"),
}.items():
    for name in forms:
        REGISTERS[name] = (root, 8 if name in ("ah", "bh", "ch", "dh") else 0)
for index in range(8, 16):
    for suffix in ("", "d", "w", "b"):
        REGISTERS[f"r{index}{suffix}"] = (f"r{index}", 0)


def trace(start, end, decode, recipes, state_limit=10000):
    """Track register bits and argument origins through a single bounded CFG."""
    initial = {reg: ("arg:" + reg, FULL) for reg in ("rcx", "rdx", "r8", "r9")}
    initial["stack-pointer"] = (0, FULL)
    work = deque([(start, initial)])
    seen, calls, unresolved = set(), set(), set()
    while work:
        address, state = work.popleft()
        stamp = (address, tuple(sorted(state.items())))
        if stamp in seen or not start <= address < end:
            continue
        if len(seen) >= state_limit:
            unresolved.add((address, "state-limit"))
            break
        seen.add(stamp)
        instruction = decode(address)
        if instruction is None or instruction.address + instruction.size > end:
            unresolved.add((address, "decode-boundary"))
            continue
        state = state.copy()
        op, operands = instruction.mnemonic, instruction.operands
        following = address + instruction.size

        def stack_address(operand):
            if operand.type != X86_OP_MEM or operand.mem.index:
                return None
            register = instruction.reg_name(operand.mem.base)
            key = {"rsp": "stack-pointer", "rbp": "frame-pointer"}.get(register)
            value, known = state.get(key, (0, 0))
            return value + operand.mem.disp if key and known == FULL else None

        def forget_stack(offset, size):
            for key in list(state):
                if key.startswith("stack:"):
                    _, address, width = key.split(":")
                    address, width = int(address), int(width)
                    if address < offset + size and offset < address + width:
                        state.pop(key)

        def forget_all_stack():
            for key in list(state):
                if key.startswith("stack:"):
                    state.pop(key)

        def read(operand):
            if operand.type == X86_OP_IMM:
                return operand.imm & FULL, FULL
            if operand.type == X86_OP_MEM:
                offset = stack_address(operand)
                if offset is None:
                    return 0, 0
                for key, (value, known) in state.items():
                    if not key.startswith("stack:"):
                        continue
                    _, address, width = key.split(":")
                    address, width = int(address), int(width)
                    if address <= offset and offset + operand.size <= address + width:
                        shift = (offset - address) * 8
                        mask = (1 << (operand.size * 8)) - 1
                        if isinstance(value, str):
                            return (value, known & mask) if not shift else (0, 0)
                        return (value >> shift) & mask, (known >> shift) & mask
                return 0, 0
            if operand.type != X86_OP_REG:
                return 0, 0
            root, shift = REGISTERS.get(instruction.reg_name(operand.reg), (None, 0))
            value, known = state.get(root, (0, 0))
            mask = (1 << (operand.size * 8)) - 1
            if isinstance(value, str):
                return (value, known & mask) if not shift else (0, 0)
            return (value >> shift) & mask, (known >> shift) & mask

        def write(operand, fact):
            if operand.type == X86_OP_MEM:
                offset = stack_address(operand)
                if offset is not None:
                    forget_stack(offset, operand.size)
                    value, known = fact
                    mask = (1 << (operand.size * 8)) - 1
                    state[f"stack:{offset}:{operand.size}"] = (
                        value if isinstance(value, str) else value & mask,
                        known & mask,
                    )
                elif "stack-escaped" in state:
                    forget_all_stack()
                return
            root, shift = REGISTERS.get(instruction.reg_name(operand.reg), (None, 0))
            if root is None:
                return
            if root in ("rsp", "rbp"):
                state.pop("stack-pointer" if root == "rsp" else "frame-pointer", None)
            width = operand.size * 8
            mask = (1 << width) - 1
            value, known = fact
            known &= mask
            if isinstance(value, str):
                # Preserve the low argument provenance used by byte task IDs.
                # High partial-register writes cannot be represented this way.
                state[root] = (value, known) if not shift else (0, 0)
                return
            value = (value & mask) << shift
            known <<= shift
            old, old_known = state.get(root, (0, 0))
            if width == 32:
                state[root] = (value, known | (FULL ^ mask))
            elif width == 64:
                state[root] = (value, known)
            else:
                preserve = FULL ^ (mask << shift)
                if isinstance(old, str):
                    old, old_known = 0, 0
                state[root] = (value | (old & preserve), known | (old_known & preserve))

        target = (
            operands[0].imm if operands and operands[0].type == X86_OP_IMM else None
        )
        if op in ("call", "jmp") and target in recipes:
            for service, task, constructor in recipes[target]:
                resolved = []
                for value in (service, task):
                    fact = (
                        state.get(value[4:], (0, 0))
                        if isinstance(value, str)
                        else (value, FULL)
                    )
                    resolved.append(fact[0] if fact[1] & 255 == 255 else None)
                calls.add((address, target, *resolved, constructor))
        if op == "call":
            offset, known = state.get("stack-pointer", (0, 0))
            if known == FULL:
                # A callee owns the 32-byte Windows x64 shadow area. Preserve
                # saved locals beyond it, without trusting volatile stack slots.
                forget_stack(offset, 32)
            if "stack-escaped" in state:
                # An unknown callee may write through a previously formed local
                # address. Do not preserve those locals as route evidence.
                forget_all_stack()
            for reg in VOLATILE:
                state.pop(reg, None)
        elif op.startswith("cmov") and len(operands) == 2:
            work.append((following, state.copy()))
            write(operands[0], read(operands[1]))
        elif op in ("push", "pop") and operands:
            offset, known = state.get("stack-pointer", (0, 0))
            if known == FULL:
                if op == "push":
                    offset -= 8
                    forget_stack(offset, 8)
                    state[f"stack:{offset}:8"] = read(operands[0])
                else:
                    write(operands[0], state.get(f"stack:{offset}:8", (0, 0)))
                    forget_stack(offset, 8)
                    offset += 8
                if (
                    op == "pop"
                    and operands[0].type == X86_OP_REG
                    and instruction.reg_name(operands[0].reg) == "rsp"
                ):
                    state.pop("stack-pointer", None)
                else:
                    state["stack-pointer"] = (offset, FULL)
        elif (
            op in ("add", "sub")
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and instruction.reg_name(operands[0].reg) == "rsp"
        ):
            offset, known = state.get("stack-pointer", (0, 0))
            value = operands[1].imm if operands[1].type == X86_OP_IMM else None
            if known == FULL and value is not None:
                state["stack-pointer"] = (
                    offset + (value if op == "add" else -value),
                    FULL,
                )
            else:
                state.pop("stack-pointer", None)
        elif op in ("mov", "movabs", "movzx", "movsx", "movsxd") and len(operands) == 2:
            if operands[0].type in (X86_OP_REG, X86_OP_MEM):
                source_pointer = None
                if operands[1].type == X86_OP_REG and operands[1].size == 8:
                    pointer = {"rsp": "stack-pointer", "rbp": "frame-pointer"}.get(
                        instruction.reg_name(operands[1].reg)
                    )
                    if pointer:
                        source_pointer = state.get(pointer, (0, 0))
                fact = read(operands[1])
                if op == "movzx":
                    width = operands[1].size * 8
                    fact = (fact[0], fact[1] | (FULL ^ ((1 << width) - 1)))
                elif op in ("movsx", "movsxd"):
                    width = operands[1].size * 8
                    if isinstance(fact[0], int) and fact[1] == (1 << width) - 1:
                        value = (
                            fact[0] - (1 << width)
                            if fact[0] & (1 << (width - 1))
                            else fact[0]
                        )
                        fact = (value & FULL, FULL)
                write(operands[0], fact)
                if operands[0].type == X86_OP_REG and instruction.reg_name(
                    operands[0].reg
                ) in ("rbp", "rsp"):
                    destination = {"rbp": "frame-pointer", "rsp": "stack-pointer"}[
                        instruction.reg_name(operands[0].reg)
                    ]
                    if source_pointer is not None:
                        state[destination] = source_pointer
                elif source_pointer is not None and source_pointer[1] == FULL:
                    state["stack-escaped"] = (1, FULL)
        elif (
            op in ("xor", "sub")
            and len(operands) == 2
            and all(item.type == X86_OP_REG for item in operands)
            and operands[0].reg == operands[1].reg
        ):
            write(operands[0], (0, FULL))
        elif op == "lea" and len(operands) == 2 and operands[1].type == X86_OP_MEM:
            offset = stack_address(operands[1])
            memory = operands[1].mem
            if not memory.index and memory.base == X86_REG_RIP:
                fact = (following + memory.disp, FULL)
            elif not memory.index and memory.base:
                root, shift = REGISTERS.get(
                    instruction.reg_name(memory.base), (None, 0)
                )
                value, mask = state.get(root, (0, 0))
                fact = (
                    ((value + memory.disp) & FULL, FULL)
                    if isinstance(value, int) and mask == FULL and not shift
                    else (0, 0)
                )
            else:
                fact = (0, 0)
            write(operands[0], fact)
            pointer = {"rsp": "stack-pointer", "rbp": "frame-pointer"}.get(
                instruction.reg_name(operands[0].reg)
            )
            if pointer:
                if offset is not None:
                    state[pointer] = (offset, FULL)
            elif offset is not None:
                state["stack-escaped"] = (1, FULL)
        elif op in ("ret", "retf", "int3", "ud2"):
            continue
        elif not op.startswith("j"):
            # Unknown instructions must invalidate every register they write.
            for operand in operands:
                if operand.type == X86_OP_MEM and operand.access & CS_AC_WRITE:
                    offset = stack_address(operand)
                    if offset is not None:
                        forget_stack(offset, operand.size)
                    elif "stack-escaped" in state:
                        forget_all_stack()
            _, written = instruction.regs_access()
            for register in written:
                root = REGISTERS.get(instruction.reg_name(register), (None, 0))[0]
                state.pop(root, None)
                if root in ("rsp", "rbp"):
                    state.pop(
                        "stack-pointer" if root == "rsp" else "frame-pointer", None
                    )
        if op.startswith("j"):
            if target is not None and start <= target < end:
                work.append((target, state.copy()))
            elif target not in recipes:
                unresolved.add((address, "external-or-indirect-branch"))
            if op == "jmp":
                continue
        work.append((following, state))
    return calls, unresolved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    assert any(
        output.is_relative_to(ROOT / folder) for folder in ("data", "validation")
    )
    raw = IMAGE.read_bytes()
    image_hash = sha256(raw).hexdigest()
    assert (
        image_hash == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    )
    pe = pefile.PE(data=raw, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    ranges, names = [], {}
    database = IMAGE.with_suffix(".exe.sqlite")
    before = database.stat()
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        db.execute("pragma query_only=on")
        db.execute("begin")
        for name, address, size in db.execute(
            "select name,address,size from functions"
        ):
            start = int(address)
            names[start] = name
            if 0 < size <= 65536:
                ranges.append((start, start + size, "sqlite-fallback"))
    ranges.sort()
    starts = [row[0] for row in ranges]
    pdata = next(
        section for section in pe.sections if section.Name.rstrip(b"\0") == b".pdata"
    )
    unwind = sorted(
        (base + start, base + end, "pe-unwind")
        for start, end, info in struct.iter_unpack(
            "<III", pdata.get_data()[: (pdata.SizeOfRawData // 12) * 12]
        )
        if start and start < end
    )
    unwind_starts = [row[0] for row in unwind]

    def owner(address):
        for entries, beginnings in ((unwind, unwind_starts), (ranges, starts)):
            position = bisect_right(beginnings, address) - 1
            if position >= 0 and entries[position][0] <= address < entries[position][1]:
                return entries[position]
        return None

    xrefs = defaultdict(set)
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        code = section.get_data()
        for opcode in (b"\xe8", b"\xe9"):
            position = code.find(opcode)
            while position >= 0:
                if position + 5 <= len(code):
                    address = base + section.VirtualAddress + position
                    target = (
                        address + 5 + struct.unpack_from("<i", code, position + 1)[0]
                    )
                    xrefs[target].add(address)
                position = code.find(opcode, position + 1)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    cache = {}

    def decode(address):
        if address not in cache:
            cache[address] = next(
                decoder.disasm(pe.get_data(address - base, 15), address, count=1), None
            )
        return cache[address]

    recipes = {
        address: {("arg:" + regs[0], "arg:" + regs[1], address)}
        for address, regs in CONSTRUCTORS.items()
    }
    calls, misses, inspected = set(), set(), {}
    unowned = set()
    for depth in range(6):
        changed = False
        candidates = set()
        for target in recipes:
            for address in xrefs.get(target, ()):
                region = owner(address)
                if region is None:
                    unowned.add(address)
                else:
                    candidates.add(region)
        for start, end, boundary in sorted(candidates):
            if start in CONSTRUCTORS or end - start > 65536:
                continue
            inspected[start] = dict(
                start=start,
                end=end,
                boundary=boundary,
                candidate_alias=names.get(start),
                bytes_sha256=sha256(pe.get_data(start - base, end - start)).hexdigest(),
            )
            found, unresolved = trace(start, end, decode, recipes)
            for result in found:
                calls.add((start, *result))
                _, _, service, task, constructor = result
                if service is not None and task is not None:
                    recipe = (service, task, constructor)
                    if recipe not in recipes.get(start, set()):
                        recipes.setdefault(start, set()).add(recipe)
                        changed = True
            misses.update((start, *item) for item in unresolved)
        if not changed:
            break
    records = [
        dict(
            function=start,
            callsite=site,
            callee=target,
            service=service & 255 if isinstance(service, int) else service,
            task=task & 255 if isinstance(task, int) else task,
            constructor=constructor,
        )
        for start, site, target, service, task, constructor in sorted(calls, key=repr)
    ]
    routes = sorted(
        {
            (row["service"], row["task"])
            for row in records
            if isinstance(row["service"], int) and isinstance(row["task"], int)
        }
    )
    result = dict(
        schema=1,
        generated_utc=datetime.now(timezone.utc).isoformat(),
        target_image=str(IMAGE),
        target_image_sha256=image_hash,
        audit_tool_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        database=str(database),
        database_changed_during_labels=database.stat().st_mtime_ns
        != before.st_mtime_ns,
        route_count=len(routes),
        routes=[dict(service=service, task=task) for service, task in routes],
        calls=records,
        inspected_functions=list(inspected.values()),
        unresolved=[
            dict(function=start, instruction=site, reason=reason)
            for start, site, reason in sorted(misses)
        ],
        unowned_candidate_sites=sorted(unowned),
        wrapper_iterations=depth + 1,
        raw_instructions_decoded=len(cache),
        scope="Bounded potential direct calls and forwarding wrappers. No indirect dispatch, stack argument, branch feasibility or native callback completion claim.",
    )
    output.write_text(json.dumps(result, indent=2) + "\n")
    if args.receipt:
        receipt = args.receipt.resolve()
        assert receipt.is_relative_to(ROOT / "validation")
        test_path = ROOT / "tools/test-native-task-bytes.py"
        tests = subprocess.run(
            [sys.executable, "-B", str(test_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        assert tests.stdout.strip() == "PASS: 24 independent x64 task-trace cases"
        exported_path = ROOT / "data/native-service-callgraph.json"
        exported = json.loads(exported_path.read_bytes())
        text_routes = {
            (item["service"], item["task"]) for item in exported["proven_calls"]
        }
        summary = dict(
            schema=1,
            passed=True,
            generated_utc=result["generated_utc"],
            target_image_sha256=image_hash,
            audit_tool_sha256=result["audit_tool_sha256"],
            test_tool_sha256=sha256(test_path.read_bytes()).hexdigest(),
            independent_x64_trace_cases=24,
            route_count=len(routes),
            inspected_functions=len(inspected),
            unwind_bounded_functions=sum(
                row["boundary"] == "pe-unwind" for row in inspected.values()
            ),
            sqlite_fallback_functions=sum(
                row["boundary"] == "sqlite-fallback" for row in inspected.values()
            ),
            state_limited_paths=sum(reason == "state-limit" for _, _, reason in misses),
            unresolved_paths=len(misses),
            unowned_candidate_sites=len(unowned),
            text_inventory_routes=len(text_routes),
            text_routes_not_recovered_from_bytes=[
                list(route) for route in sorted(text_routes - set(routes))
            ],
            additional_raw_routes=[
                list(route) for route in sorted(set(routes) - text_routes)
            ],
            raw_inventory=dict(
                path=output.relative_to(ROOT).as_posix(),
                sha256=sha256(output.read_bytes()).hexdigest(),
            ),
            original_assembly_text_used=False,
            database_aliases_used_for_call_resolution=False,
            full_method_audit_complete=False,
            native_completion_verified=False,
            scope=result["scope"],
        )
        receipt.write_text(json.dumps(summary, indent=2) + "\n")
    print(
        json.dumps(
            dict(
                routes=len(routes),
                calls=len(records),
                inspected=len(inspected),
                unresolved=len(misses),
                unowned=len(unowned),
            )
        )
    )


if __name__ == "__main__":
    main()
