"""Follow same-Replay task constructors and forwarding wrappers through its CFG.

This audit keeps branch paths separate, preserves nonvolatile register facts
across calls, and records unresolved/dynamic paths instead of guessing a task.
Names are aliases only; service/task IDs are taken from target assembly.
"""

from collections import deque
import json
from pathlib import Path
import re
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
DB = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
CONSTRUCTORS = {
    0x1421170B0: ("rdx", "r8"),
    0x142156330: ("rdx", "r8"),
    0x142117C10: ("r8", "r9"),
}
REGS = {}
for root, forms in {
    "rax": ("rax", "eax", "ax", "al"),
    "rbx": ("rbx", "ebx", "bx", "bl"),
    "rcx": ("rcx", "ecx", "cx", "cl"),
    "rdx": ("rdx", "edx", "dx", "dl"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "rbp": ("rbp", "ebp", "bp", "bpl"),
    "rsp": ("rsp", "esp", "sp", "spl"),
}.items():
    REGS.update((form, root) for form in forms)
for i in range(8, 16):
    REGS.update((f"r{i}{suffix}", f"r{i}") for suffix in ("", "d", "w", "b"))
VOLATILE = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")


def immediate(value):
    value = value.lower().strip()
    if re.fullmatch(r"-?[0-9a-f]+h", value):
        return int(value[:-1], 16)
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"0x[0-9a-f]+", value):
        return int(value, 16)
    return None


def parse(assembly):
    instructions = []
    labels = {}
    for line_no, raw in enumerate((assembly or "").splitlines(), 1):
        line = raw.split(";", 1)[0].strip().lower()
        if not line:
            continue
        if line.endswith(":"):
            labels[line[:-1]] = len(instructions)
            continue
        parts = line.split(None, 1)
        op = parts[0]
        operands = [v.strip() for v in parts[1].split(",")] if len(parts) > 1 else []
        instructions.append((op, operands, line_no))
    return instructions, labels


def analyze(row, recipes, aliases):
    code, labels = parse(row["assembly"])
    results = []
    unresolved = []
    initial = {reg: "arg:" + reg for reg in ("rcx", "rdx", "r8", "r9")}
    work = deque([(0, initial)])
    seen = set()
    limited = False
    while work:
        pc, state = work.popleft()
        if pc >= len(code):
            continue
        stamp = (pc, tuple(sorted(state.items())))
        if stamp in seen:
            continue
        if len(seen) >= 25000:
            limited = True
            break
        seen.add(stamp)
        state = state.copy()
        op, args, line = code[pc]

        def value(operand):
            const = immediate(operand)
            return const if const is not None else state.get(REGS.get(operand))

        destination = REGS.get(args[0]) if args else None
        if op == "call" and args:
            target = aliases.get(args[0])
            for recipe in recipes.get(target, []):

                def resolve(item):
                    return (
                        state.get(item[4:])
                        if isinstance(item, str) and item.startswith("arg:")
                        else item
                    )

                service, task = resolve(recipe["service"]), resolve(recipe["task"])
                proof = {
                    "name": row["name"],
                    "address": row["address"],
                    "callee": target,
                    "assembly_line": line,
                    "service": service,
                    "task": task,
                    "constructor": recipe["constructor"],
                }
                if isinstance(service, int) and isinstance(task, int):
                    proof["service"] &= 255
                    proof["task"] &= 255
                    results.append(proof)
                elif service is not None and task is not None:
                    results.append(proof)
                else:
                    unresolved.append(proof)
            for reg in VOLATILE:
                state.pop(reg, None)
        elif destination:
            source = None
            if op in ("mov", "movzx", "movsx", "movsxd") and len(args) == 2:
                source = value(args[1])
            elif op in ("xor", "sub") and len(args) == 2 and args[0] == args[1]:
                source = 0
            elif op in ("add", "sub", "and", "or", "shl", "shr") and len(args) == 2:
                left, right = state.get(destination), value(args[1])
                if isinstance(left, int) and isinstance(right, int):
                    if op == "add":
                        source = left + right
                    elif op == "sub":
                        source = left - right
                    elif op == "and":
                        source = left & right
                    elif op == "or":
                        source = left | right
                    elif op == "shl":
                        source = left << (right & 63)
                    else:
                        source = left >> (right & 63)
            elif op in ("test", "cmp", "push"):
                source = state.get(destination)
            state.pop(destination, None)
            if source is not None:
                state[destination] = source
        if op in ("ret", "retn", "int", "int3", "ud2"):
            continue
        if op.startswith("j") and args:
            target = args[0].removeprefix("short ").removeprefix("near ptr ")
            if target in labels:
                work.append((labels[target], state.copy()))
            elif op == "jmp":
                # Indirect switches and external tail targets need separate
                # recovery; do not infer a fallthrough that cannot execute.
                unresolved.append(
                    {
                        "name": row["name"],
                        "address": row["address"],
                        "assembly_line": line,
                        "tail_or_indirect_target": target,
                    }
                )
            if op == "jmp":
                continue
        work.append((pc + 1, state))
    if limited:
        unresolved.append(
            {
                "name": row["name"],
                "address": row["address"],
                "reason": "CFG state bound reached",
            }
        )

    def unique(items):
        return list({json.dumps(item, sort_keys=True): item for item in items}.values())

    return unique(results), unique(unresolved)


with sqlite3.connect(DB.as_uri() + "?mode=ro", uri=True) as connection:
    connection.execute("pragma query_only=on")
    connection.execute("begin")  # one coherent read snapshot while naming/export grows
    snapshot_stat = DB.stat()
    aliases = {}
    ambiguous = set()
    function_count = 0
    for name, address in connection.execute("select name,address from functions"):
        address = int(address)
        function_count += 1
        for alias in (
            name,
            name.replace("::", "__"),
            "sub_" + f"{address:X}",
            "func_" + f"{address:X}",
        ):
            alias = alias.lower()
            if alias in aliases and aliases[alias] != address:
                ambiguous.add(alias)
            else:
                aliases[alias] = address
    # Duplicate/overloaded display names are not address evidence. Numeric
    # aliases remain usable; ambiguous names are explicit inventory gaps.
    for alias in ambiguous:
        aliases.pop(alias, None)
    recipes = {
        address: [
            {
                "service": "arg:" + regs[0],
                "task": "arg:" + regs[1],
                "constructor": address,
            }
        ]
        for address, regs in CONSTRUCTORS.items()
    }
    rows = []
    # Task constructors are called from engine wrappers as well as SDK code.
    # Include every exported function, rather than a hand-picked SDK RVA band.
    for name, address, assembly in connection.execute(
        "select name,address,assembly from functions"
    ):
        if assembly and "call" in assembly:
            rows.append({"name": name, "address": int(address), "assembly": assembly})
    proven = []
    dynamic = []
    unresolved = []
    for depth in range(4):
        changed = False
        targets = set(recipes)
        for row in rows:
            if row["address"] in CONSTRUCTORS:
                continue
            calls = re.findall(r"^\s*call\s+([^;\n]+)", row["assembly"], re.M)
            if not any(aliases.get(call.strip().lower()) in targets for call in calls):
                continue
            results, misses = analyze(row, recipes, aliases)
            unresolved.extend(misses)
            for result in results:
                if isinstance(result["service"], int) and isinstance(
                    result["task"], int
                ):
                    proven.append(result)
                else:
                    dynamic.append(result)
                    recipe = {k: result[k] for k in ("service", "task", "constructor")}
                    forwarding = recipes.setdefault(row["address"], [])
                    if recipe not in forwarding:
                        forwarding.append(recipe)
                        changed = True
        if not changed:
            break


def unique(items):
    return list({json.dumps(item, sort_keys=True): item for item in items}.values())


proven = unique(proven)
dynamic = unique(dynamic)
unresolved = unique(unresolved)
families = {}
for row in proven:
    families.setdefault(row["service"], set()).add(row["task"])
report = {
    "schema": 2,
    "database": str(DB),
    "database_size": snapshot_stat.st_size,
    "database_mtime_ns": snapshot_stat.st_mtime_ns,
    "exported_function_count": function_count,
    "ambiguous_display_aliases": sorted(ambiguous),
    "database_changed_during_inventory": DB.stat().st_size != snapshot_stat.st_size
    or DB.stat().st_mtime_ns != snapshot_stat.st_mtime_ns,
    "method": "target assembly CFG, separate branch states, nonvolatile register preservation and bounded forwarding-wrapper propagation",
    "scope": "all exported functions; indirect virtual dispatch and memory-derived service/task IDs remain explicit gaps",
    "families": {str(key): sorted(value) for key, value in sorted(families.items())},
    "proven_calls": proven,
    "dynamic_forwarders": dynamic,
    "unresolved_paths": unresolved,
}
(ROOT / "data" / "native-service-callgraph.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print(
    "Native families:",
    len(families),
    "Proven calls:",
    len(proven),
    "Dynamic forwarders:",
    len(dynamic),
    "Unresolved paths:",
    len(unresolved),
)
