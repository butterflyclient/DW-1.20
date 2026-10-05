"""Inventory constant service/task calls from same-build assembly, not names."""

import json
import re
import sqlite3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
database = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
addresses = {
    0x1421170B0: ("rdx", "r8"),
    0x142156330: ("rdx", "r8"),
    0x142117C10: ("r8", "r9"),
}
registers = {
    "rdx": "rdx",
    "edx": "rdx",
    "dx": "rdx",
    "dl": "rdx",
    "r8": "r8",
    "r8d": "r8",
    "r8w": "r8",
    "r8b": "r8",
    "r9": "r9",
    "r9d": "r9",
    "r9w": "r9",
    "r9b": "r9",
}


def immediate(value):
    value = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]+h", value):
        return int(value[:-1], 16)
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"0x[0-9a-f]+", value):
        return int(value, 16)
    return None


with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
    connection.execute("pragma query_only=on")
    callees = {}
    for address in addresses:
        row = connection.execute(
            "select name from functions where rva=? limit 1",
            (str(address - 0x140000000),),
        ).fetchone()
        if not row:
            raise RuntimeError("Missing native task constructor at " + hex(address))
        callees[row[0].replace("::", "__")] = address
        callees["sub_" + f"{address:X}"] = address
        callees["func_" + f"{address:X}"] = address
    entries, unresolved = [], []
    for name, address, prototype, assembly in connection.execute(
        "select name,address,prototype,assembly from functions "
        "where cast(rva as integer) between ? and ?",
        (0x20E0000, 0x2360000),
    ):
        constants = {}
        lines = (assembly or "").splitlines()
        for index, source in enumerate(lines):
            line = source.split(";", 1)[0].strip()
            if not line or line.endswith(":"):
                constants.clear()
                continue
            parts = line.split(None, 1)
            instruction = parts[0].lower()
            operands = (
                [v.strip() for v in parts[1].split(",")] if len(parts) == 2 else []
            )
            if instruction == "call":
                constructor = callees.get(operands[0] if operands else "")
                if constructor:
                    service_reg, task_reg = addresses[constructor]
                    service, task = constants.get(service_reg), constants.get(task_reg)
                    proof = {
                        "name": name,
                        "address": int(address),
                        "prototype": prototype,
                        "constructor": constructor,
                        "assembly_line": index + 1,
                        "assembly": "\n".join(lines[max(0, index - 18) : index + 1]),
                    }
                    if service is not None and task is not None:
                        entries.append(
                            {**proof, "service": service & 255, "task": task & 255}
                        )
                    else:
                        unresolved.append(proof)
                constants.clear()
            elif instruction.startswith("j") or instruction in ("ret", "retn"):
                constants.clear()
            elif operands and operands[0] in registers:
                destination = registers[operands[0]]
                value = None
                if instruction == "mov" and len(operands) == 2:
                    value = immediate(operands[1])
                    if value is None:
                        value = constants.get(registers.get(operands[1]))
                elif (
                    instruction == "xor"
                    and len(operands) == 2
                    and operands[0] == operands[1]
                ):
                    value = 0
                constants.pop(destination, None)
                if value is not None:
                    constants[destination] = value

result = {
    "schema": 2,
    "database": str(database),
    "database_size": database.stat().st_size,
    "database_mtime_ns": database.stat().st_mtime_ns,
    "method": "constant register definitions within native assembly basic blocks; no name-based task inference",
    "entries": entries,
    "unresolved_constructor_calls": unresolved,
}
(root / "data" / "native-service-inventory.json").write_text(
    json.dumps(result, indent=2) + "\n"
)
print(
    "Proven calls:",
    len(entries),
    "Distinct service/task pairs:",
    len({(r["service"], r["task"]) for r in entries}),
    "Unresolved calls:",
    len(unresolved),
)
