"""Read Replay clan virtual serializers from the verified rebuilt image.

The linker symbol map resolves shifted tables and function pointers. The
original VA alias then selects exact target pseudocode; no source-build RVAs
are transferred, and this tool writes no executable/database bytes.
"""

import hashlib, json, re, sqlite3, struct
from pathlib import Path
import pefile

root = Path(__file__).resolve().parents[1]
deployment = json.loads((root / "data/deployment.json").read_text())
image = Path(deployment["executable"])
assert hashlib.sha256(image.read_bytes()).hexdigest() == deployment["sha256"]
build = json.loads(
    (Path(deployment["build_directory"]) / "build-report.json").read_text()
)
symbols = build["symbols"]
aliases = {}
for name, rva in symbols.items():
    aliases.setdefault(rva, []).append(name)
pe = pefile.PE(str(image), fast_load=True)
db = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
named = json.loads((root / "data/native-clan-all-functions.json").read_text())[
    "functions"
]
tables = {}
for row in named:
    text = row["pseudocode"] or ""
    for table in re.findall(r"\*\(_QWORD \*\)a1 = off_([0-9A-F]+);", text):
        tables.setdefault(table, []).append(row["name"])
result = []
functions = {}
with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
    for table, names in sorted(tables.items()):
        label = "gl_" + table
        if label not in symbols:
            continue
        entries = struct.unpack("<4Q", pe.get_data(symbols[label], 32))
        resolved = []
        for index, va in enumerate(entries):
            rva = va - pe.OPTIONAL_HEADER.ImageBase
            names_at = aliases.get(rva, [])
            candidates = [n for n in names_at if re.fullmatch("func_[0-9A-Fa-f]+", n)]
            row = None
            if candidates:
                address = int(candidates[0][5:], 16)
                row = connection.execute(
                    "select name,address,rva,prototype,pseudocode,assembly from functions where rva=? limit 1",
                    (str(address - 0x140000000),),
                ).fetchone()
            if row is None:
                for name in names_at:
                    row = connection.execute(
                        "select name,address,rva,prototype,pseudocode,assembly from functions where name=? limit 1",
                        (name,),
                    ).fetchone()
                    if row:
                        break
            entry = {"index": index, "linked_rva": rva, "aliases": names_at[:8]}
            if row:
                function = dict(
                    zip(
                        (
                            "name",
                            "address",
                            "rva",
                            "prototype",
                            "pseudocode",
                            "assembly",
                        ),
                        row,
                    )
                )
                entry["original_va"] = hex(int(row[1]))
                functions[row[1]] = function
            resolved.append(entry)
        result.append(
            {
                "table": label,
                "linked_rva": symbols[label],
                "constructor_names": names,
                "entries": resolved,
            }
        )
out = root / "data/native-clan-vtables.json"
out.write_text(
    json.dumps(
        {
            "database": str(db),
            "image": str(image),
            "sha256": deployment["sha256"],
            "tables": result,
            "functions": list(functions.values()),
        },
        indent=2,
    )
    + "\n"
)
print("Resolved", len(result), "tables and", len(functions), "same-Replay functions")
for table in result:
    print(
        table["table"],
        table["constructor_names"],
        [(e["index"], e.get("original_va")) for e in table["entries"]],
    )
