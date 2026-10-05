"""Read native Replay virtual table entries and their same-build function records."""

import argparse, json, sqlite3, struct
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("addresses", nargs="+", type=lambda s: int(s, 0))
p.add_argument("--entries", type=int, default=4)
p.add_argument("--output", required=True, type=Path)
a = p.parse_args()
if not 1 <= a.entries <= 16:
    raise ValueError("Bounded virtual table size required")
binary = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
database = binary.with_suffix(".exe.sqlite")
with binary.open("rb") as stream:
    stream.seek(0x3C)
    pe = struct.unpack("<I", stream.read(4))[0]
    stream.seek(pe)
    header = stream.read(24)
    if header[:4] != b"PE\0\0":
        raise ValueError("Not PE")
    count = struct.unpack_from("<H", header, 6)[0]
    optional_size = struct.unpack_from("<H", header, 20)[0]
    optional = stream.read(optional_size)
    base = struct.unpack_from("<Q", optional, 24)[0]
    sections = []
    for _ in range(count):
        section = stream.read(40)
        size, rva, rawsize, raw = struct.unpack_from("<IIII", section, 8)
        sections.append((rva, rawsize, raw))
    tables = []
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        connection.execute("pragma query_only=on")
        for address in a.addresses:
            rva = address - base if address >= base else address
            section = next(
                s
                for s in sections
                if s[0] <= rva and rva + a.entries * 8 <= s[0] + s[1]
            )
            stream.seek(section[2] + rva - section[0])
            targets = struct.unpack("<" + "Q" * a.entries, stream.read(a.entries * 8))
            methods = []
            for i, target in enumerate(targets):
                row = connection.execute(
                    "select name,address,rva,prototype,pseudocode,assembly from functions where rva=? limit 1",
                    (str(target - base),),
                ).fetchone()
                method = (
                    dict(
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
                    if row
                    else {"address": str(target)}
                )
                method["slot"] = i
                methods.append(method)
                print(hex(base + rva), i, hex(target), method.get("name", "unmapped"))
            tables.append({"address": hex(base + rva), "methods": methods})
a.output.write_text(
    json.dumps(
        {"binary": str(binary), "database": str(database), "tables": tables}, indent=2
    )
    + "\n"
)
