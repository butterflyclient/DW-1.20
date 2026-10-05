"""Locate MSVC x64 RTTI/vtables in the untouched Replay image, without database names."""

import argparse
import json
import struct
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("classes", nargs="+")
p.add_argument("--output", type=Path, required=True)
p.add_argument(
    "--minimum-code-entries",
    type=int,
    choices=range(1, 5),
    default=4,
    help="Required consecutive code pointers; small result classes may have only two virtual slots",
)
a = p.parse_args()
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
with image.open("rb") as f:
    f.seek(0x3C)
    pe = struct.unpack("<I", f.read(4))[0]
    f.seek(pe)
    header = f.read(24)
    assert header[:4] == b"PE\0\0"
    count = struct.unpack_from("<H", header, 6)[0]
    optional = f.read(struct.unpack_from("<H", header, 20)[0])
    base = struct.unpack_from("<Q", optional, 24)[0]
    sections = []
    for _ in range(count):
        h = f.read(40)
        vsize, rva, size, offset = struct.unpack_from("<4I", h, 8)
        sections.append((h[:8].rstrip(b"\0"), rva, size, offset))
    section = next(s for s in sections if s[0] == b".rdata")
    f.seek(section[3])
    data = f.read(section[2])
    names = []
    for s in sections:
        if s[0] not in (b".rdata", b".data"):
            continue
        f.seek(s[3])
        names.append((s[1], f.read(s[2])))

    def find_all(needle, buffer=data):
        start = 0
        while (index := buffer.find(needle, start)) >= 0:
            yield index
            start = index + 1

    tables = []
    for name in a.classes:
        for prefix in (b".?AV", b".?AU"):
            types = []
            for name_rva, buffer in names:
                types.extend(
                    name_rva + index - 16
                    for index in find_all(
                        prefix + name.encode("ascii") + b"@@\0", buffer
                    )
                )
            for type_rva in types:
                # TypeDescriptor may live in .data. Only the name lives at +16.
                for ref in find_all(struct.pack("<I", type_rva)):
                    col = ref - 12
                    if col < 0 or col + 24 > len(data):
                        continue
                    signature, offset, cd, typ, hierarchy, self_rva = (
                        struct.unpack_from("<6I", data, col)
                    )
                    if (
                        signature != 1
                        or typ != type_rva
                        or self_rva != section[1] + col
                    ):
                        continue
                    for pointer in find_all(struct.pack("<Q", base + self_rva)):
                        if (section[1] + pointer) % 8 or pointer + 40 > len(data):
                            continue
                        entries = struct.unpack_from("<4Q", data, pointer + 8)
                        code = next(s for s in sections if s[0] == b".text")
                        if not all(
                            base + code[1] <= v < base + code[1] + code[2]
                            for v in entries[: a.minimum_code_entries]
                        ):
                            continue
                        tables.append(
                            {
                                "class": name,
                                "object_offset": offset,
                                "type_descriptor": hex(base + type_rva),
                                "locator": hex(base + self_rva),
                                "vtable": hex(base + section[1] + pointer + 8),
                                "entries": [hex(v) for v in entries],
                            }
                        )
a.output.write_text(
    json.dumps({"image": str(image), "tables": tables}, indent=2) + "\n"
)
for table in tables:
    print(table)
