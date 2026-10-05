import json, sqlite3, struct, hashlib
from pathlib import Path

root = Path(__file__).resolve().parents[1]
db = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe.sqlite")
c = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
evidence = {}
for label, lo, hi in [
    ("umbrella", 0x2170800, 0x2171020),
    ("profile", 0x212BD00, 0x212D100),
]:
    evidence[label] = [
        dict(zip(["name", "rva", "prototype", "pseudocode", "assembly"], row))
        for row in c.execute(
            "select name,rva,prototype,pseudocode,assembly from functions where cast(rva as integer)>=? and cast(rva as integer)<?",
            (lo, hi),
        )
    ]
for rva in [0x2115950, 0x20F2A00, 0x20F0680, 0x20EFF30]:
    evidence[hex(rva)] = [
        dict(zip(["name", "rva", "prototype", "pseudocode", "assembly"], row))
        for row in c.execute(
            "select name,rva,prototype,pseudocode,assembly from functions where rva=?",
            (str(rva),),
        )
    ]
(root / "data" / "lobby-details-research.json").write_text(
    json.dumps(evidence, indent=2) + "\n"
)
for group, rows in evidence.items():
    for row in rows:
        print(group, hex(int(row["rva"])), row["name"])
        code = row["pseudocode"] or ""
        if group == "umbrella" or group.startswith("0x"):
            print(code)
        else:
            for line in code.splitlines():
                if (
                    "initTaskBuffer" in line
                    or "setTaskResult" in line
                    or "bdByteBuffer" in line
                ):
                    print(line)
exe = db.with_suffix("").read_bytes()
pe = struct.unpack_from("<I", exe, 0x3C)[0]
sections = struct.unpack_from("<H", exe, pe + 6)[0]
offset = pe + 24 + struct.unpack_from("<H", exe, pe + 20)[0]
rva = 0x26E82C0
for i in range(sections):
    virtual, base, size, raw = struct.unpack_from("<IIII", exe, offset + 40 * i + 8)
    if base <= rva < base + size:
        data = exe[raw + rva - base : raw + rva - base + 294]
        break
else:
    raise ValueError("KDF constant outside image")
assert len(data) == 294
(root / "data" / "replay-traffic-kdf.bin").write_bytes(data)
(root / "src" / "traffic_kdf.h").write_text(
    "#pragma once\n#include <array>\nnamespace lobby {\ninline constexpr std::array<unsigned char,294> trafficKdfInfo = {\n"
    + "\n".join(
        "    " + ",".join(f"0x{x:02x}" for x in data[i : i + 16]) + ","
        for i in range(0, 294, 16)
    )
    + "\n};\n}\n"
)
print("KDF evidence:", hex(rva), hashlib.sha256(data).hexdigest())
