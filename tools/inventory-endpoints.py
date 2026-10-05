"""Inventory endpoint candidates in the pinned image; call-site recovery is pending."""

import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
game = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
image = game.read_bytes()
expected = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
if hashlib.sha256(image).hexdigest() != expected:
    raise RuntimeError("Replay input does not match the reviewed build")
pe = struct.unpack_from("<I", image, 0x3C)[0]
count, optional = (
    struct.unpack_from("<H", image, pe + 6)[0],
    struct.unpack_from("<H", image, pe + 20)[0],
)
sections = []
for i in range(count):
    at = pe + 24 + optional + i * 40
    size, rva, raw_size, raw_at = struct.unpack_from("<IIII", image, at + 8)
    sections.append((rva, raw_size, raw_at))


def rva_for(at):
    for rva, size, raw in sections:
        if raw <= at < raw + size:
            return rva + at - raw
    return None


match = re.compile(
    r"demonware\.(?:net|cn)|activision\.com|callofduty\.com|battle\.net|blizzard\.com|cod\.qq\.com",
    re.I,
)
rows = []
for encoding, pattern in [
    ("ascii", rb"[\x20-\x7e]{8,16384}"),
    ("utf16", rb"(?:[\x20-\x7e]\x00){8,16384}"),
]:
    for item in re.finditer(pattern, image):
        text = item.group().decode("ascii" if encoding == "ascii" else "utf-16le")
        if not match.search(text):
            continue
        if "auth3" in text:
            role = "authentication"
        elif "loginqueue" in text:
            role = "loginqueue"
        elif "-lobby." in text:
            role = "lobby"
        elif "umbrella." in text or ".umbrella." in text:
            role = "umbrella"
        elif "uno." in text or ".uno." in text:
            role = "uno"
        elif "objectstore." in text:
            role = "objectstore"
        elif "stun." in text:
            role = "discovery"
        elif "pipes-" in text or text == "ae.demonware.net":
            role = "telemetry"
        else:
            role = "platform-or-diagnostic-review"
        rows.append(
            {
                "rva": rva_for(item.start()),
                "encoding": encoding,
                "text": text,
                "role": role,
                "runtime_template": "%s" in text or "${" in text,
                "coverage": (
                    "configuration-getter route only; call-site coverage pending"
                    if role in ("authentication", "lobby")
                    else "inventory-only"
                ),
            }
        )
output = ROOT / "data" / "endpoint-inventory.json"
output.parent.mkdir(exist_ok=True)
output.write_text(
    json.dumps(
        {
            "schema": 1,
            "image_sha256": expected,
            "strings": rows,
            "note": "String inventory identifies candidates, not proof that each is an active network destination. Runtime URL coverage is incomplete.",
        },
        indent=2,
    )
    + "\n"
)
print("Endpoint-related string records:", len(rows), "->", output)
