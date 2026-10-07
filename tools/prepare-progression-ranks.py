"""Generate Replay player rank thresholds from its retained native StringTable."""

import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = Path(
    r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay"
    r"\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable\mp\ranktable.csv.597.csv"
)
rows = list(csv.reader(source.read_text(encoding="utf-8-sig").splitlines()))
maximum = next(int(row[1]) for row in rows if row[0] == "maxrank")
ranks = {int(row[0]): int(row[2]) for row in rows
         if row[0].isdigit() and int(row[0]) <= maximum}
assert set(ranks) == set(range(maximum + 1))
values = [ranks[index] for index in range(maximum + 1)]
assert values[0] == 0 and all(a < b for a, b in zip(values, values[1:]))
digest = hashlib.sha256(source.read_bytes()).hexdigest()
lines = [
    "#pragma once", "#include <array>", "#include <stdint.h>", "",
    "// Replay code_post_gfx mp/ranktable.csv, column 2 (minimum cumulative XP).",
    "// Retained source SHA256: " + digest,
    f"inline constexpr std::array<uint64_t, {len(values)}> replayPlayerRankMinimumXp = {{",
]
for offset in range(0, len(values), 8):
    lines.append("    " + ", ".join(map(str, values[offset:offset + 8])) + ",")
lines.extend(["};", ""])
target = ROOT / "src/progression_ranks.h"
target.write_text("\n".join(lines), encoding="utf-8")
receipt = dict(source=str(source), source_sha256=digest, native_asset="mp/ranktable.csv",
               maximum_rank=maximum, header_sha256=hashlib.sha256(target.read_bytes()).hexdigest())
(ROOT / "validation/20261006-replay-progression-ranks.json").write_text(
    json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
)
print(f"Generated {len(values)} native Replay player rank thresholds")
