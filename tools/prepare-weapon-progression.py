"""Generate Replay weapon IDs/rank limits from its retained native asset tables."""

import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = Path(r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay"
              r"\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable")
LUA = Path(r"E:\replay-compiler\evidence\workstation-luafile-decompiled-all")
weapon_file = ASSETS / "loot/weapon_ids.csv.235.csv"
rank_file = ASSETS / "mp/weaponranktable.csv.627.csv"
inputs = {}


def rows(path):
    inputs[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return list(csv.reader(path.read_text(encoding="utf-8-sig").splitlines()))


weapon_rows = rows(weapon_file)
assert len(weapon_rows) == 680 and all(len(row) == 7 for row in weapon_rows)
rank_rows = rows(rank_file)
assert len(rank_rows) == 101 and all(len(row) == 4 for row in rank_rows)
minimums = [int(row[1]) for row in rank_rows]
assert [int(row[0]) for row in rank_rows] == list(range(101))
assert minimums[0] == 0 and all(a < b for a, b in zip(minimums, minimums[1:]))
assert all(int(row[3]) == minimums[i] + int(row[2]) for i, row in enumerate(rank_rows))
definitions, aliases = {}, {}
for row in weapon_rows:
    weapon_id, ref = int(row[0]), row[1]
    assert 0 < weapon_id <= 10000 and weapon_id not in aliases
    assert ref.startswith("iw8_") and all(c.isalnum() or c == "_" for c in ref)
    if ref not in definitions:
        paths = list((ASSETS / "mp/gunsmith").glob(ref[4:] + "_progression.csv.*.csv"))
        assert len(paths) == 1, ref
        progression = rows(paths[0])
        assert all(len(p) >= 6 for p in progression)
        levels = [int(p[0]) for p in progression if p[0].isdigit()]
        maximum = max(levels, default=0)
        assert maximum < len(minimums)
        definitions[ref] = dict(id=weapon_id, ref=ref, maximum_rank=maximum,
                                progression_rows=len(progression), source=str(paths[0]))
    aliases[weapon_id] = definitions[ref]["id"]
assert len(definitions) == 51 and len(definitions) <= 64
for path in (LUA / "luashared/csvutils.lua.1.lua", LUA / "ui/utils/progressionutils.lua.2223.lua"):
    inputs[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
csv_lua = (LUA / "luashared/csvutils.lua.1.lua").read_text()
ui_lua = (LUA / "ui/utils/progressionutils.lua.2223.lua").read_text()
assert 'file = "mp/weaponRankTable.csv"' in csv_lua and 'minXP = 1' in csv_lua
assert 'fileRoot = "mp/gunsmith/"' in csv_lua and 'fileSuffix = "_progression.csv"' in csv_lua
assert 'return var_40_1 + 1' in ui_lua and '.rank + 1' in ui_lua
lines = ["#pragma once", "#include <array>", "#include <cstdint>", "#include <string_view>", "",
         "// Generated from retained Replay loot IDs, native rank table and per-weapon progression.",
         "// Minimum XP is native CSV column 1; rank limits match PROGRESSION.GetMaxWeaponLevel.",
         "struct ReplayWeaponProgression", "{", "    uint16_t id, maximumRank;",
         "    std::string_view reference;", "};", "",
         f"inline constexpr std::array<ReplayWeaponProgression, {len(definitions)}> replayWeapons = {{{{"]
for d in definitions.values():
    lines.append(f'    {{{d["id"]}, {d["maximum_rank"]}, "{d["ref"]}"}},')
lines += ["}};", "", f"inline constexpr std::array<uint16_t, {max(aliases) + 1}> replayWeaponAliases = {{"]
for offset in range(0, max(aliases) + 1, 16):
    lines.append("    " + ", ".join(str(aliases.get(i, 0)) for i in
                                   range(offset, min(offset + 16, max(aliases) + 1))) + ",")
lines += ["};", "", "inline constexpr std::array<uint64_t, 101> replayWeaponMinimumXp = {"]
for offset in range(0, len(minimums), 8):
    lines.append("    " + ", ".join(map(str, minimums[offset:offset + 8])) + ",")
lines += ["};", ""]
target = ROOT / "src/weapon_progression_data.h"
target.write_text("\n".join(lines))
receipt = dict(schema=1, inputs=inputs, canonical_weapons=list(definitions.values()),
               aliases={str(k): v for k, v in aliases.items()}, minimum_xp=minimums,
               header_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
               native_weapon_record_capacity=64, empty_progression_rank_limit=0,
               semantics="Native UI uses rank + 1 as level, minimum XP column 1, maximum progression level column 0; first matching loot ref is the canonical event ID",
               native_game_verified=False)
(ROOT / "validation/20261007-weapon-progression-assets.json").write_text(
    json.dumps(receipt, indent=2) + "\n")
print("Generated 51 canonical Replay weapons, 680 aliases and 101 native XP thresholds")
