"""Generate the bounded daily assignment metadata from original Replay assets."""

import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = Path(r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable")
LUA = Path(r"E:\replay-compiler\evidence\workstation-luafile-decompiled-all\luashared\csvutils.lua.1.lua")


def prepare():
    declarations, records, sources = [], [], {}
    # A local fixed assignment policy, not a recovered historical live schedule.
    for filename, kind in (("daily_challenges.csv.62.csv", 12),
                           ("br_daily_challenges.csv.5.csv", 27),
                           ("cp_daily_challenges.csv.59.csv", 30)):
        path = ASSETS / filename
        rows = list(csv.reader(path.open()))
        assert all(len(row) == 13 for row in rows)
        sources[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        for index, row in enumerate(rows[:3]):
            identity, target, xp, item = int(row[0]), int(row[4]), int(row[5]), int(row[6] or 0)
            assert 0 < identity <= 0xFFFFFFFF and 0 < target <= 0xFFFFFFFF and xp >= 0
            criterion = ("PlayerKill", "Headshot", "Melee")[index] if kind == 12 else "Pending"
            records.append(dict(id=identity, kind=kind, name=row[1], description=row[3],
                                target=target, xp=xp, item=item, criterion=criterion, fields=row))
            fields = ", ".join(json.dumps(value) for value in row)
            declarations.append(f"    {{{identity}, {kind}, {target}, {xp}, {item}, ReplayDailyCriterion::{criterion}, {{{fields}}}}},")
    lua = LUA.read_text()
    for name in ("dailyChallenges", "brDailyChallenges", "cpDailyChallenges"):
        block = lua.split("CSV." + name + " = {", 1)[1].split("\n}", 1)[0]
        for field, index in (("id", 0), ("ref", 1), ("desc", 3), ("amount", 4), ("XP", 5), ("loot", 6)):
            assert f"{field} = {index}" in block
    sources[str(LUA)] = hashlib.sha256(LUA.read_bytes()).hexdigest()
    header = '''#pragma once
#include <array>
#include <cstdint>

// Original Replay daily StringTables have thirteen columns. Keep the unknown
// columns intact; CSV's original Lua contract binds only the named accessors.
// The local assignment policy uses the first three rows per mode each UTC day.
enum class ReplayDailyCriterion { Pending, PlayerKill, Headshot, Melee };
struct ReplayDailyChallenge
{
    uint32_t id;
    uint16_t kind;
    uint32_t target, xpReward, itemReward;
    ReplayDailyCriterion criterion;
    std::array<const char *, 13> sourceFields;
    const char *name() const { return sourceFields[1]; }
    const char *description() const { return sourceFields[3]; }
};

inline constexpr std::array<ReplayDailyChallenge, 9> replayDailyChallenges = {{
'''+"\n".join(declarations)+"\n}};\n"
    (ROOT / "src/replay_daily_challenges.h").write_text(header)
    proof = dict(passed=True, sources=sources, rows=records, native_columns=13,
                 native_cache_capacity_per_kind=3, kinds=[12, 27, 30],
                 local_assignment_policy="First three original rows per mode; reset at UTC midnight",
                 exclusions=[dict(id=row["id"], name=row["name"],
                                  reason="Original action ownership/predicate not bound; pending with zero earning")
                             for row in records if row["criterion"] == "Pending"],
                 native_game_verified=False)
    destination = ROOT / "validation/20261011-replay-daily-assets.json"
    destination.write_text(json.dumps(proof, indent=2)+"\n")
    print("PASS: nine original thirteen-column daily rows and native Lua target/XP/item bindings")


if __name__ == "__main__":
    prepare()
