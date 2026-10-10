"""Recover the complete shipped Gunsmith rank/challenge graph, without granting it."""

import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = Path(r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay"
              r"\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable")
LUA = Path(r"E:\replay-compiler\evidence\workstation-luafile-decompiled-all")


def main():
    inputs = {}
    def read(path):
        raw = path.read_bytes()
        inputs[str(path)] = hashlib.sha256(raw).hexdigest()
        return raw.decode("utf-8-sig")
    def rows(path):
        return list(csv.reader(read(path).splitlines()))
    csv_lua = read(LUA / "luashared/csvutils.lua.1.lua")
    ui_lua = read(LUA / "ui/utils/progressionutils.lua.2223.lua")
    start = csv_lua.index("CSV.gunsmithProgressionTable = {")
    layout = csv_lua[start:csv_lua.index("CSV.fontIcons", start)]
    assert "colOffset = 4" in layout
    for name, column in (("level", 0), ("lootID", 1), ("challengeID", 2),
                         ("challengeRef", 3), ("bucketID", 4)):
        assert f"{name} = {column}" in layout
    assert "return tonumber(var_47_4) + 1" in ui_lua
    challenge_start = csv_lua.index("CSV.gunsmithChallenges = {")
    challenge_layout = csv_lua[challenge_start:csv_lua.index("CSV.reticleChallenges", challenge_start)]
    for name, column in (("id", 0), ("ref", 1), ("amount", 4), ("loot", 5), ("XPReward", 6)):
        assert f"{name} = {column}" in challenge_layout
    def numbers(value):
        if not value:
            return []
        parts = value.split("|")
        assert all(p.isdigit() and 0 <= int(p) <= 2**31 - 1 for p in parts)
        return list(map(int, parts))
    challenges = {}
    for row in rows(next(ASSETS.glob("gs_challenges.csv.*.csv"))):
        assert len(row) == 7 and row[0].isdigit()
        key = int(row[0])
        assert key not in challenges
        amounts, loot, xp = map(numbers, row[4:7])
        assert all(x > 0 for x in amounts + loot)
        assert len(amounts) in (0, 1, 9)
        if amounts:
            assert len(xp) == len(amounts) and (not loot or len(loot) == len(amounts))
            assert all(a < b for a, b in zip(amounts, amounts[1:]))
        else:
            assert len(loot) == 1 and not xp
        challenges[key] = dict(id=key, reference=row[1], display_name=row[2],
                               display_condition=row[3], amounts=amounts,
                               reward_items=loot, xp_rewards=xp,
                               aggregate_rule_unresolved=not amounts,
                               retained_columns=row)
    weapon_rows = rows(next(ASSETS.glob("loot/weapon_ids.csv.*.csv")))
    weapons, refs, blocks = [], set(), []
    rank_items, referenced_challenges = set(), set()
    for weapon in weapon_rows:
        weapon_id, reference = int(weapon[0]), weapon[1]
        if reference in refs:
            continue
        refs.add(reference)
        candidates = list((ASSETS / "mp/gunsmith").glob(reference[4:] + "_progression.csv.*.csv"))
        assert len(candidates) == 1
        table = rows(candidates[0])
        levels = []
        for row_number, row in enumerate(table):
            assert len(row) >= 5 and (len(row) - 1) % 4 == 0 and row[0].lstrip("-").isdigit()
            rank = int(row[0])
            assert rank >= -1
            levels.append(rank)
            for column in range(1, len(row), 4):
                loot, challenge_id, challenge_ref, bucket = row[column:column + 4]
                if not any((loot, challenge_id, challenge_ref, bucket)):
                    continue
                assert loot and bucket.isdigit()
                items = [int(item) for item in loot.split("|")]
                assert all(0 < item <= 2**31 - 1 for item in items) and len(set(items)) == len(items)
                record = dict(weapon_id=weapon_id, weapon_reference=reference, rank=rank,
                              displayed_level=rank + 1, row=row_number, column=column,
                              items=items, bucket=int(bucket), challenge=None,
                              rank_activation_supported=rank >= 0)
                if challenge_id or challenge_ref:
                    assert challenge_id.isdigit() and challenge_ref
                    challenge = challenges[int(challenge_id)]
                    assert challenge["reference"] == challenge_ref
                    if challenge["reward_items"]:
                        assert challenge["reward_items"] == items
                    record["challenge"] = challenge
                    referenced_challenges.add(challenge["id"])
                else:
                    rank_items.update(items)
                blocks.append(record)
        maximum = max(levels, default=0)
        weapons.append(dict(id=weapon_id, reference=reference, maximum_rank=maximum,
                            rows=len(table), source=str(candidates[0])))
    assert len(weapons) == 51 and len(referenced_challenges) <= 1792
    out = dict(schema=1, inputs=inputs, weapons=weapons, blocks=blocks,
               rank_unlock_item_count=len(rank_items), challenge_count=len(referenced_challenges),
               complete_challenge_table=list(challenges.values()),
               native_gunsmith_challenge_capacity=1792, native_controller_zero_inventory_capacity=15000,
               semantics=dict(columns="level followed by repeated lootID/challengeID/challengeRef/bucketID groups",
                              rank_to_displayed_level="rank + 1",
                              unconditional="No challenge ID or reference in the block",
                              conditional="Challenge table ID/reference/target bind; condition display text is not an event rule"),
               backend_rewards_implemented=False, native_game_verified=False)
    destination = ROOT / "data/replay-gunsmith-progression.json"
    destination.write_text(json.dumps(out, indent=2) + "\n")
    rank_unlocks = sorted({(b["weapon_id"], b["rank"], item) for b in blocks
                           if b["challenge"] is None and b["rank_activation_supported"]
                           for item in b["items"]})
    header = ["#pragma once", "#include <array>", "#include <cstdint>", "",
              "// Generated from complete four-column groups in shipped Replay Gunsmith tables.",
              "// Challenge-dependent and negative-gate groups are deliberately excluded.",
              "struct ReplayRankUnlock", "{", "    uint16_t weapon, rank;", "    uint32_t item;", "};", "",
              f"inline constexpr std::array<ReplayRankUnlock, {len(rank_unlocks)}> replayRankUnlocks = {{{{"]
    header.extend(f"    {{{weapon}, {rank}, {item}}}," for weapon, rank, item in rank_unlocks)
    header.extend(["}};", ""])
    # Native UI unlocks are inventory-backed, including rank-selected local
    # profiles. Keep the complete shipped initial/player-rank publication.
    player_rows = rows(next(ASSETS.glob("mp/progression/progressionitems.csv.*.csv")))
    assert len(player_rows) == 55 and [int(row[0]) for row in player_rows] == list(range(55))
    player_unlocks = sorted({(int(row[0]), int(item))
        for index, row in enumerate(player_rows)
        for item in row[2:34 if index == 0 else 9] if item})
    initial_items = sorted({int(row[0])
        for row in rows(next(ASSETS.glob("mp/progression/initialitems.csv.*.csv"))) if row[0]})
    assert all(0 < item <= 2**31 - 1 for _, item in player_unlocks)
    assert all(0 < item <= 2**31 - 1 for item in initial_items)
    header.extend(["struct ReplayPlayerRankUnlock", "{", "    uint16_t rank;", "    uint32_t item;", "};", "",
        f"inline constexpr std::array<ReplayPlayerRankUnlock, {len(player_unlocks)}> replayPlayerRankUnlocks = {{{{"])
    header.extend(f"    {{{rank}, {item}}}," for rank, item in player_unlocks)
    header.extend(["}};", "", f"inline constexpr std::array<uint32_t, {len(initial_items)}> replayInitialItems = {{{{"])
    header.extend(f"    {item}," for item in initial_items)
    header.extend(["}};", ""])
    header_path = ROOT / "src/gunsmith_rank_unlock_data.h"
    header_path.write_text("\n".join(header))
    receipt = dict(schema=1, passed=True, catalog_path=str(destination.relative_to(ROOT)),
                   catalog_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
                   header_path=str(header_path.relative_to(ROOT)),
                   header_sha256=hashlib.sha256(header_path.read_bytes()).hexdigest(),
                   compiled_rank_unlock_count=len(rank_unlocks),
                   compiled_player_rank_unlock_count=len(player_unlocks),
                   compiled_initial_item_count=len(initial_items),
                   tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   inputs=inputs, weapon_count=len(weapons), block_count=len(blocks),
                   unconditional_blocks=sum(b["challenge"] is None for b in blocks),
                   conditional_blocks=sum(b["challenge"] is not None for b in blocks),
                   externally_gated_blocks=sum(not b["rank_activation_supported"] for b in blocks),
                   rank_unlock_item_count=len(rank_items), challenge_count=len(referenced_challenges),
                   backend_rewards_implemented=False, native_game_verified=False)
    (ROOT / "validation/20261007-gunsmith-progression-assets.json").write_text(
        json.dumps(receipt, indent=2) + "\n")
    print(f"PASS: {len(weapons)} weapons, {len(blocks)} complete reward blocks, "
          f"{len(rank_items)} rank items and {len(referenced_challenges)} bound challenges")


def prepare_local_reset(snapshot):
    """Bind the stock full-stat reset, persistence and queued command consumers."""
    import importlib.util
    import sys
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM

    snapshot = snapshot.resolve()
    assert snapshot.is_relative_to(ROOT / "data")
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    raw = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == catalog["image_sha256"]
    pe = pefile.PE(data=raw, fast_load=True)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True

    def named(name):
        rows = [r for r in catalog["functions"] if name in (r["name"], *r["aliases"])
                and not r.get("quarantined")]
        assert len(rows) == 1, name
        return rows[0]

    lua_reset = named("LUI_CoD_LuaCall_StatsResetProceed")
    code = pe.get_data(lua_reset["rva"], 160)
    calls = [i.operands[0].imm - pe.OPTIONAL_HEADER.ImageBase
             for i in decoder.disasm(code, pe.OPTIONAL_HEADER.ImageBase + lua_reset["rva"])
             if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM]
    reset = named("sub_1412A39C0")
    assert calls.count(reset["rva"]) == 1
    header = '''#pragma once
#include <stdint.h>
#include <stddef.h>
extern "C" {
unsigned DW_Progression_StatsSource(unsigned);
void DW_Progression_ResetStats(unsigned, unsigned);
void DW_Progression_SaveStats(unsigned);
uintptr_t DW_Progression_QueueCommand(int, const char *);
void DW_Progression_LUILock();
void DW_Progression_LUIUnlock();
int DW_Progression_LuaTop(void *);
void DW_Progression_LuaSetTop(void *, int);
void DW_Progression_LuaClosure(void *, int (*)(void *), int);
int DW_Progression_LuaLoad(void *, const char *, size_t, const char *);
int DW_Progression_LuaCall(void *, int, int, int);
}
'''
    (snapshot / "src/DW_ProgressionBindings.h").write_text(header)
    spec = importlib.util.spec_from_file_location("private_progression_catalog", snapshot / "tools/source_catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(snapshot / "tools"))
    spec.loader.exec_module(module)
    bindings = []
    for alias, name in (("DW_Progression_StatsSource", "q_LiveStorage_GetActiveStatsSource"),
                        ("DW_Progression_ResetStats", "sub_1412A39C0"),
                        ("DW_Progression_SaveStats", "sub_1412A3D60"),
                        ("DW_Progression_QueueCommand", "sub_1415C1C20"),
                        ("DW_Progression_LUILock", "sub_1419BDAD0"),
                        ("DW_Progression_LUIUnlock", "q_LUI_LeaveCriticalSection"),
                        ("DW_Progression_LuaTop", "lua_gettop"),
                        ("DW_Progression_LuaSetTop", "q_j_lua_settop"),
                        ("DW_Progression_LuaClosure", "sub_142083EB0"),
                        ("DW_Progression_LuaLoad", "luaL_loadbuffer"),
                        ("DW_Progression_LuaCall", "sub_142083DA0")):
        row = named(name)
        module.bind_import(row["id"], alias)
        bindings.append(dict(symbol=alias, identity=row["id"]))
    result = dict(passed=True, image_sha256=catalog["image_sha256"], bindings=bindings,
                  stock_reset_lua_call_sha256=hashlib.sha256(code).hexdigest(),
                  header_sha256=hashlib.sha256(header.encode()).hexdigest(), game_launched=False)
    (snapshot / "generated/progression-reset-integration.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    main()
