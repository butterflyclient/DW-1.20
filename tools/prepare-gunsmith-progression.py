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
    receipt = dict(schema=1, passed=True, catalog_path=str(destination.relative_to(ROOT)),
                   catalog_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
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


if __name__ == "__main__":
    main()
