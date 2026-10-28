"""Assemble the parser proof tools/test-replay-quest-earning.py consumes.

Every case is produced by executing the original Replay ProcessParams
(tools/research-challenge-event-parser.py's emulator); nothing is encoded by a
backend. Inputs: the regenerated base, target-mask and mode packet proofs, plus
three cases whose earlier research inputs were pruned:
  modifier_none      kill with both modifier words zero (fields 2, 3)
  longshot_hybrid3   Longshot (262144) with the hybrid3 attachment
  buy_teamrevive     buy_item, category teamrevive (3), item teamrevive (7)

  python tools/research-quest-earning-parser-proof.py --output data/mission-parser-20261027/quest-earning-parser.json
"""

import argparse
import hashlib
import json
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, nargs="+", default=[
        ROOT / "data/mission-parser-20261027/mode.json",
        ROOT / "data/mission-parser-20261027/base.json",
        ROOT / "data/remaining-destruction-20261010/challenge-parser-verified.json"])
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.is_relative_to(ROOT)
    cases = {}
    for path in args.inputs:
        proof = json.loads(path.read_bytes())
        assert proof["target_image_sha256"] == IMAGE_SHA
        for row in proof["cases"]:
            if "fixture_label" in row and row.get("accepted", True):
                cases.setdefault(row["fixture_label"], row)
    # Reuse the base tool's emulator. Its module body writes its own proof to
    # --output; direct that to a scratch file beside ours.
    saved = sys.argv
    sys.argv = [str(ROOT / "tools/research-challenge-event-parser.py"),
                "--output", str(output.with_name(output.stem + "-base-rerun.json"))]
    try:
        base = runpy.run_path(str(ROOT / "tools/research-challenge-event-parser.py"))
    finally:
        sys.argv = saved
    native, kill_input = base["case"], base["kill_input"]

    def add(label, name, params, check):
        row = native(name, params)
        assert row["accepted"] and check(row["values"]), (label, row)
        row["fixture_label"] = label
        cases[label] = row

    plain = kill_input("iw8_ar_mike4_mp").replace(",3,4,", ",0,0,", 1)
    add("modifier_none", "kill", plain, lambda v: v[1] == 0 and v[0] & 0xFFFF == 15)
    hybrid = kill_input("iw8_ar_mike4_mp", "hybrid3").replace(",3,4,", ",262144,0,", 1)
    add("longshot_hybrid3", "kill", hybrid,
        lambda v: v[1] == 262144 and v[5] & 255 == 1 and v[3] & 0xFFF == 28)
    add("buy_teamrevive", "buy_item", "teamrevive,teamrevive, ", lambda v: v[0] == 3 and v[1] == 7)

    # Kill producer tokens (see kill_input): 2/3 modifier words, 4 operators,
    # 5 game type, 6 attachments, 7 perks, 8 target type, 11 cause, 12 loot
    # rarity, 13 circle index. Modifier bits are ReplayKillModifier's.
    def kill(weapon="iw8_ar_mike4_mp", low=0, high=0, mode=6, attachments="no_attachments",
             perks="no_perks", target=1, cause="MOD_RIFLE_BULLET", rarity=0, circle=0):
        tokens = kill_input(weapon, attachments, cause, target, perks).split(",")
        tokens[2], tokens[3], tokens[5] = str(low), str(high), str(mode)
        tokens[12], tokens[13] = str(rarity), str(circle)
        return ",".join(tokens)

    ADS, LONGSHOT, POINTBLANK, SECONDARY = 8, 262144, 524288, 131072
    FIRSTBLOOD, QUADFEED = 33554432, 536870912
    KINGSLAYER_HIGH, VICTIM_DOWN_HIGH, ATTACKER_DOWN_HIGH = 4, 2048, 1024
    for label, low, high in (("modifier_ads", ADS, 0), ("modifier_longshot", LONGSHOT, 0),
                             ("modifier_pointblank", POINTBLANK, 0), ("modifier_firstblood", FIRSTBLOOD, 0),
                             ("modifier_quadfeed", QUADFEED, 0), ("modifier_secondary_weapon", SECONDARY, 0),
                             ("modifier_kingslayer", 0, KINGSLAYER_HIGH),
                             # The same bit value in the other mask word.
                             ("modifier_king_wrong_word", KINGSLAYER_HIGH, 0),
                             ("modifier_secondary_wrong_word", 0, SECONDARY),
                             ("modifier_victim_down_wrong_word", VICTIM_DOWN_HIGH, 0)):
        add(label, "kill", kill(low=low, high=high), lambda v, low=low, high=high: v[1] == low | (high << 32))
    for label, low, optic in (("ads_acog", ADS, "acog"), ("ads_reflex", ADS, "reflex"),
                              ("ads_thermal", ADS, "thermal"), ("longshot_reflex", LONGSHOT, "reflex"),
                              ("longshot_thermal", LONGSHOT, "thermal")):
        add(label, "kill", kill(low=low, attachments=optic), lambda v, low=low: v[1] == low)
    for label, weapon, low, high, expected in (
            ("fal_ads", "iw8_ar_falima_mp", ADS, 0, 21), ("fal_ads_no_flag", "iw8_ar_falima_mp", 0, 0, 21),
            ("m13_kingslayer", "iw8_ar_mcharlie_mp", 0, KINGSLAYER_HIGH, 19),
            ("m13_kingslayer_no_flag", "iw8_ar_mcharlie_mp", 0, 0, 19),
            ("oden_longshot", "iw8_ar_asierra12_mp", LONGSHOT, 0, 17),
            ("oden_longshot_no_flag", "iw8_ar_asierra12_mp", 0, 0, 17)):
        add(label, "kill", kill(weapon, low, high), lambda v, e=expected: v[0] & 0xFFFF == e)
    # Overkill aliases (perktable 2/26/44) and non-Overkill perks on secondaries.
    for prefix, weapon, klass in (("secondary_", "iw8_pi_golf21_mp", 129), ("secondary_smg_", "iw8_sm_mpapa5_mp", 5)):
        cause = "MOD_PISTOL_BULLET" if klass == 129 else "MOD_RIFLE_BULLET"
        for perk in ("specialty_twoprimaries", "specialty_munitions", "specialty_munitions_2",
                     "specialty_ghost", "perkpackage_munitions"):
            add(prefix + perk, "kill", kill(weapon, SECONDARY, perks=perk, cause=cause),
                lambda v, k=klass: v[5] >> 48 == k and v[1] == SECONDARY)
    # Battle Royale (game type 24): loot rarity, circle index and downed states.
    for rarity in (0, 1, 2, 3, 4, 5, 6, 7, 65535):
        add(f"br_rarity_{rarity}", "kill", kill(mode=24, rarity=rarity),
            lambda v, r=rarity: v[6] >> 32 & 0xFFFF == r and v[2] >> 32 == 24)
        add(f"br_rarity_equipment_{rarity}", "kill", kill(mode=24, rarity=rarity, target=64),
            lambda v: v[5] >> 16 & 0xFFFF == 64)
    for circle in (0, 1, 2, 256, 65535):
        add(f"br_circle_{circle}", "kill", kill(mode=24, circle=circle),
            lambda v, c=circle: v[6] >> 48 == c)
    add("br_victim_downed", "kill", kill(mode=24, high=VICTIM_DOWN_HIGH), lambda v: v[1] >> 32 == VICTIM_DOWN_HIGH)
    add("br_attacker_downed", "kill", kill(mode=24, high=ATTACKER_DOWN_HIGH), lambda v: v[1] >> 32 == ATTACKER_DOWN_HIGH)
    add("br_equipment_downed", "kill", kill(mode=24, high=VICTIM_DOWN_HIGH, target=64),
        lambda v: v[5] >> 16 & 0xFFFF == 64)
    # Kiosk rows from validation/20261010-replay-kiosk-purchase-layout.json,
    # plus letter-case, operator, unknown-name and cross-category inputs.
    layout = json.loads((ROOT / "validation/20261010-replay-kiosk-purchase-layout.json").read_bytes())
    for row in layout["purchases"]:
        add(row["fixture_label"], "buy_item", f"{row['category']},{row['name']}, ",
            lambda v, r=row: v[0] == r["category_id"] and v[1] == r["id"])
    add("buy_field_upgrade_case", "buy_item", "FIELDUPGRADE,SUPER_AMMO_DROP, ", lambda v: v[0] == 4 and v[1] == 8)
    add("buy_uav_operators", "buy_item", "killstreak,uav,wyatt_western|spetsnaz_eastern",
        lambda v: v[0] == 2 and v[1] == 5 and v[2] != 0)
    add("buy_unknown_item", "buy_item", "killstreak,not_a_kiosk_item, ", lambda v: True)
    add("buy_cross_category", "buy_item", "special,uav, ", lambda v: v[0] == 1 and v[1] == 5)
    # Match completion: end_match "<mode>,<outcome>,..." (stopkeyearning: 1 win,
    # 2 loss, 3 tie) and the stock start_match "<mode>" for each tested mode.
    for mode, outcome in ((6, 1), (6, 2), (6, 3), (7, 1), (25, 1), (25, 2), (26, 1)):
        add(f"complete_end_{mode}_{outcome}", "end_match", f"{mode},{outcome},0,0,0",
            lambda v, m=mode, o=outcome: v[0] & 0xFFFFFFFF == m and v[1] == o)
    for mode in (6, 7, 25, 26):
        add(f"complete_start_{mode}", "start_match", str(mode), lambda v, m=mode: v[1] == m)
    # Ground War contracts (surviving original-image receipt).
    ground = json.loads((ROOT / "validation/20261011-ground-war-mission-contracts.json").read_bytes())
    for row in ground["cases"]:
        if "fixture_label" in row:
            cases.setdefault(row["fixture_label"], row)
    document = dict(schema=1, target_image_sha256=IMAGE_SHA,
                    inputs=[dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
                            for p in args.inputs],
                    cases=list(cases.values()))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=1) + "\n")
    print(f"PASS: {len(cases)} labelled original parser cases")


if __name__ == "__main__":
    main()
