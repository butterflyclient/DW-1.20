"""Generate bot Gunsmith style data from original, target-proven Replay tables."""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
TARGET = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
EVIDENCE = Path(r"E:\replay-compiler\evidence")
TABLES = EVIDENCE / "workstation-stringtable-actsexport-fixed/mw19replay/code_post_gfx/mw19replay/code_post_gfx/assets/stringtable"
LUA = EVIDENCE / "workstation-luafile-decompiled-all"
LOCALIZE = EVIDENCE / "workstation/localize-eng-code-post-export/mw19replay/eng_code_post_gfx/assets/localize"

# Policy weights apply to signed game-authored Gunsmith pro/con icon counts.
# These values never represent movement, recoil or ballistic percentages.
STYLES = {
    "Mobility": {"MOVEMENT_SPEED": 3, "SPRINT_SPEED": 3, "ADS_MOVEMENT_SPEED": 2,
                 "ADS_RAISE_SPEED": 3, "RELOAD_QUICKNESS": 1},
    "AimingStability": {"ADS_SWAY_CONTROL": 4, "ADS_GUN_STEADINESS": 4,
                        "RECOIL_CONTROL": 1, "FLINCH_RESISTANCE": 1},
    "RecoilControl": {"RECOIL_CONTROL": 4, "ADS_RECOIL_CONTROL_WHEN_CROUCHED_OR_PRONE": 2,
                      "ADS_SWAY_CONTROL": 1},
    "Balanced": {"ADS_RAISE_SPEED": 1, "RECOIL_CONTROL": 1, "ADS_SWAY_CONTROL": 1,
                 "ADS_GUN_STEADINESS": 1, "MOVEMENT_SPEED": 1, "DAMAGE_RANGE": 1,
                 "BULLET_VELOCITY": 1, "MAGAZINE_AMMO_CAPACITY": 1, "RELOAD_QUICKNESS": 1},
    "Range": {"DAMAGE_RANGE": 3, "BULLET_VELOCITY": 3, "RECOIL_CONTROL": 2,
              "ADS_SWAY_CONTROL": 1, "ADS_GUN_STEADINESS": 1},
    "Aggressive": {"HIP_FIRE_ACCURACY": 3, "ADS_RAISE_SPEED": 3, "SPRINT_SPEED": 2,
                   "MOVEMENT_SPEED": 2, "FIRE_RATE": 1},
}


def read_catalog(tables=TABLES, lua=LUA, localize_root=LOCALIZE):
    """Reconstruct the stock Gunsmith joins; never infer effects from names."""
    sources = {}

    def read(path):
        path = Path(path)
        content = path.read_bytes()
        sources[str(path)] = hashlib.sha256(content).hexdigest()
        return content

    def one(paths):
        paths = list(paths)
        assert len(paths) == 1, paths
        return paths[0]

    def table(pattern):
        return list(csv.reader(read(one(tables.glob(pattern))).decode("utf-8-sig").splitlines()))

    verification = tables.parents[5] / "verification.json"
    assert json.loads(read(verification))["target"]["executable_sha256"] == TARGET
    csv_lua = read(lua / "luashared/csvutils.lua.1.lua").decode("utf-8")
    attachment_schema = dict((key, int(value)) for key, value in re.findall(
        r"(\w+)\s*=\s*(\d+)", csv_lua.split("CSV.MPAttachments = {", 1)[1].split("CSV.attachmentCategories", 1)[0]))
    for key, column in {"category": 2, "ref": 4, "baseRef": 5, "blockedCategory": 9,
                        "slot": 13, "acc": 14, "dam": 15, "rng": 16, "rof": 17,
                        "mob": 18, "ctl": 19, "modifierStart": 21, "modifierEnd": 28}.items():
        assert attachment_schema[key] == column, (key, attachment_schema)
    for path in ("ui/utils/attachmentutils.lua.2113.lua", "ui/utils/gunsmithutils.lua.2161.lua",
                 "ui/widgets/gunsmithdetailsmodlist.lua.2425.lua"):
        read(lua / path)
    localized = {}

    def label(reference):
        if reference not in localized:
            found = list(localize_root.glob(reference.lower() + ".*.json"))
            assert len(found) <= 1, reference
            localized[reference] = json.loads(read(found[0]))["value"] if found else reference
        return localized[reference]

    attachments, modifier_labels = {}, {}
    for row in table("mp/attachmenttable.csv.*.csv"):
        modifiers = []
        for value in row[21:29]:
            if value:
                key, signed = value.rsplit("|", 1)
                modifiers.append((key, int(signed)))
                modifier_labels[key] = label(key)
        attachments[row[4]] = dict(reference=row[4], base_ref=row[5], category=row[2],
                                   slot=row[13], blocked_category=row[9], modifiers=modifiers)
    mapping = table("mp/attachmentmap.csv.*.csv")
    columns = {reference: i for i, reference in enumerate(mapping[0])}
    map_rows = {row[0]: row for row in mapping[1:]}
    classes = {row[1]: row for row in table("mp/weaponclasstable.csv.*.csv")}
    weapon_loot = collections.defaultdict(list)
    base_loot = {}
    for row in table("loot/weapon_ids.csv.*.csv"):
        if row[0].isdigit():
            weapon_loot[row[1]].append(int(row[0]))
            if row[6] == row[1] + "_variant_0":
                assert row[1] not in base_loot
                base_loot[row[1]] = int(row[0])

    def resolve(generic, weapon, weapon_class):
        if generic in columns:
            column = columns[generic]
            for reference in (weapon, weapon_class):
                row = map_rows.get(reference)
                if row and column < len(row) and row[column]:
                    return row[column]
        return generic

    weapons, unresolved = [], []
    for row in table("mp/statstable.csv.*.csv"):
        weapon = row[4]
        id_pattern = "loot/" + weapon + "_attachment_ids.csv.*.csv"
        progression_pattern = "mp/gunsmith/" + weapon.removeprefix("iw8_") + "_progression.csv.*.csv"
        if not weapon or not list(tables.glob(id_pattern)) or not list(tables.glob(progression_pattern)):
            continue
        allowed = set(classes[row[1]][16].split("|")) - set(row[12].split("|"))
        ids = {int(item[0]): item for item in table(id_pattern) if item[0].isdigit()}
        compatible = {}
        for progression in table(progression_pattern):
            # The stock Gunsmith loop walks four-column buckets and stops at
            # their first empty loot ID. Do not treat every nonempty cell as an ID.
            for column in range(1, len(progression), 4):
                value = progression[column]
                if not value:
                    break
                if not value.isdigit() or int(value) not in ids:
                    continue
                item = ids[int(value)]
                resolved = resolve(item[1], weapon, row[1])
                if resolved not in attachments:
                    unresolved.append(dict(weapon=weapon, generic_ref=item[1],
                                           resolved_ref=resolved, loot_id=int(value)))
                    continue
                attachment = attachments[resolved]
                if attachment["category"] not in allowed:
                    continue
                compatible[item[1]] = dict(attachment, generic_ref=item[1], loot=int(value),
                                           variant=int((item[7] if len(item) > 7 else "") or "0"))
        assert weapon in base_loot, weapon
        weapons.append(dict(reference=weapon, native_asset=row[5], weapon_class=row[1], base_loot=base_loot[weapon],
                            attachments=list(compatible.values()), loot=weapon_loot[weapon]))
    ranks = [(int(row[0]), int(row[14])) for row in table("mp/ranktable.csv.*.csv") if row[0].isdigit()]
    assert [index for index, _ in ranks] == list(range(155))
    assert all(display == index + 1 for index, display in ranks)
    return dict(weapons=weapons, modifiers=modifier_labels, ranks=ranks,
                sources=sources, unresolved=unresolved, attachment_table_rows=len(attachments))


def render(catalog):
    quoted = lambda value: json.dumps(value, ensure_ascii=True)
    modifier_keys = sorted(catalog["modifiers"])
    modifier_ids = {key: i for i, key in enumerate(modifier_keys)}
    categories = sorted({attachment[key] for weapon in catalog["weapons"]
                         for attachment in weapon["attachments"] for key in ("category", "blocked_category")})
    assert categories[0] == "" and len(categories) < 256 and len(modifier_keys) < 256
    category_ids = {key: i for i, key in enumerate(categories)}
    modifier_rows, attachment_rows, weapon_rows, loot_rows = [], [], [], []
    for weapon_index, weapon in enumerate(catalog["weapons"]):
        first = len(attachment_rows)
        for attachment in weapon["attachments"]:
            first_modifier = len(modifier_rows)
            for key, value in attachment["modifiers"]:
                assert -128 <= value <= 127
                modifier_rows.append((modifier_ids[key], value))
            scores = [sum(weights.get(key.removeprefix("ATTACHMENTS/MOD_"), 0) * value
                          for key, value in attachment["modifiers"]) for weights in STYLES.values()]
            assert all(-32768 <= score <= 32767 for score in scores)
            assert 0 <= attachment["variant"] < 256
            attachment_rows.append((attachment, first_modifier, scores))
        weapon_rows.append((weapon, first, len(attachment_rows) - first))
        loot_rows.extend((loot, weapon_index) for loot in weapon["loot"])
    assert len(attachment_rows) < 65536 and len(modifier_rows) < 65536
    assert len({loot for loot, _ in loot_rows}) == len(loot_rows)
    lines = ["#pragma once", "#include <stdint.h>", "#include <stddef.h>",
             "// Generated from pinned Replay Gunsmith rows. Signed UI icon policy, never percentages.",
             "namespace DWBotStyle {", "enum class Style : uint8_t { " + ", ".join(STYLES) + ", Count };",
             "struct Modifier { uint8_t key; int8_t value; };",
             "struct Attachment { const char *reference, *resolvedReference; uint32_t loot; uint16_t firstModifier; uint8_t modifierCount, category, blockedCategory, variant; int16_t score[6]; };",
             "struct Weapon { const char *reference, *nativeAsset, *weaponClass; uint16_t firstAttachment, attachmentCount; uint32_t baseLoot; };",
             "struct LootWeapon { uint32_t loot; uint16_t weapon; };",
             "struct Rank { uint16_t index, displayLevel; };",
             "inline constexpr const char *StyleNames[] = {" + ", ".join(map(quoted, STYLES)) + "};",
             "inline constexpr const char *ModifierKeys[] = {" + ", ".join(map(quoted, modifier_keys)) + "};",
             "inline constexpr const char *ModifierLabels[] = {" + ", ".join(quoted(catalog['modifiers'][key]) for key in modifier_keys) + "};",
             "inline constexpr const char *Categories[] = {" + ", ".join(map(quoted, categories)) + "};",
             "inline constexpr Modifier Modifiers[] = {"]
    lines.extend("    {%u, %d}," % row for row in modifier_rows)
    lines.extend(["};", "inline constexpr Attachment Attachments[] = {"])
    for attachment, first_modifier, scores in attachment_rows:
        lines.append("    {%s, %s, %u, %u, %u, %u, %u, %u, {%s}}," % (
            quoted(attachment["generic_ref"]), quoted(attachment["reference"]), attachment["loot"],
            first_modifier, len(attachment["modifiers"]), category_ids[attachment["category"]],
            category_ids[attachment["blocked_category"]], attachment["variant"], ", ".join(map(str, scores))))
    lines.extend(["};", "inline constexpr Weapon Weapons[] = {"])
    for weapon, first, count in weapon_rows:
        lines.append("    {%s, %s, %s, %u, %u, %u}," % (quoted(weapon["reference"]), quoted(weapon["native_asset"]),
                                                 quoted(weapon["weapon_class"]), first, count, weapon["base_loot"]))
    lines.extend(["};", "inline constexpr LootWeapon LootWeapons[] = {"])
    lines.extend("    {%u, %u}," % row for row in sorted(loot_rows))
    lines.extend(["};", "inline constexpr Rank Ranks[] = {"])
    lines.extend("    {%u, %u}," % row for row in catalog["ranks"])
    lines.extend(["};", "}", ""])
    return "\n".join(lines), dict(weapons=len(weapon_rows), attachments=len(attachment_rows),
                                  modifiers=len(modifier_rows), loot=len(loot_rows), ranks=len(catalog["ranks"]))


def prepare(snapshot):
    snapshot = Path(snapshot).resolve()
    if not snapshot.is_relative_to((ROOT / "data").resolve()):
        raise ValueError("Bot style data requires a private DW snapshot")
    assert json.loads((snapshot / "generated/function-catalog.json").read_bytes())["image_sha256"] == TARGET
    catalog = read_catalog()
    header, counts = render(catalog)
    # Authored selection has one canonical owner; generated arrays exist only in
    # this private job. It may be copied by the normal integration staging step.
    selector = ROOT / "integration/replay/DW_BotStyleSelection.h"
    staged = snapshot / "src/DW_BotStyleSelection.h"
    if staged.exists():
        assert staged.read_bytes() == selector.read_bytes(), "Staged selector differs from canonical owner"
    else:
        staged.write_bytes(selector.read_bytes())
    (snapshot / "src/DW_BotStyleData.h").write_bytes(header.encode("utf-8"))
    proof = dict(schema=1, image_sha256=TARGET, passed=True, counts=counts,
                 source_inputs=catalog["sources"], excluded_unresolved=catalog["unresolved"],
                 style_policy=STYLES, signed_modifier_units="Gunsmith pro/con icon counts; not gameplay percentages",
                 generic_reference_consumer="Frontend attachment setup",
                 resolved_reference_consumer="Native GScr_Weapon_ReadAttachments internalName",
                 generated_header_sha256=hashlib.sha256(header.encode()).hexdigest(),
                 selector_sha256=hashlib.sha256(selector.read_bytes()).hexdigest(),
                 generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 game_launched=False, native_runtime_verified=False)
    (snapshot / "generated/bot-style-data.json").write_text(json.dumps(proof, indent=2) + "\n")
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.snapshot)
    print(json.dumps({key: result[key] for key in ("passed", "counts", "generated_header_sha256")}, indent=2))
