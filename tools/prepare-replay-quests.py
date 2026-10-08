"""Generate native Replay mission metadata from the verified quest StringTable."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = Path(
    r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay"
    r"\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable\quest_challenges.csv.707.csv"
)


def build(rows):
    identities, names, missions = set(), set(), {}
    quests = []
    for row in rows:
        if len(row) != 19:
            raise ValueError("Replay quest StringTable must have 19 columns")
        if row[5] not in {"ALL", "BR", "CP"}:
            continue
        # Original 1410627A0 loads precisely these mission modes and columns.
        matched = re.fullmatch(r"ch_quest(\d+)_stage(\d+)", row[1])
        identity, target, category = int(row[0]), int(row[6]), int(row[16])
        if (
            not matched
            or not 0 < identity <= 0xFFFFFFFF
            or not 0 < target <= 0xFFFFFFFF
        ):
            raise ValueError("Replay mission ID, target or name is invalid")
        mission, stage = map(int, matched.groups())
        if not (1 <= mission <= 128 and 1 <= stage <= 32):
            raise ValueError("Replay mission stages exceed native bounds")
        if category != {"ALL": 0, "BR": 1, "CP": 4}[row[5]]:
            raise ValueError("Replay mission mode/category mismatch")
        if identity in identities or row[1] in names:
            raise ValueError("Duplicate Replay mission ID or name")
        identities.add(identity)
        names.add(row[1])
        stages = missions.setdefault(mission, {})
        if stage in stages:
            raise ValueError("Duplicate Replay mission stage")
        stages[stage] = row
        if len(row[1]) > 100 or len(row[3]) > 250:
            raise ValueError("Replay mission text exceeds native result bounds")
        quests.append(
            dict(
                id=identity,
                target=target,
                category=category,
                name=row[1],
                description=row[3],
            )
        )
    for stages in missions.values():
        if set(stages) != set(range(1, max(stages) + 1)):
            raise ValueError("Replay mission stage chain has a gap")
        for stage, row in stages.items():
            if row[7] != (stages[stage + 1][1] if stage < max(stages) else ""):
                raise ValueError("Replay mission stage chain differs from the asset")
    return sorted(quests, key=lambda row: row["id"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--native-observation", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "src/replay_quest_data.h")
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    rows = list(csv.reader(args.source.read_text(encoding="utf-8-sig").splitlines()))
    observed = json.loads(args.native_observation.read_bytes())
    table = observed["native_quest_table"]
    if not (
        table["name"] == "quest_challenges.csv"
        and table["columns"] == 19
        and table["row_count"] == len(rows)
        and table["rows"] == rows
    ):
        raise ValueError("Retained quest data differs from the loaded native asset")
    quests = build(rows)
    source_hash = hashlib.sha256(args.source.read_bytes()).hexdigest()
    lines = [
        "#pragma once",
        "#include <array>",
        "#include <stdint.h>",
        "",
        "// Native Replay quest_challenges.csv: ID/name/description/target/category.",
        "// Original 1410627A0 selects ALL, BR and CP mission stage chains.",
        "// Retained asset SHA256: " + source_hash,
        "struct ReplayQuest",
        "{",
        "    uint32_t id, target, category;",
        "    const char *name, *description;",
        "};",
        "",
        f"inline constexpr std::array<ReplayQuest, {len(quests)}> replayQuests = {{{{",
    ]
    for quest in quests:
        lines.append(
            "    {%d, %d, %d, %s, %s},"
            % (
                quest["id"],
                quest["target"],
                quest["category"],
                json.dumps(quest["name"]),
                json.dumps(quest["description"]),
            )
        )
    lines.extend(["}};", ""])
    args.output.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    receipt = dict(
        schema=1,
        source=str(args.source.resolve()),
        source_sha256=source_hash,
        native_asset="quest_challenges.csv",
        native_rows=len(rows),
        native_game_sha256=observed["sha256"],
        native_pid=observed["pid"],
        native_observation_sha256=hashlib.sha256(
            args.native_observation.read_bytes()
        ).hexdigest(),
        all_native_rows_match=True,
        supported_mission_stages=len(quests),
        header_sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
        supported_modes=["ALL", "BR", "CP"],
        excluded_modes=["OPERATOR", "INTEL", "PS4"],
        completion_rules_reconstructed=False,
        quests=quests,
    )
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", newline="\n")
    print(
        f"Generated {len(quests)} native Replay mission stages; all {len(rows)} asset rows match"
    )


if __name__ == "__main__":
    main()
