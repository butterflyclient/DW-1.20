"""Publish native Battle Pass activation IDs and season rules from Replay tables."""

import argparse
import hashlib
import json
from pathlib import Path


def build(table):
    if table.get("name") != "loot/battlepass_ids.csv" or table.get("columns") != 21:
        raise ValueError("Expected Replay Battle Pass table")
    rows = table["rows"]
    if table.get("row_count") != len(rows):
        raise ValueError("Incomplete Battle Pass table")
    definitions = []
    for row in rows:
        if len(row) != 21:
            raise ValueError("Incomplete Battle Pass row")
        if row[2] not in ("0", "1"):
            continue
        item, identity, season = int(row[0]), int(row[6]), int(row[16] or 0)
        if row[2] == "0" and not (
            1 <= season <= 6
            and item == 430000 + 1000 * (season - 1)
            and identity == 3000001 + 1000 * (season - 1)
        ):
            raise ValueError("Unexpected native premium activation")
        if not row[5]:
            raise ValueError("Missing native activation event")
        # Same-Replay 0x140F350D0 routes kind 20 states to 0x140F30C60.
        # Premium activation IDs enter its native activation cache. No rank/XP
        # targets or season reward rules are synthesized here.
        state = dict(id=identity, name=row[5], kind=20, status=2, progress=0, target=0)
        definitions.append(
            {"1": row[5], "3": 20, "14": identity, "initialState": state}
        )
    if len(definitions) != 13 or len({r["14"] for r in definitions}) != 13:
        raise ValueError("Expected six premium and seven native token activations")
    return definitions


def rules(table, season_tables, current_season):
    if not 1 <= current_season <= 6:
        raise ValueError("Unsupported current season")
    activations = []
    for row in table["rows"]:
        if row[2] in ("0", "1"):
            activations.append(
                dict(
                    id=int(row[6]),
                    item=int(row[0]),
                    name=row[5],
                    season=int(row[16] or 0),
                    skips=int(row[4]),
                )
            )
    seasons = {}
    for season, data in enumerate(season_tables, 1):
        if (
            data["name"] != f"loot/battlepass_season{season}.csv"
            or data["columns"] != 11
            or data["row_count"] != 101
        ):
            raise ValueError("Incomplete native season table")
        rows = []
        for level, row in enumerate(data["rows"]):
            if len(row) != 11 or int(row[0]) != level:
                raise ValueError("Unexpected native tier")
            rows.append(
                dict(
                    rank=level,
                    xp=int(row[1]),
                    next_xp=int(row[4]),
                    items=[int(v) for v in row[2].split("|") if v and int(v) > 0],
                    free=row[3] == "1",
                    cod_points=int(row[6]),
                )
            )
        if any(a["xp"] >= b["xp"] for a, b in zip(rows, rows[1:])):
            raise ValueError("Season XP thresholds must increase")
        seasons[str(season)] = rows
    return dict(
        schema=1,
        current_season=current_season,
        activations=activations,
        seasons=seasons,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("table", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--current-season", type=int, default=3)
    args = parser.parse_args()
    raw = args.table.read_bytes()
    rows = build(json.loads(raw))
    args.output.mkdir(parents=True, exist_ok=True)
    body = (json.dumps(rows, indent=2) + "\n").encode()
    (args.output / "definitions.json").write_bytes(body)
    season_paths = [
        args.table.parent / f"loot__battlepass_season{i}.csv.json" for i in range(1, 7)
    ]
    season_data = [json.loads(p.read_bytes()) for p in season_paths]
    (args.output / "rules.json").write_text(
        json.dumps(rules(json.loads(raw), season_data, args.current_season), indent=2)
        + "\n"
    )
    (args.output / "manifest.json").write_text(
        json.dumps(
            dict(
                schema=1,
                title=5800,
                table_sha256=hashlib.sha256(raw).hexdigest(),
                definitions_sha256=hashlib.sha256(body).hexdigest(),
                rules_sha256=hashlib.sha256(
                    (args.output / "rules.json").read_bytes()
                ).hexdigest(),
                activation_ids=[r["14"] for r in rows],
                native_dispatch=hex(0x140F350D0),
                native_consumer=hex(0x140F30C60),
            ),
            indent=2,
        )
        + "\n"
    )
    print("Built thirteen native activations and all six season XP/reward tables")


if __name__ == "__main__":
    main()
