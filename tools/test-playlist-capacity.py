"""Exercise real selector capacity rules, including native Quick Play groups."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = ROOT / "data" / f"playlist-capacity-{time.time_ns()}"
    directory = fixture / "playlists/5800"
    shutil.copytree(ROOT / "data/playlists/5800", directory)
    catalog_path = directory / "catalog.json"
    original = json.loads(catalog_path.read_bytes())
    # Package revisions remain covered by the separate installed-header suite.
    # This fixture mutates rule values without touching any game publication.
    (directory / "packages.json").unlink(missing_ok=True)
    (directory / "policy.json").unlink(missing_ok=True)
    bindings = json.loads((directory / "native-dvar-names.json").read_bytes())
    key = bindings.get("party_maxplayers", "party_maxplayers")
    checks = []

    def query(playlist, **extra):
        return dict(
            ruleset_payload={
                "filter": {
                    "playlist_id": playlist,
                    "playlist_version": original["system"]["version"],
                }
            },
            **extra,
        )

    def run(value, reject=False):
        path = fixture / "query.json"
        path.write_text(json.dumps(value))
        result = subprocess.run(
            [str(args.executable.resolve()), str(fixture), str(path)],
            text=True,
            capture_output=True,
        )
        if reject:
            assert result.returncode == 1 and "contract rejected" in result.stderr
            return None
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)[0]

    config = [
        dict(playlist_ids=[48], max_slots=8, min_slots=8, num_teams=0, build_name_context="mp")
    ]
    first = run(query(17, lobby_slots={"min": 8, "max": 12}, playlist_config=config))
    second = run(query(48, lobby_slots={"min": 8, "max": 8}, playlist_config=config))
    assert first["playlist"] == second["playlist"] == 48
    assert first["maximum_members"] == second["maximum_members"] == 8
    assert first["metadata"] == second["metadata"]
    checks.append(
        "FFA selection uses its eight-slot native group rather than the twelve-slot Quick Play anchor; equivalent parties share match metadata"
    )
    config = [
        dict(playlist_ids=[36], max_slots=20, min_slots=14, num_teams=2, build_name_context="gw")
    ]
    selected = run(query(17, lobby_slots={"min": 8, "max": 12}, playlist_config=config))
    assert selected["maximum_members"] == 20
    assert selected["metadata"]["search_configuration"]["build_name_context"] == "gw"
    checks.append(
        "A selected Ground War group retains twenty slots and its context despite the twelve-slot anchor"
    )
    for playlist, maximum in [(25, 150), (89, 152), (104, 102)]:
        assert run(query(playlist))["maximum_members"] == maximum
    checks.append("BR solo, BR trio and Plunder retain native capacities of 150, 152 and 102")
    bad = copy.deepcopy(config)
    bad[0]["max_slots"] = 0
    run(query(17, playlist_config=bad), reject=True)
    bad[0]["max_slots"] = 12
    run(query(17, playlist_config=bad), reject=True)  # min 14 exceeds max 12
    conflicting = copy.deepcopy(config)
    conflicting.append({**config[0], "max_slots": 30})
    run(query(17, playlist_config=conflicting), reject=True)
    checks.append("Invalid and conflicting selected-group capacities are rejected")

    catalog = copy.deepcopy(original)
    row = next(p for p in catalog["playlists"] if p["playlist"] == 48)
    mode = next(m for m in catalog["gametypes"] if m["gametype"] == row["maps"][0]["gametype"])
    for rules in [catalog["global_dvars"], mode["dvars"], row["dvars"]]:
        for name in list(rules):
            if name.removeprefix("set ") in (key, "party_maxplayers"):
                del rules[name]
    catalog["global_dvars"]["set " + key] = 3
    mode["dvars"]["set " + key] = 5
    row["dvars"]["set " + key] = 7
    catalog_path.write_text(json.dumps(catalog))
    assert run(query(48))["maximum_members"] == 8
    value = query(48)
    value["ruleset_payload"]["dvar_overrides"] = {key: "3"}
    assert run(value)["maximum_members"] == 3
    for invalid in [0, 201, "8junk", -1, True]:
        value["ruleset_payload"]["dvar_overrides"] = {key: invalid}
        run(value, reject=True)
    row["dvars"]["set party_maxplayers"] = 8
    catalog_path.write_text(json.dumps(catalog))
    run(query(48), reject=True)
    checks.append(
        "Native global, mode and playlist precedence, pre-override even rounding, backend precedence and strict alias/type validation"
    )
    args.output.write_text(
        json.dumps(
            dict(
                passed=True,
                game_runs_performed=False,
                executable_sha256=hashlib.sha256(args.executable.read_bytes()).hexdigest(),
                fixture=str(fixture),
                checks=checks,
            ),
            indent=2,
        )
        + "\n"
    )
    print(f"PASS: {len(checks)} production selector capacity groups; no game run")


if __name__ == "__main__":
    main()
