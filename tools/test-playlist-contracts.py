"""Focused package/capacity checks against the compiled production selector."""

import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import time

from playlist_packages import inventory

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--executable", type=Path, required=True)
parser.add_argument("--game-directory", type=Path, required=True)
args = parser.parse_args()
executable = args.executable.resolve(strict=True)
fixture = ROOT / "data" / f"playlist-contract-fixture-{time.time_ns()}"
fixture.mkdir()
prepare = runpy.run_path(str(ROOT / "tools/prepare-playlist-catalog.py"))["prepare"]
checks = []


def publish(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def select(directory, reject=False):
    result = subprocess.run(
        [str(executable), str(directory)], capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if reject:
        assert result.returncode == 1 and "contract rejected" in result.stderr
        return None
    assert result.returncode == 0, result.stderr
    return {row["playlist"]: row for row in json.loads(result.stdout)}


# Inventory actual installed headers, without running or editing the game.
data = fixture / "actual-packages"
policy = data / "playlists/5800/policy.json"
policy.parent.mkdir(parents=True)
original_policy = {"minimum_players": 2, "minimum_lobby_seconds": 60,
                   "split_parties_for_team_balance": True}
publish(policy, original_policy)
receipt = prepare(data, game_directory=args.game_directory)
catalog_path = policy.parent / "catalog.json"
catalog = json.loads(catalog_path.read_bytes())
packages_path = policy.parent / "packages.json"
packages = json.loads(packages_path.read_bytes())
available = {row["name"] for row in packages["maps"] if row["available"]}
assert json.loads(policy.read_bytes()) == {**original_policy, "available_maps": sorted(available)}
assert receipt["installed_main_packages"] == len(available)
selected = select(data)
assert len(selected) == len(catalog["playlists"])
eligible_count = 0
for playlist in catalog["playlists"]:
    expected = [row for row in playlist["maps"][:20]
                if row["map"] in available and row["weight"] > 0]
    row = selected[playlist["playlist"]]
    if not expected:
        assert row.get("unavailable") is True
        continue
    eligible_count += 1
    assert row["metadata"]["eligible_entries"] == expected
    assert row["metadata"]["playlist_dvars"] == playlist.get("dvars", {})
    assert row["metadata"]["map_package_revision"] == packages["revision"]
    assert all(weight == 0 or name in available
               for name, weight in row["rules"]["map_weights"].items())
    assert len(row["rules"]["map_weights"]) <= 20
    assert len(row["rules"]["dvar_overrides"]) <= 128
checks.append("all owner playlists obey actual package eligibility and native entry/override bounds")
assert selected[104]["metadata"]["playlist_dvars"] == next(
    row["dvars"] for row in catalog["playlists"] if row["playlist"] == 104
)
assert len(selected[104]["metadata"]["playlist_dvars"]) == 161
assert len(selected[104]["rules"]["dvar_overrides"]) < 128
checks.append("Plunder retains all 161 native playlist dvars without overflowing the backend override window")
assert selected[32]["team_count"] == 2
assert len(selected[32]["metadata"]["game_types"]) > 1
checks.append("mixed-mode moshpit preserves each mode's data and consistent team layout")

# Malformed and mismatched publications must be rejected before a lobby forms.
for mutation in ("version", "duplicate", "type", "revision", "catalog"):
    bad = json.loads(json.dumps(packages))
    if mutation == "version":
        bad["playlist_version"] += 1
    elif mutation == "duplicate":
        bad["maps"].append(bad["maps"][0])
    elif mutation == "type":
        bad["maps"][0]["available"] = 1
    elif mutation == "catalog":
        bad["catalog_sha256"] = "0" * 64
    else:
        bad["revision"] = "invalid"
    publish(packages_path, bad)
    select(data, reject=True)
publish(packages_path, packages)
checks.append("stale, duplicated, mistyped and malformed package publications are rejected")
bad_catalog = json.loads(json.dumps(catalog))
next(mode for mode in bad_catalog["gametypes"] if mode["gametype"] == "cranked")["teamCount"] = 0
publish(catalog_path, bad_catalog)
# Keep the manifest internally valid so this case exercises the team-layout
# check rather than stopping at the earlier content-revision check.
matching = inventory(bad_catalog, catalog_path.read_bytes(), args.game_directory)
publish(packages_path, matching)
select(data, reject=True)
catalog_path.write_bytes((ROOT / "data/playlists/5800/catalog.json").read_bytes())
publish(packages_path, packages)
checks.append("a conflicting future team/FFA moshpit does not inherit its first mode's layout")

# A bad explicit policy must not leave a partially replaced index window.
before = {p.name: p.read_bytes() for p in policy.parent.iterdir() if p.is_file()}
absent = next(row["name"] for row in packages["maps"] if not row["available"])
try:
    prepare(data, available_maps=[absent], game_directory=args.game_directory)
    raise AssertionError("Absent explicit package admitted")
except RuntimeError as error:
    assert "absent main package" in str(error)
assert before == {p.name: p.read_bytes() for p in policy.parent.iterdir() if p.is_file()}
checks.append("failed explicit map policy preflight preserves the complete existing publication")

# Header-only synthetic packages exercise metadata boundaries; these are not maps.
synthetic = fixture / "synthetic-headers"
(synthetic / "zone").mkdir(parents=True)
header = b"IWffa100" + struct.pack("<II", 11, 4087) + b"fixture payload"
(synthetic / "zone/mp_shipment.ff").write_bytes(header)
indexed = inventory(catalog, catalog_path.read_bytes(), synthetic)
assert [row["name"] for row in indexed["maps"] if row["available"]] == ["mp_shipment"]
(synthetic / "mp_shipment.ff").write_bytes(b"bad")
rejected = inventory(catalog, catalog_path.read_bytes(), synthetic)
assert not next(row for row in rejected["maps"] if row["name"] == "mp_shipment")["available"]
assert indexed["revision"] != rejected["revision"]
checks.append("bounded header indexing honors root overrides and records metadata revisions")
proof = {
    "schema": 1, "passed": True, "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
    "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in (ROOT / "src/playlist_catalog.cpp", ROOT / "tools/playlist_packages.py")},
    "fixture_directory": str(fixture), "checks": checks,
    "playlists": len(selected), "eligible_playlists": eligible_count,
    "installed_main_packages": len(available), "game_runs_performed": False,
    "native_map_load_verified": False,
}
(ROOT / "data/playlist-contract-verification.json").write_text(json.dumps(proof, indent=2) + "\n")
print(f"PASS: {len(checks)} focused contract groups, {len(selected)} playlists, {len(available)} installed main packages; no game runs")
