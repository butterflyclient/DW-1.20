"""Index the owner's native playlist without altering its publication bytes."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import zlib
from playlist_packages import inventory

ROOT = Path(__file__).resolve().parents[1]


def prepare(directory, available_maps=None, minimum_players=None, game_directory=None):
    source = ROOT / "data" / "unified_large_playlist_tu19.aggr"
    packed = source.read_bytes()
    decoder = zlib.decompressobj()
    raw = decoder.decompress(packed, 409601)
    if (
        not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
        or len(raw) > 409600
    ):
        raise RuntimeError("Playlist exceeds Replay decompression bounds")
    raw = raw.rstrip(b"\0")
    catalog = json.loads(raw)
    modes = {g["gametype"]: g for g in catalog["gametypes"]}
    playlists = {p["playlist"]: p for p in catalog["playlists"]}
    if len(modes) != len(catalog["gametypes"]) or len(playlists) != len(
        catalog["playlists"]
    ):
        raise RuntimeError("Duplicate native mode or playlist identifiers")
    maps = set()
    entries = 0
    for playlist in playlists.values():
        for entry in playlist["maps"]:
            if entry["gametype"] not in modes:
                raise RuntimeError("Playlist references an undefined game type")
            maps.add(entry["map"])
            entries += 1
    if available_maps is not None and not set(available_maps) <= maps:
        raise RuntimeError("Map policy references a map absent from the publication")
    names_file = ROOT / "integration" / "replay" / "con_dvar_names.h"
    names = dict(
        (logical, native)
        for native, logical in re.findall(
            r'\{"([^"]+)",\s*"([^"]+)"\}', names_file.read_text()
        )
    )
    target = directory / "playlists" / "5800"
    # Preflight the complete window before replacing any existing publication.
    packages = None
    if game_directory is not None:
        packages = inventory(catalog, raw, game_directory)
        installed = {row["name"] for row in packages["maps"] if row["available"]}
        if available_maps is not None and not set(available_maps) <= installed:
            raise RuntimeError("Explicit map policy references an absent main package")
    policy = None
    if available_maps is not None or minimum_players is not None or packages is not None:
        policy_file = target / "policy.json"
        policy = json.loads(policy_file.read_text()) if policy_file.exists() else {}
        if not isinstance(policy, dict):
            raise RuntimeError("Playlist policy must be an object")
        if available_maps is not None:
            policy["available_maps"] = available_maps
        elif packages is not None:
            policy["available_maps"] = sorted(installed)
        if minimum_players is not None:
            if not 1 <= minimum_players <= 200:
                raise RuntimeError("Invalid local minimum player count")
            policy["minimum_players"] = minimum_players
    receipt = {
        "schema": 1,
        "title": 5800,
        "version": catalog["system"]["version"],
        "compressed_source": str(source),
        "compressed_sha256": hashlib.sha256(packed).hexdigest(),
        "catalog_sha256": hashlib.sha256(raw).hexdigest(),
        "native_name_map_sha256": hashlib.sha256(names_file.read_bytes()).hexdigest(),
        "playlists": len(playlists),
        "game_types": len(modes),
        "maps": len(maps),
        "match_entries": entries,
        "native_contracts": {
            "parse": "0x1410CE1A0",
            "lobby_selection": "0x141044F30",
            "choose_entry": "0x1410CBD20",
        },
        "policy_is_separate_from_publication": True,
        "package_inventory_revision": packages["revision"] if packages else None,
        "installed_main_packages": len(installed) if packages else None,
    }
    target.mkdir(parents=True, exist_ok=True)
    # Same bytes/version as the native publisher object, with independent local
    # eligibility. Run publication while the backend is stopped; replacements
    # are individually atomic, rather than a cross-file transaction.
    payloads = {
        "catalog.json": raw,
        "native-dvar-names.json": (json.dumps(names, separators=(",", ":")) + "\n").encode(),
        "provenance.json": (json.dumps(receipt, indent=2) + "\n").encode(),
    }
    if packages is not None:
        payloads["packages.json"] = (json.dumps(packages, indent=2) + "\n").encode()
    if policy is not None:
        payloads["policy.json"] = (json.dumps(policy, indent=2) + "\n").encode()
    for name, payload in payloads.items():
        destination = target / name
        pending = destination.with_suffix(destination.suffix + ".pending")
        pending.write_bytes(payload)
        pending.replace(destination)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "data")
    parser.add_argument("--available-maps", nargs="+")
    parser.add_argument("--minimum-players", type=int)
    parser.add_argument(
        "--game-directory", type=Path,
        help="Index declared root/zone/main packages and refresh map eligibility",
    )
    args = parser.parse_args()
    print(
        json.dumps(prepare(
            args.directory, args.available_maps, args.minimum_players, args.game_directory
        ))
    )
