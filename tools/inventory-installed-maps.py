"""Bind catalog matchmaking eligibility to packages in the root game install.

This checks native client/server fastfile pairs and inventories supporting
packages. It does not claim runtime completeness from filenames alone.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--game-root", type=Path, default=Path(r"E:\IW8\Builds\1.20-replay"))
p.add_argument("--title", type=int, default=5800)
p.add_argument("--update-policy", action="store_true")
a = p.parse_args()
game = a.game_root.resolve()
folder = ROOT / "data/playlists" / str(a.title)
catalog = json.loads((folder / "catalog.json").read_text(encoding="utf-8-sig"))
maps = sorted(
    {entry["map"] for playlist in catalog["playlists"] for entry in playlist["maps"]}
)
zone = game / "zone"
zone_names = {entry.name: entry for entry in zone.iterdir() if entry.is_file()}


def metadata(file):
    with file.open("rb") as stream:
        header = stream.read(16)
    st = file.stat()
    return {
        "path": str(file),
        "bytes": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "header_hex": header.hex(),
    }


rows = []
for name in maps:

    def first(filename):
        for base in (game, zone):
            path = base / filename
            if path.is_file() and path.stat().st_size > 16:
                return path
        return None

    client, server = first(name + ".ff"), first("srv_" + name + ".ff")
    supports = [
        file
        for filename, file in zone_names.items()
        if filename in (name + ".fp", "srv_" + name + ".fp", "techsets_" + name + ".ff")
    ]
    transients = [
        file
        for filename, file in zone_names.items()
        if filename.startswith(name + "_") and filename.endswith("_tr.ff")
    ]
    rows.append(
        {
            "map": name,
            "eligible": client is not None and server is not None,
            "client": metadata(client) if client else None,
            "server": metadata(server) if server else None,
            "support_packages": [metadata(file) for file in sorted(supports)],
            "transient_count": len(transients),
            "transient_bytes": sum(file.stat().st_size for file in transients),
            "runtime_package_completeness_verified": False,
        }
    )
eligible = [row["map"] for row in rows if row["eligible"]]
receipt = {
    "schema": 1,
    "scanned_utc": datetime.now(timezone.utc).isoformat(),
    "game_root": str(game),
    "method": "catalog map names with installed nonempty client/server fastfile pairs; supporting/transient inventory",
    "maps": rows,
    "eligible_maps": eligible,
}
(folder / "installed-maps.json").write_text(json.dumps(receipt, indent=2) + "\n")
if a.update_policy:
    target = folder / "policy.json"
    policy = (
        json.loads(target.read_text(encoding="utf-8-sig")) if target.exists() else {}
    )
    policy["available_maps"] = eligible
    # A test playlist preference must not override the owner's queue choice.
    policy.pop("preferred_playlist_id", None)
    pending = target.with_suffix(".pending")
    pending.write_text(json.dumps(policy, indent=2) + "\n")
    os.replace(pending, target)
print("Installed catalog map pairs:", len(eligible), ", ".join(eligible))
