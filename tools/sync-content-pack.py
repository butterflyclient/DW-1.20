"""Snapshot a server's published (non-player) content into a versioned content pack.

A content pack is what turns a fresh backend into a full one: Store catalog and
purchase rules, publisher variables and objects, Battle Pass rules, leaderboard
definitions, playlists, marketing messages, achievement definitions and the
local QoS/relay switches. The backend installs every pack under content/ into
its data folder at startup (src/content_pack.cpp), so a local server has the
same features as the primary droplet without copying anyone's runtime data.

Packs are title/build scoped so one backend can serve several game versions:
each pack's manifest names its titles and build, and every packed path already
contains its title ID. Player data, keys, sessions, logs, backups, executable
updates and map packages are never selected.

  python tools/sync-content-pack.py --from-droplet
  python tools/sync-content-pack.py --from-data data/local-play --output content/replay120

Reading the droplet is read-only (SFTP get only).
"""

import argparse
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REMOTE_DATA = "/var/lib/replay-dw"

# Published content the server reads, relative to the data folder. "*" never
# crosses a "/"; each pattern keeps its title/context segments explicit.
SELECTED = (
    "battlepass/*/rules.json",
    "leaderboard-definitions/*/*.json",
    "marketing/*/*/catalog.json",
    "marketplace/*/catalog.json",
    "marketplace/*/purchase-rules.json",
    "playlists/*/catalog.json",
    "playlists/*/native-dvar-names.json",
    "playlists/*/provenance.json",
    "playlists/*/policy.json",
    "publisher-variables/*/*/*.json",
    "achievements/*/*/definitions.json",
    "objectstore/publisher/*/*/*/*.metadata.json",
    "objectstore/publisher/*/*/*/*.content.bin",
    "ab-testing/*/*/catalog.json",
    "validated-stats/*/catalog.json",
    "inventory-validation/*/catalog.json",
    "scheduled-matches/*/matches.json",
    "rest/*/*/*/*.json",
    "geography.json",
    "platform-word-filters.json",
    "qos/local-provider.json",
    "relay/local-provider.json",
)
# Machine- or installation-specific files that look like content but are not.
EXCLUDED = (
    "playlists/*/packages.json",        # the publisher's own installed-map inventory
    "playlists/*/installed-maps.json",
)
MAX_FILE = 4 * 1024 * 1024
MAX_FILES = 4096


def selected(relative):
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts:
        return False
    if any(fnmatch.fnmatchcase(relative, pattern) and relative.count("/") == pattern.count("/")
           for pattern in EXCLUDED):
        return False
    return any(fnmatch.fnmatchcase(relative, pattern) and relative.count("/") == pattern.count("/")
               for pattern in SELECTED)


def walk_local(root):
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            relative = path.relative_to(root).as_posix()
            if selected(relative):
                yield relative, path.stat().st_size, lambda path=path: path.read_bytes()


def walk_remote(sftp):
    def recurse(directory, prefix):
        for entry in sorted(sftp.listdir_attr(directory), key=lambda e: e.filename):
            relative = f"{prefix}{entry.filename}"
            if stat.S_ISDIR(entry.st_mode):
                # Skip whole trees that only hold player or machine state.
                top = relative.split("/")[0]
                if relative.count("/") == 0 and top not in {p.split("/")[0] for p in SELECTED}:
                    continue
                if entry.filename in ("backups", "users", "content", "_transactions", "players"):
                    continue
                yield from recurse(f"{directory}/{entry.filename}", relative + "/")
            elif stat.S_ISREG(entry.st_mode) and selected(relative):
                remote = f"{directory}/{entry.filename}"

                def read(remote=remote):
                    with sftp.open(remote, "rb") as handle:
                        return handle.read()

                yield relative, entry.st_size, read
    yield from recurse(REMOTE_DATA, "")


def build(entries, output, source, pack, build_name, titles):
    staging = Path(tempfile.mkdtemp(prefix=".content-pack-", dir=output.parent))
    try:
        files = {}
        for relative, size, read in entries:
            if size > MAX_FILE:
                raise ValueError(f"{relative} exceeds the {MAX_FILE}-byte pack file limit")
            data = read()
            target = staging / "files" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            files[relative] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            if len(files) > MAX_FILES:
                raise ValueError("Too many content files for one pack")
        if not files:
            raise ValueError("No published content found")
        found_titles = sorted({int(p.split("/")[1]) for p in files
                               if p.split("/")[0] not in ("qos", "relay", "geography.json",
                                                          "platform-word-filters.json")
                               and len(p.split("/")) > 1 and p.split("/")[1].isdigit()} |
                              {int(p.split("/")[2]) for p in files
                               if p.startswith("objectstore/publisher/")})
        if titles and set(found_titles) - set(titles):
            raise ValueError(f"Content for unexpected titles {sorted(set(found_titles) - set(titles))}")
        revision = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
        manifest = {
            "schema": 1,
            "pack": pack,
            "build": build_name,
            "titles": titles or found_titles,
            "revision": revision,
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": source,
            "install": "missing-or-unmodified",
            "files": dict(sorted(files.items())),
        }
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        if output.exists():
            shutil.rmtree(output)
        staging.replace(output)
        return manifest
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    origin = parser.add_mutually_exclusive_group(required=True)
    origin.add_argument("--from-droplet", action="store_true", help="read the primary droplet over pinned SSH")
    origin.add_argument("--from-data", type=Path, help="read a local server data folder")
    parser.add_argument("--output", type=Path, default=ROOT / "content" / "replay120")
    parser.add_argument("--pack", default="replay120")
    parser.add_argument("--build", default="replay120")
    parser.add_argument("--title", type=int, action="append", dest="titles",
                        help="restrict to these title IDs (default: 5800)")
    args = parser.parse_args()
    titles = args.titles or [5800]
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.from_droplet:
        sys.path.insert(0, str(ROOT / "tools"))
        import remote_backend
        with remote_backend.connect() as client, client.open_sftp() as sftp:
            manifest = build(walk_remote(sftp), output, "primary-droplet", args.pack, args.build, titles)
    else:
        data = args.from_data.resolve(strict=True)
        manifest = build(walk_local(data), output, "local-data", args.pack, args.build, titles)
    total = sum(f["bytes"] for f in manifest["files"].values())
    print(f"{output}: {len(manifest['files'])} files, {total} bytes, revision {manifest['revision'][:16]}")


if __name__ == "__main__":
    main()
