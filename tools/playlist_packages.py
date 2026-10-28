"""Index declared Replay map packages without reading their asset payloads."""

import hashlib
import json
from pathlib import Path
import re
import struct


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.]+", value):
        raise ValueError("Invalid native map identifier")
    if value in (".", "..") or len(value) >= 24:
        raise ValueError("Map name exceeds Replay's native 24-byte field")
    return value


def basic_file(path, root):
    stat = path.stat()
    with path.open("rb") as source:
        header = source.read(16)
    result = {
        "path": path.relative_to(root).as_posix(),
        "bytes": stat.st_size,
        "header_sha256": hashlib.sha256(header).hexdigest(),
        "complete_header": len(header) == 16,
        "magic": header[:8].decode("ascii", errors="replace"),
    }
    if len(header) == 16:
        result["compression_version"], result["xfile_version"] = struct.unpack(
            "<II", header[8:16]
        )
    return result


def inventory(catalog, catalog_bytes, game_directory):
    root = Path(game_directory).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Game directory is not a directory")
    names = sorted({
        identifier(entry["map"])
        for playlist in catalog["playlists"] for entry in playlist["maps"]
    })
    rows = []
    # Root overrides precede the native zone directory. Do not discover packages
    # inside old builds, compiler archives or frontend comparison directories.
    # A DW custom map release installs its own folder (DW_MapAvailability.cpp).
    for name in names:
        candidates = []
        custom = root / "mods" / "mw120r" / "maps" / name
        for directory in (root, root / "zone", root / "main", custom):
            path = directory / (name + ".ff")
            if path.is_file():
                # Lexical containment: mods/mw120r/maps may be a junction to
                # another drive (the DW client follows a junctioned parent).
                if not path.absolute().is_relative_to(root):
                    raise ValueError("Map package escapes the game directory")
                record = basic_file(path.absolute(), root)
                for suffix in (".fp", ".fc"):
                    companion = path.with_suffix(suffix)
                    if companion.is_file():
                        record[suffix[1:]] = basic_file(companion.absolute(), root)
                candidates.append(record)
        primary = candidates[0] if candidates else None
        # Stock packages are IWffa100; zonetool-built custom maps are IWffc100.
        magic = "IWffc100" if primary and primary["path"].startswith("mods/") else "IWffa100"
        available = bool(
            primary and primary["complete_header"]
            and primary["bytes"] > 16 and primary["magic"] == magic
        )
        rows.append({
            "name": name,
            "available": available,
            "status": "main-package-present" if available else (
                "unrecognized-package-header" if primary else "main-package-absent"
            ),
            "primary": primary,
            "candidates": candidates,
        })
    body = {
        "schema": 1,
        "title": 5800,
        "playlist_version": catalog["system"]["version"],
        "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(),
        "maps": rows,
        "scope": "Declared playlist maps; primary FF header/presence and optional FP/FC metadata",
        "native_map_load_verified": False,
        "transient_completeness_verified": False,
    }
    body["revision"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    return body
