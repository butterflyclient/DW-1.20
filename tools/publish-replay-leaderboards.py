"""Publish verified column layouts while the backend is stopped; retain rollback."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import urllib.error
import urllib.request


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".pending")
    with pending.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("publication", type=Path)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--health-url", default="http://127.0.0.1:8085/health")
    args = parser.parse_args()
    try:
        urllib.request.urlopen(args.health_url, timeout=2).close()
    except urllib.error.HTTPError as error:
        raise RuntimeError("A backend listener is active; stop it before publication") from error
    except urllib.error.URLError:
        pass
    else:
        raise RuntimeError("Backend is active; stop it before publishing leaderboard layouts")
    raw = (args.publication / "catalog.json").read_bytes()
    catalog = json.loads(raw)
    assert catalog["schema"] == 1 and catalog["title"] == 5800
    assert catalog["original_image_sha256"] == \
        "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    definitions = catalog["definitions"]
    assert 0 < len(definitions) <= 2000
    assert catalog["native_column_builder"]["original_instructions_executed"]
    assert len(catalog["native_column_builder"]["cases"]) == 40
    assert all(case["passed"] for case in catalog["native_column_builder"]["cases"])
    source = args.publication / "leaderboard-definitions/5800"
    assert {p.name for p in source.iterdir()} == {f"{board}.json" for board in definitions}
    files = {}
    for board, definition in definitions.items():
        assert board.isascii() and board.isdigit() and str(int(board)) == board
        assert 0 <= int(board) < 2**32 - 1
        width = len(definition["columns"])
        assert 0 < width <= 240
        assert definition["columns"] == [f"col_{i}" for i in range(width)]
        assert definition["schema"] == 2 and definition["assets"]
        assert isinstance(definition["storage_board"], int) and \
            not isinstance(definition["storage_board"], bool) and \
            0 <= definition["storage_board"] < 2**32 - 1
        data = (source / f"{board}.json").read_bytes()
        assert json.loads(data) == definition
        files[f"leaderboard-definitions/5800/{board}.json"] = data
    root = args.data.resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = root / "leaderboard-publications/5800/backups" / stamp
    backup.mkdir(parents=True, exist_ok=False)
    receipt_path = root / "leaderboard-publications/5800/publication.json"
    files["leaderboard-publications/5800/publication.json"] = b""  # Receipt published last.
    previous = {}
    for relative in files:
        target = root / relative
        assert target.resolve().is_relative_to(root) and not target.is_symlink()
        previous[relative] = target.read_bytes() if target.exists() else None
        if target.exists():
            destination = backup / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, destination)
    (backup / "manifest.json").write_text(json.dumps({
        "previous": {name: None if data is None else sha256(data)
                     for name, data in previous.items()},
    }, indent=2) + "\n")
    receipt = {"schema": 1, "title": 5800, "generated_utc": datetime.now(timezone.utc).isoformat(),
               "catalog_sha256": sha256(raw), "asset_export_sha256": catalog["asset_export_sha256"],
               "backup": str(backup), "definitions": len(definitions),
               "files": {name: sha256(data) for name, data in files.items()
                         if name != "leaderboard-publications/5800/publication.json"},
               "player_stats_modified": False}
    files["leaderboard-publications/5800/publication.json"] = \
        (json.dumps(receipt, indent=2) + "\n").encode()
    try:
        for relative, data in files.items():
            atomic(root / relative, data)
        assert receipt_path.read_bytes() == files["leaderboard-publications/5800/publication.json"]
    except BaseException:
        for relative, data in previous.items():
            if data is None:
                (root / relative).unlink(missing_ok=True)
            else:
                atomic(root / relative, data)
        raise
    print(f"Published {len(definitions)} native column layouts; rollback: {backup}")


if __name__ == "__main__":
    main()
