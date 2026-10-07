"""Publish one complete, hash-checked Replay storefront with the server stopped.

The generated manifest names every input. Validate all bytes before changing
publisher objects, marketplace rules or variables. Keep a precise rollback
snapshot, restore it on failure and publish the deployment receipt last.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import time
import urllib.error
import urllib.request

from replay_store_config import validate as validate_root


ROOT = Path(__file__).resolve().parents[1]


def atomic(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".pending")
    pending.write_bytes(body)
    pending.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("publication", type=Path)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--health-url", default="http://127.0.0.1:8085/health")
    args = parser.parse_args()
    try:
        urllib.request.urlopen(args.health_url, timeout=2).close()
    except urllib.error.HTTPError:
        raise RuntimeError("Backend HTTP listener is running; stop it before publication")
    except urllib.error.URLError:
        pass
    else:
        raise RuntimeError("Backend is running; stop it before publication")
    source = args.publication.resolve()
    data = args.data.resolve()
    manifest = json.loads((source / "manifest.json").read_bytes())
    if manifest.get("schema") != 1 or manifest.get("title") != 5800:
        raise ValueError("This publication is not for the verified Replay title")
    payloads = {}
    for name, entry in manifest["files"].items():
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name:
            raise ValueError("Publication path escapes its source")
        raw = (source / path).read_bytes()
        if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("Publication input differs from its manifest: " + name)
        payloads[name] = raw
    root = validate_root(source / "publisher/store_v2.json")
    expected = {"publisher/store_v2.json", "variables.json", "marketplace/catalog.json",
                "marketplace/purchase-rules.json"}
    expected.update("publisher/" + name for name in root["categories"])
    if set(payloads) != expected:
        raise ValueError("Incomplete or unexpected store publication inputs")
    catalog = json.loads(payloads["marketplace/catalog.json"])
    rules = json.loads(payloads["marketplace/purchase-rules.json"])
    ids = [row["id"] for row in catalog["skus"]]
    if len(ids) != manifest["sku_count"] or len(set(ids)) != len(ids) or sorted(ids) != sorted(
            row["sku"] for row in rules["rules"]):
        raise ValueError("Catalog and purchase definitions do not describe the same offers")
    variables = json.loads(payloads["variables.json"])
    namespace = data / "publisher-variables/5800/_default/general_8_19.json"
    old_variables = json.loads(namespace.read_bytes()) if namespace.exists() else {
        "MajorVersion": "1", "MinorVersion": "0"}
    revision = int(old_variables["MinorVersion"]) + 1
    if revision > 65535:
        raise ValueError("Publisher variable version exhausted")
    for key, value in variables.items():
        if not key.startswith("online_store_") or not isinstance(value, str) or len(value) >= 128:
            raise ValueError("Invalid native store variable")
    updated = dict(old_variables, **variables, MinorVersion=str(revision))
    parent = data / "objectstore/publisher/5800/5800/infinityward"
    destinations = {namespace, data / "marketplace/5800/catalog.json",
                    data / "marketplace/5800/purchase-rules.json",
                    data / "store/5800/publication.json"}
    for name in root["categories"] + ["store_v2.json"]:
        destinations.update(parent / (name + suffix) for suffix in (
            ".metadata.json", ".content.bin", ".publication.json"))
    if any(not path.resolve().is_relative_to(data) for path in destinations):
        raise ValueError("Publication destination escapes its data root")
    backup = data / "store/5800/backups" / str(time.time_ns())
    backup.mkdir(parents=True)
    original = {}
    for path in sorted(destinations):
        relative = path.relative_to(data).as_posix()
        original[relative] = path.read_bytes() if path.exists() else None
        if original[relative] is not None:
            atomic(backup / relative, original[relative])
    atomic(backup / "files.json", json.dumps(
        {key: None if value is None else hashlib.sha256(value).hexdigest()
         for key, value in original.items()}, indent=2).encode())
    try:
        for name in root["categories"] + ["store_v2.json"]:
            subprocess.run([sys.executable, str(ROOT / "tools/publish-publisher-object.py"),
                            str(source / "publisher" / name), "--data", str(data),
                            "--replace"], check=True, stdout=subprocess.DEVNULL)
        for name in ("catalog.json", "purchase-rules.json"):
            atomic(data / "marketplace/5800" / name, payloads["marketplace/" + name])
        atomic(namespace, (json.dumps(updated, indent=2) + "\n").encode())
        receipt = {"schema": 1, "published_utc": datetime.now(timezone.utc).isoformat(),
                   "source_manifest_sha256": hashlib.sha256((source / "manifest.json").read_bytes()).hexdigest(),
                   "sku_count": len(ids), "publisher_revision": revision,
                   "backup": str(backup), "files": {}}
        for path in sorted(destinations - {data / "store/5800/publication.json"}):
            receipt["files"][path.relative_to(data).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        atomic(data / "store/5800/publication.json", (json.dumps(receipt, indent=2) + "\n").encode())
    except BaseException:
        for name, raw in original.items():
            path = data / name
            if raw is not None:
                atomic(path, raw)
            elif path.exists():
                path.unlink()
        raise
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
