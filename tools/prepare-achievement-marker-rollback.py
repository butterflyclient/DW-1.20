"""Remove a completed achievement marker before starting a pre-marker server.

Run on the Linux server while replay-dw is stopped. Default mode only inspects;
--apply durably renames an exact applied marker to a recoverable local backup.
Prepared transactions remain byte-for-byte intact for the previous binary.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate marker key")
        result[key] = value
    return result


def inspect_marker(path):
    if not path.exists() and not path.is_symlink():
        return "absent", None
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 * 1024 * 1024:
        raise ValueError("Marker must be a bounded regular file")
    marker = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    if not isinstance(marker, dict) or marker.get("phase") not in ("prepared", "applied"):
        raise ValueError("Unknown transaction phase")
    if marker["phase"] == "prepared":
        writes = marker.get("writes")
        if not isinstance(writes, list) or not writes:
            raise ValueError("Prepared transaction layout invalid")
        if any(not isinstance(write, dict) or write.get("kind") not in (
                None, "inventory", "states", "leaderboard") for write in writes):
            raise ValueError("Finish prepared recovery with the marker-aware server before rollback")
        # The old binary owns full prepared-intent validation and recovery.
        return "prepared-preserved", metadata
    if (set(marker) != {"schema", "title", "phase", "writes", "checksum"}
            or type(marker["schema"]) is not int or marker["schema"] != 1
            or type(marker["title"]) is not int or marker["title"] != 5800
            or marker["writes"] != []
            or marker["checksum"] != hashlib.sha256(b"[]").hexdigest()):
        raise ValueError("Applied marker schema or checksum invalid")
    return "applied", metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if os.name != "posix" or not args.data.is_absolute():
        raise RuntimeError("Requires Linux and an explicit absolute data directory")
    fields = subprocess.check_output([
        "systemctl", "show", "replay-dw", "-p", "MainPID", "-p", "ActiveState",
    ], text=True)
    service = dict(line.split("=", 1) for line in fields.splitlines() if "=" in line)
    if service.get("MainPID") != "0" or service.get("ActiveState") not in ("inactive", "failed"):
        raise RuntimeError("Stop replay-dw and verify its process has exited before rollback")
    path = args.data.resolve(strict=True) / "achievements/5800/event-transaction.json"
    phase, before = inspect_marker(path)
    if phase != "applied" or not args.apply:
        print(json.dumps({"marker": phase, "changed": False}))
        return
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise RuntimeError("Marker changed during stopped-service inspection")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = path.with_name("event-transaction.applied-rollback-" + stamp + ".json")
    if backup.exists():
        raise RuntimeError("Rollback backup already exists")
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.rename(path, backup)
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({"marker": "applied-archived", "changed": True,
                      "backup": backup.name}))


if __name__ == "__main__":
    main()
