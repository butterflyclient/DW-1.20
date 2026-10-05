"""Publish source bytes for Replay's native publisher-object streaming.

Run with the backend stopped. Metadata and payload are staged atomically;
immutable HTTP URLs keep already-issued versions stable during later updates.
No game asset or compiler source is changed.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source", type=Path)
parser.add_argument("--title", type=int, default=5800)
parser.add_argument("--context", default="5800")
parser.add_argument("--owner", default="infinityward")
parser.add_argument("--name")
parser.add_argument(
    "--data", type=Path, default=Path(__file__).resolve().parents[1] / "data"
)
parser.add_argument("--replace", action="store_true")
args = parser.parse_args()
source = args.source.resolve()
name = args.name or source.name
for value, capacity in ((args.context, 16), (args.owner, 30), (name, 65)):
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+", value)
        or value in (".", "..")
        or len(value) >= capacity
    ):
        raise ValueError("Invalid publisher object identity")
if (
    not 0 < args.title < 2**32
    or not source.is_file()
    or source.stat().st_size > 64 * 1024 * 1024
):
    raise ValueError("Invalid title or source size")
body = source.read_bytes()
target = (
    args.data.resolve()
    / "objectstore"
    / "publisher"
    / str(args.title)
    / args.context
    / args.owner
)
target.mkdir(parents=True, exist_ok=True)
metadata_path = target / (name + ".metadata.json")
if metadata_path.exists() and not args.replace:
    raise FileExistsError(
        "Publisher object exists; use --replace for an intentional publication"
    )
created = int(time.time())
if metadata_path.exists():
    created = json.loads(metadata_path.read_text())["created"]
metadata = dict(
    name=name,
    owner=args.owner,
    context=args.context,
    contentLength=len(body),
    checksum=base64.b64encode(hashlib.md5(body).digest()).decode(),
    objectVersion=hashlib.sha256(body).hexdigest()[:32],
    acl="public",
    category=None,
    created=created,
    modified=int(time.time()),
    expiresOn=0,
)
identity = f"{args.title}/{args.context}/{args.owner}/{name}".encode()
metadata["objectID"] = int.from_bytes(hashlib.sha256(identity).digest()[:8], "big") or 1
for destination, payload in (
    (target / (name + ".content.bin"), body),
    (metadata_path, (json.dumps(metadata, indent=2) + "\n").encode()),
):
    pending = destination.with_name(destination.name + ".pending")
    pending.write_bytes(payload)
    pending.replace(destination)
receipt = dict(
    schema=1,
    source=str(source),
    source_sha256=hashlib.sha256(body).hexdigest(),
    bytes=len(body),
    metadata=str(metadata_path),
    title=args.title,
    context=args.context,
    owner=args.owner,
    name=name,
    method="source bytes published for native metadata plus HTTP download",
)
(target / (name + ".publication.json")).write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps(receipt, indent=2))
