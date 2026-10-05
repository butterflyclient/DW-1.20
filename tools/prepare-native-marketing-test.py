"""Publish one inert local CRM message and restore exact pre-test files."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import time

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("mode", choices=("prepare", "restore"))
parser.add_argument("--observation", default="runtime-marketing-before.json")
args = parser.parse_args()
receipt_path = root / "data/native-marketing-test-publication.json"
user = struct.unpack_from("<Q", (root / "data/platform-profile.bin").read_bytes(), 8)[0]
realm = root / "data/marketing/5800/cod-iw8-bnet-pc"
paths = (
    realm / "catalog.json",
    realm / f"{user}.views.json",
    realm.parent / "_default" / f"{user}.views.json",
)

if args.mode == "restore":
    receipt = json.loads(receipt_path.read_bytes())
    for entry in receipt["files"]:
        path = Path(entry["path"])
        if path not in paths:
            raise RuntimeError("Unexpected marketing restoration path")
        if entry["existed"]:
            temporary = path.with_suffix(path.suffix + ".pending")
            temporary.write_bytes(base64.b64decode(entry["bytes"], validate=True))
            temporary.replace(path)
        else:
            path.unlink(missing_ok=True)
        if path.exists() != entry["existed"] or (
            entry["existed"]
            and path.read_bytes() != base64.b64decode(entry["bytes"], validate=True)
        ):
            raise RuntimeError("Marketing restoration bytes mismatch")
    receipt["restored"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    print("Restored exact pre-test marketing catalog and owner view journal")
else:
    if receipt_path.exists() and not json.loads(receipt_path.read_bytes()).get(
        "restored"
    ):
        raise RuntimeError("Restore the prior marketing test first")
    name = Path(args.observation)
    if name.name != args.observation:
        raise RuntimeError("Use an observation basename within data")
    observation = json.loads((root / "data" / name).read_bytes())
    request = observation["native_marketing_messages"]["request"]
    if request["context"] != "cod-iw8-bnet-pc" or request["language"] != "en":
        raise RuntimeError("Actual native marketing realm/language changed")
    content = b'{"title":"Replay backend verification","body":"{{headline}}","action":"none"}\0'
    metadata = b'{"headline":"Local published message received"}\0'
    row = dict(
        id=104006,
        assignment=104007,
        location=1,
        language="en",
        enabled=True,
        starts=0,
        expires=int(time.time()) + 3600,
        content=base64.b64encode(content).decode(),
        metadata=base64.b64encode(metadata).decode(),
        payload="",
        signature="",
    )
    receipt = dict(
        schema=1,
        restored=False,
        owner=user,
        message_id=row["id"],
        assignment=row["assignment"],
        location=1,
        content_sha256=hashlib.sha256(content).hexdigest(),
        metadata_sha256=hashlib.sha256(metadata).hexdigest(),
        expected_json={
            "title": "Replay backend verification",
            "body": "Local published message received",
            "action": "none",
        },
        files=[
            dict(
                path=str(path),
                existed=path.exists(),
                bytes=(
                    base64.b64encode(path.read_bytes()).decode()
                    if path.exists()
                    else None
                ),
            )
            for path in paths
        ],
    )
    realm.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    temporary = paths[0].with_suffix(".json.pending")
    temporary.write_text(
        json.dumps(
            dict(schema=1, title=5800, context=request["context"], messages=[row])
        )
    )
    temporary.replace(paths[0])
    print(
        "Published one inert native marketing message; exact restoration receipt saved"
    )
