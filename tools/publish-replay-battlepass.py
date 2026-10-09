"""Merge verified Battle Pass definitions and publish their complete native rules."""

import argparse
import hashlib
import json
import os
from pathlib import Path


def publish(publication, data, owner=None):
    definitions = json.loads((publication / "definitions.json").read_bytes())
    rules = (publication / "rules.json").read_bytes()
    manifest = json.loads((publication / "manifest.json").read_bytes())
    if (
        hashlib.sha256((publication / "definitions.json").read_bytes()).hexdigest()
        != manifest["definitions_sha256"]
    ):
        raise ValueError("Battle Pass definitions changed after generation")
    if hashlib.sha256(rules).hexdigest() != manifest["rules_sha256"]:
        raise ValueError("Battle Pass rules changed after generation")
    identity = None
    if owner:
        import pwd

        identity = pwd.getpwnam(owner)

    def atomic(path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        pending = path.with_name(path.name + ".pending")
        with pending.open("wb") as file:
            file.write(body)
            file.flush()
            os.fsync(file.fileno())
        if os.name != "nt":
            os.chmod(pending, 0o600)
            if identity:
                os.chown(pending, identity.pw_uid, identity.pw_gid)
                # Only these managed publication directories; never chown
                # player state trees or unrelated service data recursively.
                current = path.parent
                while current != data:
                    os.chown(current, identity.pw_uid, identity.pw_gid)
                    current = current.parent
        pending.replace(path)
        if os.name != "nt":
            fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    owned = {row["14"] for row in definitions}
    destinations = []
    for context in ("5800", "iw8"):
        path = data / "achievements/5800" / context / "definitions.json"
        previous = json.loads(path.read_bytes()) if path.exists() else []
        if not isinstance(previous, list):
            raise ValueError("Invalid existing achievement definitions")
        merged = [row for row in previous if row.get("14") not in owned] + definitions
        atomic(path, (json.dumps(merged, indent=2) + "\n").encode())
        destinations.append(str(path))
    atomic(data / "battlepass/5800/rules.json", rules)
    return dict(
        published=True,
        definitions=len(definitions),
        destinations=destinations,
        owner=owner,
        rules_sha256=manifest["rules_sha256"],
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("publication", type=Path)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--owner")
    args = parser.parse_args()
    print(
        json.dumps(
            publish(args.publication.resolve(), args.data.resolve(), args.owner),
            indent=2,
        )
    )
