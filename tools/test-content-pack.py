"""Check every content pack exactly as a checkout or source archive delivers it.

The backend refuses to start when a pack file differs from its manifest
(src/content_pack.cpp), so the bytes git exports must be the manifest's bytes.
The index is exported with git archive, the same path as a GitHub source ZIP.
"""

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True).stdout


tree = git("write-tree").decode().strip()
archive = tarfile.open(fileobj=io.BytesIO(git("archive", "--format=tar", tree, "content")))
exported = {member.name: archive.extractfile(member).read() for member in archive if member.isfile()}
packs = sorted(name for name in exported if name.count("/") == 2 and name.endswith("/manifest.json"))
assert packs, "No content pack is committed"
for name in packs:
    pack = name.rsplit("/", 1)[0]
    manifest = json.loads(exported[name])
    files = manifest["files"]
    assert manifest["schema"] == 1 and files
    # Same revision rule as tools/sync-content-pack.py.
    assert manifest["revision"] == hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(), pack
    listed = {pack + "/files/" + relative for relative in files}
    present = {path for path in exported if path.startswith(pack + "/files/")}
    assert listed == present, (pack, sorted(listed ^ present)[:5])
    for relative, entry in files.items():
        data = exported[pack + "/files/" + relative]
        assert len(data) == entry["bytes"] and hashlib.sha256(data).hexdigest() == entry["sha256"], relative
    print("PASS:", pack, len(files), "files match their manifest as exported")

# The published CRM messages are the builder's output, player-facing, and bound
# to the shipped key art and native CRM actions.
spec = importlib.util.spec_from_file_location("build_replay_crm", ROOT / "tools/build-replay-crm.py")
crm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crm)
catalog = "content/replay120/files/marketing/5800/cod-iw8-bnet-pc/catalog.json"
assert exported[catalog] == (json.dumps(crm.build(), indent=2) + "\n").encode()
locations = set()
for message in json.loads(exported[catalog])["messages"]:
    raw = base64.b64decode(message["content"])
    assert raw.endswith(b"\0") and len(raw) <= 4096
    content = json.loads(raw[:-1])
    text = " ".join(str(value) for value in content.values()).lower()
    assert "dw" not in text.split() and "demonware" not in text and "replay" not in text, content
    assert content["image"] == "mw_keyart_small" and content["popup_image"] == "mw_keyart"
    assert content["action"] == "goto_ingame" and content["action_location"] in ("social", "battlepass")
    assert content["title"] and content["content_short"] and content["content_long"]
    locations.add(message["location"])
assert locations == {1, 2, 6, 7, 11, 12}
print("PASS: six player-facing CRM messages, one MOTD and one message per mode")
