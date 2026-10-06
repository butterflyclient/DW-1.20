"""Clear host/guest friendships for owner testing; retain each original store."""

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
count = subprocess.check_output(
    ["powershell", "-NoProfile", "-Command",
     "@(Get-CimInstance Win32_Process -Filter \"Name='iw8-dw-server.exe'\").Count"],
    text=True,
)
if int(count.strip()):
    raise RuntimeError("Stop the DW backend before resetting test friendships")
config = json.loads((ROOT / "data/network.json").read_text())
identities = [ROOT / "data/platform-profile.bin"] + [
    ROOT / f"data/platform-profiles/{profile}.bin" for profile in config["clients"]
]
users = {struct.unpack_from("<Q", path.read_bytes(), 8)[0] for path in identities}
retained = ROOT / "data/retained-test-friendships"
retained.mkdir(exist_ok=True)
receipt = []
for path in sorted((ROOT / "data/social").glob("*/*/friends.json")):
    old = path.read_bytes()
    data = json.loads(old)
    removed = {}
    for key, fields in (("friends", ("a", "b")), ("pending", ("from", "to"))):
        rows = data[key]
        kept = [row for row in rows if not any(row[f]["userID"] in users for f in fields)]
        removed[key] = len(rows) - len(kept)
        data[key] = kept
    digest = hashlib.sha256(old).hexdigest()
    if any(removed.values()):
        (retained / (digest + ".json")).write_bytes(old)
        pending = path.with_suffix(".json.pending")
        pending.write_text(json.dumps(data, indent=2) + "\n")
        os.replace(pending, path)
    receipt.append({"path": str(path), "before_sha256": digest, "removed": removed})
(ROOT / "data/test-friendships-reset.json").write_text(json.dumps(receipt, indent=2) + "\n")
print("Host and provisioned guests now start with empty friendships and requests.")
