"""Create an explicitly labelled temporary local regiment through native DW.

Run only while the verified root-folder DW game is stopped. This never writes
the clan store directly; the server handles authentication and all mutations.
"""

import hashlib
import json
import subprocess
from pathlib import Path
from native_wire_client import NativeClient, binary, fields, integer, structure, text

root = Path(__file__).resolve().parents[1]
processes = subprocess.run(
    ["tasklist", "/FO", "CSV", "/NH"], check=True, capture_output=True, text=True
).stdout.lower()
if "game_dx12_ship_replay" in processes:
    raise RuntimeError("Stop Replay before issuing a new local provider session")
deployment = json.loads((root / "data/deployment.json").read_text())
image = Path(deployment["executable"])
if hashlib.sha256(image.read_bytes()).hexdigest() != deployment["sha256"]:
    raise RuntimeError("The game changed since verified deployment")
with NativeClient(root) as client:
    own = integer(1, client.user) + text(2, "uno")
    memberships = fields(client.task(197, 30, structure(binary(1, own))))
    if memberships.get(1):
        raise RuntimeError("Existing player regiment found; no test clan was created")
    request = (
        integer(1, 1)
        + integer(3, 0)
        + integer(4, 0)
        + text(5, "DW Native Validation")
        + integer(7, 3)
        + text(12, "DWTST")
    )
    created = fields(client.task(197, 20, structure(request)))
    clan_id = created[2][0]
    identifier = integer(1, 1) + integer(2, clan_id) + integer(3, 0) + integer(4, 0)
    members = fields(client.task(197, 29, structure(binary(1, identifier))))
    assert len(members[1]) == 1 and fields(fields(members[1][0])[1][0])[1] == [
        client.user
    ]
    receipt = {
        "schema": 1,
        "temporary_test_clan": True,
        "name": "DW Native Validation",
        "tag": "DWTST",
        "user": client.user,
        "title": client.title,
        "clan_id": clan_id,
        "game_sha256": deployment["sha256"],
        "server_sha256": deployment["server_sha256"],
        "method": "Authenticated independent native 210 client; game stopped; no direct store writes",
        "native_game_verified": False,
    }
    (root / "data/native-clan-test.json").write_text(
        json.dumps(receipt, indent=2) + "\n"
    )
    print(
        "Created temporary DW Native Validation regiment through the native authenticated task API"
    )
