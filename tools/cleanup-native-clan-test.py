"""Remove only the receipted temporary regiment through authenticated DW.

Replay must be stopped. No production store is edited directly.
"""

import json
import subprocess
from pathlib import Path
from native_wire_client import NativeClient, binary, fields, integer, structure

root = Path(__file__).resolve().parents[1]
if (
    "game_dx12_ship_replay"
    in subprocess.run(
        ["tasklist", "/FO", "CSV", "/NH"], check=True, capture_output=True, text=True
    ).stdout.lower()
):
    raise RuntimeError("Stop Replay before issuing a new local provider session")
path = root / "data/native-clan-test.json"
receipt = json.loads(path.read_text())
if receipt.get("removed"):
    print("Temporary test regiment was already removed")
else:
    assert (
        receipt["temporary_test_clan"]
        and receipt["name"] == "DW Native Validation"
        and receipt["tag"] == "DWTST"
    )
    with NativeClient(root) as client:
        assert client.user == receipt["user"] and client.title == receipt["title"]
        group = (
            integer(1, 1)
            + integer(2, receipt["clan_id"])
            + integer(3, 0)
            + integer(4, 0)
        )
        result = fields(client.task(197, 21, structure(binary(1, group))))
        if result.get(1):
            info = fields(result[1][0])
            assert info[5] == [receipt["name"].encode()] and info[12] == [
                receipt["tag"].encode()
            ]
            assert fields(info[6][0])[1] == [client.user] and info[8] == [1]
            assert client.task(197, 24, structure(binary(1, group))) == b""
            assert client.task(197, 21, structure(binary(1, group))) == b""
        receipt["removed"] = True
        receipt["cleanup_method"] = (
            "Authenticated task 197/24 after exact ID/name/tag/owner/member-count checks"
        )
    path.write_text(json.dumps(receipt, indent=2) + "\n")
    print("Temporary test regiment removed; original player data preserved")
