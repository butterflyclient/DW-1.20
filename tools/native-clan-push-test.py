"""Controlled clan invite/withdrawal using a separately provisioned peer.

Does not reauthenticate the running game's account or write clan storage.
Only the exact receipted temporary group can be removed.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
from native_wire_client import NativeClient, binary, fields, integer, structure, text

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "action",
    choices=(
        "invite",
        "resend",
        "withdraw",
        "rename",
        "restore_name",
        "promote",
        "demote",
        "kick",
        "cleanup",
    ),
)
args = parser.parse_args()
deployment = json.loads((root / "data/deployment.json").read_text())
if (
    hashlib.sha256(Path(deployment["executable"]).read_bytes()).hexdigest()
    != deployment["sha256"]
):
    raise RuntimeError("Native deployment changed")
profile = (root / "data/platform-profiles/native-social.bin").read_bytes()
if len(profile) != 56 or profile[20:56].split(b"\0")[0] != b"DWBackendValidation":
    raise RuntimeError("Unexpected validation peer profile")
peer = struct.unpack_from("<Q", profile, 8)[0]
target = struct.unpack_from("<Q", (root / "data/platform-profile.bin").read_bytes(), 8)[
    0
]
if peer == target:
    raise RuntimeError("Test peer must be independent from the running game")
path = root / "data/native-clan-push-test.json"
name, tag = "DW Clan Push Validation", "DWPUSH"
updated_name = "DW Clan Push Updated"

with NativeClient(root, profile="native-social") as client:
    if client.user != peer:
        raise RuntimeError("Unexpected authenticated peer")
    if args.action == "invite":
        if path.exists() and not json.loads(path.read_text()).get("removed"):
            raise RuntimeError("Clean up the previous receipted temporary group first")
        own = integer(1, peer) + text(2, "uno")
        member_rows = fields(client.task(197, 30, structure(binary(1, own))))
        if any(
            fields(row)[1] == [3]
            for member in member_rows.get(1, [])
            for row in fields(member).get(2, [])
        ):
            raise RuntimeError("Validation peer already owns a group; preserve it")
        request = (
            integer(1, 1)
            + integer(3, 0)
            + integer(4, 0)
            + text(5, name)
            + integer(7, 3)
            + text(12, tag)
        )
        created = fields(client.task(197, 20, structure(request)))
        receipt = {
            "schema": 1,
            "temporary_test_clan": True,
            "name": name,
            "tag": tag,
            "user": peer,
            "target": target,
            "title": client.title,
            "clan_id": created[2][0],
            "game_sha256": deployment["sha256"],
            "server_sha256": deployment["server_sha256"],
            "native_game_verified": False,
            "created_utc": datetime.now(timezone.utc).isoformat(),
        }
        # Record before inviting, so any later failure still has a cleanup ID.
        path.write_text(json.dumps(receipt, indent=2) + "\n")
    else:
        receipt = json.loads(path.read_text())
        if receipt.get("removed"):
            raise RuntimeError("Temporary validation group is already removed")
    if not (
        receipt["temporary_test_clan"]
        and receipt["name"] == name
        and receipt["tag"] == tag
        and receipt["user"] == peer
        and receipt["target"] == target
        and receipt["title"] == client.title
    ):
        raise RuntimeError("Temporary group receipt does not match this peer")
    group = (
        integer(1, 1) + integer(2, receipt["clan_id"]) + integer(3, 0) + integer(4, 0)
    )
    result = fields(client.task(197, 21, structure(binary(1, group))))
    info = fields(result[1][0])
    expected_count = (
        2
        if args.action in ("kick", "rename", "restore_name", "promote", "demote")
        else 1
    )
    expected_name = updated_name if args.action == "restore_name" else name
    if (
        info[5] != [expected_name.encode()]
        or info[12] != [tag.encode()]
        or fields(info[6][0])[1] != [peer]
        or info[8] != [expected_count]
    ):
        raise RuntimeError("Group ownership or membership changed; preserve it")
    user = integer(1, target) + text(2, "uno")
    if args.action in ("invite", "resend"):
        proposal = binary(1, user) + integer(2, 1) + binary(3, b"")
        client.task(197, 25, structure(binary(1, group) + binary(2, proposal)))
        receipt["invite_sent_utc"] = datetime.now(timezone.utc).isoformat()
    elif args.action in ("rename", "restore_name", "promote", "demote", "kick"):
        members = fields(client.task(197, 29, structure(binary(1, group))))
        if {fields(fields(member)[1][0])[1][0] for member in members.get(1, [])} != {
            peer,
            target,
        }:
            raise RuntimeError(
                "Temporary group members do not match the validation pair"
            )
        if args.action in ("rename", "restore_name"):
            client.task(
                197,
                22,
                structure(
                    group + text(5, updated_name if args.action == "rename" else name)
                ),
            )
        elif args.action in ("promote", "demote"):
            client.task(
                197,
                23,
                structure(
                    binary(1, group)
                    + integer(2, 2 if args.action == "promote" else 1)
                    + binary(3, user)
                    + integer(4, 0)
                ),
            )
        else:
            client.task(197, 24, structure(binary(1, group) + binary(2, user)))
        receipt[args.action + "_utc"] = datetime.now(timezone.utc).isoformat()
    else:
        request = binary(1, user) + binary(2, group) + integer(3, 0)
        client.task(197, 26, structure(binary(1, request)))
        receipt["withdrawn_utc"] = datetime.now(timezone.utc).isoformat()
        if args.action == "cleanup":
            client.task(197, 24, structure(binary(1, group)))
            if client.task(197, 21, structure(binary(1, group))):
                raise RuntimeError("Temporary group deletion was not confirmed")
            receipt["removed"] = True
            receipt["cleanup_method"] = (
                "Authenticated 197/26 and 197/24; exact ID/name/tag/owner/single-member guard"
            )
    path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        f"Temporary clan {args.action} completed through native authenticated tasks; game account session untouched"
    )
