"""Validate the complete private friendship graph before reads or publication."""

from copy import deepcopy
import json
import struct


def exercise(client, path, user, peer, request, response, checks):
    original = path.read_bytes()
    graph = json.loads(original)
    base = f"/v1/friends/uno-{user}/"
    read = request("social-service", "Friends", "get_friends", uri=base)
    invite = request(
        "friends",
        "Friends",
        "invite_friend",
        0x504F5354,
        {"users": [peer]},
        uri=base + "invitation/",
    )
    revoke = request(
        "friends",
        "Friends",
        "reject_friend_request",
        0x44454C45,
        uri=base + f"{peer['accountType']}-{peer['userID']}/",
    )

    def broken(change):
        data = deepcopy(graph)
        change(data)
        return data

    own = {"userID": user, "accountType": "uno"}
    incoming = {"from": peer, "to": own, "from_name": "Fixture Peer"}
    cases = [
        broken(lambda d: d.update(extra=True)),
        broken(lambda d: d.update(context="foreign")),
        broken(lambda d: d.update(schema=True)),
        broken(lambda d: d.pop("pending")),
        broken(lambda d: d.update(pending={})),
        broken(lambda d: d["friends"].append(deepcopy(d["friends"][0]))),
        broken(
            lambda d: d["friends"].append(
                {
                    "a": deepcopy(d["friends"][0]["b"]),
                    "b": deepcopy(d["friends"][0]["a"]),
                }
            )
        ),
        broken(lambda d: d["friends"][0].update(a=own, b=own)),
        broken(lambda d: d["friends"][0].update(extra=0)),
        broken(lambda d: d["friends"][0]["a"].update(accountType="unknown")),
        broken(lambda d: d["friends"][0]["a"].update(userID=-1)),
        broken(lambda d: d["friends"][0]["a"].update(userID=1.5)),
        broken(lambda d: d["friends"][0]["a"].update(userID=True)),
        broken(lambda d: d["friends"][0]["a"].update(userID=2**64 - 1)),
        broken(lambda d: d["friends"][0]["a"].update(name="unexpected")),
        broken(lambda d: d.update(pending=[incoming])),
        broken(lambda d: d.update(friends=[], pending=[incoming, incoming])),
        broken(
            lambda d: d.update(
                friends=[], pending=[incoming, {"from": own, "to": peer}]
            )
        ),
        broken(lambda d: d.update(friends=[], pending=[dict(incoming, to=peer)])),
        broken(lambda d: d.update(friends=[], pending=[dict(incoming, extra=True)])),
        broken(lambda d: d.update(friends=[], pending=[dict(incoming, from_name=1)])),
        broken(lambda d: d.update(friends=[], pending=[dict(incoming, from_name="")])),
        broken(
            lambda d: d.update(friends=[], pending=[dict(incoming, from_name="a" * 62)])
        ),
        broken(
            lambda d: d.update(
                friends=[], pending=[dict(incoming, from_name="bad\0name")]
            )
        ),
        broken(lambda d: d.update(friends=[d["friends"][0]] * 4097)),
    ]
    try:
        old_body = json.dumps({"users": [peer]}).encode()
        body_start = invite.index(old_body)
        for body in (
            b'{"users":' + json.dumps([peer]).encode() + b',"users":[]}',
            (
                '{"users":[{"userID":%d,"userID":%d,"accountType":"uno"}]}'
                % (peer["userID"], peer["userID"])
            ).encode(),
        ):
            packet = invite[: body_start - 4] + struct.pack("<I", len(body)) + body
            client.task(255, 10, packet, error=106)
            assert path.read_bytes() == original
        checks.append(
            "Ambiguous social mutation JSON rejects duplicate outer and nested account fields before any relationship changes"
        )
        for data in cases:
            damaged = json.dumps(data).encode()
            path.write_bytes(damaged)
            for packet in (read, invite, revoke):
                client.task(255, 10, packet, error=102)
                assert path.read_bytes() == damaged
        # Even a duplicate whose value is identical must not silently disappear.
        damaged = original.replace(b'"schema":1', b'"schema":1,"schema":1', 1)
        assert damaged != original
        path.write_bytes(damaged)
        client.task(255, 10, read, error=102)
        assert path.read_bytes() == damaged
        checks.append(
            "Complete friendship graph rejects malformed accounts, self/reversed/duplicate edges, inconsistent pending consent, oversized names/collections and duplicate persisted JSON keys before reads or writes"
        )

        aliased = deepcopy(graph)
        for row in aliased["friends"]:
            for field in ("a", "b"):
                if row[field]["userID"] == user:
                    row[field]["accountType"] = "bnet"
        saved_alias = json.dumps(aliased).encode()
        path.write_bytes(saved_alias)
        assert response(client.task(255, 10, read))[1]["users"] == [peer]
        assert path.read_bytes() == saved_alias
        # A legitimate idempotent mutation publishes the canonical provider.
        assert response(client.task(255, 10, invite))[1]["friended"] == [peer]
        canonical = json.loads(path.read_bytes())
        assert all(
            row[field]["accountType"] == "uno"
            for row in canonical["friends"]
            for field in ("a", "b")
            if row[field]["userID"] == user
        )
        checks.append(
            "Registered friendship provider aliases reconcile on a private copy; reads preserve bytes and owned idempotent mutations publish the canonical graph"
        )

        path.write_bytes(original)
        pending = path.with_name(path.name + ".pending")
        assert not pending.exists()
        pending.mkdir()
        try:
            client.task(255, 10, revoke, error=102)
            assert path.read_bytes() == original
        finally:
            pending.rmdir()
        assert response(client.task(255, 10, read))[1]["users"] == [peer]
        checks.append(
            "Actual failed friendship publication preserves the accepted relationship and does not acknowledge a removal"
        )
    finally:
        path.write_bytes(original)
