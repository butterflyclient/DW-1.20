"""Independent clan transition checks; fixture data only, no native game."""

import json
import time


def run(
    client, directory, title, user, checks, structure, integer, binary, text, fields
):
    path = directory / "clans" / str(title) / "groups.json"
    before = path.read_bytes()

    def account(uid):
        return integer(1, uid) + text(2, "uno")

    def group(gid):
        return integer(1, 1) + integer(2, gid) + integer(3, 0) + integer(4, 0)

    def invite(gid, uid):
        proposal = binary(1, account(uid)) + integer(2, 1) + binary(3, b"")
        return structure(binary(1, group(gid)) + binary(2, proposal))

    def remove(gid, uid, seconds):
        row = binary(1, account(uid)) + binary(2, group(gid)) + integer(3, seconds)
        return structure(binary(1, row))

    def switch(gid, old, role=1, uid=None):
        request = binary(1, group(gid)) + integer(2, role)
        if uid is not None:
            request += binary(3, account(uid))
        return structure(request + integer(4, old))

    def row(gid, owner, name, members, proposals=()):
        return {
            "kind": 1,
            "id": gid,
            "root_kind": 0,
            "root_id": 0,
            "title": title,
            "name": name,
            "tag": name,
            "privacy": 3,
            "owner": owner,
            "created": int(time.time()),
            "members": members,
            "proposals": list(proposals),
            "files": {},
        }

    def member(uid, role=1):
        return {
            "user": uid,
            "role": role,
            "name": "DWPlayer" if uid == user else "Peer",
        }

    def proposal(owner):
        return {
            "proposer": owner,
            "proposer_name": "Peer",
            "target": user,
            "target_name": "DWPlayer",
            "role": 1,
            "attachment": "",
            "updated": int(time.time()),
        }

    try:
        data = json.loads(before)
        owned = next(g for g in data["groups"] if g["owner"] == user)["id"]
        # Exact native acceptance request leaves role=0; preserve a member's
        # role rather than rejecting the default or treating it as promotion.
        unchanged = path.read_bytes()
        result = fields(client.task(197, 23, switch(owned, 0, role=0), structured=True))
        assert result[3] == [3] and path.read_bytes() == unchanged
        client.task(197, 23, switch(owned, 0, role=4), error=106)
        assert path.read_bytes() == unchanged
        target = user + 71
        client.task(197, 25, invite(owned, target), structured=True)
        removed = fields(
            client.task(197, 26, remove(owned, target, 3600), structured=True)
        )
        assert fields(removed[1][0])[3] == [3600]
        cooled = path.read_bytes()
        client.task(197, 26, remove(owned, target, 3600), structured=True)
        assert path.read_bytes() == cooled  # Retry does not reset the clock.
        client.task(197, 25, invite(owned, target), error=106)
        assert path.read_bytes() == cooled
        corrupt = json.loads(cooled)
        record = next(g for g in corrupt["groups"] if g["id"] == owned)["cooldowns"][
            str(target)
        ]
        record["seconds"] = -1
        path.write_text(json.dumps(corrupt))
        client.task(197, 25, invite(owned, target), error=102)
        path.write_bytes(cooled)
        expired = json.loads(cooled)
        record = next(g for g in expired["groups"] if g["id"] == owned)["cooldowns"][
            str(target)
        ]
        record["recorded"] = int(time.time()) - 3601
        path.write_text(json.dumps(expired))
        client.task(197, 25, invite(owned, target), structured=True)
        assert (
            str(target)
            not in next(
                g for g in json.loads(path.read_text())["groups"] if g["id"] == owned
            )["cooldowns"]
        )
        checks.append(
            "persisted invitation cooldown, retry clock stability, expiry and corrupt interval rejection"
        )

        # Replace a non-owner membership; the active selection follows it.
        old, new = 810000001, 810000002
        data = json.loads(before)
        data["groups"] += [
            row(old, user + 72, "OLD", [member(user + 72, 3), member(user)]),
            row(new, user + 73, "NEW", [member(user + 73, 3)], [proposal(user + 73)]),
        ]
        data["active"][str(user)] = old
        path.write_text(json.dumps(data))
        request = switch(new, old)
        result = fields(client.task(197, 23, request, structured=True))
        assert (
            fields(result[1][0])[1] == [user]
            and fields(result[2][0])[2] == [new]
            and result[3] == [1]
        )
        switched = path.read_bytes()
        data = json.loads(switched)
        assert data["active"][str(user)] == new
        assert not any(
            m["user"] == user
            for g in data["groups"]
            if g["id"] == old
            for m in g["members"]
        )
        assert any(
            m["user"] == user
            for g in data["groups"]
            if g["id"] == new
            for m in g["members"]
        )
        assert (
            fields(client.task(197, 23, request, structured=True)) == result
            and path.read_bytes() == switched
        )

        # Refusal must not remove the old membership, including a later error.
        data = json.loads(before)
        data["groups"] += [
            row(old, user + 72, "OLD", [member(user + 72, 3), member(user)]),
            row(new, user + 73, "NEW", [member(user + 73, 3)]),
        ]
        data["active"][str(user)] = old
        path.write_text(json.dumps(data))
        unchanged = path.read_bytes()
        client.task(197, 23, switch(new, old), error=101)
        assert path.read_bytes() == unchanged
        client.task(197, 23, switch(new, old, uid=user + 72), error=101)
        assert path.read_bytes() == unchanged
        client.task(197, 23, switch(new, old, role=3), error=101)
        assert path.read_bytes() == unchanged
        # Owner cannot strand a group with other members.
        data = json.loads(before)
        owned_group = next(g for g in data["groups"] if g["owner"] == user)
        owned_group["members"].append(member(user + 74))
        data["groups"].append(
            row(new, user + 73, "NEW", [member(user + 73, 3)], [proposal(user + 73)])
        )
        path.write_text(json.dumps(data))
        unchanged = path.read_bytes()
        client.task(197, 23, switch(new, owned), error=106)
        assert path.read_bytes() == unchanged
        # A sole-owned group may be left and removed; it precedes the new array
        # member to exercise pointer invalidation during erase.
        owned_group["members"].pop()
        path.write_text(json.dumps(data))
        accepted = fields(
            client.task(197, 23, switch(new, owned, role=0), structured=True)
        )
        assert accepted[3] == [1]
        assert not any(g["id"] == owned for g in json.loads(path.read_text())["groups"])
        assert (
            len(
                fields(
                    client.task(
                        197, 21, structure(binary(1, group(new))), structured=True
                    )
                )[1]
            )
            == 1
        )
        checks.append(
            "atomic clan membership replacement, active-group transfer, owner/consent safeguards, retry and erased-array stability"
        )

        for field in ("id", "owner", "created", "privacy", "title", "root_kind"):
            broken = json.loads(before)
            broken["groups"][0][field] = -1
            path.write_text(json.dumps(broken))
            client.task(197, 21, structure(binary(1, group(owned))), error=102)
        broken = json.loads(before)
        broken["groups"][0]["members"][0]["role"] = 65539
        path.write_text(json.dumps(broken))
        client.task(197, 21, structure(binary(1, group(owned))), error=102)
        checks.append(
            "full clan persistence numeric/type bounds reject wrapping IDs, roles and timestamps"
        )
    finally:
        path.write_bytes(before)

    # Leave an unrelated cooldown in the fixture to verify restart persistence.
    target = user + 79
    client.task(197, 25, invite(owned, target), structured=True)
    client.task(197, 26, remove(owned, target, 86400), structured=True)
    return {"invite": invite(owned, target), "path": path}
