"""Real two-account encrypted clan push lifecycle; isolated fixture only."""


def run(
    client,
    peer,
    user,
    peer_user,
    group_id,
    checks,
    structure,
    u32,
    integer,
    binary,
    text,
    fields,
):
    def account(uid):
        return integer(1, uid) + text(2, "uno")

    def group(gid):
        return integer(1, 1) + integer(2, gid) + integer(3, 0) + integer(4, 0)

    selected = group(group_id)

    def receive(who, event):
        kind, raw = who.receive()
        prefix = u32(event) + b"\x17"
        assert kind == 2 and raw.startswith(prefix) and raw[6] == 8
        import struct

        size = struct.unpack_from("<I", raw, 7)[0]
        assert len(raw) == size + 11
        return fields(raw[11:])

    def invitation(gid, uid, role=2):
        proposal = (
            binary(1, account(uid)) + integer(2, role) + binary(3, b"push attachment")
        )
        return structure(binary(1, group(gid)) + binary(2, proposal))

    def update_member(who, uid, role):
        return who.task(
            197,
            23,
            structure(
                binary(1, selected)
                + integer(2, role)
                + binary(3, account(uid))
                + integer(4, 0)
            ),
            structured=True,
        )

    request = invitation(group_id, peer_user)
    reply = fields(client.task(197, 25, request, structured=True))
    proposal = receive(peer, 77)
    assert proposal == fields(reply[1][0]) and set(proposal) == set(range(1, 8))
    assert fields(proposal[1][0]) == {1: [user], 2: [b"uno"], 3: [b"DWPlayer#0"]}
    assert fields(proposal[2][0]) == {
        1: [peer_user],
        2: [b"uno"],
        3: [b"Fixture Peer#0"],
    }
    client.task(197, 25, request, structured=True)
    assert peer.task(12, 6)[0] == 8  # Retry emitted no extra invitation.
    peer.task(
        197,
        23,
        structure(binary(1, selected) + integer(2, 2) + integer(4, 0)),
        structured=True,
    )
    removed, added = receive(client, 79), receive(client, 78)
    assert fields(removed[1][0])[1] == [peer_user] and removed[3] == [0]
    assert added == {
        1: [selected],
        2: [account(peer_user) + text(3, "Fixture Peer#0")],
        3: [2],
    }
    assert fields(receive(client, 82)[1][0])[2] == [group_id]
    client.task(
        197, 22, structure(selected + text(5, "Push Test Regiment")), structured=True
    )
    assert receive(peer, 83)[5] == [b"Push Test Regiment"]
    client.task(
        197, 22, structure(selected + text(5, "Push Test Regiment")), structured=True
    )
    assert peer.task(12, 6)[0] == 8  # Unchanged metadata is not a new edit.
    client.task(
        197, 22, structure(selected + text(5, "Fixture Regiment")), structured=True
    )
    assert receive(peer, 83)[5] == [b"Fixture Regiment"]

    update_member(client, peer_user, 1)
    assert receive(peer, 84)[3] == [1]
    outgoing = structure(binary(1, selected) + integer(2, 0) + text(3, ""))
    assert peer.task(197, 27, outgoing, structured=True) == client.task(
        197, 27, outgoing, structured=True
    )
    assert fields(update_member(peer, peer_user, 0))[3] == [1]
    update_member(client, peer_user, 3)
    changes = [receive(peer, 84), receive(peer, 84)]
    assert {fields(row[2][0])[1][0]: row[3][0] for row in changes} == {
        user: 2,
        peer_user: 3,
    }
    assert fields(receive(peer, 83)[6][0])[1] == [peer_user]
    update_member(peer, user, 3)
    changes = [receive(client, 84), receive(client, 84)]
    assert {fields(row[2][0])[1][0]: row[3][0] for row in changes} == {
        user: 3,
        peer_user: 2,
    }
    assert fields(receive(client, 83)[6][0])[1] == [user]
    checks.append(
        "complete native clan pushes 77/78/79/83/84, separately authenticated recipients, retries and ownership-transfer role updates"
    )

    create = structure(
        integer(1, 1)
        + integer(3, 0)
        + integer(4, 0)
        + text(5, "Push Peer Regiment")
        + integer(7, 3)
        + text(12, "PUSH")
    )
    peer_group = fields(peer.task(197, 20, create, structured=True))[2][0]
    peer.task(197, 37, structure(binary(1, group(peer_group))), structured=True)
    # Members of the old group need to clear this user's active flag too.
    assert fields(receive(client, 82)[1][0])[2] == [peer_group]
    peer.task(197, 37, structure(binary(1, selected)), structured=True)
    active = receive(client, 82)
    assert (
        fields(active[1][0])[2] == [group_id]
        and fields(active[2][0])[1] == [peer_user]
        and active[3] == [2]
    )
    client.task(
        197,
        24,
        structure(binary(1, selected) + binary(2, account(peer_user))),
        structured=True,
    )
    departed = receive(peer, 80)
    assert fields(departed[2][0])[1] == [peer_user] and departed[3] == [2]
    cleared = receive(peer, 82)
    assert fields(cleared[1][0])[2] == [0] and fields(cleared[2][0])[1] == [peer_user]
    peer.task(197, 27, outgoing, error=101)
    checks.append(
        "native ordinary-member activation can read outgoing proposals; departed accounts cannot access them"
    )
    peer.task(197, 25, invitation(peer_group, user), structured=True)
    assert fields(receive(client, 77)[4][0])[2] == [peer_group]
    peer.task(197, 24, structure(binary(1, group(peer_group))), structured=True)
    assert fields(receive(client, 79)[2][0])[2] == [peer_group]
    assert receive(client, 81)[2] == [peer_group]
    assert client.task(12, 6)[0] == 8 and peer.task(12, 6)[0] == 8
    checks.append(
        "native active-group/member-removal/disband pushes 82/80/81 and outstanding invitation withdrawal on clan deletion"
    )
