"""Exercise native channel member updates with independent signed accounts."""

import copy
import json

from tournament_fixtures import no_update


def exercise(directory, title, new_client, helpers, checks):
    u64, text, structure, pb_text, pb_integer, pb_bytes, pb_fields = helpers
    clients = [new_client(60 + index) for index in range(3)]
    owner, peer, third = (connection for _, connection in clients)
    owner_id, peer_id, third_id = (user for user, _ in clients)
    names = {
        user: f"Tournament Fixture {60 + index}"
        for index, (user, _) in enumerate(clients)
    }
    path = directory / "channels" / f"{title}.json"
    category = "party"

    def request(channel=0, subscriber=0):
        return structure(
            pb_text(1, category) + pb_integer(2, channel) + pb_integer(3, subscriber)
        )

    def row(channel):
        return json.loads(path.read_bytes())["channels"][f"{category}:{channel}"]

    def receive(connection, actor, joined, channel, count=None):
        kind, packet = connection.receive()
        assert kind == 2
        offset = 0

        def number(tag, size):
            nonlocal offset
            assert packet[offset] == tag
            value = int.from_bytes(packet[offset + 1 : offset + size + 1], "little")
            offset += size + 1
            return value

        def string():
            nonlocal offset
            assert packet[offset] == 16
            end = packet.index(0, offset + 1)
            value = packet[offset + 1 : end].decode()
            offset = end + 1
            return value

        assert number(8, 4) == (24 if joined else 25)
        assert number(10, 8) == actor and string() == names[actor]
        assert string() == category and number(10, 8) == channel
        assert number(8, 4) == 0
        assert string() == category and number(10, 8) == channel
        subscribers = number(8, 4)
        assert count is None or subscribers == count
        assert number(8, 4) == 200 and number(10, 8) == owner_id
        assert number(1, 1) == 0 and number(1, 1) == 0
        revision = number(8, 4)
        assert 0 < revision <= row(channel)["revision"] and offset == len(packet)
        return revision

    def info(connection, channel):
        query = structure(
            pb_bytes(
                1, pb_text(1, category) + pb_integer(2, channel) + pb_integer(3, 0)
            )
        )
        result = connection.task(198, 7, query, structured=True)
        return dict(
            (tag, value) for tag, _, value in pb_fields(pb_fields(result)[0][2])
        )

    try:
        result = owner.task(198, 6, request(), structured=True)
        channel = dict(
            (tag, value) for tag, _, value in pb_fields(pb_fields(result)[0][2])
        )[2]
        first = info(owner, channel)
        assert first[3] == 1 and first[8] == row(channel)["revision"]
        no_update(owner)
        peer.task(198, 1, request(channel), structured=True)
        second_version = receive(owner, peer_id, True, channel, 2)
        assert second_version > first[8]
        no_update(peer)
        peer.task(198, 1, request(channel), structured=True)
        assert info(peer, channel)[8] == second_version
        no_update(owner)
        checks.append(
            "Native channel event-24 contains full typed member/channel-info DTO, real signed sender/name, subscriber count, admin, booleans and monotonic UInt32 dataVersion; owned repeat subscribe/create is idempotent"
        )

        # A second socket for this same signed identity must not remove membership.
        additional = type(peer)(auth_identity=peer.fixture_auth_identity)
        additional.close()
        no_update(owner)
        assert str(peer_id) in row(channel)["members"]
        peer.close()
        receive(owner, peer_id, False, channel, 1)
        peer = type(peer)(auth_identity=peer.fixture_auth_identity)
        clients[1] = (peer_id, peer)
        no_update(peer)
        peer.task(198, 1, request(channel), structured=True)
        receive(owner, peer_id, True, channel, 2)
        checks.append(
            "Channel membership survives another valid socket closing; last live socket departure emits exact event-25 to peers, and same-session reconnect requires a new owned subscription generation"
        )

        # Remove/rejoin before the 250ms queued leave is written. Obsolete leave
        # must not remove the newly joined native member from the existing peer.
        peer.task(198, 2, request(channel), structured=True)
        peer.task(198, 1, request(channel), structured=True)
        receive(owner, peer_id, True, channel, 2)
        no_update(owner)
        third.task(198, 1, request(channel), structured=True)
        receive(owner, third_id, True, channel, 3)
        receive(peer, third_id, True, channel, 3)
        third.task(198, 12, structure(pb_text(1, category)), structured=True)
        receive(owner, third_id, False, channel, 2)
        receive(peer, third_id, False, channel, 2)
        no_update(third)
        checks.append(
            "Generation revalidation suppresses obsolete queued leave after rapid rejoin; owned category unsubscribe notifies every remaining peer with exact event-25 and removes recipient authority"
        )

        # Distinct concurrent member joins are retained even though the whole
        # channel revision changes between enqueue and transport write.
        peer.task(198, 2, request(channel), structured=True)
        receive(owner, peer_id, False, channel, 1)
        peer.task(198, 1, request(channel), structured=True)
        third.task(198, 1, request(channel), structured=True)
        receive(owner, peer_id, True, channel, 2)
        receive(owner, third_id, True, channel, 3)
        receive(peer, third_id, True, channel, 3)
        no_update(third)
        checks.append(
            "Independent simultaneous channel joins retain both member deltas instead of dropping an earlier join when another account advances the aggregate dataVersion"
        )

        state = json.loads(path.read_bytes())
        for corruption in (
            lambda value: value.update(title=title + 1),
            lambda value: value.update(title=float(title)),
            lambda value: value.update(schema=1.0),
            lambda value: value["channels"][f"{category}:{channel}"].update(
                category="../bad"
            ),
            lambda value: value["channels"][f"{category}:{channel}"].update(
                revision=1 << 32
            ),
            lambda value: value["channels"][f"{category}:{channel}"]["members"][
                str(peer_id)
            ].update(generation=1 << 32),
            lambda value: value["channels"][f"{category}:{channel}"]["members"].update(
                {"01": {"name": "bad", "expires": 1}}
            ),
            lambda value: value["channels"][f"{category}:{channel}"]["members"][
                str(peer_id)
            ].update(name="x" * 64),
            lambda value: value["channels"][f"{category}:{channel}"].update(
                revision=(1 << 32) - 1
            ),
            lambda value: value["channels"][f"{category}:{channel}"].update(
                members={
                    str(index + 1): {"name": "excess", "expires": 1}
                    for index in range(201)
                }
            ),
        ):
            damaged = copy.deepcopy(state)
            corruption(damaged)
            path.write_text(json.dumps(damaged))
            before = path.read_bytes()
            owner.task(198, 2, request(channel), error=102)
            assert path.read_bytes() == before
        valid_document = json.dumps(state)
        for damaged in (
            valid_document.replace('"schema": 1', '"schema": 1, "schema": 1', 1),
            valid_document + "{}",
        ):
            path.write_text(damaged)
            before = path.read_bytes()
            owner.task(198, 2, request(channel), error=102)
            assert path.read_bytes() == before
        path.write_text(json.dumps(state))
        original = path.read_bytes()
        # Block actual publication. No notification may escape an unsaved change.
        blocker = path.with_suffix(".json.pending")
        blocker.mkdir()
        try:
            third.task(198, 2, request(channel), error=102)
            assert path.read_bytes() == original
            no_update(owner)
            no_update(peer)
        finally:
            blocker.rmdir()
        third.task(198, 2, request(channel), structured=True)
        receive(owner, third_id, False, channel, 2)
        receive(peer, third_id, False, channel, 2)
        owner.task(198, 2, request(channel), structured=True)
        receive(peer, owner_id, False, channel, 1)
        peer.task(198, 2, request(channel), structured=True)
        no_update(peer)
        checks.append(
            "Complete channel title/category/key/member/name/revision/generation layouts reject corrupted storage before mutation; real blocked atomic publication emits no phantom leave and an owned retry publishes it once"
        )
    finally:
        for _, connection in clients:
            connection.close()
