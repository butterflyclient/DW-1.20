"""Focused independent-party, native text-chat and earned-XP wire checks."""

import base64
import copy
import json
import select
import struct
import time

from native_wire_client import binary, fields, integer, structure, text as proto_text, u32, u64


def exercise(host, peer, stranger, data, query, tokens, policy, ordinary,
             receive, documents, text, checks):
    policy(True)
    path = data / "playlists/5800/policy.json"
    configured = json.loads(path.read_text())
    configured["minimum_lobby_seconds"] = 60
    path.write_text(json.dumps(configured))
    create = copy.deepcopy(query)
    create.update(members=[host.user], tokens=[tokens[0]])
    create["ruleset_payload"]["join_in_progress"] = False
    mm = documents(ordinary(host, 18, text(json.dumps(create))))[0]["mm_id"]
    kind, created = receive(host)
    assert created.startswith(u32(2005) + u64(mm))
    lobby = struct.unpack_from("<Q", created, 15)[0]
    join = copy.deepcopy(create)
    join.update(members=[peer.user], tokens=[tokens[1]])
    # A distinct first choice with an overlapping Quick Play selection.
    join["ruleset_payload"]["filter"]["playlist_id"] = 2
    join["playlist_config"] = [{"playlist_ids": [1]}]
    join["ruleset_payload"]["join_in_progress"] = True
    joined_mm = documents(ordinary(peer, 18, text(json.dumps(join))))[0]["mm_id"]
    kind, changed = receive(host)
    assert changed.startswith(u32(2006) + u64(lobby))
    docs = documents(changed[23:])
    assert not peer.pushes and not select.select([peer.socket], [], [], 0.1)[0]
    assert ordinary(host, 15, u64(lobby) + u64(docs[1]["update_id"])
                    + text(json.dumps(docs[0]))) == b"\x01\x01"
    kind, joined = receive(peer)
    assert joined.startswith(u32(2001) + u64(joined_mm) + u64(lobby))
    _, changed = receive(host)
    docs = documents(changed[23:])
    assert docs == documents(joined[23:])
    assert docs[1]["team_balance"]["teams"] == {"0": [host.user], "1": [peer.user]}
    names = json.loads((data / "playlists/5800/native-dvar-names.json").read_text())
    assert docs[1]["ruleset_payload"]["dvar_overrides"][names["party_minLobbyTime"]] == 60
    checks.append("independent parties with overlapping playlists and differing JIP preferences share one host-ready lobby with a 60-second native wait")

    def account(client):
        return integer(1, client.user) + proto_text(2, "uno")

    def batch(client, xp):
        event = proto_text(1, "mp_addxp") + integer(2, int(time.time())) + integer(4, 0)
        event += binary(3, proto_text(1, "Param0") + integer(2, xp))
        first_party = integer(1, client.platform_account_id) + proto_text(2, "bnet")
        return binary(1, account(client)) + binary(2, event) + binary(3, first_party) + integer(4, 113)

    def report(entries, request):
        raw = proto_text(1, "5800")
        raw += b"".join(binary(2, batch(client, xp)) for client, xp in entries)
        raw += proto_text(3, base64.urlsafe_b64encode(request).decode().rstrip("="))
        return structure(raw)

    def reward(client, expected):
        kind, packet = receive(client)
        prefix = u32(67) + u64(1) + u64(client.user) + text("uno") + text("5800")
        prefix += b"\x07\x01\0\0\0" + u32(1) + b"\x07\x01\0\0\0"
        assert kind == 2 and packet.startswith(prefix + b"\x10") and packet[-1] == 0
        event = json.loads(packet[len(prefix) + 1:-1])
        assert event["id_"] == 1000000 and event["kind"] == 0
        assert event["multiProgress"]["xp"]["value"] == expected

    request = bytes(range(16))
    packet = report([(host, 1500), (peer, 3500)], request)
    assert host.task(125, 2, packet) == b""
    reward(host, 1500)
    reward(peer, 3500)
    journals = [data / "achievements/5800/5800" / str(c.user) / "events.json" for c in (host, peer)]
    before = [p.read_bytes() for p in journals]
    assert host.task(125, 2, packet) == b""
    assert [p.read_bytes() for p in journals] == before
    for client, expected, rank in ((host, 1500, 0), (peer, 3500, 1)):
        states = fields(client.task(125, 3, structure(
            proto_text(1, "5800") + integer(3, 100) + proto_text(4, "") + integer(8, 0))))
        row = next(fields(row) for row in states[1] if fields(row)[11] == [1000000])
        progress = {fields(p)[1][0].decode(): fields(p)[2][0] for p in row[10]}
        assert progress == {"xp": expected, "rank": rank}
    checks.append("native earned XP updates both host and remote member, persists player rank using Replay thresholds, and cannot double-award a batch retry")
    for sender, entries in ((peer, [(host, 1000)]), (host, [(stranger, 1000)])):
        try:
            sender.task(125, 2, report(entries, bytes(reversed(range(16)))))
            raise AssertionError("Unauthorized progression writer accepted")
        except RuntimeError as error:
            assert "returned 101" in str(error)
        assert [p.read_bytes() for p in journals] == before
    checks.append("non-host and non-member progression submissions cannot modify another player's XP")

    performance = text("5800") + u32(1)
    for client in (host, peer):
        performance += u64(client.user) + b"\x09" + struct.pack("<q", 42)
    assert host.task(152, 1, performance, structured=False) == b""
    for client in (host, peer):
        stored = json.loads((data / "performance/5800/5800" / f"{client.user}.json").read_text())
        assert stored["owner"] == client.user and stored["types"]["1"]["recent"] == [42]
    checks.append("listen-host performance batches retain per-player ownership")

    create_chat = structure(proto_text(1, "chat") + integer(2, 0) + integer(3, host.user))
    channel = fields(host.task(198, 6, create_chat))[1][0]
    channel_id = fields(channel)[2][0]
    subscribe = structure(proto_text(1, "chat") + integer(2, channel_id) + integer(3, peer.user))
    peer.task(198, 1, subscribe)
    kind, membership = receive(host)
    assert kind == 2 and membership.startswith(u32(24) + u64(peer.user))
    body = b"Replay multiplayer chat fixture\0"
    message = structure(proto_text(1, "chat") + integer(2, channel_id)
                        + binary(3, body) + integer(4, 0))
    assert host.task(198, 3, message) == b""
    for client in (host, peer):
        kind, message = receive(client)
        assert kind == 2 and message.startswith(u32(22) + u64(host.user))
        assert body in message
    checks.append("native lobby text channel carries the first message to both subscribed players")
    ordinary(host, 10, u64(lobby))
    ended = (2, u32(2002) + u64(lobby) + u64(0))
    assert receive(host) == ended and receive(peer) == ended

    # The real Replay host writer emits an empty state before a match starts.
    # Its accepted host document must remain available to another solo search.
    mm = documents(ordinary(host, 18, text(json.dumps(create))))[0]["mm_id"]
    _, created = receive(host)
    lobby = struct.unpack_from("<Q", created, 15)[0]
    docs = documents(created[32:])
    docs[0]["game_state"] = {"state": ""}
    assert ordinary(host, 15, u64(lobby) + u64(docs[1]["update_id"])
                    + text(json.dumps(docs[0]))) == b"\x01\x01"
    receive(host)
    joined_mm = documents(ordinary(peer, 18, text(json.dumps(join))))[0]["mm_id"]
    _, joined = receive(peer)
    assert joined.startswith(u32(2001) + u64(joined_mm) + u64(lobby))
    receive(host)
    checks.append("Replay's empty waiting-state host document admits a compatible independent party")
    ordinary(host, 10, u64(lobby))
    ended = (2, u32(2002) + u64(lobby) + u64(0))
    assert receive(host) == ended and receive(peer) == ended
