"""Exact Replay presence-join request/event contracts, without launching maps."""

import json
import struct
import time


def exercise(
    host,
    peer,
    directory,
    title,
    host_user,
    peer_user,
    player_info,
    query,
    helpers,
    checks,
):
    u32, u64, text, boolean = helpers

    def strings(raw):
        values = []
        while raw:
            assert raw[0] == 16
            end = raw.index(0, 1)
            values.append(raw[1:end].decode())
            raw = raw[end + 1 :]
        return values

    def start(client, request, error=0):
        raw = client.task(145, 18, text(json.dumps(request)), error=error)
        return json.loads(strings(raw)[0])["mm_id"] if not error else None

    def documents(client, lobby):
        return list(map(json.loads, strings(client.task(145, 13, u64(lobby)))))

    peer.task(145, 2, text(json.dumps(player_info)))
    peer_token = struct.unpack_from("<Q", peer.task(145, 3), 1)[0]
    host_token = struct.unpack_from("<Q", host.task(145, 3), 1)[0]
    create = {
        **query,
        "members": [host_user],
        "tokens": [host_token],
        "lobby_slots": {"min": 1, "max": 2},
    }
    full_mm = start(host, {**create, "lobby_slots": {"min": 1, "max": 1}})
    kind, payload = host.receive()
    assert kind == 2 and payload.startswith(u32(2005) + u64(full_mm))
    full_lobby = struct.unpack_from("<Q", payload, 15)[0]
    full_path = (
        directory / "matchmaking" / str(title) / "lobbies" / f"{full_lobby}.json"
    )
    full_before = full_path.read_bytes()
    start(
        peer,
        {
            "members": [peer_user],
            "tokens": [peer_token],
            "lobby_id_to_presence_join": full_lobby,
        },
        108,
    )
    assert full_path.read_bytes() == full_before
    assert host.task(145, 10, u64(full_lobby)) == []
    assert host.receive() == (2, u32(2002) + u64(full_lobby) + u64(0))
    checks.append(
        "a valid full lobby rejects another signed member without changing its persisted documents"
    )
    original_mm = start(host, create)
    kind, payload = host.receive()
    assert kind == 2 and payload.startswith(u32(2005) + u64(original_mm))
    lobby = struct.unpack_from("<Q", payload, 15)[0]
    host_doc, backend = map(json.loads, strings(payload[32:]))
    path = directory / "matchmaking" / str(title) / "lobbies" / f"{lobby}.json"
    join = {
        "members": [peer_user],
        "tokens": [peer_token],
        "lobby_id_to_presence_join": lobby,
    }
    before = path.read_bytes()
    for altered, code in (
        ({**join, "tokens": [peer_token + 1]}, 14507),
        ({**join, "lobby_id_to_presence_join": 0}, 106),
        ({**join, "lobby_id_to_presence_join": 2**64 - 1}, 106),
        ({**join, "player_id_to_presence_join": host_user}, 106),
        ({**join, "lobby_id_to_presence_join": lobby + 1}, 108),
        (
            {
                "members": [peer_user],
                "tokens": [peer_token],
                "player_id_to_presence_join": host_user + 1,
            },
            108,
        ),
    ):
        start(peer, altered, code)
        assert path.read_bytes() == before

    # The existing host controls its presence-join flag through native CAS.
    def update(document, revision):
        assert host.task(
            145, 15, u64(lobby) + u64(revision) + text(json.dumps(document))
        ) == boolean(True)
        kind, push = host.receive()
        assert kind == 2 and push.startswith(u32(2006) + u64(lobby) + u64(revision + 1))
        return list(map(json.loads, strings(push[23:])))

    closed, backend = update({**host_doc, "lobby_open_for_pres_join": False}, 1)
    start(peer, join, 108)
    host_doc, backend = update({**closed, "lobby_open_for_pres_join": True}, 2)
    checks.append(
        "Replay presence-join fields bypass new-playlist creation; signed party tokens, target IDs and host join policy reject invalid requests without lobby mutations"
    )

    joined_mm = start(peer, join)
    kind, push = peer.receive()
    assert kind == 2 and push.startswith(u32(2001) + u64(joined_mm) + u64(lobby))
    joined_docs = list(map(json.loads, strings(push[23:])))
    kind, updated = host.receive()
    assert kind == 2 and updated.startswith(u32(2006) + u64(lobby) + u64(4))
    assert list(map(json.loads, strings(updated[23:]))) == joined_docs
    assert documents(host, lobby) == documents(peer, lobby) == joined_docs
    joined_host, joined_backend = joined_docs
    assert joined_host["listen_server"] == host_doc["listen_server"]
    assert joined_backend["dtls"] == backend["dtls"]
    assert joined_backend["ruleset_payload"] == backend["ruleset_payload"]
    assert joined_backend["player_id_to_mm_id"] == {
        str(host_user): original_mm,
        str(peer_user): joined_mm,
    }
    assert joined_host["player_state"] == {str(host_user): 2, str(peer_user): 2}
    assert joined_backend["listen_server"]["lobby_host_order"] == [host_user, peer_user]
    assert sorted(joined_backend["team_balance"]["teams"]["0"]) == sorted(
        [host_user, peer_user]
    )
    peer.task(145, 15, u64(lobby) + u64(4) + text(json.dumps(joined_host)), error=101)
    checks.append(
        "native event-2001 assigned only to joining party, event-2006 sent to existing members; shared lobby revisions/host/DTLS/playlist maps and per-player matchmaking IDs preserved"
    )

    # Explicit by-player lookup uses the current assignment, rather than an
    # arbitrary stale lobby from the creator's previous searches.
    by_player = {
        "members": [peer_user],
        "tokens": [peer_token],
        "player_id_to_presence_join": host_user,
    }
    next_mm = start(peer, by_player)
    assert peer.receive()[1].startswith(u32(2001) + u64(next_mm) + u64(lobby))
    assert host.receive()[1].startswith(u32(2006) + u64(lobby) + u64(5))
    assert len(json.loads(path.read_bytes())["members"]) == 2
    checks.append(
        "presence-by-player resolves the persisted current lobby and repeated joins retain unique membership while binding the new owner search"
    )

    # Cancel before delivery; the queued join cannot escape as a stale native
    # callback. Existing members still receive their committed document change.
    cancelled = start(peer, join)
    assert peer.task(145, 8, u64(cancelled)) == boolean(True)
    assert host.receive()[1].startswith(u32(2006) + u64(lobby) + u64(6))
    time.sleep(0.35)
    assert peer.task(12, 6).startswith(b"\x08")
    checks.append(
        "cancelled presence searches suppress their queued join event while preserving the committed lobby update"
    )

    superseded = start(peer, join)
    latest = start(peer, join)
    assert superseded != latest
    assert peer.receive()[1].startswith(u32(2001) + u64(latest) + u64(lobby))
    assert host.receive()[1].startswith(u32(2006) + u64(lobby) + u64(7))
    assert host.receive()[1].startswith(u32(2006) + u64(lobby) + u64(8))
    assert peer.task(12, 6).startswith(b"\x08")
    checks.append(
        "a superseded presence assignment cannot deliver an old native join callback after a newer search has replaced that member's matchmaking ID"
    )

    saved = path.read_bytes()
    policy_path = directory / "playlists" / str(title) / "policy.json"
    policy = policy_path.read_bytes()
    blocked = json.loads(policy)
    blocked["available_maps"] = []
    policy_path.write_text(json.dumps(blocked))
    start(peer, join, 108)
    assert path.read_bytes() == saved
    policy_path.write_bytes(policy)
    checks.append(
        "current installed-map/playlist publication is rechecked; joining does not substitute unavailable map data"
    )
    assert host.task(145, 10, u64(lobby)) == []
    assert host.receive() == peer.receive() == (2, u32(2002) + u64(lobby) + u64(0))
    start(peer, by_player, 108)
    return {"id": lobby, "path": path}


def prepare_offline_lobby(peer, peer_user, query, helpers):
    u32, u64, text, boolean = helpers
    token = struct.unpack_from("<Q", peer.task(145, 3), 1)[0]
    peer.task(
        145, 18, text(json.dumps({**query, "members": [peer_user], "tokens": [token]}))
    )
    kind, packet = peer.receive()
    assert kind == 2 and packet.startswith(u32(2005))
    return struct.unpack_from("<Q", packet, 15)[0]


def reject_offline_owner(
    client, peer_user, lobby, directory, title, user, helpers, checks
):
    u32, u64, text, boolean = helpers
    token = struct.unpack_from("<Q", client.task(145, 3), 1)[0]
    path = directory / "matchmaking" / str(title) / "lobbies" / f"{lobby}.json"
    before = path.read_bytes()
    for field, target in (
        ("lobby_id_to_presence_join", lobby),
        ("player_id_to_presence_join", peer_user),
    ):
        client.task(
            145,
            18,
            text(json.dumps({"members": [user], "tokens": [token], field: target})),
            error=108,
        )
        assert path.read_bytes() == before
    checks.append(
        "unexpired persisted lobbies and current-player assignments do not revive disconnected hosts; both presence targets reject without a document mutation"
    )
