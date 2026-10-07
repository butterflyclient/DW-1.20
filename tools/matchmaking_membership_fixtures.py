"""Encrypted Replay host snapshots, departure transactions and document clocks."""

import copy
import json
import select
import struct
import time


def exercise(host, peer, directory, title, user, peer_user, query, helpers, checks):
    u32, u64, text, boolean = helpers
    root = directory / "matchmaking" / str(title)
    host_token = struct.unpack_from("<Q", host.task(145, 3), 1)[0]
    peer_token = struct.unpack_from("<Q", peer.task(145, 3), 1)[0]
    create = {
        **copy.deepcopy(query),
        "members": [user],
        "tokens": [host_token],
        "lobby_slots": {"min": 1, "max": 2},
        "team_balance": {"num_teams": 2},
        "private_lobby": {"initial_party_id": 23},
    }

    def strings(raw):
        values = []
        while raw:
            assert raw[0] == 16
            end = raw.index(0, 1)
            values.append(json.loads(raw[1:end]))
            raw = raw[end + 1 :]
        return values

    def start(client, request):
        return strings(client.task(145, 18, text(json.dumps(request))))[0]["mm_id"]

    def created(client=host, request=create, party=False):
        mm = start(client, request)
        kind, packet = client.receive()
        assert kind == 2 and packet.startswith(u32(2005) + u64(mm))
        if party:
            lobby = struct.unpack_from("<Q", packet, 15)[0]
            documents = strings(packet[32:])
            path = root / "lobbies" / f"{lobby}.json"
            before = path.read_bytes()
            assert json.loads(before)["pending_join_members"] == [peer_user]
            assert not select.select([peer.s], [], [], 0.35)[0]
            peer.task(
                145, 15, u64(lobby) + u64(documents[1]["update_id"])
                + text(json.dumps(documents[0])), error=101,
            )
            assert host.task(
                145, 15, u64(lobby) + u64(0) + text(json.dumps(documents[0]))
            ) == boolean(False)
            assert path.read_bytes() == before
            assert not select.select([peer.s], [], [], 0.35)[0]
            assert host.task(
                145, 15, u64(lobby) + u64(documents[1]["update_id"])
                + text(json.dumps(documents[0]))
            ) == boolean(True)
            kind, update = host.receive()
            assert kind == 2 and update.startswith(u32(2006) + u64(lobby))
            documents = strings(update[23:])
            # The non-searching party member needs JoinLobby, whose native
            # envelope omits the update-ID field, after the host installs keys.
            assert peer.receive() == (
                2,
                u32(2001) + u64(mm) + u64(lobby) + update[23:],
            )
            assert strings(peer.task(145, 13, u64(lobby))) == documents
            assert "pending_join_members" not in json.loads(path.read_bytes())
            # A second host update must be a document event, never another Join.
            assert host.task(
                145, 15, u64(lobby) + u64(documents[1]["update_id"])
                + text(json.dumps(documents[0]))
            ) == boolean(True)
            kind, update = host.receive()
            assert kind == 2 and update.startswith(u32(2006) + u64(lobby))
            assert peer.receive() == (kind, update)
            checks.append(
                "party JoinLobby waits for an accepted owner host document; stale/non-owner updates do not release it, shared documents match and later updates cannot repeat the join"
            )
            return lobby, mm, strings(update[23:])
        return struct.unpack_from("<Q", packet, 15)[0], mm, strings(packet[32:])

    def join(lobby):
        request = {
            "members": [peer_user],
            "tokens": [peer_token],
            "lobby_id_to_presence_join": lobby,
        }
        mm = start(peer, request)
        kind, packet = peer.receive()
        assert kind == 2 and packet.startswith(u32(2001) + u64(mm) + u64(lobby))
        documents = strings(packet[23:])
        assert host.receive()[1].startswith(u32(2006) + u64(lobby))
        return mm, documents

    def snapshot():
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*.json")
        }

    def update(lobby, documents, states, revision=None, error=0):
        changed = copy.deepcopy(documents[0])
        changed["player_state"] = states
        expected = documents[1]["update_id"] if revision is None else revision
        return host.task(
            145, 15, u64(lobby) + u64(expected) + text(json.dumps(changed)), error=error
        )

    def updated(lobby, members, previous_time):
        kind, packet = host.receive()
        assert kind == 2 and packet.startswith(u32(2006) + u64(lobby))
        documents = strings(packet[23:])
        assert documents == strings(host.task(145, 13, u64(lobby)))
        state = json.loads((root / "lobbies" / f"{lobby}.json").read_bytes())
        assert set(state["members"]) == set(members)
        assert (
            documents[0]["update_time"] == documents[1]["update_time"] > previous_time
        )
        return state, documents

    def disband(client, lobby, party=False):
        assert client.task(145, 10, u64(lobby)) == []
        packet = (2, u32(2002) + u64(lobby) + u64(0))
        assert client.receive() == packet
        if party:
            assert peer.receive() == packet

    lobby, host_mm, documents = created()
    peer_mm, documents = join(lobby)
    before = snapshot()
    peer.task(145, 15, u64(lobby) + u64(2) + text(json.dumps(documents[0])), error=101)
    for states in (
        {str(peer_user): 2},
        {str(user): 4},
        {str(user): 5},
        {str(user): 2, str(peer_user + 1): 2},
    ):
        update(lobby, documents, states, error=106)
        assert snapshot() == before
    checks.append(
        "host snapshots reject non-owner updates, missing/removing host, invalid status and unknown members without changing durable state"
    )

    # The first native stage is WONT_CONNECT (3), acknowledged until the next
    # complete host snapshot omits it as READY_TO_REMOVE (4).
    assert update(lobby, documents, {str(user): 2, str(peer_user): 3}) == boolean(True)
    _, documents = updated(lobby, [user, peer_user], documents[1]["update_time"])
    assert peer.receive()[1].startswith(u32(2006) + u64(lobby))
    assert update(lobby, documents, {str(user): 2}) == boolean(True)
    state, current = updated(lobby, [user], documents[1]["update_time"])
    for field in ("players", "player_id_to_mm_id", "player_id_to_service_level"):
        assert set(state["backend_doc"][field]) == {str(user)}
    assert state["backend_doc"]["listen_server"]["lobby_host_order"] == [user]
    assert state["backend_doc"]["team_balance"]["teams"] == {"0": [user], "1": []}
    index = json.loads((root / "current-lobbies.json").read_bytes())["lobbies"]
    assert index[str(user)] == lobby and str(peer_user) not in index
    assert (
        json.loads((root / "searches" / f"{peer_mm}.json").read_bytes())["active"]
        is False
    )
    assert (
        json.loads((root / "searches" / f"{host_mm}.json").read_bytes())["active"]
        is True
    )
    peer.task(145, 13, u64(lobby), error=101)
    # A racing old host snapshot receives the ordinary native false result,
    # rather than reviving the retired player or returning a layout error.
    before = snapshot()
    assert update(lobby, documents, documents[0]["player_state"]) == boolean(False)
    assert snapshot() == before
    new_mm, rejoined = join(lobby)
    assert (
        new_mm != peer_mm
        and len(
            json.loads((root / "lobbies" / f"{lobby}.json").read_bytes())["members"]
        )
        == 2
    )
    assert rejoined[1]["update_time"] > current[1]["update_time"]
    disband(host, lobby, True)
    checks.append(
        "native WONT_CONNECT acknowledgment then omitted READY_TO_REMOVE releases member/team/capacity/index/search state; stale snapshots cannot resurrect it and a fresh join succeeds"
    )

    # One search can represent an entire party: removing one member must not
    # cancel the retained member's shared search. Optional per-player fields and
    # squads are the complete layout, not just the fields populated at creation.
    party = {
        **copy.deepcopy(create),
        "members": [user, peer_user],
        "tokens": [host_token, peer_token],
        "lobby_slots": {"min": 1, "max": 4},
    }
    lobby, shared_mm, documents = created(request=party, party=True)
    path = root / "lobbies" / f"{lobby}.json"
    stored = json.loads(path.read_bytes())
    stored["backend_doc"]["team_balance"]["squads"] = {"0": [user, peer_user]}
    stored["backend_doc"]["team_balance"]["squad_size"] = 2
    stored["backend_doc"]["player_id_to_performance"] = {
        str(user): 1,
        str(peer_user): 2,
    }
    stored["backend_doc"]["player_id_to_slots"] = {str(user): 1, str(peer_user): 1}
    path.write_text(json.dumps(stored))
    replacement = {
        **copy.deepcopy(create),
        "members": [peer_user],
        "tokens": [peer_token],
        "player_id_to_slots": {str(peer_user): 0},
    }
    newer_lobby, newer_mm, _ = created(peer, replacement)
    assert update(lobby, documents, {str(user): 2, str(peer_user): 4}) == boolean(True)
    state, documents = updated(lobby, [user], documents[1]["update_time"])
    assert state["backend_doc"]["team_balance"]["squads"] == {"0": [user]}
    assert state["backend_doc"]["player_id_to_performance"] == {str(user): 1}
    assert state["backend_doc"]["player_id_to_slots"] == {str(user): 1}
    assert (
        json.loads((root / "searches" / f"{shared_mm}.json").read_bytes())["active"]
        is True
    )
    assert (
        json.loads((root / "searches" / f"{newer_mm}.json").read_bytes())["active"]
        is True
    )
    assert (
        json.loads((root / "current-lobbies.json").read_bytes())["lobbies"][
            str(peer_user)
        ]
        == newer_lobby
    )
    disband(host, lobby)
    disband(peer, newer_lobby)
    checks.append(
        "explicit READY_TO_REMOVE clears squads/performance/slots while preserving a shared party search and a newer player lobby assignment"
    )

    lobby, _, documents = created()
    peer_mm, documents = join(lobby)
    # A valid future clock makes this check independent of host scheduling or
    # second boundaries: both consecutive updates must advance beyond it.
    path = root / "lobbies" / f"{lobby}.json"
    stored = json.loads(path.read_bytes())
    future = int(time.time()) + 100
    stored["backend_doc"]["update_time"] = future
    path.write_text(json.dumps(stored))
    block = root / "current-lobbies.json.pending"
    block.mkdir()
    try:
        update(lobby, documents, {str(user): 2}, error=102)
        journal = json.loads((root / "transaction.json").read_bytes())
        assert journal["phase"] == "prepared" and len(journal["writes"]) == 3
        host.task(145, 13, u64(lobby), error=102)
    finally:
        block.rmdir()
    documents = strings(host.task(145, 13, u64(lobby)))
    assert documents[1]["update_time"] == future + 1
    assert (
        json.loads((root / "current-lobbies.json").read_bytes())["lobbies"].get(
            str(peer_user)
        )
        != lobby
    )
    assert (
        json.loads((root / "searches" / f"{peer_mm}.json").read_bytes())["active"]
        is False
    )
    assert json.loads((root / "transaction.json").read_bytes())["phase"] == "applied"
    assert update(lobby, documents, {str(user): 2}) == boolean(True)
    _, documents = updated(lobby, [user], future + 1)
    assert documents[1]["update_time"] == future + 2
    before = snapshot()
    stored = json.loads(path.read_bytes())
    saved = path.read_bytes()
    stored["backend_doc"]["update_time"] = 2**64 - 1
    path.write_text(json.dumps(stored))
    try:
        overflow_before = snapshot()
        update(lobby, documents, {str(user): 2}, error=106)
        assert snapshot() == overflow_before
    finally:
        path.write_bytes(saved)
    assert snapshot() == before
    disband(host, lobby)
    checks.append(
        "member removal recovers after a real blocked index write; document timestamps strictly advance across rapid updates and reject UInt64 overflow without mutations"
    )
