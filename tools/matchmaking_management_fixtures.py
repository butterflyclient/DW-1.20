"""Focused current-assignment, overlapping-party and host-shape contracts."""

import copy
import json
import select
import struct
import time


def exercise(clients, data, query, tokens, policy, ordinary, receive, documents, text, u32, u64, checks):
    host, peer, third, fourth = clients
    root = data / "matchmaking" / "5800"
    policy(False)

    def snapshot():
        return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*.json")}

    def reject(client, task, payload, error=108):
        before = snapshot()
        try:
            ordinary(client, task, payload)
            raise AssertionError("Rejected management mutation succeeded")
        except RuntimeError as failure:
            assert "returned " + str(error) in str(failure)
        assert snapshot() == before

    def drain():
        time.sleep(0.35)
        for client in clients:
            while client.pushes or select.select([client.socket], [], [], 0)[0]:
                receive(client)

    def create(client, request, companions=()):
        mm = documents(ordinary(client, 18, text(json.dumps(request))))[0]["mm_id"]
        _, created = receive(client)
        assert created.startswith(u32(2005) + u64(mm))
        lobby = struct.unpack_from("<Q", created, 15)[0]
        docs = documents(created[32:])
        assert ordinary(client, 15, u64(lobby) + u64(docs[1]["update_id"])
                        + text(json.dumps(docs[0]))) == b"\x01\x01"
        _, updated = receive(client)
        for companion in companions:
            assert receive(companion) == (2, u32(2001) + u64(mm) + u64(lobby) + updated[23:])
        return lobby, documents(updated[23:])

    lobby, current = create(host, query, (peer,))
    for field, value in (("game_state", []), ("game_state", {"state": 2}),
                         ("lobby_open", "true"), ("lobby_open_for_pres_join", 1)):
        malformed = copy.deepcopy(current[0])
        malformed[field] = value
        before = snapshot()
        try:
            ordinary(host, 15, u64(lobby) + u64(current[1]["update_id"])
                     + text(json.dumps(malformed)))
            raise AssertionError("Malformed host field accepted: " + field)
        except RuntimeError as error:
            assert "returned 106" in str(error)
        assert snapshot() == before

    # Native host parsing does not require game_state. Missing state must keep
    # the same waiting semantics as the already-supported empty native state.
    missing = copy.deepcopy(current[0])
    del missing["game_state"]
    assert ordinary(host, 15, u64(lobby) + u64(current[1]["update_id"])
                    + text(json.dumps(missing))) == b"\x01\x01"
    _, updated = receive(host)
    assert receive(peer) == (2, updated)
    current = documents(updated[23:])
    assert "game_state" not in current[0]
    assert documents(ordinary(host, 13, u64(lobby))) == current
    ready = copy.deepcopy(current[0])
    ready["dw_bot_count"] = 1
    assert ordinary(host, 15, u64(lobby) + u64(current[1]["update_id"])
                    + text(json.dumps(ready))) == b"\x01\x01"
    _, updated = receive(host)
    assert receive(peer) == (2, updated)
    current = documents(updated[23:])
    checks.append("optional host game state remains readable and waiting/start-ready; wrong game-state/open-flag types reject before publication")

    joining = {"members": [peer.user, third.user], "tokens": [tokens[1], tokens[2]],
               "lobby_id_to_presence_join": lobby}
    mm = documents(ordinary(third, 18, text(json.dumps(joining))))[0]["mm_id"]
    _, joined = receive(third)
    assert joined.startswith(u32(2001) + u64(mm) + u64(lobby))
    assert receive(peer) == (2, joined)
    _, observed = receive(host)
    current = documents(joined[23:])
    assert documents(observed[23:]) == current
    assert current[1]["team_balance"]["teams"] == {
        "0": [host.user, peer.user, third.user], "1": []}
    checks.append("overlapping normal MP party stays on its retained member's team instead of splitting onto the least occupied team")

    newer = {**copy.deepcopy(query), "members": [peer.user], "tokens": [tokens[1]],
             "private_lobby": {"initial_party_id": 904}}
    newer_lobby, _ = create(peer, newer)
    joining = {"members": [fourth.user], "tokens": [tokens[3]],
               "lobby_id_to_presence_join": lobby}
    mm = documents(ordinary(fourth, 18, text(json.dumps(joining))))[0]["mm_id"]
    assert receive(fourth)[1].startswith(u32(2001) + u64(mm) + u64(lobby))
    for observer in (host, third):
        assert receive(observer)[1].startswith(u32(2006) + u64(lobby))
    index = json.loads((root / "current-lobbies.json").read_bytes())
    assert index["lobbies"][str(peer.user)] == newer_lobby
    assert index["lobbies"][str(fourth.user)] == lobby
    time.sleep(0.35)
    assert not peer.pushes and not select.select([peer.socket], [], [], 0)[0]
    checks.append("joining a retained older roster changes only the requesting party's current assignments and preserves another member's newer lobby")

    path = root / "lobbies" / f"{lobby}.json"
    retained = path.read_bytes()
    separated = json.loads(retained)
    separated["backend_doc"]["team_balance"]["teams"] = {
        "0": [host.user, peer.user], "1": [third.user, fourth.user]}
    path.write_text(json.dumps(separated))
    try:
        split = {"members": [peer.user, third.user], "tokens": [tokens[1], tokens[2]],
                 "lobby_id_to_presence_join": lobby}
        reject(third, 18, text(json.dumps(split)))
    finally:
        path.write_bytes(retained)
    checks.append("normal MP overlap across existing teams rejects without moving players or publishing new assignments")

    moved = {**copy.deepcopy(query), "members": [host.user], "tokens": [tokens[0]],
             "private_lobby": {"initial_party_id": 905}}
    moved_lobby, _ = create(host, moved)
    reject(fourth, 18, text(json.dumps(joining)))
    old_docs = documents(ordinary(host, 13, u64(lobby)))
    reject(host, 15, u64(lobby) + u64(old_docs[1]["update_id"])
           + text(json.dumps(old_docs[0])))
    assert documents(ordinary(host, 13, u64(lobby))) == old_docs
    checks.append("a host's superseded lobby rejects presence admission and active host mutation while historical document inspection remains available")

    # Historical cleanup is an established contract. Drain any legacy stale
    # observer pushes before each owner's normal disband acknowledgement.
    drain()
    for owner, value in ((host, lobby), (host, moved_lobby), (peer, newer_lobby)):
        assert ordinary(owner, 10, u64(value)) == b""
        assert receive(owner) == (2, u32(2002) + u64(value) + u64(0))
        drain()

    live_lobby, _ = create(peer, newer)
    expired = json.loads(retained)
    expired_id = lobby + 1
    while (root / "lobbies" / f"{expired_id}.json").exists():
        expired_id += 1
    expired.update(id=expired_id, expires=1)
    expired["backend_doc"]["lobby_id"] = expired_id
    (root / "lobbies" / f"{expired_id}.json").write_text(json.dumps(expired))
    index_path = root / "current-lobbies.json"
    crowded = json.loads(index_path.read_bytes())
    assert crowded["lobbies"] == {str(peer.user): live_lobby}
    crowded["lobbies"].update({str(user): expired_id for user in range(1, 4096)})
    assert len(crowded["lobbies"]) == 4096
    index_path.write_text(json.dumps(crowded))
    fresh = {**copy.deepcopy(query), "members": [fourth.user], "tokens": [tokens[3]],
             "private_lobby": {"initial_party_id": 906}}
    fresh_lobby, _ = create(fourth, fresh)
    reclaimed = json.loads(index_path.read_bytes())
    assert reclaimed["lobbies"] == {str(peer.user): live_lobby, str(fourth.user): fresh_lobby}
    assert (root / "lobbies" / f"{expired_id}.json").exists()
    checks.append("a full 4096-player index reclaims expired assignments atomically for a new search, preserves live assignments and retains historical lobby files")
    for owner, value in ((peer, live_lobby), (fourth, fresh_lobby)):
        assert ordinary(owner, 10, u64(value)) == b""
        assert receive(owner) == (2, u32(2002) + u64(value) + u64(0))
        drain()

    from native_wire_client import NativeClient
    private = {**copy.deepcopy(query), "members": [host.user], "tokens": [tokens[0]],
               "private_lobby": {"initial_party_id": 907}}
    owned_lobby, owned_docs = create(host, private)
    stored = json.loads((root / "lobbies" / f"{owned_lobby}.json").read_bytes())
    owned_search = stored["backend_doc"]["player_id_to_mm_id"][str(host.user)]
    offset = host.socket.getpeername()[1] - 3075
    with NativeClient(data.parent, port_offset=offset) as independent:
        assert independent.user == host.user
        assert independent.session_fingerprint != host.session_fingerprint
        assert host.task(12, 6, b"", structured=False).startswith(b"\x08")
        for task in (8, 9):
            reject(independent, task, u64(owned_search), error=101)
        reject(independent, 10, u64(owned_lobby), error=101)
        assert documents(ordinary(host, 13, u64(owned_lobby))) == owned_docs
    assert ordinary(host, 8, u64(owned_search)) == b"\x01\x01"
    assert ordinary(host, 9, u64(owned_search)) == b"\x01\x01"
    assert ordinary(host, 10, u64(owned_lobby)) == b""
    assert receive(host) == (2, u32(2002) + u64(owned_lobby) + u64(0))
    checks.append("independent same-account credentials cannot cancel/shutdown/disband another live session's allocation; the original owner remains valid and can perform all three")
