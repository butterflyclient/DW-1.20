"""Replay primary-player reservations and authenticated PC platform constraints."""

import copy
import json
import struct


def exercise(host, peer, directory, title, user, peer_user, query, helpers, checks):
    u32, u64, text, boolean = helpers
    root = directory / "matchmaking" / str(title)
    host_token = struct.unpack_from("<Q", host.task(145, 3), 1)[0]
    peer_token = struct.unpack_from("<Q", peer.task(145, 3), 1)[0]
    create = {
        **copy.deepcopy(query),
        "members": [user],
        "tokens": [host_token],
        "player_id_to_slots": {str(user): 1},
        "acceptable_platforms": ["bnet"],
        "lobby_slots": {"min": 1, "max": 3},
        "team_balance": {"num_teams": 2},
    }
    join = {
        **copy.deepcopy(create),
        "members": [peer_user],
        "tokens": [peer_token],
        "player_id_to_slots": {str(peer_user): 1},
    }
    join["ruleset_payload"]["only_join_existing_lobbies"] = True

    def strings(raw):
        out = []
        while raw:
            assert raw[0] == 16
            end = raw.index(0, 1)
            out.append(json.loads(raw[1:end]))
            raw = raw[end + 1 :]
        return out

    def start(client, request, error=0):
        raw = client.task(145, 18, text(json.dumps(request)), error=error)
        return strings(raw)[0]["mm_id"] if not error else None

    def snapshot():
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*.json")
        }

    def reject(client, request, error):
        before = snapshot()
        start(client, request, error)
        assert snapshot() == before

    def created(request=create):
        mm = start(host, request)
        kind, packet = host.receive()
        assert kind == 2 and packet.startswith(u32(2005) + u64(mm))
        return struct.unpack_from("<Q", packet, 15)[0], strings(packet[32:])

    def joined(client, request, lobby, observer):
        mm = start(client, request)
        kind, packet = client.receive()
        assert kind == 2 and packet.startswith(u32(2001) + u64(mm) + u64(lobby))
        documents = strings(packet[23:])
        assert observer.receive()[1].startswith(u32(2006) + u64(lobby))
        assert documents == strings(host.task(145, 13, u64(lobby)))
        return documents

    def disband(lobby, paired=False):
        assert host.task(145, 10, u64(lobby)) == []
        assert host.receive() == (2, u32(2002) + u64(lobby) + u64(0))
        if paired:
            assert peer.receive() == (2, u32(2002) + u64(lobby) + u64(0))

    for slots in (
        [],
        {str(user): -1},
        {str(user): 2},
        {str(user): True},
        {str(user): 0.5},
        {str(peer_user): 0},
        {"0" + str(user): 0},
    ):
        reject(host, {**create, "player_id_to_slots": slots}, 106)
    reject(host, {**create, "lobby_slots": {"max": 1}}, 106)
    checks.append(
        "primary-slot requests reject malformed/nonmember reservations and parties exceeding capacity before any matchmaking publication"
    )

    for platforms in ([], "bnet", ["bnet", "bnet"], [1], ["BNET"], ["bnet\0"]):
        reject(host, {**create, "acceptable_platforms": platforms}, 106)
    reject(host, {**create, "acceptable_platforms": ["steam"]}, 108)
    reject(host, {**create, "acceptable_platforms": ["xb3", "ps4"]}, 108)
    checks.append(
        "native bnet platform constraints reject invalid arrays and excluded Replay PC sessions without creating lobbies"
    )

    lobby, documents = created()
    assert documents[1]["player_id_to_slots"] == {str(user): 1}
    reject(peer, join, 108)
    presence = {
        "members": [peer_user],
        "tokens": [peer_token],
        "player_id_to_slots": {str(peer_user): 1},
        "lobby_id_to_presence_join": lobby,
    }
    reject(peer, presence, 108)
    unrestricted = copy.deepcopy(join)
    unrestricted.pop("acceptable_platforms")
    unrestricted["player_id_to_slots"][str(peer_user)] = 0
    joined_docs = joined(peer, unrestricted, lobby, host)
    assert joined_docs[1]["player_id_to_slots"] == {str(user): 1, str(peer_user): 0}
    assert joined_docs[1]["team_balance"]["teams"] == {"0": [user], "1": [peer_user]}
    disband(lobby, True)
    checks.append(
        "public and presence joins count primary plus secondary slots; compatible restricted/unrestricted PC parties retain native reservation/team documents"
    )

    party = {
        **copy.deepcopy(create),
        "members": [user, peer_user],
        "tokens": [host_token, peer_token],
        "player_id_to_slots": {str(user): 1, str(peer_user): 1},
        "lobby_slots": {"max": 4},
        "private_lobby": {"initial_party_id": 29},
    }
    lobby, documents = created(party)
    kind, packet = peer.receive()
    assert kind == 2 and packet.startswith(u32(2005))
    assert struct.unpack_from("<Q", packet, 15)[0] == lobby
    assert strings(packet[32:]) == documents
    # A presence request for an existing primary updates its reservation once;
    # it must not count that player's original slot a second time.
    presence["lobby_id_to_presence_join"] = lobby
    presence["player_id_to_slots"][str(peer_user)] = 0
    updated = joined(peer, presence, lobby, host)
    assert updated[1]["player_id_to_slots"] == {str(user): 1, str(peer_user): 0}
    assert updated[1]["update_time"] > documents[1]["update_time"]
    host_doc = {**updated[0], "player_state": {str(user): 2}}
    assert host.task(
        145, 15, u64(lobby) + u64(updated[1]["update_id"]) + text(json.dumps(host_doc))
    ) == boolean(True)
    remaining = host.receive()
    assert remaining[1].startswith(u32(2006) + u64(lobby))
    state = json.loads((root / "lobbies" / f"{lobby}.json").read_bytes())
    assert state["backend_doc"]["player_id_to_slots"] == {str(user): 1}
    assert state["members"] == [user]
    disband(lobby)
    checks.append(
        "presence reassignments update secondary reservations without double counting; native departure clears those reservations in the shared transaction"
    )

    # Persisted lobbies created by the earlier backend have no reservation or
    # platform fields. They remain zero-secondary PC lobbies, without migration
    # writes during an unavailable read/search.
    legacy = {**copy.deepcopy(create), "player_id_to_slots": {str(user): 0}}
    lobby, _ = created(legacy)
    path = root / "lobbies" / f"{lobby}.json"
    state = json.loads(path.read_bytes())
    state.pop("query_constraints")
    state["backend_doc"].pop("player_id_to_slots")
    path.write_text(json.dumps(state))
    legacy_join = copy.deepcopy(unrestricted)
    legacy_join["player_id_to_slots"][str(peer_user)] = 1
    documents = joined(peer, legacy_join, lobby, host)
    assert documents[1]["player_id_to_slots"] == {str(peer_user): 1}
    disband(lobby, True)
    checks.append(
        "pre-reservation persisted lobbies remain compatible and acquire validated secondary reservations on assignment"
    )
