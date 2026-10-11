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
    # Secondary-slot exhaustion must use the native three-player rule too;
    # public search slot hints no longer reduce the shipped match capacity.
    bindings = json.loads(
        (directory / "playlists" / str(title) / "native-dvar-names.json").read_bytes()
    )
    create["ruleset_payload"].setdefault("dvar_overrides", {})[
        bindings.get("party_maxplayers", "party_maxplayers")
    ] = 3
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
        lobby = struct.unpack_from("<Q", packet, 15)[0]
        documents = strings(packet[32:])
        if len(request["members"]) == 1:
            assert host.task(
                145, 15, u64(lobby) + u64(documents[1]["update_id"])
                + text(json.dumps(documents[0]))
            ) == boolean(True)
            kind, update = host.receive()
            assert kind == 2 and update.startswith(u32(2006) + u64(lobby))
            documents = strings(update[23:])
        return lobby, documents

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

    # Request bots through the authenticated host path, then exercise both
    # admission routes before the native client can consume that fixed count.
    capacity_key = bindings.get("party_maxplayers", "party_maxplayers")
    for by_presence in (False, True):
        for capacity in (3, 4):
            reserved_create = copy.deepcopy(create)
            reserved_create["ruleset_payload"]["dvar_overrides"][capacity_key] = capacity
            lobby, documents = created(reserved_create)
            document = copy.deepcopy(documents[0])
            document["dw_bot_count"] = 1
            assert host.task(
                145, 15, u64(lobby) + u64(documents[1]["update_id"])
                + text(json.dumps(document))
            ) == boolean(True)
            kind, update = host.receive()
            assert kind == 2 and update.startswith(u32(2006) + u64(lobby))
            path = root / "lobbies" / f"{lobby}.json"

            def assert_reservation():
                state = json.loads(path.read_bytes())
                assert state["maximum_members"] == capacity
                assert state["operator_bots_requested"]
                assert state["operator_bot_count"] == 1
                count_key = bindings.get("replay_dw_botCount", "replay_dw_botCount")
                assert state["backend_doc"]["ruleset_payload"]["dvar_overrides"][count_key] == 1
                return state

            assert_reservation()
            if by_presence:
                reserved_join = {
                    "members": [peer_user], "tokens": [peer_token],
                    "player_id_to_slots": {str(peer_user): 1},
                    "lobby_id_to_presence_join": lobby,
                }
            else:
                reserved_join = copy.deepcopy(join)
                reserved_join["ruleset_payload"]["dvar_overrides"][capacity_key] = capacity
            # Host primary+guest and one reserved bot occupy three slots.
            # A joining primary+guest must fail even when humans alone fit.
            reject(peer, reserved_join, 108)
            reserved_join["player_id_to_slots"][str(peer_user)] = 0
            if capacity == 3:
                reject(peer, reserved_join, 108)
                assert_reservation()
                disband(lobby)
            else:
                joined(peer, reserved_join, lobby, host)
                state = assert_reservation()
                assert state["members"] == [user, peer_user]
                assert state["backend_doc"]["player_id_to_slots"] == {
                    str(user): 1, str(peer_user): 0,
                }
                disband(lobby, True)
    checks.append(
        "Public and presence joins reserve queued native bot counts, count guest slots, reject exhausted capacity without writes and admit fitting real players without changing bot count or playlist limit"
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
    assert host.task(
        145, 15, u64(lobby) + u64(documents[1]["update_id"])
        + text(json.dumps(documents[0]))
    ) == boolean(True)
    kind, update = host.receive()
    assert kind == 2 and update.startswith(u32(2006) + u64(lobby))
    documents = strings(update[23:])
    kind, packet = peer.receive()
    assert kind == 2 and packet.startswith(u32(2001))
    assert struct.unpack_from("<Q", packet, 6)[0] == documents[1][
        "player_id_to_mm_id"
    ][str(peer_user)]
    assert struct.unpack_from("<Q", packet, 15)[0] == lobby
    assert strings(packet[23:]) == documents
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
