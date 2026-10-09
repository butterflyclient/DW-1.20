"""Independent encrypted-client checks of Replay public lobby filling."""

import copy
import json
import struct


def exercise(
    host, peer, directory, title, user, peer_user, player_info, query, helpers, checks
):
    u32, u64, text, boolean = helpers
    root = directory / "matchmaking" / str(title)
    host_token = struct.unpack_from("<Q", host.task(145, 3), 1)[0]
    peer.task(145, 2, text(json.dumps(player_info)))
    peer_token = struct.unpack_from("<Q", peer.task(145, 3), 1)[0]
    create = {
        **copy.deepcopy(query),
        "members": [user],
        "tokens": [host_token],
        "lobby_slots": {"min": 1, "max": 2},
        "team_balance": {"num_teams": 2, "lock_squad": False},
    }
    create["ruleset_payload"].update(
        join_in_progress=False, only_join_existing_lobbies=False
    )
    # This deliberately tiny laboratory match must also publish a native
    # two-player rule. An anchor's search max does not change shipped rules.
    bindings = json.loads((directory / "playlists" / str(title) / "native-dvar-names.json").read_bytes())
    create["ruleset_payload"].setdefault("dvar_overrides", {})[
        bindings.get("party_maxplayers", "party_maxplayers")
    ] = 2
    join = {
        **copy.deepcopy(create),
        "members": [peer_user],
        "tokens": [peer_token],
        "player_id_to_slots": {str(peer_user): 0},
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

    def start(client, value, error=0):
        raw = client.task(145, 18, text(json.dumps(value)), error=error)
        return strings(raw)[0]["mm_id"] if not error else None

    def created(value=create):
        mm = start(host, value)
        kind, packet = host.receive()
        assert kind == 2 and packet.startswith(u32(2005) + u64(mm))
        lobby = struct.unpack_from("<Q", packet, 15)[0]
        docs = strings(packet[32:])
        # A native owner acknowledges its initial host document before it can
        # accept new peers. Deferred pre-ACK joins have a separate focused test.
        assert host.task(145, 15, u64(lobby) + u64(docs[1]["update_id"])
                         + text(json.dumps(docs[0]))) == boolean(True)
        kind, updated = host.receive()
        assert kind == 2 and updated.startswith(u32(2006) + u64(lobby))
        return lobby, strings(updated[23:])

    def disband(lobby, joined=False):
        assert host.task(145, 10, u64(lobby)) == []
        assert host.receive() == (2, u32(2002) + u64(lobby) + u64(0))
        if joined:
            assert peer.receive() == (2, u32(2002) + u64(lobby) + u64(0))

    def unchanged_reject(lobby, altered, error=108):
        before = {
            str(path): path.read_bytes() for path in (root / "lobbies").glob("*.json")
        }
        searches = {
            str(path): path.read_bytes() for path in (root / "searches").glob("*.json")
        }
        index = (root / "current-lobbies.json").read_bytes()
        start(peer, altered, error)
        assert before == {
            str(path): path.read_bytes() for path in (root / "lobbies").glob("*.json")
        }
        assert searches == {
            str(path): path.read_bytes() for path in (root / "searches").glob("*.json")
        }
        assert (root / "current-lobbies.json").read_bytes() == index

    lobby, initial = created()
    changed = copy.deepcopy(join)
    changed["ruleset_payload"]["filter"]["netcode_version"] += 1
    unchanged_reject(lobby, changed)
    changed = copy.deepcopy(join)
    changed["lobby_slots"]["max"] = 3
    # Compatibility uses the native match limit, rather than the anchor's
    # search hint. Change the actual rule as well to request a different pool.
    changed["ruleset_payload"]["dvar_overrides"][
        bindings.get("party_maxplayers", "party_maxplayers")
    ] = 3
    unchanged_reject(lobby, changed)
    changed = copy.deepcopy(join)
    changed["lobby_slots"]["max"] = 0
    unchanged_reject(lobby, changed, 106)
    changed = copy.deepcopy(join)
    changed["tokens"] = [peer_token + 1]
    unchanged_reject(lobby, changed, 14507)
    # A historical member's assignment must not revive a lobby after its host
    # moved to another one, even when the old host's auth session is still live.
    index_path = root / "current-lobbies.json"
    saved_index = index_path.read_bytes()
    orphaned = json.loads(saved_index)
    orphaned["lobbies"][str(user)] = lobby + 1
    orphaned["lobbies"][str(peer_user)] = lobby
    index_path.write_text(json.dumps(orphaned))
    try:
        unchanged_reject(lobby, join)
    finally:
        index_path.write_bytes(saved_index)
    checks.append(
        "public search rejects mismatched netcode/capacity, malformed slots and invalid live-party tokens without publishing lobby/search/index changes"
    )

    mm = start(peer, join)
    kind, packet = peer.receive()
    assert kind == 2 and packet.startswith(u32(2001) + u64(mm) + u64(lobby))
    joined = strings(packet[23:])
    assert host.receive() == (
        2,
        u32(2006)
        + u64(lobby)
        + u64(initial[1]["update_id"] + 1)
        + text(json.dumps(joined[0], separators=(",", ":")))
        + text(json.dumps(joined[1], separators=(",", ":"))),
    )
    # Compare independently read result documents to both push snapshots.
    assert (
        strings(host.task(145, 13, u64(lobby)))
        == strings(peer.task(145, 13, u64(lobby)))
        == joined
    )
    assert joined[0]["listen_server"] == initial[0]["listen_server"]
    assert joined[1]["dtls"] == initial[1]["dtls"]
    assert joined[1]["ruleset_payload"] == initial[1]["ruleset_payload"]
    assert joined[1]["team_balance"]["teams"] == {"0": [user], "1": [peer_user]}
    assert joined[1]["player_id_to_mm_id"][str(peer_user)] == mm
    index = json.loads((root / "current-lobbies.json").read_bytes())["lobbies"]
    assert index[str(user)] == index[str(peer_user)] == lobby
    assert json.loads((root / "transaction.json").read_bytes())["phase"] == "applied"
    disband(lobby, True)
    checks.append(
        "two independently authenticated public searches share one durable lobby; native event-2001/event-2006 retain host address/DTLS/rules and balance the joining party onto a distinct team"
    )

    lobby, _ = created({**create, "private_lobby": {"initial_party_id": 17}})
    unchanged_reject(lobby, join)
    disband(lobby)
    lobby, initial = created()
    closed = {**initial[0], "lobby_open": False}
    assert host.task(
        145, 15, u64(lobby) + u64(initial[1]["update_id"]) + text(json.dumps(closed))
    ) == boolean(True)
    assert host.receive()[1].startswith(u32(2006) + u64(lobby) + u64(initial[1]["update_id"] + 1))
    unchanged_reject(lobby, join)
    disband(lobby)
    checks.append(
        "private and closed host lobbies never enter public matching; join-existing-only searches fail unavailable instead of creating an unrelated lobby"
    )

    lobby, initial = created()
    playing = {**initial[0], "game_state": {"state": "in_game"}}
    assert host.task(
        145, 15, u64(lobby) + u64(initial[1]["update_id"]) + text(json.dumps(playing))
    ) == boolean(True)
    assert host.receive()[1].startswith(u32(2006) + u64(lobby) + u64(initial[1]["update_id"] + 1))
    unchanged_reject(lobby, join)
    # Replay's native UpdateHostDoc writes in_game, rather than playing.
    disband(lobby)
    progress = copy.deepcopy(create)
    progress["ruleset_payload"]["join_in_progress"] = True
    lobby, initial = created(progress)
    playing = {**initial[0], "game_state": {"state": "in_game"}}
    assert host.task(
        145, 15, u64(lobby) + u64(initial[1]["update_id"]) + text(json.dumps(playing))
    ) == boolean(True)
    assert host.receive()[1].startswith(u32(2006) + u64(lobby) + u64(initial[1]["update_id"] + 1))
    progress_join = {
        **copy.deepcopy(progress),
        "members": [peer_user],
        "tokens": [peer_token],
        "player_id_to_slots": {str(peer_user): 0},
    }
    progress_join["ruleset_payload"]["only_join_existing_lobbies"] = True
    mm = start(peer, progress_join)
    assert peer.receive()[1].startswith(u32(2001) + u64(mm) + u64(lobby))
    assert host.receive()[1].startswith(u32(2006) + u64(lobby) + u64(initial[1]["update_id"] + 2))
    disband(lobby, True)
    checks.append(
        "native in_game lobbies honor join-in-progress policy and retain the same assigned game instead of spawning a second match"
    )
