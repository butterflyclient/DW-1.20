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
    # Revision is an explicit transient acknowledgement publication; every
    # other native playlist/netcode/map rule must remain exactly unchanged.
    expected_rules = json.loads(json.dumps(initial[1]["ruleset_payload"]))
    expected_rules["dvar_overrides"]["replay_dw_autoFillRevision"] = joined[1]["update_id"] % 2147483647
    assert joined[1]["ruleset_payload"] == expected_rules
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

    # Full two-player running match: a real newcomer replaces the committed
    # bot through the same public admission transaction and native publications.
    lobby, initial = created(progress)
    fill = copy.deepcopy(initial[0])
    fill["dw_bot_count"] = 1
    assert host.task(145, 15, u64(lobby) + u64(initial[1]["update_id"])
                     + text(json.dumps(fill))) == boolean(True)
    current = strings(host.receive()[1][23:])
    playing = copy.deepcopy(current[0])
    playing["game_state"] = {"state": "in_game"}
    assert host.task(145, 15, u64(lobby) + u64(current[1]["update_id"])
                     + text(json.dumps(playing))) == boolean(True)
    current = strings(host.receive()[1][23:])
    stale_host = copy.deepcopy(current)
    path = root / "lobbies" / f"{lobby}.json"
    before = json.loads(path.read_bytes())
    assert before["maximum_members"] == 2 and before["operator_bot_count"] == 1
    mm = start(peer, progress_join)
    packet = peer.receive()[1]
    assert packet.startswith(u32(2001) + u64(mm) + u64(lobby))
    joined = strings(packet[23:])
    assert strings(host.receive()[1][23:]) == joined
    committed = json.loads(path.read_bytes())
    assert committed["maximum_members"] == 2 and committed["operator_bot_count"] == 0
    assert set(committed["members"]) == {user, peer_user}
    assert joined[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_botCount"] == 0
    assert joined[1]["dtls"] == before["backend_doc"]["dtls"]
    # A stale host snapshot cannot drop the new primary or undo replacement.
    unchanged = path.read_bytes()
    assert host.task(145, 15, u64(lobby) + u64(stale_host[1]["update_id"])
                     + text(json.dumps(stale_host[0]))) == boolean(False)
    assert path.read_bytes() == unchanged
    # Repeat admission at an all-human full cap: same lobby, zero new humans,
    # zero additional bot removals. Existing reservations cannot be changed.
    retry_mm = start(peer, progress_join)
    assert peer.receive()[1].startswith(u32(2001) + u64(retry_mm) + u64(lobby))
    current = strings(host.receive()[1][23:])
    committed = json.loads(path.read_bytes())
    assert committed["maximum_members"] == 2 and committed["operator_bot_count"] == 0
    assert len(committed["members"]) == 2
    over = copy.deepcopy(progress_join)
    over["player_id_to_slots"][str(peer_user)] = 1
    unchanged_reject(lobby, over)
    presence = copy.deepcopy(over)
    presence["lobby_id_to_presence_join"] = lobby
    unchanged_reject(lobby, presence)
    duplicate = copy.deepcopy(progress_join)
    duplicate["members"] *= 2
    duplicate["tokens"] *= 2
    unchanged_reject(lobby, duplicate, 106)
    checks.append("running admission replaces one committed bot, retains capacity/DTLS, rejects guest overflow and duplicate identities, and retries without another removal")
    # Authenticate a live handoff after replacement; the successor keeps the
    # reduced committed roster and existing humans, including the old host.
    handoff = copy.deepcopy(current[0])
    handoff["player_state"] = {str(user): 2, str(peer_user): 2}
    handoff["dw_migration_target"] = peer_user
    assert host.task(145, 15, u64(lobby) + u64(current[1]["update_id"])
                     + text(json.dumps(handoff))) == boolean(True)
    current = strings(host.receive()[1][23:])
    assert strings(peer.receive()[1][23:]) == current
    successor = copy.deepcopy(current[0])
    successor["listen_server"] = {"host_player_id": peer_user,
                                 "host_address": player_info["listen_server"]["local_address"]}
    assert peer.task(145, 15, u64(lobby) + u64(current[1]["update_id"])
                     + text(json.dumps(successor))) == boolean(True)
    migrated = strings(peer.receive()[1][23:])
    assert strings(host.receive()[1][23:]) == migrated
    committed = json.loads(path.read_bytes())
    assert committed["owner"] == peer_user and committed["operator_bot_count"] == 0
    assert set(committed["members"]) == {user, peer_user} and committed["maximum_members"] == 2
    def peer_publish(document, revision):
        assert peer.task(145, 15, u64(lobby) + u64(revision)
                         + text(json.dumps(document))) == boolean(True)
        packet = peer.receive()[1]
        if str(user) in document["player_state"]:
            assert host.receive() == (2, packet)
        return strings(packet[23:])
    current = migrated
    # Zero remains a committed roster while the host enters countdown, then
    # the ordinary intermission path clears the request for the next round.
    for phase in ("countdown", "intermission"):
        transition = copy.deepcopy(current[0])
        transition["game_state"] = {"state": phase}
        current = peer_publish(transition, current[1]["update_id"])
        saved = json.loads(path.read_bytes())
        if phase == "countdown":
            assert saved["operator_bot_count"] == 0 and saved["operator_bots_requested"] is True
        else:
            assert "operator_bot_count" not in saved and "operator_bots_requested" not in saved
    invalid = copy.deepcopy(current[0])
    invalid["dw_bot_count"] = 0
    unchanged = path.read_bytes()
    peer.task(145, 15, u64(lobby) + u64(current[1]["update_id"])
              + text(json.dumps(invalid)), error=106)
    assert path.read_bytes() == unchanged
    # Retire the old host's owned fixture membership, fill the resulting slot
    # in the next round, and authenticate that same real player joining again.
    retire = copy.deepcopy(current[0])
    retire["player_state"] = {str(peer_user): 2}
    current = peer_publish(retire, current[1]["update_id"])
    refill = copy.deepcopy(current[0])
    refill["dw_bot_count"] = 1
    current = peer_publish(refill, current[1]["update_id"])
    assert json.loads(path.read_bytes())["operator_bot_count"] == 1
    transition = copy.deepcopy(current[0])
    transition["game_state"] = {"state": "in_game"}
    current = peer_publish(transition, current[1]["update_id"])
    rejoin = copy.deepcopy(progress_join)
    rejoin["members"] = [user]
    rejoin["tokens"] = [host_token]
    rejoin["player_id_to_slots"] = {str(user): 0}
    mm = start(host, rejoin)
    assert host.receive()[1].startswith(u32(2001) + u64(mm) + u64(lobby))
    current = strings(peer.receive()[1][23:])
    saved = json.loads(path.read_bytes())
    assert saved["operator_bot_count"] == 0 and saved["maximum_members"] == 2
    assert set(saved["members"]) == {user, peer_user}
    checks.append("last manual bot zero survives migration/countdown, clears on intermission, rejects a new zero request, and replaces a fresh next-round bot without raising capacity")
    peer.task(145, 10, u64(lobby))
    assert host.receive() == peer.receive() == (2, u32(2002) + u64(lobby) + u64(0))
    checks.append("stale host publication cannot undo running admission; authenticated host migration retains the reduced roster without refilling bots")

    lobby, current = created(progress)
    path = root / "lobbies" / f"{lobby}.json"
    def publish(document):
        assert host.task(145, 15, u64(lobby) + u64(current[1]["update_id"])
                         + text(json.dumps(document))) == boolean(True)
        return strings(host.receive()[1][23:])
    arm = copy.deepcopy(current[0])
    arm.update(dw_auto_fill_bots=True, dw_auto_fill_complete=False,
               dw_auto_fill_request=1, dw_bot_count=0)
    current = publish(arm)
    # Only this disposable fixture clock is aged; real backend data is untouched.
    saved = json.loads(path.read_bytes())
    saved["auto_fill_started_ms"] = 1
    path.write_text(json.dumps(saved))
    for request, complete in ((2, False), (3, True)):
        arm = copy.deepcopy(current[0])
        arm.update(dw_auto_fill_bots=True, dw_auto_fill_complete=complete,
                   dw_auto_fill_request=request, dw_bot_count=1)
        current = publish(arm)
    playing = copy.deepcopy(current[0])
    playing["game_state"] = {"state": "in_game"}
    current = publish(playing)
    before = json.loads(path.read_bytes())
    mm = start(peer, progress_join)
    assert peer.receive()[1].startswith(u32(2001) + u64(mm) + u64(lobby))
    current = strings(host.receive()[1][23:])
    after = json.loads(path.read_bytes())
    rules = current[1]["ruleset_payload"]["dvar_overrides"]
    assert after["operator_bot_count"] == after["auto_fill_target"] == 0
    assert after["maximum_members"] == 2 and after["auto_fill_complete"] is True
    assert after["auto_fill_request"] == before["auto_fill_request"] == 3
    assert after["auto_fill_started_ms"] == before["auto_fill_started_ms"] == 1
    assert rules["replay_dw_botCount"] == rules["replay_dw_autoFillBotTarget"] == 0
    assert rules["replay_dw_autoFillBotsComplete"] == 1
    disband(lobby, True)
    checks.append("completed automatic fill running join lowers committed bot count and target together while preserving completion, request token, clock and capacity")
