"""Real encrypted native-host ballot publication and transition regressions."""
import copy
import json
import struct


def exercise(clients, data, query, tokens, ordinary, receive, documents, text, u32, u64, checks):
    host, peer = clients[:2]
    root = data / "matchmaking/5800"
    policy = data / "playlists/5800/policy.json"
    previous = policy.read_bytes()
    policy.write_text(json.dumps({"available_maps": ["mp_backlot2", "mp_cave_am", "mp_crash2"],
                                  "minimum_players": 1, "split_parties_for_team_balance": False}))
    request = copy.deepcopy(query)
    current = None
    lobby = None

    def publish(sender, payload, error=0):
        nonlocal current
        path = root / "lobbies" / f"{lobby}.json"
        before = path.read_bytes()
        before_files = {str(file.relative_to(root)): file.read_bytes() for file in root.rglob("*.json")}
        wire = u64(lobby) + u64(current[1]["update_id"]) + text(json.dumps(payload))
        if error:
            try:
                ordinary(sender, 15, wire)
                raise AssertionError("Invalid ballot snapshot accepted")
            except RuntimeError as failure:
                assert "returned " + str(error) in str(failure)
            assert path.read_bytes() == before
            assert {str(file.relative_to(root)): file.read_bytes() for file in root.rglob("*.json")} == before_files
            return json.loads(before)
        assert ordinary(sender, 15, wire) == b"\x01\x01"
        _, packet = receive(sender)
        assert packet.startswith(u32(2006) + u64(lobby))
        current = documents(packet[23:])
        state = json.loads(path.read_bytes())
        index = json.loads((root / "current-lobbies.json").read_bytes())["lobbies"]
        for other in clients:
            if other is not sender and other.user in state["members"] and index.get(str(other.user)) == lobby:
                assert receive(other) == (2, packet)
        return state

    def join(client, token):
        nonlocal current
        joining = copy.deepcopy(request)
        joining.update(members=[client.user], tokens=[token])
        joining["ruleset_payload"]["only_join_existing_lobbies"] = True
        mm = documents(ordinary(client, 18, text(json.dumps(joining))))[0]["mm_id"]
        _, packet = receive(client)
        assert packet.startswith(u32(2001) + u64(mm) + u64(lobby))
        current = documents(packet[23:])
        members = json.loads((root / "lobbies" / f"{lobby}.json").read_bytes())["members"]
        for observer in clients:
            if observer is not client and observer.user in members:
                assert receive(observer) == (2, u32(2006) + u64(lobby) + u64(current[1]["update_id"]) + packet[23:])

    try:
        mm = documents(ordinary(host, 18, text(json.dumps(request))))[0]["mm_id"]
        _, packet = receive(host)
        lobby = struct.unpack_from("<Q", packet, 15)[0]
        current = documents(packet[32:])
        assert not any("mapVote" in key for key in current[1]["ruleset_payload"]["dvar_overrides"])
        initial = copy.deepcopy(current[0])
        assert ordinary(host, 15, u64(lobby) + u64(current[1]["update_id"])
                        + text(json.dumps(initial))) == b"\x01\x01"
        _, packet = receive(host)
        assert receive(peer) == (2, u32(2001) + u64(mm) + u64(lobby) + packet[23:])
        current = documents(packet[23:])
        arm = copy.deepcopy(current[0])
        arm["dw_map_vote"] = {"version": 1, "entry": 0, "votes": {}}
        lobby_path = root / "lobbies" / f"{lobby}.json"
        saved_lobby = lobby_path.read_bytes()
        oversized = json.loads(saved_lobby)
        overrides = oversized["backend_doc"]["ruleset_payload"]["dvar_overrides"]
        for number in range(128 - len(overrides)):
            overrides["audit_overflow_" + str(number)] = 0
        assert len(overrides) == 128
        lobby_path.write_text(json.dumps(oversized))
        publish(host, arm, error=106)
        lobby_path.write_bytes(saved_lobby)
        state = publish(host, arm)
        assert len(state["map_vote"]["choices"]) == 3 and not state["map_vote"]["complete"]
        assert {choice["gametype"] for choice in state["map_vote"]["choices"]} == {"tdm"}
        assert "dw_map_vote" not in state["host_doc"]
        premature = copy.deepcopy(current[0])
        premature["game_state"] = {"state": "countdown"}
        publish(host, premature, error=106)
        vote = copy.deepcopy(current[0])
        vote["dw_map_vote"] = {"version": 1, "entry": 0,
                               "votes": {str(host.user): 2, str(peer.user): 2}}
        state = publish(host, vote)
        assert state["map_vote"]["votes"] == vote["dw_map_vote"]["votes"]
        original_weights = copy.deepcopy(state["map_vote"]["original_weights"])
        index_path = root / "current-lobbies.json"
        saved_index = index_path.read_bytes()
        index = json.loads(saved_index); index["lobbies"].pop(str(peer.user))
        index_path.write_text(json.dumps(index))
        state = publish(host, vote)
        assert state["map_vote"]["votes"] == {str(host.user): 2}
        index_path.write_bytes(saved_index)
        state = publish(host, vote)
        join(clients[2], tokens[2])
        pending = copy.deepcopy(current[0])
        pending["dw_map_vote"] = {"version": 1, "entry": 0,
                                  "votes": {str(host.user): 2, str(peer.user): 2, str(clients[2].user): 3}}
        state = publish(host, pending)
        assert state["map_vote"]["votes"][str(clients[2].user)] == 3
        leaving = copy.deepcopy(current[0]); leaving["player_state"].pop(str(clients[2].user))
        state = publish(host, leaving)
        assert clients[2].user not in state["members"] and str(clients[2].user) not in state["map_vote"]["votes"]
        handoff = copy.deepcopy(current[0]); handoff["dw_map_vote"] = vote["dw_map_vote"]
        handoff["dw_migration_target"] = peer.user
        state = publish(host, handoff)
        started = state["map_vote"]["started_ms"]
        successor = copy.deepcopy(current[0])
        successor["listen_server"]["host_player_id"] = peer.user
        successor["dw_map_vote"] = vote["dw_map_vote"]
        state = publish(peer, successor)
        assert state["owner"] == peer.user and state["map_vote"]["started_ms"] == started
        path = root / "lobbies" / f"{lobby}.json"
        state["map_vote"]["started_ms"] = 1
        path.write_text(json.dumps(state))
        state = publish(peer, successor)
        assert state["map_vote"]["complete"] and state["map_vote"]["winner"] == 1
        selected = state["map_vote"]["choices"][1]["map"]
        assert all(weight == (1 if name == selected else 0)
                   for name, weight in state["backend_doc"]["ruleset_payload"]["map_weights"].items())
        frozen = copy.deepcopy(state["map_vote"])
        join(clients[3], tokens[3])
        assert json.loads(path.read_bytes())["map_vote"] == frozen
        late = copy.deepcopy(current[0])
        late["dw_map_vote"] = {"version": 1, "entry": 0, "votes": {str(host.user): 1}}
        state = publish(peer, late)
        assert state["map_vote"] == frozen
        playing = copy.deepcopy(current[0]); playing["game_state"] = {"state": "in_game"}
        publish(peer, playing)
        waiting = copy.deepcopy(current[0]); waiting["game_state"] = {"state": "intermission"}
        state = publish(peer, waiting)
        assert "map_vote" not in state and state["map_vote_cycle"] == 1
        assert state["backend_doc"]["ruleset_payload"]["map_weights"] == original_weights
        tie = copy.deepcopy(current[0])
        tie["dw_map_vote"] = {"version": 1, "entry": 0,
                              "votes": {str(host.user): 1, str(peer.user): 2}}
        state = publish(peer, tie)
        state["map_vote"]["started_ms"] = 1; path.write_text(json.dumps(state))
        state = publish(peer, tie)
        assert state["map_vote"]["winner"] == 0
        poisoned = copy.deepcopy(state)
        poisoned["map_vote"]["original_weights"]["bad_map"] = "invalid"
        path.write_text(json.dumps(poisoned))
        publish(peer, tie, error=106)
        path.write_text(json.dumps(state))
        checks.append("feature handshake publishes three same-mode maps and shared human tally; launch waits, migration preserves deadline, frozen winner survives late votes, next round resets and ties choose first option")
        checks.append("current allocation gates votes; new humans join before and after freeze; pending departures remove votes; two rounds restore original weights and reject poisoned recovery weights")
        checks.append("128-override stored lobby rejects expanded ballot publication before committing any lobby/search/index/journal mutation")
        assert ordinary(peer, 10, u64(lobby)) == b""
        ended = (2, u32(2002) + u64(lobby) + u64(0))
        for client in (host, peer, clients[3]): assert receive(client) == ended
    finally:
        policy.write_bytes(previous)
