"""Allocate real authenticated tournament rounds through the native lobby path."""

import copy
import json
import struct
import time

from tournament_fixtures import no_update, updates


def exercise(directory, title, player_info, match_query, new_client, helpers, checks):
    u64, text, boolean = helpers
    root = directory / "tournaments" / str(title)
    catalog_path, enrollment_path = root / "catalog.json", root / "enrollments.json"
    policy_path = directory / "playlists" / str(title) / "policy.json"
    map_path, revision_path = root / "map-pools.json", root / "map-pools.applied.json"
    originals = {
        p: p.read_bytes() if p.exists() else None
        for p in (catalog_path, enrollment_path, policy_path, map_path, revision_path)
    }
    mm_root = directory / "matchmaking" / str(title)
    tournament = (1 << 62) + 561
    clients, search_ids = [], {}
    query = {"ruleset_payload": copy.deepcopy(match_query["ruleset_payload"])}
    maps = ["mp_shipment", "mp_rust", "mp_shipment", "mp_rust"]
    map_policy = {
        "schema": 1,
        "title": title,
        "revision": 73,
        "rounds": [["mp_rust", "mp_shipment"] for _ in range(4)],
    }
    enabled_policy = json.loads(originals[policy_path])
    enabled_policy["available_maps"] = ["mp_rust", "mp_shipment"]
    publication = {
        "id": tournament,
        "name": str(tournament),
        "data_center": "local",
        "expires": int(time.time()) + 7200,
        "registration_open": True,
        "start_search_offset_seconds": 1.25,
        "formation": {"team_size": 1, "num_teams": 8},
        "round_rules": [copy.deepcopy(query) for _ in range(3)],
        "native_map_pool_revision": map_policy["revision"],
        "live_updates": False,
    }

    def publish(path, value):
        pending = path.with_suffix(path.suffix + ".pending")
        pending.write_text(json.dumps(value))
        pending.replace(path)

    def all_updates():
        return updates([connection for _, connection in clients])

    def ready(position, error=0):
        return clients[position][1].task(
            145, 19, u64(tournament) + u64(0xFFFFFFFF), error=error
        )

    def lobby_packet(position, bracket, round_index, match_index):
        identity, connection = clients[position]
        kind, packet = connection.receive()
        assert kind == 2 and packet[0] == 8
        event = struct.unpack_from("<I", packet, 1)[0]
        assert event in (2001, 2005)
        assert packet[5:14] == u64(search_ids[identity])
        lobby_id = struct.unpack_from("<Q", packet, 15)[0]
        assert packet[14:23] == u64(lobby_id)
        offset = 23
        if event == 2005:
            assert packet[offset : offset + 9] == u64(1)
            offset += 9
        documents = []
        for _ in range(2):
            assert packet[offset] == 16
            end = packet.index(0, offset + 1)
            documents.append(json.loads(packet[offset + 1 : end]))
            offset = end + 1
        assert offset == len(packet)
        host, backend = documents
        assignment = bracket["rounds"][round_index]["matches"][match_index]
        assert assignment["lobbyID"] == lobby_id
        state = json.loads((mm_root / "lobbies" / f"{lobby_id}.json").read_bytes())
        assert event == (2005 if state["owner"] == identity else 2001)
        assert host == state["host_doc"] and backend == state["backend_doc"]
        assert backend["tournament"] == {
            "tournament_id": tournament,
            "round_id": round_index,
            "lobby_to_tournament_team_ids": {
                "0": assignment["teamIDs"][0],
                "1": assignment["teamIDs"][1],
            },
        }
        expected_teams = {
            str(side): bracket["teams"][team]["playerIDs"]
            for side, team in enumerate(assignment["teamIDs"])
        }
        assert backend["team_balance"]["teams"] == expected_teams
        assert not host["team_balance"]["can_change_teams"]
        assert not host["lobby_open_for_pres_join"] and "public_pool" not in state
        assert backend["ruleset_payload"]["map_weights"][maps[round_index]] == 1
        assert all(
            weight == 0
            for map_name, weight in backend["ruleset_payload"]["map_weights"].items()
            if map_name != maps[round_index]
        )
        for member in state["members"]:
            search = json.loads(
                (mm_root / "searches" / f"{search_ids[member]}.json").read_bytes()
            )
            assert search["lobby_id"] == lobby_id
            assert (
                search["round_id"] == round_index and search["match_id"] == match_index
            )
            index = json.loads((mm_root / "current-lobbies.json").read_bytes())
            assert index["lobbies"][str(member)] == lobby_id
        return state

    blocker = revision_path.with_suffix(revision_path.suffix + ".pending")
    blocker_created = False
    try:
        # Install the fault before making the policy visible to idle readers.
        # Publishing first races the backend's legitimate revision commit.
        root.mkdir(parents=True, exist_ok=True)
        blocker.mkdir()
        blocker_created = True
        publish(map_path, map_policy)
        publish(policy_path, enabled_policy)
        publish(
            catalog_path, {"schema": 1, "title": title, "tournaments": [publication]}
        )
        for i in range(8):
            identity, connection = new_client(20 + i)
            clients.append((identity, connection))
            if i == 0:
                native_names = json.loads(
                    (
                        directory / "playlists" / str(title) / "native-dvar-names.json"
                    ).read_bytes()
                )
                # No response is published until the revision receipt is durable.
                try:
                    connection.task(95, 1, text("") + text("general"), error=102)
                    assert not revision_path.exists()
                finally:
                    blocker.rmdir()
                    blocker_created = False
                variables = connection.task(95, 1, text("") + text("general"))
                assert variables[:6] == b"\x06\x01\0\x06\x49\0"
                assert variables[6:16] == text("general") + b"\x10"
                document = json.loads(variables[16:-1])
                for round_index in range(4):
                    name = native_names[
                        f"online_tournament_round_{round_index}_mapnames"
                    ]
                    assert document[name] == "mp_rust,mp_shipment"
                accepted = revision_path.read_bytes()
                for bad_json in (
                    json.dumps(map_policy) + " trailing-content",
                    json.dumps(map_policy).replace(
                        '"revision": 73', '"revision": 72, "revision": 73'
                    ),
                ):
                    map_path.write_text(bad_json)
                    connection.task(95, 1, text("") + text("general"), error=102)
                    assert revision_path.read_bytes() == accepted
                for bad in (
                    dict(map_policy, revision=0),
                    dict(map_policy, title=title + 1),
                    dict(map_policy, rounds=[["mp_rust", "mp_rust"] for _ in range(4)]),
                    dict(map_policy, rounds=[["map_" + str(n) for n in range(9)]] * 4),
                    dict(
                        map_policy,
                        rounds=[["mp_shipment", "mp_rust"] for _ in range(4)],
                    ),
                    dict(map_policy, revision=72),
                ):
                    publish(map_path, bad)
                    connection.task(95, 1, text("") + text("general"), error=102)
                    assert revision_path.read_bytes() == accepted
                publish(map_path, map_policy)
                assert (
                    connection.task(95, 1, text("iw8") + text("general")) == variables
                )
                checks.append(
                    "Canonical tournament pools publish native Replay dvar bindings with version 73 only after durable revision storage; blocked writes, trailing/duplicate JSON, malformed pools, foreign title, duplicate/oversized pools, rollback and changed content under the same revision fail before revision mutation"
                )
            assert connection.task(145, 2, text(json.dumps(player_info))) == []
            token = struct.unpack_from("<Q", connection.task(145, 3), 1)[0]
            connection.task(
                145,
                29,
                text(
                    json.dumps(
                        {"data_center": "local", "tournament_name": str(tournament)}
                    )
                ),
            )
            search = connection.task(
                145,
                18,
                text(
                    json.dumps(
                        {
                            "members": [identity],
                            "tokens": [token],
                            "tournament": {"team_size": 1},
                        }
                    )
                ),
            )
            search_ids[identity] = json.loads(search[1:-1])["mm_id"]
            kind, packet = connection.receive()
            assert kind == 2 and packet[:14] == b"\x08\xd9\x07\0\0" + u64(
                search_ids[identity]
            )
            assert connection.task(145, 23, u64(tournament) + boolean(True)) == []
            all_updates()

        # Match data may not bypass the published installation's available maps.
        unavailable = json.loads(originals[policy_path])
        unavailable["available_maps"] = []
        publish(policy_path, unavailable)
        ready(0)
        all_updates()
        ready(1)
        blocked = all_updates()
        assert blocked["rounds"][0]["matches"][0]["lobbyID"] == 0
        no_update(clients[0][1])
        no_update(clients[1][1])

        # Force interruption after the bracket/lobby/search snapshots have been
        # prepared, before the account assignment index can be published.
        blocker = mm_root / "current-lobbies.json.pending"
        blocker.mkdir()
        publish(policy_path, enabled_policy)
        try:
            ready(1, error=102)
            journal = json.loads((mm_root / "transaction.json").read_bytes())
            assert journal["phase"] == "prepared"
            paths = {entry["path"] for entry in journal["writes"]}
            assert "tournament-enrollments.json" in paths
            assert f"tournaments/{tournament}.json" in paths
            assert "current-lobbies.json" in paths
            assert sum(path.startswith("lobbies/") for path in paths) == 1
            assert sum(path.startswith("searches/") for path in paths) == 2
        finally:
            blocker.rmdir()
        recovered = json.loads(clients[1][1].task(145, 20)[1:-1])
        assert recovered["rounds"][0]["matches"][0]["lobbyID"]
        bracket = all_updates()
        first_lobby = lobby_packet(0, bracket, 0, 0)
        assert lobby_packet(1, bracket, 0, 0) == first_lobby
        assert (
            json.loads((mm_root / "transaction.json").read_bytes())["phase"]
            == "applied"
        )
        ready(1)
        no_update(clients[1][1])
        checks.append(
            "Tournament ready-up waits for available playlist maps and recovers one coupled bracket/enrollment/lobby/search/account-index transaction after a real blocked assignment write; retry keeps its lobby identity"
        )

        for left in range(2, 8, 2):
            ready(left)
            all_updates()
            ready(left + 1)
            bracket = all_updates()
            state = lobby_packet(left, bracket, 0, left // 2)
            assert lobby_packet(left + 1, bracket, 0, left // 2) == state
        assert len({m["lobbyID"] for m in bracket["rounds"][0]["matches"]}) == 4
        checks.append(
            "Four independent ready tournament matches allocate distinct closed native lobbies with actual party search IDs, exact create/join envelopes, Replay tournament/team/round metadata and native-selected available map rules"
        )

        # A connection lost after publication recovers both bracket and its join.
        identity, old = clients[1]
        authentication = old.fixture_auth_identity
        old.close()
        replacement = type(old)(auth_identity=authentication)
        clients[1] = (identity, replacement)
        kind, packet = replacement.receive()
        assert kind == 2 and packet[:6] == b"\x08\xda\x07\0\0\x10"
        bracket = json.loads(packet[6:-1])
        assert lobby_packet(1, bracket, 0, 0) == first_lobby
        no_update(replacement)
        checks.append(
            "Temporary same-session reconnect catches up the current bracket and allocated round join once through the existing idle publisher, without a new lobby or repeated native create/join callbacks"
        )

        # Consume real owned results, then require new round-scoped ready calls.
        for round_index in range(3):
            matches = list(bracket["rounds"][round_index]["matches"])
            winners = []
            for match_index, match in enumerate(matches):
                state = json.loads(
                    (mm_root / "lobbies" / f"{match['lobbyID']}.json").read_bytes()
                )
                owner = next(
                    connection for uid, connection in clients if uid == state["owner"]
                )
                assert (
                    owner.task(
                        145,
                        21,
                        text(
                            json.dumps(
                                {
                                    "tournamentID": tournament,
                                    "lobbyID": match["lobbyID"],
                                    "winningTeamID": match["teamIDs"][0],
                                    "matchResultPayload": {"scores": [6, 3]},
                                }
                            )
                        ),
                    )
                    == []
                )
                bracket = all_updates()
                winners.append(match["teamIDs"][0])
            if round_index == 2:
                break
            assert all(
                m["lobbyID"] == 0 and m["readyPlayerIDs"] == []
                for m in bracket["rounds"][round_index + 1]["matches"]
            )
            for next_match in range(len(winners) // 2):
                positions = [winners[2 * next_match], winners[2 * next_match + 1]]
                for position in positions:
                    ready(position)
                    bracket = all_updates()
                state = lobby_packet(positions[0], bracket, round_index + 1, next_match)
                assert (
                    lobby_packet(positions[1], bracket, round_index + 1, next_match)
                    == state
                )
        record = json.loads(
            (mm_root / "tournaments" / f"{tournament}.json").read_bytes()
        )
        journal = json.loads((root / "results" / f"{tournament}.json").read_bytes())
        assert len(journal["results"]) == 7
        assert (
            len({m["lobbyID"] for r in record["state"]["rounds"] for m in r["matches"]})
            == 7
        )
        assert bracket["rounds"][2]["matches"][0]["winningTeamID"] == 0
        checks.append(
            "Authenticated host results advance all seven matches through an eight-team tournament; later rounds require fresh scoped readiness and retain distinct native lobby/search/index assignments without carrying forward old ready flags"
        )
        accepted = revision_path.read_bytes()
        revised = dict(map_policy, revision=74, rounds=[["mp_shipment"]] * 4)
        publish(map_path, revised)
        changed = dict(publication, native_map_pool_revision=74)
        publish(catalog_path, {"schema": 1, "title": title, "tournaments": [changed]})
        clients[0][1].task(145, 20, error=102)
        assert (
            json.loads((mm_root / "tournaments" / f"{tournament}.json").read_bytes())
            == record
        )
        # Controlled fixture restoration only; production revisions cannot roll back.
        revision_path.write_bytes(accepted)
        publish(map_path, map_policy)
        publish(
            catalog_path, {"schema": 1, "title": title, "tournaments": [publication]}
        )
        assert (
            json.loads(clients[0][1].task(145, 20)[1:-1])["rounds"] == bracket["rounds"]
        )
        checks.append(
            "Backend rounds follow Replay's 16-bit tournament-ID map slices and repeat-avoidance fallback; an active competition pins the full policy and rejects changed pools without changing its bracket"
        )
        import tournament_withdrawal_fixtures

        tournament_withdrawal_fixtures.exercise(
            directory, title, clients, publication, bracket, helpers, publish, checks
        )
        import tournament_unavailability_fixtures

        tournament_unavailability_fixtures.exercise(
            directory, title, clients, publication, helpers, publish, checks
        )
    finally:
        if blocker_created:
            blocker.rmdir()
        for _, connection in clients:
            connection.close()
        for path, content in originals.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(content)
