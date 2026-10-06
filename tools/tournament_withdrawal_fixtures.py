"""Retire managed tournaments through authenticated native leave/decline tasks."""

import copy
import json
import struct

from tournament_fixtures import no_update, updates


def exercise(directory, title, clients, publication, bracket, helpers, publish, checks):
    u64, text, boolean = helpers
    root = directory / "tournaments" / str(title)
    mm = directory / "matchmaking" / str(title)
    catalog = root / "catalog.json"
    enrollment = root / "enrollments.json"
    original_id = publication["id"]

    def termination_path(tournament):
        return mm / "tournament-terminations" / f"{tournament}.json"

    # This bracket completed all seven matches through real owned task-21 results.
    # Neither the champion nor eliminated players can cancel it by leaving.
    for position, (_, connection) in enumerate(clients):
        assert connection.task(145, 22) == []
        if position + 1 < len(clients):
            updates([peer for _, peer in clients[position + 1 :]])
        assert not termination_path(original_id).exists()
    for round_ in bracket["rounds"]:
        for match in round_["matches"]:
            assert json.loads(
                (mm / "lobbies" / f"{match['lobbyID']}.json").read_bytes()
            )["disbanded"]
    checks.append(
        "Authenticated departure after elimination or a completed final preserves all seven actual results and never cancels the finished managed tournament"
    )

    for iteration, action in enumerate(("decline", "leave"), 1):
        tournament = original_id + iteration
        row = dict(publication, id=tournament, name=str(tournament))
        publish(catalog, {"schema": 1, "title": title, "tournaments": [row]})
        search_ids = {}
        for position, (user, connection) in enumerate(clients):
            token = struct.unpack_from("<Q", connection.task(145, 3), 1)[0]
            connection.task(
                145,
                29,
                text(
                    json.dumps(
                        {"tournament_name": str(tournament), "data_center": "local"}
                    )
                ),
            )
            response = connection.task(
                145,
                18,
                text(
                    json.dumps(
                        {
                            "members": [user],
                            "tokens": [token],
                            "tournament": {"team_size": 1},
                        }
                    )
                ),
            )
            search_ids[user] = json.loads(response[1:-1])["mm_id"]
            kind, packet = connection.receive()
            assert kind == 2 and packet[:14] == b"\x08\xd9\x07\0\0" + u64(
                search_ids[user]
            )
            connection.task(145, 23, u64(tournament) + boolean(True))
            bracket = updates([peer for _, peer in clients[: position + 1]])
        assert bracket["tournamentStatus"] == "PLAYING"

        if action == "leave":
            for position in (0, 1):
                clients[position][1].task(145, 19, u64(tournament) + u64(0xFFFFFFFF))
                bracket = updates([connection for _, connection in clients])
            for user, connection in clients[:2]:
                kind, packet = connection.receive()
                event = struct.unpack_from("<I", packet, 1)[0]
                assert kind == 2 and event in (2001, 2005)
                assert packet[5:14] == u64(search_ids[user])
            lobby = bracket["rounds"][0]["matches"][0]["lobbyID"]
            assert lobby
            # A same-session reconnect is a transport event, never a withdrawal.
            user, old = clients[1]
            authentication = old.fixture_auth_identity
            old.close()
            replacement = type(old)(auth_identity=authentication)
            clients[1] = (user, replacement)
            kind, packet = replacement.receive()
            assert kind == 2 and packet[:6] == b"\x08\xda\x07\0\0\x10"
            assert replacement.receive()[0] == 2
            assert not termination_path(tournament).exists()
            no_update(replacement)

            # An eliminated participant may depart while other matches are still
            # waiting. Retire that completed transport, preserving its winner's
            # active party search so advancement remains possible.
            lobby_state = json.loads((mm / "lobbies" / f"{lobby}.json").read_bytes())
            reporter = next(
                peer for uid, peer in clients if uid == lobby_state["owner"]
            )
            reporter.task(
                145,
                21,
                text(
                    json.dumps(
                        {
                            "tournamentID": tournament,
                            "lobbyID": lobby,
                            "winningTeamID": 0,
                            "matchResultPayload": {"scores": [6, 3]},
                        }
                    )
                ),
            )
            bracket = updates([peer for _, peer in clients])
            results_path = root / "results" / f"{tournament}.json"
            result_bytes = results_path.read_bytes()
            assert clients[1][1].task(145, 22) == []
            bracket = updates(
                [peer for position, (_, peer) in enumerate(clients) if position != 1]
            )
            assert not termination_path(tournament).exists()
            assert json.loads((mm / "lobbies" / f"{lobby}.json").read_bytes())[
                "disbanded"
            ]
            assert json.loads(
                (mm / "searches" / f"{search_ids[clients[0][0]]}.json").read_bytes()
            )["active"]
            assert not json.loads(
                (mm / "searches" / f"{search_ids[clients[1][0]]}.json").read_bytes()
            )["active"]
            assert results_path.read_bytes() == result_bytes
            # Rejoin only the eliminated account's historical registration; its
            # retired party search cannot allocate a new match.
            clients[1][1].task(
                145,
                29,
                text(
                    json.dumps(
                        {"tournament_name": str(tournament), "data_center": "local"}
                    )
                ),
            )
            clients[1][1].task(145, 28, u64(tournament))
            bracket = updates([peer for _, peer in clients])
            for position in (2, 3):
                clients[position][1].task(145, 19, u64(tournament) + u64(0xFFFFFFFF))
                bracket = updates([peer for _, peer in clients])
            for _, peer in clients[2:4]:
                kind, packet = peer.receive()
                assert kind == 2 and struct.unpack_from("<I", packet, 1)[0] in (
                    2001,
                    2005,
                )
            active_lobby = bracket["rounds"][0]["matches"][1]["lobbyID"]
            assert active_lobby and active_lobby != lobby

        actor, connection = clients[0]
        before_enrollment = enrollment.read_bytes()
        before_transaction = (mm / "transaction.json").read_bytes()
        connection.task(145, 22, u64(tournament), error=106)
        connection.task(145, 23, u64(tournament + 100) + boolean(False), error=14526)
        assert enrollment.read_bytes() == before_enrollment
        assert (mm / "transaction.json").read_bytes() == before_transaction

        def withdraw(error=0):
            parameters = (
                u64(tournament) + boolean(False) if action == "decline" else b""
            )
            return connection.task(
                145, 23 if action == "decline" else 22, parameters, error=error
            )

        if action == "leave":
            # Entire source layouts are validated before the transaction begins.
            search_path = mm / "searches" / f"{search_ids[actor]}.json"
            original = search_path.read_bytes()
            corrupt = json.loads(original)
            corrupt["member_sessions"] = {}
            publish(search_path, corrupt)
            try:
                withdraw(error=102)
                assert enrollment.read_bytes() == before_enrollment
                assert (mm / "transaction.json").read_bytes() == before_transaction
                assert not termination_path(tournament).exists()
            finally:
                search_path.write_bytes(original)
            blocker = termination_path(tournament).with_suffix(".json.pending")
            blocker.parent.mkdir(exist_ok=True)
            blocker.mkdir()
            try:
                withdraw(error=102)
                transaction = json.loads((mm / "transaction.json").read_bytes())
                assert transaction["phase"] == "prepared"
                paths = {entry["path"] for entry in transaction["writes"]}
                assert "tournament-enrollments.json" in paths
                assert f"tournament-terminations/{tournament}.json" in paths
                assert (
                    "current-lobbies.json" in paths
                    and "tournament-searches.json" in paths
                )
                assert f"lobbies/{active_lobby}.json" in paths
                assert sum(path.startswith("searches/") for path in paths) == 7
            finally:
                blocker.rmdir()
            # An owned retry rolls forward the same terminal record. It cannot
            # resurrect the lost participation or allocate another lobby.
            assert withdraw() == []
        else:
            assert withdraw() == []

        for _, peer in clients[1:]:
            kind, packet = peer.receive()
            assert kind == 2 and packet == (
                b"\x08\xdc\x07\0\0"
                + u64(tournament)
                + u64(0)
                + text("Tournament publication is no longer available")
            )
        terminal = json.loads(termination_path(tournament).read_bytes())
        assert terminal == {
            "schema": 1,
            "title": title,
            "id": tournament,
            "expires": row["expires"],
            "actor": actor,
            "action": action,
            "recorded": terminal["recorded"],
            "state": bracket,
        }
        assert terminal["actor"] == actor and terminal["action"] == action
        assert terminal["state"]["tournamentStatus"] == "PLAYING"
        assert terminal["state"]["rounds"] == bracket["rounds"]
        if action == "leave":
            assert results_path.read_bytes() == result_bytes
        else:
            assert not (root / "results" / f"{tournament}.json").exists()
        players = json.loads(enrollment.read_bytes())["players"]
        assert str(actor) not in players
        for user, _ in clients[1:]:
            assert (
                players[str(user)]["id"] == tournament
                and players[str(user)]["accepted"]
            )
            assert (
                players[str(user)]["live_updates"] and not players[str(user)]["ready"]
            )
            assert (
                "ready_round" not in players[str(user)]
                and "ready_match" not in players[str(user)]
            )
        index = json.loads((mm / "tournament-searches.json").read_bytes())
        assert all(str(user) not in index["searches"] for user, _ in clients)
        for search in search_ids.values():
            assert not json.loads((mm / "searches" / f"{search}.json").read_bytes())[
                "active"
            ]
        if action == "leave":
            assert json.loads((mm / "lobbies" / f"{lobby}.json").read_bytes())[
                "disbanded"
            ]
            assignments = json.loads((mm / "current-lobbies.json").read_bytes())[
                "lobbies"
            ]
            assert all(value != lobby for value in assignments.values())
        for _, peer in clients:
            no_update(peer)
        peer = clients[1][1]
        peer.task(145, 20, error=14526)
        peer.task(145, 19, u64(tournament) + u64(0xFFFFFFFF), error=14526)
        peer.task(145, 23, u64(tournament) + boolean(True), error=14526)
        peer.task(
            145,
            29,
            text(
                json.dumps({"tournament_name": str(tournament), "data_center": "local"})
            ),
            error=108,
        )
        if action == "leave":
            peer.task(
                145,
                21,
                text(
                    json.dumps(
                        {
                            "tournamentID": tournament,
                            "lobbyID": lobby,
                            "winningTeamID": 0,
                            "matchResultPayload": {"scores": [6, 3]},
                        }
                    )
                ),
                error=14529,
            )
        checks.append(
            f"Managed PLAYING {action} retires {'an allocated lobby and ' if action == 'leave' else ''}all eight live party searches atomically; native event-2012 is delivered once even with live updates disabled, and stale readiness/accept/result/registration cannot resurrect the competition"
        )

        # The terminal schema is complete and fail-closed, including actor identity.
        variants = [
            dict(terminal, title=title + 1),
            dict(terminal, actor=0),
            dict(terminal, actor=(1 << 64) - 1),
            dict(terminal, action="timeout"),
            dict(terminal, extra=True),
            dict(terminal, recorded=terminal["expires"] + 1),
        ]
        for corrupt in variants:
            publish(termination_path(tournament), corrupt)
            peer.task(145, 20, error=102)
        publish(termination_path(tournament), terminal)
        for _, peer in clients[1:]:
            assert peer.task(145, 22) == []
        assert json.loads(termination_path(tournament).read_bytes()) == terminal
    checks.append(
        "Withdrawal validates complete retirement/terminal snapshots, preserves enrollment on malformed source, recovers a blocked terminal write with owned retry, preserves actual results and winning searches after elimination, retains terminal audit data after peer leave, and never interprets a temporary same-session disconnect as cancellation"
    )
