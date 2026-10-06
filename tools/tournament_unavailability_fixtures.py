"""Retire unavailable managed competitions without fabricating match results."""

import json
import time

from tournament_fixtures import no_update, updates


def exercise(directory, title, clients, publication, helpers, publish, checks):
    u64, text, boolean = helpers
    root = directory / "tournaments" / str(title)
    mm = directory / "matchmaking" / str(title)
    catalog = root / "catalog.json"

    def register(position, row, search=True, accept=True):
        user, connection = clients[position]
        connection.task(
            145,
            29,
            text(json.dumps({"tournament_name": row["name"], "data_center": "local"})),
        )
        if search:
            token = int.from_bytes(connection.task(145, 3)[1:], "little")
            result = connection.task(
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
            search_id = json.loads(result[1:-1])["mm_id"]
            kind, packet = connection.receive()
            assert kind == 2 and packet[:14] == b"\x08\xd9\x07\0\0" + u64(search_id)
        else:
            search_id = None
        if accept:
            connection.task(145, 23, u64(row["id"]) + boolean(True))
        return search_id

    for iteration, mode in enumerate(
        ("forming", "playing", "expired", "offline-playing"), 10
    ):
        playing = mode in ("playing", "offline-playing")
        offline = mode == "offline-playing"
        tournament = publication["id"] + iteration
        row = dict(
            publication,
            id=tournament,
            name=str(tournament),
            expires=int(time.time()) + (8 if mode == "expired" else 7200),
        )
        other = dict(
            row,
            id=tournament + 100,
            name=str(tournament + 100),
            expires=int(time.time()) + 7200,
        )
        publish(catalog, {"schema": 1, "title": title, "tournaments": [row, other]})
        count = 8 if playing else 2
        search_ids = {}
        for position in range(count):
            user, _ = clients[position]
            search_ids[user] = register(position, row)
            bracket = updates([connection for _, connection in clients[: position + 1]])
        assert bracket["tournamentStatus"] == ("PLAYING" if count == 8 else "FORMING")

        unrelated_search = None
        if not playing:
            # A registered user without a reserved slot is not itself
            # proof that this globally live publication has been withdrawn.
            register(2, row, search=False, accept=False)
            clients[2][1].task(145, 20, error=14526)
            terminal_path = mm / "tournament-terminations" / f"{tournament}.json"
            assert not terminal_path.exists()
            unrelated_search = register(3, other)
            updates([clients[3][1]])
            unrelated_bytes = (
                mm / "searches" / f"{unrelated_search}.json"
            ).read_bytes()
            count = 3

        lobby = None
        if playing:
            for position in (0, 1):
                clients[position][1].task(145, 19, u64(tournament) + u64(0xFFFFFFFF))
                bracket = updates([peer for _, peer in clients])
            lobby = bracket["rounds"][0]["matches"][0]["lobbyID"]
            assert lobby
            for _, connection in clients[:2]:
                kind, packet = connection.receive()
                assert kind == 2 and packet[:5] in (
                    b"\x08\xd1\x07\0\0",
                    b"\x08\xd5\x07\0\0",
                )

        result_path = root / "results" / f"{tournament}.json"
        result_before = result_path.read_bytes() if result_path.exists() else None
        terminal_path = mm / "tournament-terminations" / f"{tournament}.json"
        if playing:
            # Force interrupted durable publication. No successful event can be
            # sent before the complete shared transaction has rolled forward.
            blocker = terminal_path.with_suffix(".json.pending")
            blocker.mkdir()
            if offline:
                for _, connection in clients:
                    connection.close()
            publish(catalog, {"schema": 1, "title": title, "tournaments": [other]})
            try:
                if offline:
                    deadline = time.monotonic() + 6
                    while time.monotonic() < deadline:
                        journal = json.loads((mm / "transaction.json").read_bytes())
                        if journal["phase"] == "prepared" and any(
                            entry["path"]
                            == f"tournament-terminations/{tournament}.json"
                            for entry in journal["writes"]
                        ):
                            break
                        time.sleep(0.05)
                    else:
                        raise AssertionError(
                            "Offline retirement did not prepare a transaction"
                        )
                else:
                    clients[0][1].task(145, 20, error=102)
                assert not terminal_path.exists()
                journal = json.loads((mm / "transaction.json").read_bytes())
                assert journal["phase"] == "prepared"
                paths = {entry["path"] for entry in journal["writes"]}
                assert f"lobbies/{lobby}.json" in paths
                assert "current-lobbies.json" in paths
                assert "tournament-searches.json" in paths
                assert "tournament-enrollments.json" in paths
                assert sum(path.startswith("searches/") for path in paths) == 8
                if not offline:
                    for _, connection in clients:
                        no_update(connection)
            finally:
                blocker.rmdir()
        elif mode == "forming":
            publish(catalog, {"schema": 1, "title": title, "tournaments": [other]})
        else:
            # The wire client's ordinary receive timeout is shorter than this
            # deliberately real-clock expiry window. Let the idle publisher run
            # before requiring the buffered native event.
            time.sleep(max(0, row["expires"] - time.time()) + 0.25)

        if offline:
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                if (
                    terminal_path.exists()
                    and json.loads((mm / "transaction.json").read_bytes())["phase"]
                    == "applied"
                ):
                    break
                time.sleep(0.05)
            else:
                raise AssertionError(
                    "Offline retirement did not finish without a client task"
                )
            for position, (user, connection) in enumerate(clients):
                clients[position] = (
                    user,
                    type(connection)(auth_identity=connection.fixture_auth_identity),
                )

        for _, connection in clients[:count]:
            assert connection.receive() == (
                2,
                b"\x08\xdc\x07\0\0"
                + u64(tournament)
                + u64(0)
                + text("Tournament publication is no longer available"),
            )
        terminal = json.loads(terminal_path.read_bytes())
        assert (
            terminal["action"] == "publication-unavailable" and terminal["actor"] == 0
        )
        assert terminal["state"] == bracket
        if mode == "expired":
            assert terminal["recorded"] >= row["expires"]
        for search_id in search_ids.values():
            assert not json.loads((mm / "searches" / f"{search_id}.json").read_bytes())[
                "active"
            ]
        index = json.loads((mm / "tournament-searches.json").read_bytes())
        assert all(str(user) not in index["searches"] for user in search_ids)
        players = json.loads((root / "enrollments.json").read_bytes())["players"]
        for user, connection in clients[:count]:
            assert (
                players[str(user)]["live_updates"] and not players[str(user)]["ready"]
            )
            assert "ready_round" not in players[str(user)]
            assert "ready_match" not in players[str(user)]
            connection.task(145, 20, error=14526)
            no_update(connection)
        if lobby:
            assert json.loads((mm / "lobbies" / f"{lobby}.json").read_bytes())[
                "disbanded"
            ]
            assert (
                lobby
                not in json.loads((mm / "current-lobbies.json").read_bytes())[
                    "lobbies"
                ].values()
            )
        if unrelated_search:
            assert (
                mm / "searches" / f"{unrelated_search}.json"
            ).read_bytes() == unrelated_bytes
            assert index["searches"][str(clients[3][0])] == unrelated_search
            no_update(clients[3][1])
        assert (
            result_path.read_bytes() if result_path.exists() else None
        ) == result_before

        # Re-publishing an ID is not permission to resurrect a retired session.
        publish(catalog, {"schema": 1, "title": title, "tournaments": [row, other]})
        clients[0][1].task(
            145,
            29,
            text(json.dumps({"tournament_name": row["name"], "data_center": "local"})),
            error=108,
        )
        for corrupt in (
            dict(terminal, actor=clients[0][0]),
            dict(terminal, expires=0),
            dict(terminal, action="expiry"),
            dict(terminal, extra=True),
        ):
            publish(terminal_path, corrupt)
            clients[0][1].task(145, 20, error=102)
        publish(terminal_path, terminal)
        for _, connection in clients[:count]:
            assert connection.task(145, 22) == []
        if unrelated_search:
            assert clients[3][1].task(145, 22) == []
        if offline:
            checks.append(
                "Offline managed publication retirement runs without participant connections or tasks, recovers a blocked terminal transaction, retires allocated searches/lobbies/indexes and delivers exact native event-2012 once on reconnect"
            )
        else:
            checks.append(
                f"Managed {mode} publication unavailability atomically retires owned searches/lobbies, preserves unrelated competitions and actual result journals, clears readiness, sends native event-2012 once, recovers interrupted publication and prevents stale ID resurrection"
            )
