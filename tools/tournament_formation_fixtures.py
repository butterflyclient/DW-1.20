"""Form brackets from real authenticated fixture clients, without seeded players."""

import json
import struct
import time

from tournament_fixtures import no_update


def exercise(
    client,
    peer,
    directory,
    title,
    user,
    peer_user,
    player_info,
    new_client,
    helpers,
    checks,
):
    u64, text, boolean = helpers
    root = directory / "tournaments" / str(title)
    catalog_path, enrollment_path = root / "catalog.json", root / "enrollments.json"
    originals = {p: p.read_bytes() for p in (catalog_path, enrollment_path)}
    mm_root = directory / "matchmaking" / str(title)
    clients = [(user, client), (peer_user, peer)]
    extra = []
    tournament = (1 << 62) + 471

    def row(size=1, identifier=tournament):
        return {
            "id": identifier,
            "name": str(identifier),
            "data_center": "local",
            "expires": int(time.time()) + 7200,
            "registration_open": True,
            "start_search_offset_seconds": 1.25,
            "formation": {"team_size": size, "num_teams": 8},
            # Explicit pushes are consumed below; disable optional idle edits.
            "live_updates": False,
        }

    def publish(value):
        content = json.dumps(
            {"schema": 1, "title": title, "tournaments": [value]}
        ).encode()
        pending = catalog_path.with_suffix(".json.pending")
        pending.write_bytes(content)
        pending.replace(catalog_path)
        return content

    def register(connection, publication):
        result = connection.task(
            145,
            29,
            text(
                json.dumps(
                    {
                        "data_center": publication["data_center"],
                        "tournament_name": publication["name"],
                    }
                )
            ),
        )
        assert json.loads(result[1:-1]) == {"start_search_offset_seconds": 1.25}

    def token(connection):
        assert connection.task(145, 2, text(json.dumps(player_info))) == []
        return struct.unpack_from("<Q", connection.task(145, 3), 1)[0]

    def search(connection, query):
        result = connection.task(145, 18, text(json.dumps(query)))
        return json.loads(result[1:-1])["mm_id"]

    def joined(connection, search_id):
        kind, packet = connection.receive()
        assert kind == 2 and packet[:14] == b"\x08\xd9\x07\0\0" + u64(search_id)
        assert packet[14] == 16 and packet[-1] == 0
        return json.loads(packet[15:-1])

    def updated(connection):
        kind, packet = connection.receive()
        assert kind == 2 and packet[:6] == b"\x08\xda\x07\0\0\x10" and packet[-1] == 0
        return json.loads(packet[6:-1])

    try:
        assert peer.task(145, 22) == [] and client.task(145, 22) == []
        no_update(client)
        no_update(peer)
        publication = row()
        published_bytes = publish(publication)
        assert "state" not in publication and "players" not in publication
        for i in range(6):
            identity, connection = new_client(i)
            assert identity not in {uid for uid, _ in clients}
            clients.append((identity, connection))
            extra.append(connection)
        accepted = []
        for identity, connection in clients:
            issued = token(connection)
            register(connection, publication)
            connection.task(145, 20, error=14526)  # Registered, not allocated yet.
            query = {
                "members": [identity],
                "tokens": [issued],
                "tournament": {"team_size": 1},
            }
            search_id = search(connection, query)
            bracket = joined(connection, search_id)
            assert bracket["tournamentStatus"] == "FORMING"
            expected = [uid for uid, _ in accepted] + [identity]
            assert [p["playerID"] for p in bracket["players"]] == expected
            assert [team["playerIDs"] for team in bracket["teams"]] == [
                [uid] for uid in expected
            ] + [[]] * (8 - len(expected))
            assert connection.task(145, 23, u64(tournament) + boolean(True)) == []
            accepted.append((identity, connection))
            status = "PLAYING" if len(accepted) == 8 else "FORMING"
            for _, receiver in accepted:
                snapshot = updated(receiver)
                assert snapshot["tournamentStatus"] == status
                assert snapshot["players"] == bracket["players"]
            assert catalog_path.read_bytes() == published_bytes
        formed = json.loads(client.task(145, 20)[1:-1])
        assert formed["tournamentDefinition"] == {
            "teamSize": 1,
            "numTeams": 8,
            "numPlayers": 8,
        }
        assert [len(r["matches"]) for r in formed["rounds"]] == [4, 2, 1]
        record_path = mm_root / "tournaments" / f"{tournament}.json"
        record = json.loads(record_path.read_bytes())
        assert len(record["parties"]) == 8 and record["state"] == formed
        enrolled = json.loads(enrollment_path.read_bytes())["players"]
        assert all(enrolled[str(uid)]["accepted_session"] for uid, _ in clients)
        checks.append(
            "Automatic tournament capacity publication accepts unassigned registrations and allocates eight independently authenticated real parties, with generated native teams/rounds and no publisher player IDs"
        )
        checks.append(
            "Automatic bracket remains FORMING until all slots and live-session acknowledgements are present; eighth native-wire acknowledgement commits PLAYING and exact event-2010 documents for all accepted users"
        )

        assert client.task(145, 19, u64(tournament) + u64(0xFFFFFFFF)) == []
        for _, connection in clients:
            snapshot = updated(connection)
            assert snapshot["rounds"][0]["matches"][0]["readyPlayerIDs"] == [user]
            assert not any(
                m["lobbyID"] for r in snapshot["rounds"] for m in r["matches"]
            )
        # Immutable competition identity cannot be changed under an active bracket.
        bad = dict(publication, formation={"team_size": 2, "num_teams": 8})
        publish(bad)
        client.task(145, 20, error=102)
        assert json.loads(record_path.read_bytes()) == record
        publish(publication)
        checks.append(
            "Formed bracket uses owned session-bound readiness; changing competition capacity under the same ID fails closed without rewriting the durable allocation"
        )

        # Only the two retained test connections need cleanup. Others close without
        # issuing owner tasks, and the original enrollment bytes are restored below.
        for connection in extra:
            connection.close()
        extra.clear()
        assert client.task(145, 22) == []
        updated(peer)
        assert peer.task(145, 22) == []

        publication = row(2, tournament + 1)
        publish(publication)
        register(client, publication)
        register(peer, publication)
        query = {
            "members": [user, peer_user],
            "tokens": [token(client), token(peer)],
            "tournament": {"team_size": 2},
        }
        search_id = search(client, query)
        assert joined(client, search_id) == joined(peer, search_id)
        assert (
            client.task(145, 19, u64(tournament + 1) + u64(0xFFFFFFFF), error=101) == []
        )
        assert client.task(145, 23, u64(tournament + 1) + boolean(True)) == []
        updated(client)
        path = mm_root / "tournaments" / f"{tournament + 1}.json"
        blocker = path.with_suffix(".json.pending")
        blocker.mkdir()
        try:
            peer.task(145, 23, u64(tournament + 1) + boolean(True), error=102)
            journal = json.loads((mm_root / "transaction.json").read_bytes())
            assert journal["phase"] == "prepared"
            assert {entry["path"] for entry in journal["writes"]} == {
                "tournament-enrollments.json",
                f"tournaments/{tournament + 1}.json",
            }
        finally:
            blocker.rmdir()
        assert json.loads(peer.task(145, 20)[1:-1])["tournamentStatus"] == "FORMING"
        assert (
            json.loads((mm_root / "transaction.json").read_bytes())["phase"]
            == "applied"
        )
        assert json.loads(enrollment_path.read_bytes())["players"][str(peer_user)][
            "accepted"
        ]
        assert peer.task(145, 23, u64(tournament + 1) + boolean(True)) == []
        no_update(peer)
        checks.append(
            "Interrupted automatic acknowledgement rolls forward its fixed cross-domain enrollment target and formation snapshot together; retry stays idempotent after storage failure"
        )

        assert client.task(145, 22) == []
        kind, packet = peer.receive()
        assert kind == 2 and packet == b"\x08\xdb\x07\0\0" + u64(tournament + 1)
        record = json.loads(path.read_bytes())
        assert record["parties"] == {} and record["state"]["players"] == []
        entry = json.loads(enrollment_path.read_bytes())["players"][str(peer_user)]
        assert entry["formation_disbanded"] and not entry["accepted"]
        peer.task(145, 20, error=14526)
        replacement = search(
            peer,
            {
                "members": [peer_user],
                "tokens": [token(peer)],
                "tournament": {"team_size": 2},
            },
        )
        assert replacement != search_id
        assert joined(peer, replacement)["players"] == [{"playerID": peer_user}]
        assert (
            "formation_disbanded"
            not in json.loads(enrollment_path.read_bytes())["players"][str(peer_user)]
        )
        assert peer.task(145, 23, u64(tournament + 1) + boolean(False)) == []
        assert json.loads(path.read_bytes())["state"]["players"] == []
        checks.append(
            "Forming-party withdrawal releases the entire reservation, preserves peer registration while resetting acceptance, emits exact event-2011, and permits slot reuse/owned decline with no stale assignment"
        )
    finally:
        for connection in extra:
            connection.close()
        for path, content in originals.items():
            pending = path.with_suffix(path.suffix + ".pending")
            pending.write_bytes(content)
            pending.replace(path)
