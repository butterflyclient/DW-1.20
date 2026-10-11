"""Exercise native tournament search/join without seeding accepted enrollment."""

import copy
import json
import struct
import time

from tournament_fixtures import no_update, updates


def exercise(client, peer, directory, title, user, peer_user, helpers, checks):
    u64, text, boolean = helpers
    root = directory / "tournaments" / str(title)
    catalog_path, enrollment_path = root / "catalog.json", root / "enrollments.json"
    originals = {path: path.read_bytes() for path in (catalog_path, enrollment_path)}
    mm_root = directory / "matchmaking" / str(title)
    index_path = mm_root / "tournament-searches.json"
    tournament = (1 << 62) + 371
    catalog = json.loads(originals[catalog_path])
    row = copy.deepcopy(catalog["tournaments"][0])
    row.update(id=tournament, name=str(tournament), expires=int(time.time()) + 3600)
    row.pop("live_updates", None)  # A join is needed independently of live edits.
    state = row["state"]
    state.update(
        tournamentID=tournament,
        tournamentStatus="FORMING",
        tournamentDefinition={"teamSize": 2, "numTeams": 8, "numPlayers": 16},
        players=[{"playerID": user}, {"playerID": peer_user}],
        teams=[
            {"teamID": i, "playerIDs": [user, peer_user] if i == 0 else []}
            for i in range(8)
        ],
    )
    for r in state["rounds"]:
        for i, match in enumerate(r["matches"]):
            match.clear()
            match.update(
                teamIDs=[2 * i, 2 * i + 1] if r["roundID"] == 0 else [],
                readyPlayerIDs=[],
                lobbyID=0,
                expired=False,
                winningTeamID=-1,
            )
    catalog["tournaments"] = [row]
    registration = text(
        json.dumps({"data_center": row["data_center"], "tournament_name": row["name"]})
    )
    query = {
        "members": [user, peer_user],
        "tokens": [
            struct.unpack_from("<Q", connection.task(145, 3), 1)[0]
            for connection in (client, peer)
        ],
        "tournament": {"team_size": 2},
    }

    def publish(value=catalog):
        pending = catalog_path.with_suffix(".json.pending")
        pending.write_text(json.dumps(value))
        for attempt in range(50):
            try:
                pending.replace(catalog_path)
                break
            except PermissionError:
                if attempt == 49:
                    raise
                time.sleep(0.01)

    def start(value=query, error=0):
        result = client.task(145, 18, text(json.dumps(value)), error=error)
        return json.loads(result[1:-1])["mm_id"] if not error else None

    def joins(search):
        for connection in (client, peer):
            kind, packet = connection.receive()
            assert kind == 2 and packet[:14] == b"\x08\xd9\x07\0\0" + u64(search)
            assert packet[14] == 16 and packet[-1] == 0
            assert json.loads(packet[15:-1]) == state
        assert all(
            not entry["accepted"]
            for entry in json.loads(enrollment_path.read_bytes())["players"].values()
        )

    try:
        assert peer.task(145, 22) == [] and client.task(145, 22) == []
        no_update(client)
        no_update(peer)
        publish()
        start(error=14526)
        assert client.task(145, 29, registration)
        start(error=101)  # The party peer must register too.
        assert peer.task(145, 29, registration)
        before = enrollment_path.read_bytes()
        for invalid in (0, 5, -1, True, "2", (1 << 32) + 2):
            damaged = copy.deepcopy(query)
            damaged["tournament"]["team_size"] = invalid
            start(damaged, error=106)
        for field in (
            "private_lobby",
            "lobby_id_to_presence_join",
            "player_id_to_presence_join",
        ):
            start(dict(query, **{field: {}}), error=106)
        start(dict(query, tournament={"team_size": 3}), error=108)
        foreign = copy.deepcopy(catalog)
        foreign["tournaments"][0]["state"]["teams"][0]["playerIDs"] = [user]
        foreign["tournaments"][0]["state"]["teams"][1]["playerIDs"] = [peer_user]
        publish(foreign)
        start(error=101)
        publish()
        assert enrollment_path.read_bytes() == before and not index_path.exists()
        checks.append(
            "Tournament search enforces actual party tokens, owned enrollment, same published team, team-size bounds and incompatible-search rejection without mutation"
        )

        search = start()
        joins(search)
        search_path = mm_root / "searches" / f"{search}.json"
        persisted = json.loads(search_path.read_bytes())
        assert persisted["tournament_id"] == tournament and persisted["lobby_id"] == 0
        assert persisted["member_sessions"][str(user)] == persisted["owner_session"]
        snapshots = (search_path.read_bytes(), index_path.read_bytes())
        assert start() == search
        assert snapshots == (search_path.read_bytes(), index_path.read_bytes())
        no_update(client)
        no_update(peer)
        time.sleep(1.1)
        no_update(client)
        no_update(peer)
        checks.append(
            "Exact event-2009 search-ID/bracket envelope reaches both registered party members before acceptance; durable search/index transaction, retry identity and per-connection idle deduplication"
        )

        assert client.task(145, 23, u64(tournament) + boolean(True)) == []
        updates((client,), state)
        assert peer.task(145, 23, u64(tournament) + boolean(True)) == []
        updates((client, peer), state)
        assert client.task(145, 19, u64(tournament) + u64(0xFFFFFFFF)) == []
        expected = copy.deepcopy(state)
        expected["rounds"][0]["matches"][0]["readyPlayerIDs"] = [user]
        updates((client, peer), expected)
        checks.append(
            "Native join acknowledgement and readiness consume the newly returned formation search without seeded acceptance, with subsequent event-2010 state updates"
        )

        assert peer.task(145, 22) == [] and client.task(145, 22) == []
        no_update(client)
        no_update(peer)
        assert client.task(145, 29, registration) and peer.task(145, 29, registration)
        assert client.task(145, 8, u64(search)) == boolean(True)
        started = time.monotonic()
        cancelled = start()
        assert cancelled != search
        assert client.task(145, 9, u64(cancelled)) == boolean(True)
        assert time.monotonic() - started < 0.5
        time.sleep(1.1)
        no_update(client)
        no_update(peer)
        assert not json.loads(search_path.read_bytes())["active"]
        checks.append(
            "Both native cancel and shutdown revoke delayed tournament joins, and replacement searches retire the previous token before publishing the new index"
        )

        # Invalid durable state is a storage failure, never an invented join.
        index = index_path.read_bytes()
        damaged = json.loads(index)
        damaged["searches"][str(user)] = 0
        index_path.write_text(json.dumps(damaged))
        start(error=102)
        index_path.write_bytes(index)
        current = start()
        joins(current)
        active_path = mm_root / "searches" / f"{current}.json"
        expired = json.loads(active_path.read_bytes())
        expired["expires"] = 1
        active_path.write_text(json.dumps(expired))
        state["tournamentStatus"] = (
            "PLAYING"  # Would cause a new join if expiry were ignored.
        )
        publish()
        time.sleep(1.1)
        no_update(client)
        no_update(peer)
        checks.append(
            "Corrupt tournament search indexes fail closed; expired searches cannot emit a changed bracket through the idle publisher"
        )
    finally:
        # No fixture acceptance or publication is left in production; this entire
        # directory is an isolated protocol realm, and restore the prior test data.
        peer.task(145, 22)
        client.task(145, 22)
        for path, content in originals.items():
            pending = path.with_suffix(path.suffix + ".pending")
            pending.write_bytes(content)
            pending.replace(path)
