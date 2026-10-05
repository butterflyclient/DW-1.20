"""Independent same-Replay tournament wire/state/isolation contract checks.

Uses explicitly published brackets, not invented retail match scheduling.
The native callback and bracket consumer addresses are recorded in the docs.
"""

import copy
import json
import time


def exercise(client, peer, directory, title, user, peer_user, helpers, checks):
    u64, text, boolean = helpers
    root = directory / "tournaments" / str(title)
    root.mkdir(parents=True, exist_ok=True)
    catalog_path, enrollment_path = root / "catalog.json", root / "enrollments.json"
    tournament = (1 << 62) + 173
    teams = [{"teamID": index, "playerIDs": []} for index in range(8)]
    teams[0]["playerIDs"], teams[1]["playerIDs"] = [user], [peer_user]
    state = {
        "tournamentID": tournament,
        "tournamentStatus": "FORMING",
        "tournamentDefinition": {"teamSize": 1, "numTeams": 8, "numPlayers": 8},
        "players": [{"playerID": user}, {"playerID": peer_user}],
        "teams": teams,
        "rounds": [
            {
                "roundID": index,
                "matches": [
                    {
                        "teamIDs": [2 * match, 2 * match + 1] if index == 0 else [],
                        "readyPlayerIDs": [],
                        "lobbyID": 0,
                        "expired": False,
                        "winningTeamID": -1,
                    }
                    for match in range(8 >> (index + 1))
                ],
            }
            for index in range(3)
        ],
    }
    row = {
        "id": tournament,
        "name": str(int(time.time()) + 3600),
        "data_center": "local",
        "expires": int(time.time()) + 7200,
        "registration_open": True,
        "start_search_offset_seconds": 3.5,
        "state": state,
    }
    catalog = {"schema": 1, "title": title, "tournaments": [row]}

    def publish(value=catalog):
        catalog_path.write_text(json.dumps(value), encoding="utf-8")

    def registration(value=row):
        return text(
            json.dumps(
                {"data_center": value["data_center"], "tournament_name": value["name"]}
            )
        )

    def get_state(connection=client):
        result = connection.task(145, 20)
        assert (
            isinstance(result, bytes) and result[:1] == b"\x10" and result[-1:] == b"\0"
        )
        return json.loads(result[1:-1])

    client.task(145, 20, error=14526)
    for task, params in (
        (19, u64(tournament) + u64(0xFFFFFFFF)),
        (23, u64(tournament) + boolean(True)),
        (28, u64(tournament)),
    ):
        client.task(145, task, params, error=14526)
    assert client.task(145, 22) == []
    client.task(145, 29, registration(), error=108)
    publish()
    result = client.task(145, 29, registration())
    assert result == text('{"start_search_offset_seconds":3.5}')
    before = enrollment_path.read_bytes()
    assert client.task(145, 29, registration()) == result
    assert enrollment_path.read_bytes() == before and get_state() == state
    assert client.task(145, 23, u64(tournament) + boolean(True)) == []
    assert client.task(145, 28, u64(tournament)) == []
    assert client.task(145, 19, u64(tournament) + u64(0xFFFFFFFF)) == []
    expected = copy.deepcopy(state)
    expected["rounds"][0]["matches"][0]["readyPlayerIDs"] = [user]
    assert get_state() == expected
    checks.append(
        "Replay 145/19/20/22/23/28/29 exact wire contracts, published bracket, enrollment, registration string and first-unfinished-match readiness"
    )

    before = enrollment_path.read_bytes()
    for task, params in (
        (19, u64(tournament) + u64(0)),
        (19, u64(0) + u64(0xFFFFFFFF)),
        (23, u64(tournament) + b"\x01\x02"),
        (23, u64(tournament) + boolean(True) + u64(1)),
        (29, text("broken")),
        (29, text("[]")),
        (29, text(json.dumps({"tournament_name": row["name"]}))),
        (29, text("x" * 256)),
    ):
        client.task(145, task, params, error=106)
        assert enrollment_path.read_bytes() == before
    client.task(145, 28, u64(tournament + 1), error=14526)
    unavailable = dict(row, name="unpublished")
    client.task(145, 29, registration(unavailable), error=108)
    for mutate in (
        lambda value: value.update(title=title + 1),
        lambda value: value["tournaments"][0]["state"]["teams"][0].update(teamID=8),
        lambda value: value["tournaments"][0]["state"]["tournamentDefinition"].update(
            teamSize=(1 << 32) + 1
        ),
        lambda value: value["tournaments"][0]["state"]["rounds"][0]["matches"][
            0
        ].update(teamIDs=[(1 << 32), 1]),
        lambda value: value["tournaments"][0]["state"]["rounds"][0]["matches"][
            0
        ].update(winningTeamID=(1 << 32)),
        lambda value: value["tournaments"][0]["state"]["rounds"][0]["matches"][
            0
        ].update(readyPlayerIDs=[user + 999]),
        lambda value: value["tournaments"].append(
            copy.deepcopy(value["tournaments"][0])
        ),
        lambda value: value["tournaments"][0]["state"].update(extra="x" * 16384),
    ):
        damaged = copy.deepcopy(catalog)
        mutate(damaged)
        publish(damaged)
        client.task(145, 20, error=102)
        assert enrollment_path.read_bytes() == before
    publish()
    client.task(145, 21, text("{}"), error=106)
    checks.append(
        "Tournament malformed requests roll back, full bracket fixed-array bounds and 64-bit narrowing rejection, publication errors remain storage failures"
    )

    peer.task(145, 20, error=14526)
    assert peer.task(145, 29, registration()) == result
    assert peer.task(145, 19, u64(tournament) + u64(0xFFFFFFFF)) == []
    expected["rounds"][0]["matches"][0]["readyPlayerIDs"].append(peer_user)
    assert get_state() == expected and get_state(peer) == expected
    assert peer.task(145, 22) == []
    peer.task(145, 20, error=14526)
    expected["rounds"][0]["matches"][0]["readyPlayerIDs"] = [user]
    assert get_state() == expected
    foreign = copy.deepcopy(catalog)
    foreign["tournaments"][0]["state"]["teams"][1]["playerIDs"] = []
    foreign["tournaments"][0]["state"]["players"] = [{"playerID": user}]
    publish(foreign)
    peer.task(145, 29, registration(), error=101)
    publish()
    assert client.task(145, 23, u64(tournament) + boolean(False)) == []
    client.task(145, 20, error=14526)
    client.task(145, 28, u64(tournament), error=14526)
    assert client.task(145, 29, registration()) == result
    assert client.task(145, 19, u64(tournament) + u64(0xFFFFFFFF)) == []
    expired = copy.deepcopy(catalog)
    expired["tournaments"][0]["expires"] = 1
    publish(expired)
    client.task(145, 20, error=14526)
    client.task(145, 29, registration(), error=108)
    publish()
    checks.append(
        "Tournament account isolation, unassigned participant rejection, shared readiness, owned leave/decline/rejoin and expired publication rejection"
    )
    result_fixture = exercise_results(
        client, peer, directory, title, user, peer_user, helpers, checks, catalog
    )
    return {
        "path": enrollment_path,
        "bytes": enrollment_path.read_bytes(),
        "state": result_fixture["state"],
        "result": result_fixture,
    }


def exercise_results(
    client, peer, directory, title, user, peer_user, helpers, checks, original_catalog
):
    u64, text, boolean = helpers
    root = directory / "tournaments" / str(title)
    catalog_path = root / "catalog.json"
    catalog = copy.deepcopy(original_catalog)
    row = catalog["tournaments"][0]
    tournament = row["id"]

    def publish(value=catalog):
        catalog_path.write_text(json.dumps(value), encoding="utf-8")

    def get_state(connection=client):
        return json.loads(connection.task(145, 20)[1:-1])

    registration = text(
        json.dumps({"data_center": row["data_center"], "tournament_name": row["name"]})
    )
    assert peer.task(145, 29, registration)
    assert peer.task(145, 23, u64(tournament) + boolean(True)) == []
    player_root = directory / "matchmaking" / str(title) / "players"
    info = json.loads((player_root / f"{user}.json").read_text())["info"]
    assert peer.task(145, 2, text(json.dumps(info))) == []
    tokens = [
        int.from_bytes(connection.task(145, 3)[1:], "little")
        for connection in (client, peer)
    ]
    playlist = json.loads(
        (directory / "playlists" / str(title) / "catalog.json").read_text()
    )
    query = {
        "members": [user, peer_user],
        "tokens": tokens,
        "ruleset_payload": {
            "filter": {
                "playlist_id": 1,
                "netcode_version": 1,
                "playlist_version": playlist["system"]["version"],
            }
        },
    }
    assert json.loads(client.task(145, 18, text(json.dumps(query)))[1:-1])["mm_id"]
    kind, push = client.receive()
    assert kind == 2
    # The native push contains typed UInt32 event, UInt64 search, UInt64 lobby.
    assert push[14] == 10
    lobby = int.from_bytes(push[15:23], "little")
    assert peer.receive() == (kind, push)
    lobby_path = directory / "matchmaking" / str(title) / "lobbies" / f"{lobby}.json"
    lobby_bytes = lobby_path.read_bytes()
    row["state"]["tournamentStatus"] = "PLAYING"
    row["state"]["rounds"][0]["matches"][0]["lobbyID"] = lobby
    publish()
    result_path = root / "results" / f"{tournament}.json"
    submission = {
        "tournamentID": tournament,
        "lobbyID": lobby,
        "winningTeamID": 0,
        "matchResultPayload": {"scores": [6, 4]},
    }

    def submit(value=submission, connection=client, error=0):
        return connection.task(145, 21, text(json.dumps(value)), error=error)

    submit(error=101)  # Client registration alone does not accept participation.
    assert client.task(145, 23, u64(tournament) + boolean(True)) == []
    enrollment_bytes = (root / "enrollments.json").read_bytes()
    for mutate in (
        lambda value: value.update(tournamentID=0),
        lambda value: value.update(lobbyID=0),
        lambda value: value.update(winningTeamID=16),
        lambda value: value.update(winningTeamID=(1 << 32)),
        lambda value: value.update(winningTeamID=-1),
        lambda value: value.update(extra=True),
        lambda value: value["matchResultPayload"].update(scores=[1]),
        lambda value: value["matchResultPayload"].update(scores=[1, 2, 3]),
        lambda value: value["matchResultPayload"].update(scores=[1, -1]),
        lambda value: value["matchResultPayload"].update(scores=[65536, 1]),
        lambda value: value["matchResultPayload"].update(scores=[1.0, 2]),
        lambda value: value["matchResultPayload"].update(extra=0),
    ):
        invalid = copy.deepcopy(submission)
        mutate(invalid)
        submit(invalid, error=106)
    for invalid in (
        text("broken"),
        text("[]"),
        text(json.dumps(submission)[:-1] + ',"lobbyID":1}'),
        text(json.dumps(submission)) + u64(1),
        text("x" * 256),
    ):
        client.task(145, 21, invalid, error=106)
    submit(dict(submission, tournamentID=tournament + 1), error=14529)
    submit(dict(submission, lobbyID=lobby + 1), error=108)
    submit(dict(submission, winningTeamID=2), error=101)
    submit(connection=peer, error=101)
    assert not result_path.exists()
    assert (root / "enrollments.json").read_bytes() == enrollment_bytes
    checks.append(
        "Replay 145/21 exact typed 256-byte JSON request, duplicate-key/type/range/terminator rejection, accepted enrollment and signed reporting-host isolation"
    )

    for mutate, error in (
        (lambda value: value.update(expires=1), 108),
        (lambda value: value.update(disbanded=True), 108),
        (lambda value: value.update(members=[user]), 101),
        (lambda value: value["backend_doc"].update(lobby_id=lobby + 1), 102),
        (lambda value: value.update(title=title + 1), 102),
    ):
        damaged = json.loads(lobby_bytes)
        mutate(damaged)
        lobby_path.write_text(json.dumps(damaged))
        submit(error=error)
        assert not result_path.exists()
    lobby_path.unlink()
    submit(error=108)
    lobby_path.write_bytes(lobby_bytes)
    unavailable = copy.deepcopy(catalog)
    unavailable["tournaments"][0]["state"]["rounds"][0]["matches"][0]["expired"] = True
    unavailable["tournaments"][0]["state"]["rounds"][0]["matches"][0][
        "expireReason"
    ] = 1
    publish(unavailable)
    submit(error=108)
    publish()
    assert not result_path.exists()
    assert submit() == []
    committed = result_path.read_bytes()
    assert submit() == [] and result_path.read_bytes() == committed
    submit(dict(submission, winningTeamID=1), error=14536)
    submit({**submission, "matchResultPayload": {"scores": [7, 4]}}, error=14536)
    submit(connection=peer, error=101)
    assert result_path.read_bytes() == committed
    journal = json.loads(committed)
    assert journal["title"] == title and journal["tournament"] == tournament
    assert len(journal["results"]) == 1
    entry = journal["results"][0]
    assert entry["reporter"] == user and entry["lobby"] == lobby
    assert (
        entry["winner"] == 0 and entry["teams"] == [0, 1] and entry["scores"] == [6, 4]
    )
    assert entry["round"] == 0 and entry["match"] == 0 and entry["recorded"] > 0
    expected = copy.deepcopy(row["state"])
    expected["rounds"][0]["matches"][0].update(
        winningTeamID=0, matchResultPayload={"scores": [6, 4]}
    )
    assert get_state() == expected and get_state(peer) == expected
    checks.append(
        "Tournament result requires a live authenticated host lobby with both published teams; one atomic durable result, exact retry and native 14536 conflict without publication or enrollment mutation"
    )

    # A separately published sibling result completes the two-child prerequisite.
    # No synthetic accounts, native memory writes or game match are needed here.
    row["state"]["rounds"][0]["matches"][1].update(
        winningTeamID=2, matchResultPayload={"scores": [7, 3]}
    )
    publish()
    publication_bytes = catalog_path.read_bytes()
    expected["rounds"][0]["matches"][1].update(
        winningTeamID=2, matchResultPayload={"scores": [7, 3]}
    )
    expected["rounds"][1]["matches"][0]["teamIDs"] = [0, 2]
    assert get_state() == expected and get_state(peer) == expected
    assert client.task(145, 19, u64(tournament) + u64(0xFFFFFFFF)) == []
    expected["rounds"][1]["matches"][0]["readyPlayerIDs"] = [user]
    assert get_state() == expected
    assert catalog_path.read_bytes() == publication_bytes
    assert result_path.read_bytes() == committed
    for mutate in (
        lambda value: value.update(title=title + 1),
        lambda value: value["results"].append(copy.deepcopy(value["results"][0])),
        lambda value: value["results"][0].update(winner=2),
        lambda value: value["results"][0].update(scores=[65536, 0]),
        lambda value: value["results"][0].update(round=4),
        lambda value: value["results"][0].update(match=7),
        lambda value: value["results"][0].update(teams=[1, 0]),
    ):
        damaged = json.loads(committed)
        mutate(damaged)
        result_path.write_text(json.dumps(damaged))
        before = result_path.read_bytes()
        client.task(145, 20, error=102)
        submit(error=102)
        assert result_path.read_bytes() == before
    result_path.write_bytes(committed)
    for mutate in (
        lambda value: value["tournaments"][0]["state"]["rounds"][0]["matches"][
            0
        ].update(teamIDs=[1, 0]),
        lambda value: value["tournaments"][0]["state"]["rounds"][1]["matches"][
            0
        ].update(teamIDs=[1, 2]),
        lambda value: value["tournaments"][0]["state"]["rounds"][0]["matches"][
            1
        ].update(lobbyID=lobby),
    ):
        damaged = copy.deepcopy(catalog)
        mutate(damaged)
        publish(damaged)
        client.task(145, 20, error=102)
        assert result_path.read_bytes() == committed
    publish()
    assert get_state() == expected
    assert catalog_path.read_bytes() == publication_bytes
    checks.append(
        "Tournament two-child winner advancement in native global-team order, round-scoped readiness, full result-journal/publication consistency and corrupt-state preservation"
    )
    return {
        "path": result_path,
        "bytes": committed,
        "submission": text(json.dumps(submission)),
        "state": expected,
        "publication_path": catalog_path,
        "publication_bytes": publication_bytes,
    }


def check_restart(client, fixture, checks):
    assert json.loads(client.task(145, 20)[1:-1]) == fixture["state"]
    assert fixture["path"].read_bytes() == fixture["bytes"]
    checks.append(
        "Tournament enrollment and owned readiness survive backend process restart without changing published bracket or persistent receipt"
    )
    result = fixture["result"]
    assert client.task(145, 21, result["submission"]) == []
    assert result["path"].read_bytes() == result["bytes"]
    assert result["publication_path"].read_bytes() == result["publication_bytes"]
    checks.append(
        "Tournament result and advancement survive a real backend restart; original authenticated reporter can retry without duplicate writes or published bracket edits"
    )
