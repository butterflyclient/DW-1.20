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
    client.task(145, 21, text("{}"), error=108)
    checks.append(
        "Tournament malformed requests roll back, full bracket fixed-array bounds and 64-bit narrowing rejection, publication errors remain storage failures, legacy task 21 unavailable"
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
    return {
        "path": enrollment_path,
        "bytes": enrollment_path.read_bytes(),
        "state": expected,
    }


def check_restart(client, fixture, checks):
    assert json.loads(client.task(145, 20)[1:-1]) == fixture["state"]
    assert fixture["path"].read_bytes() == fixture["bytes"]
    checks.append(
        "Tournament enrollment and owned readiness survive backend process restart without changing published bracket or persistent receipt"
    )
