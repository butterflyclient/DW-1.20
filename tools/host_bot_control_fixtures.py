"""Host-authenticated bot controls, with real encrypted native 145/15 tasks."""

import copy
import json
import struct


def exercise(host, peer, directory, title, user, query, helpers, checks):
    u32, u64, text, boolean = helpers
    root = directory / "matchmaking" / str(title)
    token = struct.unpack_from("<Q", host.task(145, 3), 1)[0]
    request = copy.deepcopy(query)
    request.pop("private_lobby", None)
    request.update(members=[user], tokens=[token], lobby_slots={"min": 1, "max": 2})
    request["ruleset_payload"]["only_join_existing_lobbies"] = False

    def strings(raw):
        documents = []
        while raw:
            assert raw[0] == 16
            end = raw.index(0, 1)
            documents.append(json.loads(raw[1:end]))
            raw = raw[end + 1 :]
        return documents

    mm = strings(host.task(145, 18, text(json.dumps(request))))[0]["mm_id"]
    kind, packet = host.receive()
    assert kind == 2 and packet.startswith(u32(2005) + u64(mm))
    lobby = struct.unpack_from("<Q", packet, 15)[0]
    docs = strings(packet[32:])
    path = root / "lobbies" / f"{lobby}.json"

    def update(document, revision=None, error=0):
        return host.task(
            145,
            15,
            u64(lobby)
            + u64(docs[1]["update_id"] if revision is None else revision)
            + text(json.dumps(document)),
            error=error,
        )

    def received():
        kind, packet = host.receive()
        assert kind == 2 and packet.startswith(u32(2006) + u64(lobby))
        return strings(packet[23:])

    assert update(docs[0]) == boolean(True)
    docs = received()
    capacity = json.loads(path.read_bytes())["maximum_members"]
    for invalid in (0, -1, 200, capacity, "1", True):
        document = copy.deepcopy(docs[0])
        document["dw_bot_count"] = invalid
        before = path.read_bytes()
        update(document, error=106)
        assert path.read_bytes() == before
    document["dw_bot_count"] = 1
    before = path.read_bytes()
    peer.task(
        145, 15, u64(lobby) + u64(docs[1]["update_id"]) + text(json.dumps(document)), error=101
    )
    assert path.read_bytes() == before
    assert update(document, revision=docs[1]["update_id"] - 1) == boolean(False)
    assert path.read_bytes() == before
    checks.append(
        "Host bot requests reject invalid counts, non-owners and stale revisions without changing persistent lobby state"
    )

    assert update(document) == boolean(True)
    docs = received()
    state = json.loads(path.read_bytes())
    bindings = json.loads(
        (directory / "playlists" / str(title) / "native-dvar-names.json").read_bytes()
    )
    count_key = bindings.get("replay_dw_botCount", "replay_dw_botCount")
    legacy_key = bindings.get("replay_dw_fillBots", "replay_dw_fillBots")
    assert state["maximum_members"] == capacity and state["operator_bot_count"] == 1
    assert docs[1]["ruleset_payload"]["dvar_overrides"][count_key] == 1
    assert docs[1]["ruleset_payload"]["dvar_overrides"][legacy_key] == 0
    assert "dw_bot_count" not in docs[0]
    assert update(docs[0]) == boolean(True)
    docs = received()
    assert docs[1]["ruleset_payload"]["dvar_overrides"][count_key] == 1
    checks.append(
        "Authenticated native host documents retain bot counts across refreshes without changing playlist capacity or using operator credentials"
    )

    document = copy.deepcopy(docs[0])
    document["game_state"]["state"] = "countdown"
    assert update(document) == boolean(True)
    docs = received()
    document = copy.deepcopy(docs[0])
    document["game_state"]["state"] = "intermission"
    assert update(document) == boolean(True)
    docs = received()
    state = json.loads(path.read_bytes())
    assert not state.get("operator_bots_requested", False)
    assert not docs[1]["ruleset_payload"]["dvar_overrides"].get(count_key, 0)
    assert state["maximum_members"] == capacity
    host.task(145, 8, u64(mm))
    checks.append(
        "A completed matchmaking round restores bot controls while preserving the original player limit"
    )
