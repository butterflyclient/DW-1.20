"""Authenticated dashboard control tested against disposable native-wire clients."""

import json
import copy
import secrets
import struct
import urllib.error
import urllib.request


def request(base, token, key="", method="POST", fill_bots=False, bot_count=1):
    headers = {"X-Replay-Operator": key, "Content-Type": "text/plain"}
    route = "/operator/fill-bots" if fill_bots else "/operator/start-match"
    body = json.dumps({"match_token": token, "bot_count": bot_count}).encode() if fill_bots else token.encode()
    request = urllib.request.Request(base + route, body, headers, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as failure:
        response = failure
    with response:
        return response.status, json.load(response)


def before_match(base, data, clients, activity, lobby_path, strings, checks):
    match = activity()["matches"][0]
    assert match["can_start"] and not match["start_requested"]
    token = match["start_token"]
    assert len(token) == 64
    before = lobby_path.read_bytes()
    assert request(base, token)[0] == 503
    key = secrets.token_hex(32)
    (data / "operator-access.key").write_text(key + "\n")
    assert request(base, token, "f" * 64)[0] == 403
    assert request(base, token, key, "GET")[0] == 405
    assert request(base, "g" * 64, key)[0] == 400
    assert request(base, "0" * 64, key)[0] == 404
    assert lobby_path.read_bytes() == before
    checks.append("Operator key required; malformed, unknown and wrong-method requests leave the lobby untouched")
    old = json.loads(before)
    for count in (0, -1, 200, True, 1.5, "2"):
        assert request(base, token, key, fill_bots=True, bot_count=count)[0] == 400
        assert lobby_path.read_bytes() == before
    assert request(base, token, key, fill_bots=True, bot_count=2)[0] == 409
    assert lobby_path.read_bytes() == before
    response = request(base, token, key, fill_bots=True)
    assert response[0] == 202, response
    filled = json.loads(lobby_path.read_bytes())
    assert filled["operator_bots_requested"] and filled["maximum_members"] == old["maximum_members"]
    assert filled["operator_bot_count"] == 1
    assert filled["members"] == old["members"]
    overrides = filled["backend_doc"]["ruleset_payload"]["dvar_overrides"]
    bindings = json.loads((data / "playlists/5800/native-dvar-names.json").read_bytes())
    assert overrides.get(bindings["party_maxplayers"]) == old["backend_doc"]["ruleset_payload"]["dvar_overrides"].get(bindings["party_maxplayers"])
    assert overrides["replay_dw_botCount"] == 1 and overrides["replay_dw_fillBots"] == 0
    assert overrides["replay_dw_forceStart"] == 0
    saved = lobby_path.read_bytes()
    assert request(base, token, key, fill_bots=True)[0] == 200
    assert lobby_path.read_bytes() == saved
    assert request(base, token, key, fill_bots=True, bot_count=2)[0] == 409
    checks.append("Custom bot counts validate integer/slot bounds and preserve playlist capacity, native teams and real roster; retries are exact and legacy shrinking consumer stays off")
    assert request(base, token, key)[0] == 202
    state = json.loads(lobby_path.read_bytes())
    assert state["update_id"] == old["update_id"] + 2
    assert state["operator_start_requested"]
    bindings = json.loads((data / "playlists/5800/native-dvar-names.json").read_bytes())
    overrides = state["backend_doc"]["ruleset_payload"]["dvar_overrides"]
    for name in ("party_minLobbyTime", "party_minVoteTime"):
        assert overrides[bindings[name]] == 0
    assert overrides[bindings["party_minplayers"]] == 1
    assert overrides["replay_dw_forceStart"] == 1
    assert state["members"] == old["members"]
    assert state["backend_doc"]["team_balance"] == old["backend_doc"]["team_balance"]
    assert state["host_doc"]["game_state"] == old["host_doc"]["game_state"]
    for client in clients:
        for _ in range(12):
            kind, packet = (2, client.pushes.pop(0)) if client.pushes else client.receive()
            assert kind == 2
            if packet[:5] != b"\x08" + struct.pack("<I", 2006):
                continue
            revision = struct.unpack_from("<Q", packet, 15)[0]
            if revision == state["update_id"]:
                host, backend = strings(packet[23:])
                expected_backend = copy.deepcopy(state["backend_doc"])
                assert not state["match_selection"].get("squad_size", 0)
                expected_backend["ruleset_payload"]["dvar_overrides"].update(
                    replay_dw_squadSize=0, replay_dw_reservedSquads="0" * 50,
                    replay_dw_autoFillBotsActive=0, replay_dw_autoFillBotsComplete=0,
                    replay_dw_autoFillBotTarget=0, replay_dw_autoFillAck=0,
                    replay_dw_autoFillRevision=state["update_id"] % 2147483647
                )
                assert host == state["host_doc"] and backend == expected_backend
                break
        else:
            raise AssertionError("Native lobby update did not reach every participant")
    checks.append("Start publishes the real 2006 update and native host start control to every participant, with operator minimum and wait timers applied")
    saved = lobby_path.read_bytes()
    assert request(base, token, key)[0] == 200
    assert lobby_path.read_bytes() == saved
    assert key not in json.dumps(activity())
    checks.append("Retry is idempotent, and the operator secret is absent from public snapshots")
    return key, token, old


def after_match(base, clients, activity, lobby_path, fixture, call, u64, text, checks):
    key, old_token, original = fixture
    before = lobby_path.read_bytes()
    assert request(base, old_token, key)[0] == 409
    assert lobby_path.read_bytes() == before
    assert not activity()["matches"][0]["can_start"]
    checks.append("An active match cannot be started again")
    state = json.loads(before)
    host = state["host_doc"]
    host["game_state"]["state"] = "intermission"
    assert call(clients[0], 15, u64(state["id"]) + u64(state["update_id"]) + text(json.dumps(host))) == b"\x01\x01"
    state = json.loads(lobby_path.read_bytes())
    assert not state.get("operator_start_requested", False)
    assert not state.get("operator_bots_requested", False)
    assert state["maximum_members"] == original["maximum_members"]
    assert state["backend_doc"]["ruleset_payload"]["dvar_overrides"] == original["backend_doc"]["ruleset_payload"]["dvar_overrides"]
    match = activity()["matches"][0]
    assert match["can_start"] and match["start_token"] != old_token
    before = lobby_path.read_bytes()
    assert request(base, old_token, key)[0] == 404
    assert lobby_path.read_bytes() == before
    checks.append("Next-round waiting settings return, and an old round's button token cannot start the new round")
