"""Encrypted host-document auto fill contracts; time aging stays inside disposable fixture data."""

import copy, json, struct, time, hashlib, secrets
from operator_match_start_fixtures import request as operator_request


def exercise(host, peer, directory, title, user, query, helpers, checks):
    u32, u64, text, boolean = helpers
    root = directory / "matchmaking" / str(title)
    token = struct.unpack_from("<Q", host.task(145, 3), 1)[0]
    request = copy.deepcopy(query)
    request.pop("private_lobby", None)
    request.update(members=[user], tokens=[token], lobby_slots={"min": 1, "max": 2})
    request["ruleset_payload"]["only_join_existing_lobbies"] = False

    def strings(raw):
        out = []
        while raw:
            assert raw[0] == 16
            end = raw.index(0, 1)
            out.append(json.loads(raw[1:end]))
            raw = raw[end + 1 :]
        return out

    mm = strings(host.task(145, 18, text(json.dumps(request))))[0]["mm_id"]
    kind, packet = host.receive()
    assert kind == 2 and packet.startswith(u32(2005) + u64(mm))
    lobby = struct.unpack_from("<Q", packet, 15)[0]
    docs = strings(packet[32:])
    path = root / "lobbies" / f"{lobby}.json"
    controller = host

    def update(document, error=0, revision=None):
        return controller.task(
            145,
            15,
            u64(lobby)
            + u64(docs[1]["update_id"] if revision is None else revision)
            + text(json.dumps(document)),
            error=error,
        )

    peer_in_lobby = False

    def received():
        kind, packet = host.receive()
        assert kind == 2 and packet.startswith(u32(2006) + u64(lobby))
        if peer_in_lobby:
            assert peer.receive() == (kind, packet)
        return strings(packet[23:])

    request_token = 0

    def auto(count, complete=False, enabled=True):
        nonlocal request_token
        request_token += 1
        h = copy.deepcopy(docs[0])
        h.update(
            dw_auto_fill_request=request_token,
            dw_auto_fill_bots=enabled,
            dw_auto_fill_complete=complete,
            dw_bot_count=count,
        )
        return h

    # Replay can attach its zero-bot arm to the first native host document,
    # before host_ready is established. It cannot add bots or declare the
    # timed fill complete during this initial publication.
    invalid = auto(1)
    update(invalid, error=106)
    invalid = auto(0, complete=True)
    update(invalid, error=106)
    assert update(auto(0)) == boolean(True)
    docs = received()
    assert json.loads(path.read_bytes())["host_ready"] is True
    checks.append("First native host publication accepts only a zero-bot incomplete auto-fill arm; early additions/completion remain rejected")
    rules = docs[1]["ruleset_payload"]["dvar_overrides"]
    target = rules["replay_dw_autoFillBotTarget"]
    assert (
        rules["replay_dw_autoFillBotsActive"] == 1
        and rules["replay_dw_autoFillBotsComplete"] == 0
        and target > 0
    )
    access = directory / "operator-access.key"
    previous_access = access.read_bytes() if access.exists() else None
    key = secrets.token_hex(32)
    access.write_text(key + "\n")
    state = json.loads(path.read_bytes())
    match_token = hashlib.sha256(
        (
            str(title)
            + ":"
            + str(lobby)
            + ":"
            + state["owner_session"]
            + ":"
            + str(state.get("operator_start_cycle", 0))
        ).encode()
    ).hexdigest()
    base = "http://127.0.0.1:" + str(host.s.getpeername()[1] - 3075 + 8085)
    saved = path.read_bytes()
    try:
        assert operator_request(base, match_token, key)[0] == 409
        assert path.read_bytes() == saved
    finally:
        if previous_access is None:
            access.unlink()
        else:
            access.write_bytes(previous_access)
    before = path.read_bytes()
    update(auto(target, True), error=106)
    assert path.read_bytes() == before
    h = copy.deepcopy(docs[0])
    h["game_state"]["state"] = "countdown"
    update(h, error=106)
    assert path.read_bytes() == before
    peer.task(
        145,
        15,
        u64(lobby) + u64(docs[1]["update_id"]) + text(json.dumps(auto(0))),
        error=101,
    )
    assert path.read_bytes() == before
    oldrevision = rules["replay_dw_autoFillRevision"]
    assert update(auto(target)) == boolean(True)
    docs = received()
    rules = docs[1]["ruleset_payload"]["dvar_overrides"]
    assert (
        rules["replay_dw_botCount"] == 0
        and rules["replay_dw_autoFillRevision"] != oldrevision
    )
    # Deterministic elapsed test does not sleep or touch any real profile/service.
    state = json.loads(path.read_bytes())
    state["auto_fill_started_ms"] = int(time.time() * 1000) - 45001
    path.write_text(json.dumps(state))
    before = path.read_bytes()
    update(auto(target, True), error=106)
    assert path.read_bytes() == before
    assert update(auto(target)) == boolean(True)
    docs = received()
    assert docs[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_botCount"] == target
    assert update(auto(target, True)) == boolean(True)
    docs = received()
    assert (
        docs[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_autoFillBotsComplete"]
        == 1
    )
    # Explicit nonzero -> off must publish count0, not merely remove a key
    # whose previous native dvar value could remain applied.
    nonzero = json.loads(path.read_bytes())["operator_bot_count"]
    assert nonzero > 0
    historical = json.loads(path.read_bytes())
    historical["backend_doc"]["ruleset_payload"]["dvar_overrides"].pop(
        "replay_dw_botCount", None
    )
    path.write_text(json.dumps(historical))
    assert update(auto(0, False, False)) == boolean(True)
    docs = received()
    off = docs[1]["ruleset_payload"]["dvar_overrides"]
    assert (
        off["replay_dw_autoFillBotsActive"] == 0
        and off["replay_dw_autoFillAck"] == request_token
        and off["replay_dw_botCount"] == 0
    )
    # Manual controls after disabling still publish their actual count.
    manual = copy.deepcopy(docs[0])
    manual["dw_bot_count"] = 1
    assert update(manual) == boolean(True)
    docs = received()
    assert docs[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_botCount"] == 1
    manual = copy.deepcopy(docs[0])
    manual["game_state"]["state"] = "countdown"
    assert update(manual) == boolean(True)
    docs = received()
    manual = copy.deepcopy(docs[0])
    manual["game_state"]["state"] = "intermission"
    assert update(manual) == boolean(True)
    docs = received()
    assert docs[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_botCount"] == 0
    assert update(auto(0)) == boolean(True)
    docs = received()
    rearmed = json.loads(path.read_bytes())
    rearmed["auto_fill_started_ms"] = int(time.time() * 1000) - 45001
    path.write_text(json.dumps(rearmed))
    assert update(auto(target)) == boolean(True)
    docs = received()
    assert update(auto(target, True)) == boolean(True)
    docs = received()
    checks.append(
        "Valid historical rules lacking count: nonzero automatic fill disable publishes exactAck and explicit Count0; subsequent manual Count1 is retained and completed-round reset publishes Count0"
    )
    # A human joins a full automatic bot roster. Both participants receive the
    # lower target and incomplete gate; join revision cannot acknowledge a request.
    info = json.loads((root / "players" / f"{user}.json").read_bytes())["info"]
    peer.task(145, 2, text(json.dumps(info)))
    peer_token = struct.unpack_from("<Q", peer.task(145, 3), 1)[0]
    peer_user = next(
        json.loads(p.read_bytes())["user"]
        for p in (root / "players").glob("*.json")
        if json.loads(p.read_bytes()).get("token") == peer_token
    )
    joining = copy.deepcopy(request)
    joining.update(
        members=[peer_user], tokens=[peer_token], player_id_to_slots={str(peer_user): 0}
    )
    joining["ruleset_payload"]["only_join_existing_lobbies"] = True
    prior_ack = docs[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_autoFillAck"]
    peer_mm = strings(peer.task(145, 18, text(json.dumps(joining))))[0]["mm_id"]
    kind, packet = peer.receive()
    assert kind == 2 and packet.startswith(u32(2001) + u64(peer_mm) + u64(lobby))
    peer_docs = strings(packet[23:])
    docs = received()
    assert docs == peer_docs
    peer_in_lobby = True
    rules = docs[1]["ruleset_payload"]["dvar_overrides"]
    assert (
        rules["replay_dw_autoFillBotTarget"] == target - 1
        and rules["replay_dw_botCount"] == target - 1
    )
    assert (
        rules["replay_dw_autoFillBotsComplete"] == 0
        and rules["replay_dw_autoFillAck"] == prior_ack
    )
    target -= 1
    assert update(auto(target, True)) == boolean(True)
    docs = received()
    assert (
        docs[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_autoFillBotsComplete"]
        == 1
    )
    duplicate = auto(target, True)
    duplicate["dw_auto_fill_request"] = docs[1]["ruleset_payload"]["dvar_overrides"][
        "replay_dw_autoFillAck"
    ]
    before = path.read_bytes()
    update(duplicate, error=106)
    assert path.read_bytes() == before
    before = path.read_bytes()
    assert update(auto(target, True), revision=docs[1]["update_id"] - 1) == boolean(
        False
    )
    assert path.read_bytes() == before
    # The monotonic token belongs to the authenticated host process, not the
    # lobby forever. Claim a real session-bound handoff with a restarted counter.
    assert target > 0  # This public native playlist retains vacant bot slots.
    request_token = 99
    handoff = auto(target, False)
    handoff["dw_migration_target"] = peer_user
    assert update(handoff) == boolean(True)
    docs = received()
    old = json.loads(path.read_bytes())
    assert old["auto_fill_request"] == 100 and old["operator_bot_count"] == target
    claim = copy.deepcopy(docs[0])
    claim["listen_server"] = {
        "host_player_id": peer_user,
        "host_address": info["listen_server"]["local_address"],
    }
    claim.update(
        dw_auto_fill_request=1,
        dw_auto_fill_bots=True,
        dw_auto_fill_complete=False,
        dw_bot_count=0,
    )
    assert peer.task(
        145, 15, u64(lobby) + u64(docs[1]["update_id"]) + text(json.dumps(claim))
    ) == boolean(True)
    docs = received()
    migrated = json.loads(path.read_bytes())
    assert migrated["owner"] == peer_user and migrated["auto_fill_request"] == 1
    assert migrated["operator_bot_count"] == 0 and not migrated["auto_fill_complete"]
    assert migrated["auto_fill_started_ms"] > old["auto_fill_started_ms"]
    rules = docs[1]["ruleset_payload"]["dvar_overrides"]
    assert (
        rules["replay_dw_autoFillAck"] == 1
        and rules["replay_dw_botCount"] == 0
        and rules["replay_dw_autoFillBotsComplete"] == 0
    )
    before = path.read_bytes()
    host.task(
        145,
        15,
        u64(lobby) + u64(docs[1]["update_id"]) + text(json.dumps(auto(target))),
        error=101,
    )
    assert path.read_bytes() == before
    controller = peer
    request_token = 1
    update(auto(target, True), error=106)
    assert path.read_bytes() == before
    migrated["auto_fill_started_ms"] = int(time.time() * 1000) - 45001
    path.write_text(json.dumps(migrated))
    assert update(auto(target)) == boolean(True)
    docs = received()
    assert update(auto(target, True)) == boolean(True)
    docs = received()
    checks.append(
        "Real session-bound host migration resets old token100/pool/timer, accepts successor token1/count0, rejects old owner and holds successor completion for server delay"
    )
    h = copy.deepcopy(docs[0])
    h["game_state"]["state"] = "countdown"
    assert update(h) == boolean(True)
    docs = received()
    h = copy.deepcopy(docs[0])
    h["game_state"]["state"] = "intermission"
    assert update(h) == boolean(True)
    docs = received()
    state = json.loads(path.read_bytes())
    assert not state.get("auto_fill_bots", False) and "operator_bot_count" not in state
    assert (
        docs[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_autoFillBotsActive"]
        == 0
    )
    controller.task(145, 10, u64(lobby))
    assert host.receive() == peer.receive() == (2, u32(2002) + u64(lobby) + u64(0))
    checks.append(
        "Encrypted automatic fill enforces server delay, owner/CAS binding, exact request acknowledgement, all-member publication, human replacement, operator force-start denial, prior target-count completion, native start gate and round reset"
    )
