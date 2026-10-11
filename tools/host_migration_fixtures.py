"""Replay's existing get-documents / host-update migration contract.

Only isolated fixture accounts and files are used. The party election is not
simulated by a new wire event: an authenticated member submits the native claim.
"""

import base64
import copy
import json
import struct
import time


def exercise(
    candidate,
    owner,
    owner_auth,
    Client,
    directory,
    title,
    user,
    owner_user,
    query,
    native_rest,
    rest_response,
    helpers,
    checks,
):
    u32, u64, text, boolean = helpers
    root = directory / "matchmaking" / str(title)
    player_path = root / "players" / f"{user}.json"
    candidate_token = struct.unpack_from("<Q", candidate.task(145, 3), 1)[0]
    owner_token = struct.unpack_from("<Q", owner.task(145, 3), 1)[0]
    address = json.loads(player_path.read_bytes())["info"]["listen_server"][
        "local_address"
    ]
    original_info = json.loads((root / "players" / f"{owner_user}.json").read_bytes())[
        "info"
    ]
    owner_info = copy.deepcopy(original_info)
    owner_info["listen_server"]["local_address"] = base64.b64encode(
        b"\xfd" * 84
    ).decode()
    assert owner_info["listen_server"]["local_address"] != address
    owner.task(145, 2, text(json.dumps(owner_info)))
    request = {
        **copy.deepcopy(query),
        "members": [owner_user, user],
        "tokens": [owner_token, candidate_token],
        "lobby_slots": {"min": 1, "max": 4},
        "private_lobby": {"initial_party_id": 61},
    }

    def strings(raw):
        result = []
        while raw:
            assert raw[0] == 16
            end = raw.index(0, 1)
            result.append(json.loads(raw[1:end]))
            raw = raw[end + 1 :]
        return result

    def create():
        mm = strings(owner.task(145, 18, text(json.dumps(request))))[0]["mm_id"]
        kind, packet = owner.receive()
        assert kind == 2 and packet.startswith(u32(2005) + u64(mm))
        lobby = struct.unpack_from("<Q", packet, 15)[0]
        documents = strings(packet[32:])
        assert owner.task(
            145, 15, u64(lobby) + u64(documents[1]["update_id"])
            + text(json.dumps(documents[0]))
        ) == boolean(True)
        kind, update = owner.receive()
        assert kind == 2 and update.startswith(u32(2006) + u64(lobby))
        assert candidate.receive() == (
            2,
            u32(2001) + u64(mm) + u64(lobby) + update[23:],
        )
        return lobby, mm, strings(update[23:])

    def claim(lobby, docs, revision=None, error=0):
        host = copy.deepcopy(docs[0])
        host["listen_server"] = {"host_player_id": user, "host_address": address}
        host["player_state"] = {str(user): 2}
        if str(owner_user) in docs[0]["player_state"]:
            host["player_state"][str(owner_user)] = 4
        return candidate.task(
            145,
            15,
            u64(lobby)
            + u64(docs[1]["update_id"] if revision is None else revision)
            + text(json.dumps(host)),
            error=error,
        )

    def snapshot():
        return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*.json")}

    def wait_offline():
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status, body = rest_response(
                candidate.task(
                    255,
                    10,
                    native_rest(
                        "social-service",
                        "UsersPresence",
                        "get_users_presence",
                        uri=f"/v1/users/presence/?context=iw8&users=uno-{owner_user}",
                    ),
                )
            )
            assert status == 200
            if not body["users"][0]["presence"]["online"]:
                return
            time.sleep(0.05)
        raise AssertionError("Owned fixture host did not disconnect")

    def reopen():
        return Client(
            auth_identity=(
                base64.b64decode(owner_auth["server_ticket"]),
                base64.b64decode(owner_auth["client_ticket"])[97:121],
            )
        )

    lobby, mm, docs = create()
    path = root / "lobbies" / f"{lobby}.json"
    before = snapshot()
    claim(lobby, docs, error=101)
    assert snapshot() == before
    assert strings(candidate.task(145, 13, u64(lobby))) == docs
    checks.append(
        "host migration denies takeover while the original native host lease is live"
    )

    owner.close()
    wait_offline()
    assert strings(candidate.task(145, 13, u64(lobby))) == docs
    assert claim(lobby, docs, revision=0) == boolean(False)
    for change in ("address", "host_missing", "host_removing"):
        host = copy.deepcopy(docs[0])
        host["listen_server"] = {"host_player_id": user, "host_address": address}
        host["player_state"] = {str(user): 2}
        if change == "address":
            host["listen_server"]["host_address"] = base64.b64encode(
                b"\xfe" * 84
            ).decode()
        elif change == "host_missing":
            host["player_state"] = {}
        else:
            host["player_state"][str(user)] = 4
        candidate.task(
            145, 15, u64(lobby) + u64(docs[1]["update_id"])
            + text(json.dumps(host)), error=106,
        )
        assert snapshot() == before
    checks.append(
        "host migration keeps get-documents readable, returns native false for stale CAS and rejects wrong native addresses or missing/removing successor"
    )

    search_path = root / "searches" / f"{mm}.json"
    index_path = root / "current-lobbies.json"
    for target, edit in (
        (
            player_path,
            lambda state: state.update(
                token_session=base64.b64encode(b"x" * 32).decode()
            ),
        ),
        (player_path, lambda state: state.update(token_expires=0)),
        (
            search_path,
            lambda state: state["query"]["tokens"].__setitem__(1, candidate_token ^ 1),
        ),
        (search_path, lambda state: state.update(active=False)),
        (index_path, lambda state: state["lobbies"].__setitem__(str(user), lobby ^ 1)),
    ):
        original = target.read_bytes()
        changed = json.loads(original)
        edit(changed)
        target.write_text(json.dumps(changed))
        tampered = snapshot()
        try:
            claim(lobby, docs, error=108)
            assert snapshot() == tampered
        finally:
            target.write_bytes(original)
    assert snapshot() == before
    checks.append(
        "host migration requires current assignment, live token lease and original search-token binding; newer logins/searches cannot revive historical membership"
    )

    original = json.loads(path.read_bytes())
    assert claim(lobby, docs) == boolean(True)
    kind, packet = candidate.receive()
    assert kind == 2 and packet.startswith(
        u32(2006) + u64(lobby) + u64(docs[1]["update_id"] + 1)
    )
    current = strings(packet[23:])
    assert current == strings(candidate.task(145, 13, u64(lobby)))
    stored = json.loads(path.read_bytes())
    assert stored["owner"] == user and stored["members"] == [user]
    assert (
        stored["owner_session"] == json.loads(player_path.read_bytes())["token_session"]
    )
    assert current[0]["listen_server"] == {
        "host_player_id": user,
        "host_address": address,
    }
    assert current[1]["dtls"] == docs[1]["dtls"]
    # Revision is an explicit transient acknowledgement publication; every
    # other native playlist/netcode/map rule must remain exactly unchanged.
    expected_rules = json.loads(json.dumps(docs[1]["ruleset_payload"]))
    expected_rules["dvar_overrides"]["replay_dw_autoFillRevision"] = current[1]["update_id"] % 2147483647
    assert current[1]["ruleset_payload"] == expected_rules
    assert stored["match_selection"] == original["match_selection"]
    assert current[1]["listen_server"]["lobby_host_order"] == [user]
    assert (
        current[0]["update_time"] == current[1]["update_time"] > docs[1]["update_time"]
    )
    for field in (
        "players",
        "player_id_to_mm_id",
        "player_id_to_service_level",
        "player_id_to_slots",
    ):
        assert set(current[1][field]) == {str(user)}
    index = json.loads(index_path.read_bytes())["lobbies"]
    assert index[str(user)] == lobby and str(owner_user) not in index
    assert (
        json.loads(search_path.read_bytes())["active"] is True
    )  # Retained shared search.
    checks.append(
        "host migration atomically moves ownership and native address, preserves DTLS/map/rules, retires departed member/index state and emits native update 2006 with monotonic clocks"
    )

    owner = reopen()
    try:
        owner.task(145, 13, u64(lobby), error=101)
        owner.task(145, 15, u64(lobby) + u64(1) + text(json.dumps(docs[0])), error=101)
        assert json.loads(path.read_bytes()) == stored
        assert claim(lobby, current) == boolean(True)
        assert candidate.receive()[1].startswith(
            u32(2006) + u64(lobby) + u64(current[1]["update_id"] + 1)
        )
        candidate.task(145, 10, u64(lobby))
        assert candidate.receive() == (2, u32(2002) + u64(lobby) + u64(0))
        checks.append(
            "host migration fences a returned former host while the successor can perform ordinary host updates and native disband"
        )

        lobby, mm, docs = create()
        path = root / "lobbies" / f"{lobby}.json"
        owner.close()
        wait_offline()
        # An actual second-file publication failure leaves a durable prepared
        # journal. Recovery must publish all ownership and membership changes.
        blocked = root / "current-lobbies.json.pending"
        blocked.mkdir()
        try:
            claim(lobby, docs, error=102)
        finally:
            blocked.rmdir()
        recovered = strings(candidate.task(145, 13, u64(lobby)))
        assert recovered[0]["listen_server"]["host_player_id"] == user
        state = json.loads(path.read_bytes())
        assert state["owner"] == user and state["members"] == [user]
        assert recovered[1]["dtls"] == docs[1]["dtls"]
        assert recovered[1]["listen_server"]["lobby_host_order"] == [user]
        index = json.loads(index_path.read_bytes())["lobbies"]
        assert index[str(user)] == lobby and str(owner_user) not in index
        assert claim(lobby, recovered) == boolean(True)
        assert candidate.receive()[1].startswith(
            u32(2006) + u64(lobby) + u64(recovered[1]["update_id"] + 1)
        )
        candidate.task(145, 10, u64(lobby))
        assert candidate.receive() == (2, u32(2002) + u64(lobby) + u64(0))
        checks.append(
            "host migration recovers a real interrupted ownership/index publication as one durable transaction, with no mixed former-host authority"
        )
        replacement = reopen()
        replacement.task(145, 2, text(json.dumps(original_info)))
        return replacement
    except BaseException:
        owner.close()
        raise
