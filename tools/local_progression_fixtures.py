"""Nonce-signed local XP restore, INI rank selection and legacy login checks."""

import os
import struct
import json
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from native_wire_client import NativeClient, fields, integer, structure, text


def exercise(root, data, offset, checks):
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_numbers()
    blob = struct.pack("<II", 0x31534345, 32)
    blob += public.x.to_bytes(32, "big") + public.y.to_bytes(32, "big")
    name = b"Local XP Signature Fixture".ljust(36, b"\0")
    url = f"http://127.0.0.1:{8085 + offset}"

    def post(path, body):
        with urllib.request.urlopen(urllib.request.Request(url + path, body), timeout=5) as response:
            return response.read()

    def login(version=2, user=0, xp=0, rank=0, restore=False, reset=False, options=None):
        nonce = os.urandom(32)
        challenge = post("/platform/client/challenge", blob + nonce)
        prefix = struct.pack("<II", 0x31494452, version) + nonce + challenge + blob + name
        if version == 2:
            prefix += struct.pack("<IQQII", (int(restore) | (2 if reset else 0)) if options is None else options, user, xp, rank, 0)
        r, s = utils.decode_dss_signature(key.sign(prefix, ec.ECDSA(hashes.SHA256())))
        return post("/platform/client/login", prefix + r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def total(reply):
        with NativeClient(root, port_offset=offset, platform_reply=reply) as client:
            result = fields(client.task(125, 3, structure(
                text(1, "5800") + integer(3, 100) + text(4, "") + integer(8, 0))))
            row = next(fields(row) for row in result[1] if fields(row)[11] == [1000000])
            progress = {fields(p)[1][0].decode(): fields(p)[2][0] for p in row[10]}
            return client.user, progress

    user, value = total(login(rank=5))
    assert value == {"xp": 15000, "rank": 4}
    _, value = total(login(user=user, xp=17500, restore=True))
    assert value == {"xp": 17500, "rank": 4}
    _, value = total(login(version=1))
    assert value == {"xp": 17500, "rank": 4}
    path = data / "achievements/5800/5800" / str(user) / "events.json"
    before = path.read_bytes()
    try:
        login(user=user + 1, xp=999999, restore=True)
        raise AssertionError("Foreign local progression accepted")
    except urllib.error.HTTPError as error:
        assert error.code in (400, 401)
    assert path.read_bytes() == before
    checks.append("signed machine login restores locally owned XP and selects Replay rank, retains legacy login compatibility, and rejects another identity's progression")
    account = path.parent
    inventory = data / "marketplace/5800" / str(user) / "inventory.json"
    inventory.parent.mkdir(parents=True, exist_ok=True)
    inventory.write_text(json.dumps({"items": [{"1": 429001, "2": 2}], "balances": [{"currency": 20, "amount": 9000}]}))
    leaderboard = data / "leaderboard-stats/5800" / f"{user}.json"
    leaderboard.parent.mkdir(parents=True, exist_ok=True)
    leaderboard.write_text('{}')
    contexts = [data / "achievements/5800" / c / str(user) for c in ("5800", "iw8")]
    for folder in contexts:
        folder.mkdir(parents=True, exist_ok=True)
        if not (folder / "events.json").exists():
            (folder / "events.json").write_text(json.dumps({"schema": 1, "next": 1, "events": [], "requests": []}))
        (folder / "states.json").write_text(json.dumps([
            {"id": 1501, "name": "reset-mission", "kind": 15, "status": 3, "progress": 100, "target": 100},
            {"id": 2000015, "name": "iw8_ar_mike4", "kind": 5, "status": 1, "progress": 0, "target": 0,
             "multiProgress": [{"name": "xp", "current": 20000, "target": 0}, {"name": "rank", "current": 20, "target": 0}]},
            {"id": 3002000, "name": "battlepass_season3", "kind": 20, "status": 1,
             "progress": 0, "target": 0, "premium": True}]))
    def user_states(reply):
        with NativeClient(root, port_offset=offset, platform_reply=reply) as client:
            assert client.user == user
            return {context: json.loads(fields(client.task(
                125, 9, structure(text(1, context))))[1][0])
                    for context in ("5800", "iw8")}

    projected = user_states(login(version=1))
    for context, state in projected.items():
        assert state["battlepass3_owned"] == 1 and type(state["battlepass3_owned"]) is int
        saved_state = data / "achievement-user-state/5800" / context / f"{user}.json"
        assert json.loads(saved_state.read_bytes())["battlepass3_owned"] == 1
        stored = json.loads(saved_state.read_bytes())
        stored.update(
            br_tutorial_rewarded={str(index): True for index in range(4)},
            player_xp_end_time=1234567890,
            weapon_xp_end_time=1234567891,
        )
        saved_state.write_text(json.dumps(stored))
    user_state_paths = [data / "achievement-user-state/5800" / c / f"{user}.json"
                        for c in ("5800", "iw8")]
    before = {p: p.read_bytes() for p in [inventory, leaderboard, *(f / 'events.json' for f in contexts), *(f / 'states.json' for f in contexts), *user_state_paths]}
    for arguments in [dict(user=user + 1, restore=True, reset=True),
                      dict(user=user, restore=True, reset=True, xp=1),
                      dict(user=user, restore=True, reset=True, rank=2),
                      dict(user=user, options=2), dict(user=user, options=4)]:
        try:
            login(**arguments)
            raise AssertionError('Invalid full-reset request accepted')
        except urllib.error.HTTPError as error:
            assert error.code in (400, 401)
        assert all(p.read_bytes() == value for p, value in before.items())
    with NativeClient(root, port_offset=offset, platform_reply=login(version=1)) as client:
        blocker = user_state_paths[1].with_name(user_state_paths[1].name + ".pending")
        blocker.mkdir()
        try:
            try:
                login(user=user, restore=True, reset=True)
                raise AssertionError('Blocked user-state reset publication accepted')
            except urllib.error.HTTPError as error:
                assert error.code == 400
            intent = data / "achievements/5800/event-transaction.json"
            prepared_bytes = intent.read_bytes()
            prepared = json.loads(prepared_bytes)
            user_writes = [w for w in prepared['writes'] if w.get('kind') == 'user_state']
            assert prepared['phase'] == 'prepared' and len(user_writes) == 2
            assert {w['context'] for w in user_writes} == {'5800', 'iw8'}
            assert all(w['after'] == {} for w in user_writes)
            assert json.loads(user_state_paths[0].read_bytes()) == {}
            assert user_state_paths[1].read_bytes() == before[user_state_paths[1]]
            for context in ('5800', 'iw8'):
                try:
                    client.task(125, 9, structure(text(1, context)))
                    raise AssertionError('Partially reset user state exposed')
                except RuntimeError as error:
                    assert 'returned 102' in str(error)
            assert intent.read_bytes() == prepared_bytes
        finally:
            blocker.rmdir()
        # Read the still-old second-context document first on this existing
        # authenticated connection. Recovery must run before loading its JSON,
        # otherwise tutorial/boost fields can leak into the first reset reply.
        for context in ('iw8', '5800'):
            state = json.loads(fields(client.task(
                125, 9, structure(text(1, context))))[1][0])
            assert state == {}
    checks.append('interrupted full reset journals both user-state snapshots and blocks native reads until complete roll-forward')
    reset_reply = login(user=user, restore=True, reset=True)
    _, value = total(reset_reply)
    assert value == {"xp": 0, "rank": 0}
    for state in user_states(reset_reply).values():
        assert state == {}
        assert all(state.get(f"battlepass{season}_owned", 0) == 0 for season in range(7))
    for state in user_states(login(version=1)).values():
        assert state == {}
        assert all(state.get(f"battlepass{season}_owned", 0) == 0 for season in range(7))
    checks.append('full reset clears materialized premium Battle Pass ownership on native user-state reads in both contexts and after reconnect')
    for folder in contexts:
        journal = json.loads((folder / 'events.json').read_bytes())
        assert journal['player_xp'] == 0 and journal['weapon_xp'] == {} and journal['matches'] == {}
        assert json.loads((folder / 'states.json').read_bytes()) == []
    fresh = json.loads(inventory.read_bytes())
    assert fresh['balances'] == [] and not any(i['1'] == 429001 for i in fresh['items'])
    assert json.loads(leaderboard.read_bytes()) == {}
    assert all(json.loads(p.read_bytes()) == {} for p in user_state_paths)
    # Retrying a nonce-signed reset cannot resurrect the discarded state.
    final = {p: p.read_bytes() for p in before}
    _, value = total(login(user=user, restore=True, reset=True))
    assert value == {"xp": 0, "rank": 0} and all(p.read_bytes() == v for p, v in final.items())
    checks.append('full reset requires a signed matching identity, rejects mixed restore/rank/XP flags without mutation, atomically clears missions/weapon ranks/Battle Pass/inventory/currency/leaderboards in both contexts and remains idempotent')
