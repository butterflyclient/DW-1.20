"""Verify multi-player XP preflight and interrupted journal recovery on native wire."""

import copy
import hashlib
import json

from native_wire_client import fields, integer, structure, text


def exercise(host, peer, data, report, reward, checks):
    clients = sorted((host, peer), key=lambda client: client.user)
    first, last = clients
    paths = [data / "achievements/5800/5800" / str(client.user) / "events.json"
             for client in clients]
    intent = data / "achievements/5800/event-transaction.json"

    def query(client):
        return client.task(125, 3, structure(
            text(1, "5800") + integer(3, 100) + text(4, "") + integer(8, 0)
        ))

    def rejected(client, task, packet, code):
        try:
            client.task(125, task, packet)
            raise AssertionError("Rejected progression fixture was accepted")
        except RuntimeError as error:
            assert f"returned {code}" in str(error)

    conflict_id = bytes([81]) * 16
    old = json.loads(paths[1].read_bytes())["player_xp"]
    assert host.task(125, 2, report([(last, 25)], conflict_id)) == b""
    reward(last, old + 25)
    baseline = [path.read_bytes() for path in paths]
    rejected(host, 2, report([(first, 25), (last, 26)], conflict_id), 106)
    assert [path.read_bytes() for path in paths] == baseline and not intent.exists()
    checks.append("a later owner's conflicting XP retry rejects every recipient before any journal changes")

    request = bytes([82]) * 16
    packet = report([(first, 37), (last, 37)], request)
    block = paths[1].with_name("events.json.pending")
    block.mkdir()
    try:
        rejected(host, 2, packet, 102)
        saved = intent.read_bytes()
        prepared = json.loads(saved)
        assert prepared["phase"] == "prepared" and len(prepared["writes"]) == 2
        assert json.loads(paths[0].read_bytes()) == prepared["writes"][0]["after"]
        assert paths[1].read_bytes() == baseline[1]
        rejected(first, 3, structure(
            text(1, "5800") + integer(3, 100) + text(4, "") + integer(8, 0)
        ), 102)
        assert intent.read_bytes() == saved
        checks.append("a real second-file failure retains a flushed complete XP intent and blocks partial state reads")

        def digest(value):
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            return hashlib.sha256(raw).hexdigest()

        for mutation in ("context", "destination", "checksum", "duplicate", "foreign-image"):
            bad = copy.deepcopy(prepared)
            before = [path.read_bytes() for path in paths]
            if mutation == "context":
                bad["writes"][-1]["context"] = "../escape"
            elif mutation == "destination":
                bad["writes"][-1]["receipt_key"] = "../events"
            elif mutation == "checksum":
                bad["writes"][-1]["after_digest"] = "0" * 64
            elif mutation == "duplicate":
                bad["writes"].append(copy.deepcopy(bad["writes"][0]))
            else:
                bad["writes"][-1]["before_digest"] = "0" * 64
            bad["checksum"] = digest(bad["writes"])
            intent.write_text(json.dumps(bad))
            rejected(first, 3, structure(
                text(1, "5800") + integer(3, 100) + text(4, "") + integer(8, 0)
            ), 106)
            assert [path.read_bytes() for path in paths] == before
        intent.write_bytes(saved)
        checks.append("XP recovery rejects escaping, duplicate, corrupt and conflicting snapshots before publishing any recipient")
    finally:
        block.rmdir()
    for client, path, before in zip(clients, paths, baseline):
        states = fields(query(client))
        row = next(fields(row) for row in states[1] if fields(row)[11] == [1000000])
        progress = {fields(value)[1][0].decode(): fields(value)[2][0] for value in row[10]}
        assert progress["xp"] == json.loads(before)["player_xp"] + 37
        assert json.loads(path.read_bytes())["player_xp"] == progress["xp"]
    assert not intent.exists()
    committed = [path.read_bytes() for path in paths]
    assert host.task(125, 2, packet) == b""
    assert [path.read_bytes() for path in paths] == committed
    checks.append("XP roll-forward finishes both native state results and retry receipts without double-awarding")
