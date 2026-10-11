"""Verify multi-player XP preflight and interrupted journal recovery on native wire."""

import copy
import hashlib
import json

from achievement_transaction_fixtures import assert_applied
from native_wire_client import binary, fields, integer, structure, text


def mission_snapshot(client):
    """Read both actual native response shapes, including mission and XP rows."""
    page, rows = "", {}
    while True:
        result = fields(client.task(125, 3, structure(
            text(1, "5800") + integer(3, 100) + text(4, page) + integer(8, 0))))
        for raw in result.get(1, []):
            row = fields(raw)
            assert row[11][0] not in rows
            rows[row[11][0]] = row
        page = result[2][0].decode()
        if not page:
            break
    inventory = fields(client.task(80, 69, structure(
        text(1, "5800") + text(2, "") + integer(3, 100))))
    return rows, inventory


def exercise_mission_window(host, peer, data, checks):
    """Recover a complete mixed mission/XP/inventory intent on native wire."""
    intent = data / "achievements/5800/event-transaction.json"
    state_paths = [data / "achievements/5800/5800" / str(c.user) / "states.json"
                   for c in (host, peer)]
    journal = state_paths[0].with_name("events.json")
    inventory = data / "marketplace/5800" / str(host.user) / "inventory.json"

    # Produce the event history and retry receipt through the actual request
    # handler. The fixture must preserve them when adding its mixed snapshot.
    event = text(1, "frontend_login") + integer(2, 123) + integer(4, 0)
    packet = structure(text(1, "5800") + binary(2, event) + text(3, "mission-window"))
    assert host.task(125, 1, packet) == b""
    original_journal = json.loads(journal.read_bytes())
    assert original_journal["events"] and original_journal["requests"]
    inventory.parent.mkdir(parents=True, exist_ok=True)
    inventory.write_text(json.dumps({"items": [], "balances": []}))
    paths = [journal, inventory, *state_paths]
    baseline = [p.read_bytes() for p in paths]
    after = [json.loads(raw) for raw in baseline]
    after[0]["player_xp"] = 3500
    after[1]["items"] = [{"1": 170052, "2": 1}]
    for document, identity in ((after[2], 1503), (after[3], 1500)):
        row = next(row for row in document if row["id"] == identity)
        row.update(progress=row["target"], status=3, completionTimestamp=456)

    def digest(value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()

    writes = []
    for client, kind, before, document in zip(
            (host, host, host, peer), (None, "inventory", "states", "states"),
            baseline, after):
        row = dict(owner=client.user, platform_account=client.platform_account_id,
                   context="5800", receipt_key="", after=document,
                   after_digest=digest(document), before_digest=digest(json.loads(before)))
        if kind:
            row["kind"] = kind
        writes.append(row)
    prepared = dict(schema=1, title=5800, phase="prepared", writes=writes,
                    checksum=digest(writes))

    def rejected(client, service, task, packet, code):
        try:
            client.task(service, task, packet)
        except RuntimeError as failure:
            assert str(failure) == f"Native task {service}/{task} returned {code}"
        else:
            raise AssertionError("Partial mission transaction was exposed")

    query = structure(text(1, "5800") + integer(3, 100) + text(4, "") + integer(8, 0))
    for mutation in ("context", "kind", "duplicate-id", "multi-limit", "target-type", "conflict"):
        bad = copy.deepcopy(prepared)
        last = bad["writes"][-1]
        if mutation == "context":
            last["context"] = "../escape"
        elif mutation == "kind":
            last["kind"] = "unknown"
        elif mutation == "duplicate-id":
            last["after"].append(copy.deepcopy(last["after"][0]))
        elif mutation == "multi-limit":
            last["after"][0]["multiProgress"] = [{"name": "bad", "current": 0, "target": 1}] * 5
        elif mutation == "target-type":
            last["after"][0]["target"] = 1.5
        else:
            last["before_digest"] = "0" * 64
        last["after_digest"] = digest(last["after"])
        bad["checksum"] = digest(bad["writes"])
        intent.write_text(json.dumps(bad))
        rejected(host, 125, 3, query, 106)
        assert [p.read_bytes() for p in paths] == baseline
    checks.append("mixed mission/XP/inventory recovery validates every destination and complete native state layout before writing any earlier recipient")

    blocker = state_paths[1].with_name("states.json.pending")
    blocker.mkdir()
    try:
        intent.write_text(json.dumps(prepared))
        saved = intent.read_bytes()
        rejected(host, 125, 3, query, 102)
        assert [json.loads(p.read_bytes()) for p in paths[:3]] == after[:3]
        assert state_paths[1].read_bytes() == baseline[3]
        rejected(peer, 80, 69, structure(text(1, "5800") + text(2, "") + integer(3, 100)), 102)
        assert intent.read_bytes() == saved
        checks.append("a later mission-file failure retains the flushed mixed intent and blocks both achievement and inventory reads until recovery")
    finally:
        blocker.rmdir()
    retirement_blocker = intent.with_name("event-transaction.json.pending")
    retirement_blocker.mkdir()
    try:
        rejected(host, 125, 3, query, 102)
        assert [json.loads(p.read_bytes()) for p in paths] == after
        assert intent.read_bytes() == saved
        rejected(peer, 80, 69, structure(text(1, "5800") + text(2, "") + integer(3, 100)), 102)
        assert intent.read_bytes() == saved
    finally:
        retirement_blocker.rmdir()
    snapshots = [mission_snapshot(c) for c in (host, peer)]
    assert [json.loads(p.read_bytes()) for p in paths] == after
    assert_applied(intent)
    marker = intent.read_bytes()
    # A later independent inventory writer must not conflict with an already
    # completed recovery window. Only this disposable fixture is modified.
    independent = json.loads(inventory.read_bytes())
    independent["balances"] = [{"currency": 20, "amount": 1}]
    inventory.write_text(json.dumps(independent))
    mission_snapshot(host)
    assert json.loads(inventory.read_bytes()) == independent
    assert intent.read_bytes() == marker
    checks.append("failed completion-marker publication retains the prepared intent after all checkpoints apply; retry durably completes and permits a later independent inventory write")
    progress = {fields(p)[1][0].decode(): fields(p)[2][0]
                for p in snapshots[0][0][1000000][10]}
    assert progress["xp"] == 3500
    item = next(fields(row) for row in snapshots[0][1][4] if fields(row)[1] == [170052])
    assert item[2] == [1]
    assert snapshots[0][0][1503][5] == snapshots[1][0][1500][5] == [3]
    assert snapshots[0][0][1503][6] == snapshots[1][0][1500][6] == [456]
    committed = [p.read_bytes() for p in paths]
    assert host.task(125, 1, packet) == b""
    refreshed = [p.read_bytes() for p in paths]
    # This fixture's manually prepared intent omitted ordinary rank grants.
    # The real retry repairs those entitlements from its retained 3500 XP.
    # It must preserve both mission files, the event/retry history and the
    # already granted mission item, then remain byte-stable on another retry.
    assert [refreshed[index] for index in (0, 2, 3)] == [
        committed[index] for index in (0, 2, 3)
    ]
    before_items = {row["1"]: row for row in json.loads(committed[1])["items"]}
    after_items = {row["1"]: row for row in json.loads(refreshed[1])["items"]}
    for identity, row in before_items.items():
        assert after_items[identity] == row
    assert host.task(125, 1, packet) == b""
    assert [p.read_bytes() for p in paths] == refreshed
    assert json.loads(journal.read_bytes())["requests"] == original_journal["requests"]
    assert json.loads(journal.read_bytes())["events"] == original_journal["events"]
    checks.append("mixed roll-forward preserves mission completion, XP and retry history; rank entitlement catch-up preserves the mission grant and remains idempotent")
    return [mission_snapshot(c) for c in (host, peer)]


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
    assert [path.read_bytes() for path in paths] == baseline
    assert_applied(intent)
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
    assert_applied(intent)
    committed = [path.read_bytes() for path in paths]
    assert host.task(125, 2, packet) == b""
    assert [path.read_bytes() for path in paths] == committed
    for client, path in zip(clients, paths):
        assert reward(client, json.loads(path.read_bytes())["player_xp"])["reason"] == "inProgress"
    checks.append("XP roll-forward finishes both native state results and retry receipts without double-awarding")
