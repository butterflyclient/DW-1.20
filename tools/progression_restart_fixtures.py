"""Recover a real journal/archive interruption across an isolated backend restart."""

import base64
import json
import time

from achievement_transaction_fixtures import assert_applied
from native_wire_client import NativeClient, binary, fields, integer, structure, text


def exercise(fixture, data, offset, restart, checks):
    with NativeClient(fixture, port_offset=offset) as client:
        journal = data / "achievements/5800/5800" / str(client.user) / "events.json"
        saved = json.loads(journal.read_bytes())
        xp = saved["player_xp"]
        # Seed only this disposable fixture's legacy hot window. Native owner
        # receipts carry no users field in the old reportEvents representation.
        while len(saved["requests"]) < 256:
            saved["requests"].append({
                "id": f"restart-fixture-{len(saved['requests'])}", "digest": "a" * 32,
            })
        journal.write_text(json.dumps(saved))
        before = journal.read_bytes()
        first_receipt = saved["requests"][0]
        event = text(1, "mp_addxp") + integer(2, int(time.time())) + integer(4, 0)
        event += binary(3, text(1, "Param0") + integer(2, 123))
        owner = integer(1, client.user) + text(2, "uno")
        first_party = integer(1, client.platform_account_id) + text(2, "bnet")
        batch = binary(1, owner) + binary(2, event) + binary(3, first_party) + integer(4, 113)
        request = base64.urlsafe_b64encode(bytes([83]) * 16).decode().rstrip("=")
        packet = structure(text(1, "5800") + binary(2, batch) + text(3, request))
        block = journal.with_name("events.json.pending")
        block.mkdir()
        try:
            try:
                client.task(125, 2, packet)
                raise AssertionError("Blocked archive/journal publication succeeded")
            except RuntimeError as error:
                assert "returned 102" in str(error)
            intent = data / "achievements/5800/event-transaction.json"
            prepared = json.loads(intent.read_bytes())
            assert len(prepared["writes"]) == 2
            assert prepared["writes"][0]["receipt_key"]
            assert prepared["writes"][1]["receipt_key"] == ""
            assert journal.read_bytes() == before
            receipts = list((journal.parent / "receipts").glob("*.json"))
            assert any(json.loads(path.read_bytes())["receipt"] == first_receipt for path in receipts)
        finally:
            block.rmdir()
    previous, current = restart()
    assert previous != current
    with NativeClient(fixture, port_offset=offset) as client:
        states = fields(client.task(125, 3, structure(
            text(1, "5800") + integer(3, 100) + text(4, "") + integer(8, 0)
        )))
        row = next(fields(row) for row in states[1] if fields(row)[11] == [1000000])
        progress = {fields(value)[1][0].decode(): fields(value)[2][0] for value in row[10]}
        assert progress["xp"] == xp + 123
        assert_applied(intent)
        committed = journal.read_bytes()
        assert len(json.loads(committed)["requests"]) == 256
        assert client.task(125, 2, packet) == b"" and journal.read_bytes() == committed
        from progression_delivery_fixtures import reward
        reward(client, xp + 123)
    checks.append("a real archive/journal interruption survives backend process restart, rolls forward, and retains once-only XP receipts")
