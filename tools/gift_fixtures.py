"""Independent recipient DTOs and interrupted multi-account purchase recovery."""

import base64
import copy
import hashlib
import json
import struct

from native_wire_client import binary, fields, integer, structure, text as pb_text
from fixture_io import retry_sharing


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def journal(title, buyer, transaction, before, after):
    key = hashlib.sha256((str(title) + "\n" + transaction).encode()).hexdigest()
    body = {
        "schema": 1,
        "title": title,
        "buyer": buyer,
        "transaction": transaction,
        "request": after[buyer]["purchases"][key]["request"],
        "phase": "prepared",
        "owners": [
            {
                "owner": owner,
                "before_checksum": (
                    digest(before[owner]) if before[owner] is not None else None
                ),
                "after": state,
                "after_checksum": digest(state),
            }
            for owner, state in sorted(after.items())
        ],
    }
    return dict(body, checksum=digest(body))


def exercise(client, other, directory, title, buyer, helpers, checks):
    u32, u64, text, blob, boolean = helpers
    recipient = struct.unpack_from(
        "<Q", (directory / "platform-profile.bin").read_bytes(), 8
    )[0]
    assert recipient != buyer
    root = directory / "marketplace" / str(title)
    paths = {
        owner: root / str(owner) / "inventory.json" for owner in (buyer, recipient)
    }
    original_recipient = (
        paths[recipient].read_bytes() if paths[recipient].exists() else None
    )
    rules_path = root / "purchase-rules.json"
    original_rules = rules_path.read_bytes()
    rules = json.loads(original_rules)
    journal_path = root / "pending-purchase.json"

    def applied():
        completed = json.loads(journal_path.read_bytes())
        assert completed["phase"] == "applied" and completed["owners"] == []
        checksum = completed.pop("checksum")
        assert checksum == digest(completed)

    def request(transaction="gift-native", destination=recipient, quantity=2):
        return (
            text(str(title))
            + text(transaction)
            + u32(2)
            + u32(50011)
            + u32(50012)
            + u32(2)
            + u32(quantity)
            + u32(1)
            + u32(2)
            + u32(0)
            + u32(2)
            + u64(destination)
            + text("uno")
            + u64(buyer)
            + text("bnet")
            + u32(2)
            + blob(b"gift metadata")
            + blob(b"")
            + b"\x03\x00"
            + boolean(False)
        )

    def snapshot():
        return {
            owner: path.read_bytes() if path.exists() else None
            for owner, path in paths.items()
        }

    def states():
        return {
            owner: json.loads(raw) if raw is not None else None
            for owner, raw in snapshot().items()
        }

    def restore(images):
        for owner, raw in images.items():
            if raw is None:
                retry_sharing(lambda: paths[owner].unlink(missing_ok=True))
            else:
                paths[owner].parent.mkdir(parents=True, exist_ok=True)
                paths[owner].write_bytes(raw)

    before_bytes = snapshot()
    client.task(80, 106, request(), error=108)
    assert snapshot() == before_bytes and not journal_path.exists()
    rules["rules"][0]["allow_gifting"] = True
    rules_path.write_text(json.dumps(rules))
    client.task(80, 106, request(destination=recipient + 1), error=108)
    assert snapshot() == before_bytes
    malformed = copy.deepcopy(rules)
    malformed["rules"][0]["allow_gifting"] = 1
    rules_path.write_text(json.dumps(malformed))
    client.task(80, 106, request(), error=102)
    assert snapshot() == before_bytes
    rules_path.write_text(json.dumps(rules))
    checks.append(
        "gift publication opt-in, existing local accounts and boolean schema enforced before debit"
    )

    before = states()
    params = request()
    result = client.task(80, 106, params)
    after = states()
    coupon = lambda index, transaction="gift-native": (
        text(hashlib.sha256(f"{transaction}\n{index}".encode()).hexdigest()[:24])
        + u64(recipient)
        + text("uno")
        + boolean(True)
        + u32(52)
        + u64(buyer)
        + text("uno")
        + u32(50011)
        + u32(0)
        + u32(0)
        + b"\x07"
        + struct.pack("<i", 1)
    )
    assert result == text("gift-native") + u32(2) + coupon(0) + coupon(1)
    quantities = lambda state: {row["1"]: row["2"] for row in state["items"]}
    balances = lambda state: {
        row["currency"]: row["amount"] for row in state["balances"]
    }
    old_recipient = before[recipient] or {"items": [], "balances": []}
    assert quantities(after[buyer])[850] == quantities(before[buyer])[850]
    assert quantities(after[buyer])[851] == quantities(before[buyer])[851] + 1
    assert balances(after[buyer])[20] == balances(before[buyer])[20] - 40
    assert (
        quantities(after[recipient])[850] == quantities(old_recipient).get(850, 0) + 4
    )
    assert balances(after[recipient])[30] == balances(old_recipient).get(30, 0) + 6
    assert balances(after[recipient]).get(20, 0) == balances(old_recipient).get(20, 0)
    query = structure(
        pb_text(1, str(title)) + pb_text(2, "") + integer(3, 1000) + integer(4, 850)
    )
    decoded = fields(other.task(80, 69, query, structured=True))
    owned = fields(decoded[1][0])
    assert owned[1] == [recipient]
    assert any(
        fields(row)[1] == [850]
        and fields(row)[2] == [quantities(after[recipient])[850]]
        for row in decoded[4]
    )
    final = snapshot()
    applied()
    completed_marker = journal_path.read_bytes()
    assert client.task(80, 106, params) == result and snapshot() == final
    assert journal_path.read_bytes() == completed_marker
    client.task(80, 106, request(destination=buyer), error=106)
    assert snapshot() == final
    checks.append(
        "mixed self/gift SKU orders debit only buyer, grant exact recipient items/currency and return native coupons with recipient owner and authenticated buyer"
    )

    # A late recipient overflow must not debit the already validated buyer or
    # change another recipient; no journal should have been published.
    broken = copy.deepcopy(after[recipient])
    next(row for row in broken["items"] if row["1"] == 850)["2"] = 2**32 - 1
    paths[recipient].write_text(json.dumps(broken))
    broken_images = snapshot()
    client.task(80, 106, request("gift-overflow"), error=102)
    assert snapshot() == broken_images and journal_path.read_bytes() == completed_marker
    restore(final)
    checks.append(
        "recipient overflow rolls back the entire multi-account intent; retry recipient changes conflict without side effects"
    )

    pending = journal(title, buyer, "gift-native", before, after)
    for damage in (
        "checksum",
        "late-owner",
        "conflicting-current",
        "oversize-after",
        "wrong-title",
        "wrong-buyer",
        "duplicate-owner",
        "missing-buyer",
        "receipt-owner",
        "bad-phase",
    ):
        restore(before_bytes)
        damaged = copy.deepcopy(pending)
        if damage == "checksum":
            damaged["checksum"] = "0" * 64
        elif damage == "late-owner":
            damaged["owners"][-1]["after_checksum"] = "1" * 64
        elif damage == "conflicting-current":
            state = copy.deepcopy(before[buyer])
            state["balances"][0]["amount"] += 1
            paths[buyer].write_text(json.dumps(state))
        elif damage == "oversize-after":
            damaged["owners"][-1]["after"]["oversize"] = "x" * (4 * 1024 * 1024)
            damaged["owners"][-1]["after_checksum"] = digest(
                damaged["owners"][-1]["after"]
            )
        elif damage == "wrong-title":
            damaged["title"] += 1
        elif damage == "wrong-buyer":
            damaged["buyer"] = 0
        elif damage == "duplicate-owner":
            damaged["owners"].append(copy.deepcopy(damaged["owners"][0]))
        elif damage == "missing-buyer":
            damaged["owners"] = [
                entry for entry in damaged["owners"] if entry["owner"] != buyer
            ]
        elif damage == "receipt-owner":
            entry = next(
                entry for entry in damaged["owners"] if entry["owner"] == buyer
            )
            next(iter(entry["after"]["purchases"].values()))["owner"] = recipient
            entry["after_checksum"] = digest(entry["after"])
        elif damage == "bad-phase":
            damaged["phase"] = "applied"
        if damage != "checksum":
            damaged.pop("checksum")
            damaged["checksum"] = digest(damaged)
        journal_path.write_text(canonical(damaged))
        saved = snapshot()
        saved_journal = journal_path.read_bytes()
        other.task(80, 69, query, structured=True, error=102)
        assert snapshot() == saved and journal_path.read_bytes() == saved_journal
        retry_sharing(journal_path.unlink)
    checks.append(
        "complete journal checksum/title/owner/size/current-image validation precedes every checkpoint; damaged or conflicting intents block reads without overwriting any account"
    )

    # Model interruption before the first checkpoint, after either checkpoint,
    # and after both checkpoints but before the applied marker. No production fault
    # hook is needed: these are the exact persisted states of a crashed process.
    for completed in ((), (buyer,), (recipient,), (buyer, recipient)):
        restore(before_bytes)
        for owner in completed:
            paths[owner].parent.mkdir(parents=True, exist_ok=True)
            paths[owner].write_text(canonical(after[owner]))
        journal_path.write_text(canonical(pending))
        assert client.task(80, 106, params) == result
        applied()
        assert states() == after
    checks.append(
        "multi-account recovery handles interruption before, between and after account checkpoints and returns the original response without another debit/grant"
    )

    # A real second-checkpoint CreateFile failure verifies the preparation and
    # recovery path, rather than testing only manually authored journal images.
    before_bytes = snapshot()
    before = states()
    block = paths[sorted(paths)[1]].with_name("inventory.json.pending")
    block.mkdir()
    params = request("gift-disk", quantity=1)
    client.task(80, 106, params, error=102)
    pending_bytes = journal_path.read_bytes()
    pending = json.loads(pending_bytes)
    assert pending["phase"] == "prepared"
    other.task(80, 69, query, structured=True, error=102)
    assert journal_path.read_bytes() == pending_bytes
    blocked_images = snapshot()
    other.task(80, 132, text(str(title)) + u32(16), error=102)
    assert snapshot() == blocked_images
    block.rmdir()
    other.task(80, 69, query, structured=True)
    applied()
    after = {entry["owner"]: entry["after"] for entry in pending["owners"]}
    assert states() == after
    result = text("gift-disk") + u32(1) + coupon(0, "gift-disk")
    stable_images = snapshot()
    assert client.task(80, 106, params) == result and snapshot() == stable_images
    checks.append(
        "gift disk failure retains the complete flushed intent, blocks inventory/wallet reads, then recovers both accounts and returns the exact retry without another debit or grant"
    )
    rules_path.write_bytes(original_rules)
    fixture = {
        "paths": paths,
        "before": before_bytes,
        "after": after,
        "journal": pending,
        "journal_path": journal_path,
        "request": params,
        "result": result,
        "recipient_original": original_recipient,
        "recipient": recipient,
    }
    restore({recipient: original_recipient})
    return fixture


def prepare_restart(fixture):
    for owner, raw in fixture["before"].items():
        path = fixture["paths"][owner]
        if raw is None:
            retry_sharing(lambda: path.unlink(missing_ok=True))
        else:
            path.write_bytes(raw)
    owner = fixture["recipient"]
    path = fixture["paths"][owner]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical(fixture["after"][owner]))
    fixture["journal_path"].write_text(canonical(fixture["journal"]))


def check_restart(client, fixture, checks):
    assert client.task(80, 106, fixture["request"]) == fixture["result"]
    completed = json.loads(fixture["journal_path"].read_bytes())
    assert completed["phase"] == "applied" and completed["owners"] == []
    assert all(
        json.loads(path.read_bytes()) == fixture["after"][owner]
        for owner, path in fixture["paths"].items()
    )
    path = fixture["paths"][fixture["recipient"]]
    if fixture["recipient_original"] is None:
        retry_sharing(path.unlink)
    else:
        path.write_bytes(fixture["recipient_original"])
    checks.append(
        "fresh server process rolls forward an interrupted gift before any marketplace read/write and preserves exact owner retry despite removed offers/rules"
    )
