"""Independent same-Replay legacy balance and full SKU catalog checks."""

import base64
import copy
import json
import struct


def exercise(client, directory, title, user, inventory_path, helpers, checks):
    u32, text, blob, boolean = helpers
    u8 = lambda n: b"\x03" + bytes([n])
    u16 = lambda n: b"\x06" + struct.pack("<H", n)
    balance_query = text(str(title)) + u32(16)
    assert client.task(80, 132, balance_query) == u8(20) + u32(123)
    client.task(80, 132, text(str(title)) + u32(0), error=106)
    client.task(80, 132, text("wrong") + u32(16), error=106)
    saved = inventory_path.read_bytes()
    for key, value in [
        ("amount", -1),
        ("amount", 1.5),
        ("amount", 1 << 63),
        ("source", -1),
    ]:
        broken = json.loads(saved)
        broken["balances"][0][key] = value
        inventory_path.write_text(json.dumps(broken))
        client.task(80, 132, balance_query, error=102)
    too_large = json.loads(saved)
    too_large["balances"][0]["amount"] = 1 << 32
    inventory_path.write_text(json.dumps(too_large))
    client.task(80, 132, balance_query, error=102)
    inventory_path.write_bytes(saved)
    checks.append(
        "native legacy UByte8/UInt32 balances share the structured store and reject lossy numeric conversions"
    )

    path = directory / "marketplace" / str(title) / "catalog.json"
    query = (
        lambda maximum=10, show_all=False, filters=(): text(str(title))
        + u16(maximum)
        + boolean(show_all)
        + b"".join(map(u32, filters))
    )
    assert client.task(80, 134, query()) == []
    sku = {
        "id": 411,
        "product": 52,
        "type": 1,
        "data": base64.b64encode(b"sku bytes").decode(),
        "ignore_entitlements": 0,
        "sale_start": 100,
        "sale_end": 200,
        "rental_duration": 0,
        "promotional": base64.b64encode(b"Local catalog").decode(),
        "original": 410,
        "collision": 3,
        "modified": 101,
        "coupon_enabled": 1,
        "prices": [{"currency": 20, "amount": 75}],
        "enabled": True,
    }
    hidden = dict(sku, id=412, enabled=False, prices=[])
    publication = {"schema": 1, "skus": [hidden, sku]}
    path.write_text(json.dumps(publication))

    def expected(row):
        return (
            u32(row["id"])
            + u32(row["product"])
            + u8(row["type"])
            + blob(base64.b64decode(row["data"]))
            + u8(row["ignore_entitlements"])
            + u32(row["sale_start"])
            + u32(row["sale_end"])
            + u32(row["rental_duration"])
            + blob(base64.b64decode(row["promotional"]))
            + u32(row["original"])
            + u16(row["collision"])
            + u32(row["modified"])
            + u8(row["coupon_enabled"])
            + u32(len(row["prices"]))
            + b"".join(u8(p["currency"]) + u32(p["amount"]) for p in row["prices"])
        )

    assert client.task(80, 134, query()) == expected(sku)
    assert client.task(80, 134, query(show_all=True)) == expected(sku) + expected(
        hidden
    )
    assert client.task(80, 134, query(show_all=True, filters=[412])) == expected(hidden)
    assert client.task(80, 134, query(show_all=True, maximum=1)) == expected(sku)
    assert client.task(80, 134, query(filters=[999])) == []
    client.task(80, 134, query(maximum=0), error=106)
    client.task(80, 134, query(filters=[411, 411]), error=106)
    for change in ["negative", "prices", "duplicate"]:
        broken = copy.deepcopy(publication)
        if change == "negative":
            broken["skus"][0]["product"] = -1
        if change == "prices":
            broken["skus"][0]["prices"] = [{"currency": 20, "amount": 75}] * 11
        if change == "duplicate":
            broken["skus"][0]["id"] = 411
        path.write_text(json.dumps(broken))
        client.task(80, 134, query(), error=102)
    path.write_text(json.dumps(publication))
    checks.append(
        "full native store SKU DTO including metadata/promotional blobs, rental/sale fields, prices, visibility, filters and publication validation"
    )
