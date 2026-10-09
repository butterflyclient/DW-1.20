"""Exercise the generated native store through an isolated encrypted lobby.

No game or primary account is used. Verify publisher download, native catalog,
free/paid purchase, ownership enforcement and persistent grant contents.
"""

import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from progression_delivery_fixtures import decode_event67

from native_wire_client import (
    NativeClient,
    binary,
    fields,
    integer as pb_integer,
    structure,
    text as pb_text,
    u32,
)

ROOT = Path(__file__).resolve().parents[1]


def text(value):
    return b"\x10" + value.encode() + b"\0"


def buy(sku, transaction=""):
    return (
        text("5800")
        + text(transaction)
        + u32(1)
        + u32(sku)
        + u32(1)
        + u32(1)
        + u32(1)
        + u32(0)
        + u32(0)
        + u32(0)
        + b"\x03\0\x01\0"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--publication", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--zero-prices", action="store_true")
    parser.add_argument(
        "--variants", action="store_true", help="Require sale and smart offer checks"
    )
    args = parser.parse_args()
    fixture = ROOT / "data" / ("store-fixture-" + str(time.time_ns()))
    data = fixture / "data"
    data.mkdir(parents=True)
    (data / "replay-traffic-kdf.bin").write_bytes(
        (ROOT / "data/replay-traffic-kdf.bin").read_bytes()
    )
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    subprocess.run(
        [str(args.server), str(data), "--provision-profile", "store", "Store Fixture"],
        check=True,
        stdout=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    offset = None
    for candidate in range(10400, 10600):
        held = []
        try:
            for port in (8085, 8443, 3075):
                probe = socket.socket()
                held.append(probe)
                probe.bind(("127.0.0.1", port + candidate))
            offset = candidate
            break
        except OSError:
            pass
        finally:
            for probe in held:
                probe.close()
    if offset is None:
        raise RuntimeError("No isolated fixture ports available")
    base = "http://127.0.0.1:" + str(8085 + offset)
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/publish-replay-store-catalog.py"),
            str(args.publication),
            "--data",
            str(data),
            "--health-url",
            base + "/health",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    checks = []
    manifest = json.loads((args.publication / "manifest.json").read_bytes())
    if manifest.get("battlepass_source_sha256"):
        module_path = ROOT / "tools/build-replay-battlepass.py"
        spec = importlib.util.spec_from_file_location("battlepass_publication", module_path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        table_path = ROOT / "data/store-asset-research/live/loot__battlepass_ids.csv.json"
        assert hashlib.sha256(table_path.read_bytes()).hexdigest() == manifest["battlepass_source_sha256"]
        definitions = module.build(json.loads(table_path.read_bytes()))
        destination = data / "achievements/5800/5800/definitions.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(definitions))
    with (fixture / "stdout.log").open("wb") as log:
        process = subprocess.Popen(
            [str(args.server), str(data), "--port-offset", str(offset)],
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
        )
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("Fixture server exited")
                try:
                    urllib.request.urlopen(base + "/health", timeout=0.5).close()
                    break
                except urllib.error.URLError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("Fixture server did not become ready")
            with NativeClient(fixture, profile="store", port_offset=offset) as client:
                for name in ["store_v2.json"] + json.loads(
                    (args.publication / "publisher/store_v2.json").read_bytes()
                )["categories"]:
                    header = pb_text(1, "DW-Objectstore-ObjectIDs") + pb_text(
                        2, json.dumps([{"owner": "infinityward", "name": name}])
                    )
                    request = structure(
                        pb_text(1, "GET")
                        + pb_text(2, "/v2/core/publishers/objects/?context=5800")
                        + binary(4, header)
                    )
                    reply = fields(client.task(193, 16, request))
                    assert reply[2] == [200]
                    metadata = json.loads(reply[3][0])["objects"][0]["metadata"]
                    actual = urllib.request.urlopen(
                        metadata["contentURL"], timeout=5
                    ).read()
                    assert (
                        actual == (args.publication / "publisher" / name).read_bytes()
                    )
                checks.append(
                    "native publisher root and all category metadata/HTTP content match publication"
                )
                variables = client.task(
                    95, 1, text("") + text("general_8_19"), structured=False
                )
                assert b"online_store_featured" in variables
                checks.append(
                    "native versioned publisher variables expose the same featured/category IDs"
                )
                namespace = data / "publisher-variables/5800/_default/general_8_19.json"
                saved = namespace.read_bytes()
                tuning = json.loads(saved)
                tuning["native_buffer_check"] = "x" * 127
                namespace.write_text(json.dumps(tuning))
                assert b"x" * 127 in client.task(
                    95, 1, text("") + text("general_8_19"), structured=False
                )
                tuning["native_buffer_check"] += "x"
                namespace.write_text(json.dumps(tuning))
                try:
                    client.task(
                        95, 1, text("") + text("general_8_19"), structured=False
                    )
                except RuntimeError as failure:
                    assert str(failure) == "Native task 95/1 returned 106"
                else:
                    raise AssertionError("Native publisher value truncation accepted")
                namespace.write_bytes(saved)
                checks.append(
                    "native tuning accepts 127 bytes and rejects 128-byte truncated values"
                )
                catalog = json.loads(
                    (args.publication / "marketplace/catalog.json").read_bytes()
                )
                rules = json.loads(
                    (args.publication / "marketplace/purchase-rules.json").read_bytes()
                )
                free = next(
                    row for row in catalog["skus"] if row["prices"][0]["amount"] == 0
                )
                if args.zero_prices:
                    assert all(row["prices"] == [{"currency": 20, "amount": 0}] for row in catalog["skus"])
                    paid = next(row for row in catalog["skus"] if row["product"] != free["product"])
                    checks.append("Every published bundle and variant costs zero COD points")
                else:
                    paid = next(row for row in catalog["skus"] if row["prices"][0]["amount"] > 0)
                for row in (free, paid):
                    request = text("5800") + b"\x06\x01\0\x01\x01" + u32(row["id"])
                    reply = client.task(80, 134, request, structured=False)
                    assert reply[:5] == u32(row["id"])
                checks.append("real Replay SKU IDs are readable through native 80/134")
                inventory = (
                    data / "marketplace/5800" / str(client.user) / "inventory.json"
                )

                def reject(params, error):
                    before = inventory.read_bytes() if inventory.exists() else None
                    try:
                        client.task(80, 106, params, structured=False)
                    except RuntimeError as failure:
                        assert str(failure) == f"Native task 80/106 returned {error}"
                    else:
                        raise AssertionError("Invalid purchase accepted")
                    assert (
                        inventory.read_bytes() if inventory.exists() else None
                    ) == before

                def refreshed(sku_id, state):
                    kind, payload = (
                        (2, client.pushes.pop(0)) if client.pushes else client.receive()
                    )
                    assert kind == 2
                    owner, context, body = decode_event67(payload, client.user)
                    assert (
                        owner == client.user
                        and context == "5800"
                        and set(body) == {"type", "name", "reason", "kind", "triggers"}
                        and body["type"] == "ACHIEVEMENT"
                        and body["name"] == "marketplace_inventory"
                        and body["reason"] == "completed"
                        and body["kind"] == 18
                    )
                    (trigger,) = body["triggers"]
                    assert trigger["type"] == "GRANT_PRODUCT"
                    quantities = {
                        item["id"]: item["quantity"]
                        for item in trigger["inventory"]["granted_items"]
                    }
                    rule = next(row for row in rules["rules"] if row["sku"] == sku_id)
                    selected = {item["1"] for item in rule["items"]}
                    assert quantities == {
                        item["1"]: item["2"]
                        for item in state["items"]
                        if item["1"] in selected
                    }

                if not args.zero_prices:
                    reject(buy(paid["id"]), 101)
                    checks.append("native paid offer rejects insufficient currency without creating inventory")
                response = client.task(80, 106, buy(free["id"]), structured=False)
                assert response[0] == 16 and len(response[1:].split(b"\0", 1)[0]) == 24
                state = json.loads(inventory.read_bytes())
                expected = next(
                    row for row in rules["rules"] if row["sku"] == free["id"]
                )["items"]
                assert {row["1"]: row["2"] for row in state["items"]} == {
                    row["1"]: row["2"] for row in expected
                }
                checks.append(
                    "free purchase returns native completion and persists exact visible/hidden grants"
                )
                for limit in (None, 1000):
                    owned = next(
                        row for row in state["items"] if row["1"] == free["id"]
                    )
                    if limit is None:
                        owned.pop("18", None)
                    else:
                        owned["18"] = limit
                    inventory.write_text(json.dumps(state))
                    reject(buy(free["id"]), 102)
                checks.append(
                    "owned bundle cannot be purchased again with missing or weaker stored limit"
                )
                state["balances"] = [
                    {"currency": 20, "amount": paid["prices"][0]["amount"], "source": 0}
                ]
                inventory.write_text(json.dumps(state))
                client.task(
                    80, 106, buy(paid["id"], "stock-paid-fixture"), structured=False
                )
                state = json.loads(inventory.read_bytes())
                assert state["balances"][0]["amount"] == 0
                assert (
                    next(row for row in state["items"] if row["1"] == paid["id"])["2"]
                    == 1
                )
                checks.append(
                    "native paid purchase debits stock price and grants stock ownership atomically"
                )
                if args.variants:
                    sale = next(
                        row
                        for row in catalog["skus"]
                        if row["id"] == row["original"] + 20000
                        and row["original"] not in (free["id"], paid["id"])
                    )
                    smart = next(
                        row
                        for row in catalog["skus"]
                        if row["id"] == row["original"] + 60000
                        and next(
                            rule for rule in rules["rules"] if rule["sku"] == row["id"]
                        )["enabled"]
                    )
                    state["balances"] = [
                        {"currency": 20, "amount": 100000, "source": 0}
                    ]
                    inventory.write_text(json.dumps(state))
                    client.task(
                        80, 106, buy(sale["id"], "sale-fixture"), structured=False
                    )
                    state = json.loads(inventory.read_bytes())
                    refreshed(sale["id"], state)
                    assert (
                        state["balances"][0]["amount"]
                        == 100000 - sale["prices"][0]["amount"]
                    )
                    assert (
                        next(
                            item
                            for item in state["items"]
                            if item["1"] == sale["original"]
                        )["2"]
                        == 1
                    )
                    assert all(item["1"] != sale["id"] for item in state["items"])
                    reject(buy(sale["original"]), 102)
                    reject(buy(sale["id"]), 102)
                    checks.append(
                        "native sale SKU debits its CSV price and grants base ownership shared with regular SKU"
                    )
                    saved_sale = inventory.read_bytes()
                    client.task(
                        80, 106, buy(sale["id"], "sale-fixture"), structured=False
                    )
                    assert inventory.read_bytes() == saved_sale
                    refreshed(sale["id"], state)
                    checks.append(
                        "sale retry neither debits twice nor grants a synthetic sale inventory item"
                    )
                    smart_rule = next(
                        rule for rule in rules["rules"] if rule["sku"] == smart["id"]
                    )
                    prerequisites = smart_rule["required_owned_items"]
                    state = json.loads(inventory.read_bytes())
                    state["items"] = [
                        item
                        for item in state["items"]
                        if item["1"] not in prerequisites
                    ]
                    inventory.write_text(json.dumps(state))
                    reject(buy(smart["id"]), 101)
                    state["items"].extend(
                        {"1": value, "2": 0} for value in prerequisites
                    )
                    inventory.write_text(json.dumps(state))
                    reject(buy(smart["id"]), 101)
                    for item in state["items"]:
                        if item["1"] in prerequisites:
                            item["2"] = 1
                    inventory.write_text(json.dumps(state))
                    balance = state["balances"][0]["amount"]
                    client.task(
                        80, 106, buy(smart["id"], "smart-fixture"), structured=False
                    )
                    state = json.loads(inventory.read_bytes())
                    refreshed(smart["id"], state)
                    assert (
                        state["balances"][0]["amount"]
                        == balance - smart["prices"][0]["amount"]
                    )
                    assert (
                        next(
                            item
                            for item in state["items"]
                            if item["1"] == smart["original"]
                        )["2"]
                        == 1
                    )
                    reject(buy(smart["original"]), 102)
                    checks.append(
                        "smart price requires actual positive prerequisite ownership before any debit or grant"
                    )
                    active_sales = set(
                        json.loads((args.publication / "manifest.json").read_bytes())[
                            "sale_bundle_ids"
                        ]
                    )
                    disabled = [
                        row
                        for row in rules["rules"]
                        if row["sku"] - 60000 in active_sales
                    ]
                    assert disabled and all(not row["enabled"] for row in disabled)
                    reject(buy(disabled[0]["sku"]), 108)
                    checks.append(
                        "published sale takes precedence over the same bundle's smart variant"
                    )
            with NativeClient(fixture, profile="store", port_offset=offset) as client:
                checkpoint = inventory.read_bytes()
                client.task(
                    80, 106, buy(paid["id"], "stock-paid-fixture"), structured=False
                )
                assert inventory.read_bytes() == checkpoint
                checks.append(
                    "fresh authenticated session retries the durable transaction without another debit"
                )
                manifest = json.loads((args.publication / "manifest.json").read_bytes())
                if manifest.get("battlepass_source_sha256"):
                    for sku in (432000, 432001, 430002, 450002):
                        offer = next(row for row in catalog["skus"] if row["id"] == sku)
                        assert offer["prices"] == [{"currency": 20, "amount": 0}] and offer["sale_end"] == 0
                        before = json.loads(inventory.read_bytes())
                        client.task(80, 106, buy(sku, "bp-free-" + str(sku)), structured=False)
                        after = json.loads(inventory.read_bytes())
                        assert after["balances"] == before["balances"]
                        expected = next(row for row in rules["rules"] if row["sku"] == sku)["items"]
                        for grant in expected:
                            old = next((row["2"] for row in before["items"] if row["1"] == grant["1"]), 0)
                            new = next(row["2"] for row in after["items"] if row["1"] == grant["1"])
                            assert new == old + grant["2"]
                    checks.append("Native premium Battle Pass, premium-plus-skips, regular and sale tier skips grant their exact CSV items without charging COD points")
                    request = structure(pb_text(1, "5800") + pb_text(2, "") + pb_integer(3, int(time.time())) + pb_integer(4, 3002001))
                    assert client.task(125, 5, request) == b""
                    state_path = data / "achievements/5800/5800" / str(client.user) / "states.json"
                    states = json.loads(state_path.read_bytes())
                    assert next(row for row in states if row["id"] == 3002001)["status"] == 1
                    before = state_path.read_bytes()
                    assert client.task(125, 5, request) == b"" and state_path.read_bytes() == before
                    checks.append("Season 3 premium activation completes through native 125/5, persists its kind-20 state and repeats without changing that state")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
    proof = {
        "schema": 1,
        "passed": True,
        "checks": checks,
        "server_sha256": hashlib.sha256(args.server.read_bytes()).hexdigest(),
        "publication_sha256": hashlib.sha256(
            (args.publication / "manifest.json").read_bytes()
        ).hexdigest(),
        "native_game_verified": False,
        "fixture": str(fixture),
    }
    args.output.write_bytes((json.dumps(proof, indent=2) + "\n").encode())
    print("PASS: " + str(len(checks)) + " generated Replay store contract checks")


if __name__ == "__main__":
    main()
