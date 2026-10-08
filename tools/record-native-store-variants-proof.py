"""Bind a real sale purchase, native cache delta and durable grants to one build."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return json.loads(path.read_bytes())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cohort", type=Path)
    parser.add_argument("--sku", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    folder = args.cohort.resolve()
    assert folder.is_relative_to((ROOT / "data").resolve())
    before = load(folder / "native-before-purchase.json")
    after = load(folder / "native-after-purchase.json")
    launch = load(folder / "native/alpha/launch.json")
    deployment = load(folder / "native/alpha/deployment.json")
    state = load(folder / "native-durable-inventory.json")
    rules = load(folder / "native-publication/marketplace/purchase-rules.json")
    catalog = load(folder / "native-publication/marketplace/catalog.json")
    rule = next(row for row in rules["rules"] if row["sku"] == args.sku)
    offer = next(row for row in catalog["skus"] if row["id"] == args.sku)
    assert offer["id"] == offer["original"] + 20000
    assert offer["prices"] == [{"currency": 20, "amount": 0}]
    assert (
        deployment["private_test_build"]
        and digest(Path(deployment["executable"])) == deployment["sha256"]
    )
    assert before["pid"] == after["pid"] == launch["pid"]
    assert (
        before["sha256"] == after["sha256"] == launch["sha256"] == deployment["sha256"]
    )
    assert before["native_user_xuid"] == after["native_user_xuid"]
    assert before["observed_utc"] < after["observed_utc"]
    for row in (before, after):
        server = row["server_process_verified"]
        assert server["verified_live_process"] and server["launch_receipt_matches"]
        assert (
            server["sha256"]
            == server["process_sha256"]
            == launch["server_process"]["sha256"]
            == deployment["server_sha256"]
        )
        assert server["pid"] == launch["server_process"]["pid"]
        assert not row["native_loot_inventory"]["ownership_override_applied"]
    quantities = lambda rows: {r["item_id"]: r["quantity"] for r in rows}
    initial = quantities(before["native_loot_inventory"]["items"])
    actual = quantities(after["native_loot_inventory"]["items"])
    durable = {r["1"]: r["2"] for r in state["items"]}
    selected = {r["1"] for r in rule["items"]}
    expected = {r["1"]: initial.get(r["1"], 0) + r["2"] for r in rule["items"]}
    assert all(
        actual.get(item) == durable.get(item) == quantity
        for item, quantity in expected.items()
    )
    assert {item for item in actual if actual[item] != initial.get(item, 0)} == selected
    receipts = [
        r
        for r in state["purchases"].values()
        if len(r["orders"]) == 1 and r["orders"][0]["sku"] == args.sku
    ]
    assert len(receipts) == 1
    receipt = receipts[0]
    assert receipt["owner"] == before["native_user_xuid"]
    assert receipt["orders"][0]["recipient"] == receipt["owner"]
    assert (
        receipt["orders"][0]["quantity"] == 1
        and set(receipt["refresh_items"]) == selected
    )
    assert any(
        "service=80 task=106 operation=marketplace-purchase-committed error=0 results=1"
        in line
        for line in after["server_log_since_launch"]
    )
    assert before["native_player_progression"] == after["native_player_progression"]
    evidence = [
        "native-before-purchase.json",
        "native-after-purchase.json",
        "native-durable-inventory.json",
        "native/alpha/launch.json",
        "native/alpha/deployment.json",
        "source.json",
        "linux-build.json",
        "linux-variants.json",
        "linux-startup-verification.json",
        "native-sale-purchased.jpg",
        "native-publication/manifest.json",
    ]
    proof = dict(
        schema=1,
        passed=True,
        generated_utc=datetime.now(timezone.utc).isoformat(),
        server_sha256=deployment["server_sha256"],
        game_sha256=deployment["sha256"],
        pid=launch["pid"],
        private_test_game=True,
        shipping_image_completion_inherited=False,
        native_sale_purchase_completion_verified=True,
        native_immediate_inventory_update_verified=True,
        native_inventory_override_applied=False,
        sku=args.sku,
        base_bundle=offer["original"],
        inventory_before=len(initial),
        inventory_after=len(actual),
        granted_quantities=expected,
        progression_unchanged=True,
        native_smart_purchase_verified=False,
        native_paid_sale_verified=False,
        full_backend_complete=False,
        scope="Real zero-price sale purchase through native Store UI; exact saved base/child quantities appeared without restarting the game",
        recorder_sha256=digest(Path(__file__)),
        evidence={
            str((folder / name).relative_to(ROOT).as_posix()): digest(folder / name)
            for name in evidence
        },
    )
    target = ROOT / "validation/20261008-store-reward-target.json"
    research = load(target)
    assert research["passed"] and research["reward_version"]["tag"] == 3
    assert research["tool_sha256"] == digest(ROOT / "tools/research-gunsmith-rewards-target.py")
    proof["evidence"][target.relative_to(ROOT).as_posix()] = digest(target)
    args.output.write_text(json.dumps(proof, indent=2) + "\n", newline="\n")
    print(
        "PASS: real sale purchase, immediate native inventory and durable grants agree"
    )


if __name__ == "__main__":
    main()
