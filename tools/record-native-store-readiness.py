"""Bind a native free-bundle claim, inventory refresh and restart to their artifacts.

This records already observed game evidence. It does not run a purchase, grant
items, change a profile or infer native completion from a protocol fixture.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def reference(path):
    path = path.resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("Evidence must remain inside the backend project")
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def quantities(items, native):
    result = {}
    for item in items:
        key = item["item_id"] if native else item["1"]
        value = item["quantity"] if native else item["2"]
        if key in result or not isinstance(key, int) or not isinstance(value, int):
            raise ValueError("Ambiguous inventory record")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--publication", required=True, type=Path)
    parser.add_argument("--sku", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    before, after, restarted = [
        json.loads((evidence / name).read_bytes())
        for name in ("before.json", "after-submit.json", "restarted.json")
    ]
    durable = json.loads((evidence / "durable-after.json").read_bytes())
    target = ROOT / "validation/20261007-replay-store-target.json"
    target_proof = json.loads(target.read_bytes())
    if not target_proof["passed"]:
        raise ValueError("Native store target contract is not verified")
    catalog_path = args.publication / "marketplace/catalog.json"
    rules_path = args.publication / "marketplace/purchase-rules.json"
    sku = next(
        row
        for row in json.loads(catalog_path.read_bytes())["skus"]
        if row["id"] == args.sku
    )
    rule = next(
        row
        for row in json.loads(rules_path.read_bytes())["rules"]
        if row["sku"] == args.sku
    )
    if sku["prices"] != [{"currency": 20, "amount": 0}] or rule["currencies"]:
        raise ValueError(
            "This verifier covers free bundles without currency grants only"
        )
    if before["pid"] != after["pid"] or after["pid"] == restarted["pid"]:
        raise ValueError("Missing native purchase or separate process restart")
    user = before["native_user_xuid"]
    game = before["sha256"]
    server = before["server_process_verified"]["sha256"]
    for observation in (before, after, restarted):
        if (
            observation["native_user_xuid"] != user
            or observation["sha256"] != game
            or observation["server_process_verified"]["sha256"] != server
            or not observation["server_process_verified"]["verified_live_process"]
            or observation["platform_auth_state"] != 2
        ):
            raise ValueError("Native identity, process or backend binding changed")
        inventory = observation["native_loot_inventory"]
        if inventory["ownership_override_applied"]:
            raise ValueError("Virtual unlock quantities cannot prove a native grant")
        if inventory["count"] != len(inventory["items"]):
            raise ValueError("Native inventory sample is incomplete")
    old = quantities(before["native_loot_inventory"]["items"], True)
    new = quantities(after["native_loot_inventory"]["items"], True)
    loaded = quantities(restarted["native_loot_inventory"]["items"], True)
    saved = quantities(durable["items"], False)
    expected = quantities(rule["items"], False)
    gains = {
        item: quantity - old.get(item, 0)
        for item, quantity in new.items()
        if quantity != old.get(item, 0)
    }
    if gains != expected or new != loaded:
        raise ValueError("Native grant or restart does not match the published bundle")
    if any(saved.get(item) != new[item] for item in expected):
        raise ValueError("Durable marketplace quantities do not match native inventory")
    if durable["purchase_count"] != 1 or durable["balances"]:
        raise ValueError("Expected one free claim with no wallet balance")
    completion = [
        line
        for line in after["server_log_since_launch"]
        if "service=80 task=106 operation=marketplace-purchase-committed error=0 results=1"
        in line
    ]
    reloads = [
        line
        for line in restarted["server_log_since_launch"]
        if "service=80 task=69 operation=inventory-read error=0 results=" in line
    ]
    if len(completion) != 1 or not reloads:
        raise ValueError(
            "Native purchase and fresh inventory-read task evidence is missing"
        )
    if any(
        observation["native_player_progression"]["xp"] != 0
        for observation in (before, after, restarted)
    ):
        raise ValueError("This temporary profile test must not change player XP")
    paths = [
        evidence / name
        for name in (
            "before.json",
            "after-submit.json",
            "restarted.json",
            "durable-after.json",
            "alpha-launch-purchase.json",
            "alpha-launch-restarted.json",
            "alpha-deployment.json",
            "alpha-ini-used.ini",
            "native-purchased.jpg",
            "observer-source.py",
            "native-loot-inventory-source.py",
        )
    ] + [catalog_path, rules_path, target]
    proof = {
        "schema": 1,
        "passed": True,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "native_free_bundle_purchase_completion_verified": True,
        "native_inventory_refresh_verified": True,
        "native_inventory_process_restart_reload_verified": True,
        "native_purchase_ui": "Purchased; all six contents checked; Items added to inventory",
        "backend_sha256": server,
        "private_game_sha256": game,
        "purchase_pid": after["pid"],
        "restarted_pid": restarted["pid"],
        "temporary_player": user,
        "sku": args.sku,
        "bundle": "Standard Issue I",
        "native_inventory_count_before": len(old),
        "native_inventory_count_after": len(new),
        "native_grants": expected,
        "purchase_receipts": durable["purchase_count"],
        "native_purchase_task": completion[0],
        "native_restart_inventory_task": reloads[-1],
        "player_xp_unchanged": 0,
        "real_money_or_first_party_purchase_tested": False,
        "native_paid_or_gift_purchase_tested": False,
        "full_backend_complete": False,
        "scope": "Actual original game UI purchase and native inventory on an owned temporary profile; no grant was injected by a fixture or process-memory write",
        "evidence": [reference(path) for path in paths],
    }
    output = args.output.resolve()
    if not output.is_relative_to(ROOT):
        raise ValueError("Readiness output must remain inside the backend project")
    output.write_text(json.dumps(proof, indent=2) + "\n")
    print(
        f"Native free bundle {args.sku}: {len(expected)} grants, durable and reloaded"
    )


if __name__ == "__main__":
    main()
