"""Build Replay's storefront and purchase rules from a verified bundle table.

Input is the read-only native StringTable export (name, columns, row_count,
rows). No game assets are modified. Sale and smart-bundle IDs/prices follow
Replay's native store Lua. First-party and Battle Pass offers remain separate.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

COLS = {
    "id": 0,
    "name": 1,
    "description": 2,
    "flavorText": 3,
    "licence": 4,
    "bundleType": 5,
    "image": 6,
    "previewImage": 7,
    "titleImage": 8,
    "currencyID": 9,
    "currencyAmount": 10,
    "saleCurrencyAmount": 11,
    "firstPartyProductID": 12,
    "numItems": 13,
    "itemStart": 14,
    "numHiddenItems": 24,
    "hiddenItemStart": 25,
    "smartID": 35,
    "smartCost": 36,
    "isBattlePassBundle": 37,
    "purchaseEnd": 38,
    "dlcRef": 39,
}


def number(value, maximum=2**32 - 1, empty=0):
    if value == "":
        return empty
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ValueError("Bundle table integer is not canonical decimal text")
    result = int(value)
    if not 0 <= result <= maximum:
        raise ValueError("Bundle table integer exceeds its native field")
    return result


def build(document, stamp, sale_ids=(), zero_prices=False):
    if document.get("name") != "loot/bundle_ids.csv" or document.get("columns") != 40:
        raise ValueError("Expected Replay's 40-column loot/bundle_ids.csv")
    rows = document.get("rows")
    if (
        not isinstance(rows, list)
        or not 1 <= len(rows) <= 1024
        or document.get("row_count") != len(rows)
    ):
        raise ValueError("Invalid native bundle table row count")
    eligible, excluded, seen = [], [], set()
    for row in rows:
        if (
            not isinstance(row, list)
            or len(row) != 40
            or any(not isinstance(value, str) or "\0" in value for value in row)
        ):
            raise ValueError("Incomplete bundle table row")
        bundle = number(row[COLS["id"]])
        if not 400000 <= bundle < 410000 or bundle in seen:
            raise ValueError("Duplicate or unsupported native bundle ID")
        seen.add(bundle)
        visible = number(row[COLS["numItems"]], 10)
        hidden = number(row[COLS["numHiddenItems"]], 10)
        grants = Counter({bundle: 1})
        for first, count in (
            (COLS["itemStart"], visible),
            (COLS["hiddenItemStart"], hidden),
        ):
            for value in row[first : first + count]:
                item = number(value)
                if not item or item == bundle:
                    raise ValueError("Missing or recursive bundle grant")
                grants[item] += 1
        ending = number(row[COLS["purchaseEnd"]])
        reason = (
            "first-party"
            if row[COLS["firstPartyProductID"]]
            else (
                "battle-pass"
                if number(row[COLS["isBattlePassBundle"]], 1)
                else "expired" if ending and ending <= stamp else None
            )
        )
        if reason:
            excluded.append({"id": bundle, "reason": reason})
            continue
        currency = number(row[COLS["currencyID"]], 255)
        price = number(row[COLS["currencyAmount"]])
        if currency != 20:
            raise ValueError(
                "Regular Replay bundles require the native COD Points currency"
            )
        if not row[COLS["name"]] or not row[COLS["image"]]:
            raise ValueError("Bundle lacks its native presentation references")
        eligible.append(
            {
                "id": bundle,
                "row": row,
                "grants": grants,
                "price": price,
                "currency": currency,
                "ending": ending,
            }
        )
    if not eligible:
        raise ValueError("No supported native bundles in this publication")
    sale_ids = list(sale_ids)
    if (
        len(sale_ids) > 18
        or len(sale_ids) != len(set(sale_ids))
        or any(
            type(value) is not int or value not in {item["id"] for item in eligible}
            for value in sale_ids
        )
    ):
        raise ValueError("Sales must name at most 18 distinct eligible native bundles")
    skus, rules = [], []
    for bundle in eligible:
        sku = bundle["id"]
        skus.append(
            {
                "id": sku,
                "product": sku,
                "type": 1,
                "data": "",
                "ignore_entitlements": 0,
                "sale_start": 0,
                "sale_end": bundle["ending"],
                "rental_duration": 0,
                "promotional": "",
                "original": sku,
                "collision": 0,
                "modified": stamp,
                "coupon_enabled": 0,
                "enabled": True,
                "prices": [{"currency": bundle["currency"], "amount": 0 if zero_prices else bundle["price"]}],
            }
        )
        items = [
            {"1": item, "2": count} for item, count in sorted(bundle["grants"].items())
        ]
        # Only the bundle is single ownership. Shared child items can legitimately
        # appear in several bundles and must retain their accumulated quantity.
        next(item for item in items if item["1"] == sku)["18"] = 1
        rules.append(
            {
                "sku": sku,
                "enabled": True,
                "allow_ignore_entitlements": False,
                "allow_gifting": False,
                "sources": [0],
                "maximum_quantity": 1,
                "items": items,
                "currencies": [],
            }
        )
        # STORE.GetBundlePurchaseID selects +20000 for a published sale before
        # considering +60000 for ownership of the CSV's smartID. Grant the base
        # bundle record in both cases: ownership must span every price variant.
        base_offer, base_rule = skus[-1], rules[-1]
        variants = []
        if sku in sale_ids:
            if not bundle["row"][COLS["saleCurrencyAmount"]]:
                raise ValueError("Native sale lacks its explicit price")
            sale_price = number(bundle["row"][COLS["saleCurrencyAmount"]])
            if sale_price > bundle["price"]:
                raise ValueError("Native sale price exceeds the regular price")
            variants.append((sku + 20000, sale_price, None))
        smart_id = number(bundle["row"][COLS["smartID"]], 2**32 - 2)
        if smart_id:
            if smart_id == sku or not bundle["row"][COLS["smartCost"]]:
                raise ValueError("Smart offer lacks its distinct prerequisite or price")
            smart_price = number(bundle["row"][COLS["smartCost"]])
            if smart_price > bundle["price"]:
                raise ValueError("Native smart price exceeds the regular price")
            variants.append((sku + 60000, smart_price, smart_id))
        for variant_id, price, prerequisite in variants:
            offer = dict(base_offer)
            offer.update(
                id=variant_id,
                original=sku,
                prices=[{"currency": bundle["currency"], "amount": 0 if zero_prices else price}],
            )
            skus.append(offer)
            rule = dict(base_rule, sku=variant_id)
            if prerequisite is not None:
                rule["required_owned_items"] = [prerequisite]
                if sku in sale_ids:
                    # Native sale selection takes precedence over the smart price.
                    rule["enabled"] = False
            rules.append(rule)
    groups = [
        (
            "featured",
            "MENU/STORE_CAT_FEATURED",
            "online_store_featured",
            sorted(
                eligible,
                key=lambda item: (
                    item["id"] not in sale_ids,
                    item["price"] != 0,
                    item["id"],
                ),
            )[:18],
        ),
        (
            "operator",
            "MENU/BUNDLE_TYPE_OPERATOR",
            "online_store_category_5",
            [
                item
                for item in eligible
                if item["row"][5] == "MENU/BUNDLE_TYPE_OPERATOR"
            ][:18],
        ),
        (
            "weapon",
            "MENU/BUNDLE_TYPE_WEAPON",
            "online_store_category_6",
            [item for item in eligible if item["row"][5] == "MENU/BUNDLE_TYPE_WEAPON"][
                :18
            ],
        ),
        (
            "temp_category_1",
            "MENU/BUNDLE_TYPE_VARIETY",
            "online_store_category_7",
            [item for item in eligible if item["row"][5] == "MENU/BUNDLE_TYPE_VARIETY"][
                :18
            ],
        ),
    ]
    categories, variables = {}, {}
    for order, (identity, caption, variable, items) in enumerate(groups):
        if not items:
            continue
        name = "store_" + identity + ".json"
        categories[name] = {
            "id": identity,
            "name": caption,
            "order": order,
            "layoutType": 3,
            "asset": items[0]["row"][COLS["image"]],
            "numItemsShown": len(items),
            "idPubVar": variable,
            # A missing timer falls back to the current time in shipped Lua.
            # Its one-second change refreshes the carousel and resets selection.
            "timerPubVar": "online_store_featured_timer",
            "items": [
                {"order": 0, "layoutOnlyItem": True, "usesFirstPartyStore": False}
            ],
        }
        value = ",".join(str(item["id"]) for item in items)
        # Original 14107BB50 supplies a 128-byte getKeyValueByIterator buffer.
        # Keep whole IDs inside its 127-byte payload; never emit a cut-off ID.
        if len(value) >= 128:
            raise ValueError(
                "Native publisher variable buffer cannot hold this listing"
            )
        variables[variable] = variables[variable + "_warzone"] = value
    sales = ",".join(map(str, sale_ids))
    variables["online_store_sales_items"] = variables[
        "online_store_sales_items_warzone"
    ] = sales
    variables["online_store_featured_timer"] = variables[
        "online_store_featured_timer_warzone"
    ] = "2147483647"
    return {
        "root": {"layoutType": 3, "categories": list(categories)},
        "categories": categories,
        "variables": variables,
        "catalog": {"schema": 1, "skus": skus},
        "rules": {"schema": 1, "rules": rules},
        "excluded": excluded,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("table", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timestamp", type=int, default=int(time.time()))
    parser.add_argument("--zero-prices", action="store_true",
                        help="Publish every supported local bundle/variant for zero COD points")
    parser.add_argument(
        "--sale-ids",
        type=int,
        nargs="*",
        default=[],
        help="Native base bundle IDs currently on sale (up to 18)",
    )
    args = parser.parse_args()
    if not 0 < args.timestamp < 2**32:
        parser.error("Invalid publication timestamp")
    original = args.table.read_bytes()
    publication = build(json.loads(original), args.timestamp, args.sale_ids, args.zero_prices)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    files = {}

    def save(name, value):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = (json.dumps(value, indent=2) + "\n").encode()
        if name.startswith("publisher/") and len(payload) >= 2048:
            raise ValueError("Publisher document exceeds Replay's native buffer")
        path.write_bytes(payload)
        files[name] = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }

    save("publisher/store_v2.json", publication["root"])
    for name, document in publication["categories"].items():
        save("publisher/" + name, document)
    save("marketplace/catalog.json", publication["catalog"])
    save("marketplace/purchase-rules.json", publication["rules"])
    save("variables.json", publication["variables"])
    manifest = {
        "schema": 1,
        "title": 5800,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": {
            "asset": "loot/bundle_ids.csv",
            "sha256": hashlib.sha256(original).hexdigest(),
            "rows": len(json.loads(original)["rows"]),
            "columns": COLS,
        },
        "sku_count": len(publication["catalog"]["skus"]),
        "sale_bundle_ids": args.sale_ids,
        "zero_prices": args.zero_prices,
        "excluded": publication["excluded"],
        "files": files,
        "native_purchase_verified": False,
    }
    (output / "manifest.json").write_bytes(
        (json.dumps(manifest, indent=2) + "\n").encode()
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "skus": manifest["sku_count"],
                "excluded": len(manifest["excluded"]),
                "categories": len(publication["categories"]),
            }
        )
    )


if __name__ == "__main__":
    main()
