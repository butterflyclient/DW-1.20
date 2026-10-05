"""Independent Replay 195/1 proxy wire, publication and durable journal checks."""

import copy
import hashlib
import json
import time


def exercise(client, directory, title, user, helpers, checks):
    structure, integer, text, blob, fields = helpers
    context = str(title)  # Exact native ExchangeLootCrate caller uses decimal title.
    root = directory / "loot-generation" / str(title) / context
    catalog_path = root / "catalog.json"
    receipts_path = root / "receipts" / f"{user}.json"
    root.mkdir(parents=True, exist_ok=True)
    client_data = '{"drop_versions":[0],"active_streams":[0]}'
    response = '{"localFixture":true,"message":"opaque \\ response"}'
    digest = hashlib.sha256(client_data.encode()).hexdigest()
    row = dict(
        drop=27,
        client_data_sha256=digest,
        script_response=response,
        enabled=True,
        starts=0,
        expires=0,
    )
    catalog = dict(schema=1, title=title, context=context, responses=[row])

    def publish(value=catalog):
        catalog_path.write_text(json.dumps(value), encoding="utf-8")

    def params(
        data=client_data,
        owner=user,
        drop=27,
        context=context,
        method="POST",
        body=None,
        content_type="application/json",
        query=None,
        extra=b"",
        account_type="bnet",
    ):
        url = f"/v1/users/{account_type}-{owner}/loot-drop/{drop}/?"
        url += query if query is not None else f"client=replaylocal&context={context}"
        body = json.dumps({"clientData": data}) if body is None else body
        header = blob(4, text(1, "Content-Type") + text(2, content_type))
        return structure(
            text(1, method) + text(2, url) + text(3, body) + header + extra
        )

    def decode(raw):
        values = fields(raw)
        assert [tag for tag, kind, value in values] == [1, 2, 3]
        assert values[1] == (2, 0, 200)
        body = values[2][2]
        assert fields(values[0][2]) == [
            (1, 2, b"Content-Length"),
            (2, 2, str(len(body)).encode()),
        ]
        assert len(body) < 16000
        result = json.loads(body)
        assert list(result) == ["scriptResponse"] and isinstance(
            result["scriptResponse"], str
        )
        return result["scriptResponse"]

    client.task(195, 1, params(), error=108)
    assert not receipts_path.exists()
    publish()
    assert decode(client.task(195, 1, params(), structured=True)) == response
    original = receipts_path.read_bytes()
    receipts = json.loads(original)
    assert receipts == dict(
        schema=1,
        title=title,
        context=context,
        owner=user,
        next_id=2,
        receipts=[
            dict(
                id=1,
                drop=27,
                client_data_sha256=digest,
                script_response=response,
                recorded=receipts["receipts"][0]["recorded"],
            )
        ],
    )
    assert abs(receipts["receipts"][0]["recorded"] - time.time()) < 10
    assert client_data.encode() not in original
    assert decode(client.task(195, 1, params(), structured=True)) == response
    second = json.loads(receipts_path.read_bytes())
    assert second["next_id"] == 3 and second["receipts"][0] == receipts["receipts"][0]
    assert second["receipts"][1]["id"] == 2
    updated = copy.deepcopy(catalog)
    updated["responses"][0]["script_response"] = "later publication"
    publish(updated)
    assert decode(client.task(195, 1, params(), structured=True)) == "later publication"
    original = receipts_path.read_bytes()
    catalog_path.unlink()
    client.task(195, 1, params(), error=108)
    client.task(195, 1, params(data="unknown"), error=108)
    assert receipts_path.read_bytes() == original
    checks.append(
        "Replay scripted-loot HTTP proxy status/header/body and opaque scriptResponse; native constant clientData opens are separate ordered journal records and observe live publication edits/removal"
    )

    publish()
    for request, error in (
        (params(owner=user + 1), 101),
        (params(context="other"), 108),
        (params(drop=28), 108),
        (params(data="changed"), 108),
        (params(method="GET"), 106),
        (params(content_type="text/plain"), 106),
        (params(body="{}"), 106),
        (params(body='{"clientData":7}'), 106),
        (params(body='{"clientData":"one","clientData":"two"}'), 106),
        (params(body='{"clientData":"one","extra":1}'), 106),
        (params(body="{"), 106),
        (params(data="a" * 1000), 106),
        (params(data="a\0b"), 106),
        (params(context="../escape"), 106),
        (params(context="x" * 16), 106),
        (params(drop="027"), 106),
        (params(drop=2**32), 106),
        (params(query="client=x&context=iw8&context=iw8"), 106),
        (params(query="client=x&context=%00"), 106),
        (params(query="client=x&context=%0Z"), 106),
        (params(query="client=x&context=iw8&"), 106),
        (params(query="context=iw8"), 106),
        (params(extra=text(1, "POST")), 106),
        (params(extra=text(3, "{}")), 106),
        (params(extra=blob(4, text(1, "Content-Type"))), 106),
        (
            params(
                extra=blob(4, text(1, "Content-Type") + text(2, "application/json"))
            ),
            106,
        ),
    ):
        client.task(195, 1, request, error=error)
        assert receipts_path.read_bytes() == original
    assert (
        decode(
            client.task(
                195,
                1,
                params(context=f"%{ord(context[0]):02x}" + context[1:]),
                structured=True,
            )
        )
        == response
    )
    assert (
        decode(client.task(195, 1, params(account_type="uno"), structured=True))
        == response
    )
    original = receipts_path.read_bytes()
    receipts = json.loads(original)
    assert receipts["next_id"] == 6 and len(receipts["receipts"]) == 5
    checks.append(
        "Scripted-loot signed owner/title/context isolation, canonical UInt32 drop IDs, percent-decoded bounded queries, JSON/header duplicates and malformed requests rejected without mutation"
    )

    fresh_data = "fresh publication request"
    fresh = dict(
        row, client_data_sha256=hashlib.sha256(fresh_data.encode()).hexdigest()
    )
    fresh_catalog = dict(catalog, responses=[fresh])
    for mutate in (
        lambda value: value.update(title=title + 1),
        lambda value: value.update(context="other"),
        lambda value: value.update(schema=2),
        lambda value: value["responses"].append(copy.deepcopy(fresh)),
        lambda value: value["responses"][0].update(drop=-1),
        lambda value: value["responses"][0].update(drop=2**32),
        lambda value: value["responses"][0].update(client_data_sha256="g" * 64),
        lambda value: value["responses"][0].update(script_response=7),
        lambda value: value["responses"][0].update(script_response="a\0b"),
        lambda value: value["responses"][0].update(script_response="a" * 16000),
        lambda value: value["responses"][0].update(script_response="\n" * 7990),
        lambda value: value["responses"][0].update(enabled=1),
        lambda value: value["responses"][0].update(starts=-1),
        lambda value: value["responses"][0].update(starts=10, expires=9),
    ):
        value = copy.deepcopy(fresh_catalog)
        mutate(value)
        publish(value)
        client.task(195, 1, params(data=fresh_data), error=102)
        assert receipts_path.read_bytes() == original
    publish({})
    client.task(195, 1, params(data=fresh_data), error=102)
    for changed in (
        dict(fresh, enabled=False),
        dict(fresh, starts=int(time.time()) + 3600),
        dict(fresh, expires=int(time.time()) - 1),
    ):
        publish(dict(catalog, responses=[changed]))
        client.task(195, 1, params(data=fresh_data), error=108)
    for mutate in (
        lambda value: value.update(owner=user + 1),
        lambda value: value.update(title=title + 1),
        lambda value: value.update(context="other"),
        lambda value: value.update(next_id=100),
        lambda value: value["receipts"].append(copy.deepcopy(value["receipts"][0])),
        lambda value: value["receipts"][0].update(script_response="a" * 16000),
    ):
        value = copy.deepcopy(receipts)
        mutate(value)
        receipts_path.write_text(json.dumps(value))
        client.task(195, 1, params(), error=102)
        assert json.loads(receipts_path.read_bytes()) == value
    receipts_path.write_bytes(original)
    publish(fresh_catalog)
    full = copy.deepcopy(receipts)
    full["receipts"] = [
        dict(receipts["receipts"][0], id=index + 1) for index in range(4096)
    ]
    full["next_id"] = 4097
    receipts_path.write_text(json.dumps(full))
    capacity_bytes = receipts_path.read_bytes()
    client.task(195, 1, params(data=fresh_data), error=108)
    assert receipts_path.read_bytes() == capacity_bytes
    full["receipts"].append(dict(receipts["receipts"][0], id=4097))
    full["next_id"] = 4098
    receipts_path.write_text(json.dumps(full))
    client.task(195, 1, params(data=fresh_data), error=102)
    receipts_path.write_bytes(original)
    assert (
        decode(client.task(195, 1, params(data=fresh_data), structured=True))
        == response
    )
    # Keep a changed publication in place for the independent process-restart check.
    fresh_catalog["responses"][0]["script_response"] = "after restart publication"
    publish(fresh_catalog)
    checks.append(
        "Whole scripted-loot publication/receipt schema validation, disabled/time filtering, corrupt-state errors, response raw/escaped native buffer bounds and live disk publication"
    )
    return dict(
        params=params(data=fresh_data),
        response="after restart publication",
        receipts_path=receipts_path,
        receipts=json.loads(receipts_path.read_bytes()),
        decode=decode,
    )


def check_restart(client, fixture, checks):
    assert (
        fixture["decode"](client.task(195, 1, fixture["params"], structured=True))
        == fixture["response"]
    )
    current = json.loads(fixture["receipts_path"].read_bytes())
    assert current["next_id"] == fixture["receipts"]["next_id"] + 1
    assert current["receipts"][:-1] == fixture["receipts"]["receipts"]
    assert current["receipts"][-1]["script_response"] == fixture["response"]
    checks.append(
        "Scripted-loot owner journal persists across a real server restart; a new native opening appends its next ID and uses current publication"
    )
