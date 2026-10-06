"""Exact Replay regulation REST DTOs and account-owned durable preferences."""

import copy
from datetime import datetime, timezone
import json


def exercise(client, directory, title, owner, request, response, blob, checks):
    root = directory / "regulations" / str(title)
    publication = root / "publication.json"
    preferences = root / "preferences" / f"{owner}.json"
    uri = f"/v1.0/accounts/uno/{owner}/optouts/?client=iw8"

    def parameters(operation, body=None, route=None, method=None):
        return request(
            "umbrella",
            "Regulations",
            operation,
            method=(
                (0x505554 if body is not None else 0x474554)
                if method is None
                else method
            ),
            body=body,
            uri=route
            or (
                "/v1.0/regulations/?client=iw8"
                if operation == "fetchRegulations"
                else uri
            ),
        )

    def call(operation, body=None, route=None, method=None):
        return response(
            client.task(255, 10, parameters(operation, body, route, method))
        )

    assert call("fetchRegulations")[0] == 503
    assert call("getUserPreference") == (200, {"optouts": []})
    assert not preferences.exists()
    policy = {
        "schema": 1,
        "title": title,
        "regulations": [{"name": "ccpa", "version": (1 << 64) - 1}],
    }
    root.mkdir(parents=True)
    publication.write_text(json.dumps(policy))
    assert call("fetchRegulations") == (200, {"regulations": policy["regulations"]})
    checks.append(
        "Regulation publication uses the exact native name/UInt64-version array; absent publication is unavailable and fresh preference reads create no implicit privacy choice"
    )
    choice = {
        "regulation": {"name": "ccpa", "version": 0},
        "clientMessageVersion": (1 << 64) - 1,
        "value": True,
    }
    assert call("setUserPreference", choice) == (200, {"success": True})
    status, body = call("getUserPreference")
    assert status == 200 and len(body["optouts"]) == 1
    row = body["optouts"][0]
    assert set(row) == {
        "regulation",
        "clientMessageVersion",
        "value",
        "updated",
        "updatedTimestamp",
    }
    assert row["regulation"] == policy["regulations"][0]
    assert (
        row["clientMessageVersion"] == choice["clientMessageVersion"]
        and row["value"] is True
    )
    assert (
        datetime.fromtimestamp(row["updatedTimestamp"], timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        == row["updated"]
    )
    baseline = preferences.read_bytes(), preferences.stat().st_mtime_ns
    assert call("setUserPreference", choice) == (200, {"success": True})
    assert (preferences.read_bytes(), preferences.stat().st_mtime_ns) == baseline
    assert call("getUserPreference", route=uri.replace("/uno/", "/bnet/")) == (
        status,
        body,
    )
    wrong = uri.replace(str(owner), str(owner + 1))
    assert call("getUserPreference", route=wrong)[0] == 403
    assert call("setUserPreference", choice, wrong)[0] == 403
    assert preferences.read_bytes() == baseline[0]
    assert (
        call(
            "setUserPreference",
            dict(choice, regulation={"name": "unknown", "version": 0}),
        )[0]
        == 404
    )
    assert (
        call(
            "setUserPreference", dict(choice, regulation={"name": "ccpa", "version": 1})
        )[0]
        == 409
    )
    checks.append(
        "Native optouts DTO includes regulation/client-message UInt64s, real boolean and matching UTC/timestamp; signed account aliases share only the owner's choices and exact retries do not rewrite them"
    )

    for bad in (
        dict(choice, value=1),
        dict(choice, clientMessageVersion=1.0),
        dict(choice, regulation={"name": "nameislong", "version": 0}),
        dict(choice, regulation={"name": "ccpa", "version": -1}),
        dict(choice, extra=True),
    ):
        client.task(255, 10, parameters("setUserPreference", bad), error=106)
    for bad_uri in (
        uri.replace(str(owner), "0" + str(owner)),
        uri.replace("client=iw8", "client=iw8&client=other"),
        uri.replace("client=iw8", "client=%00"),
        uri.replace("/uno/", "/steam/"),
        uri.replace("/optouts/", "/../../"),
    ):
        client.task(255, 10, parameters("getUserPreference", route=bad_uri), error=106)
    client.task(255, 10, parameters("fetchRegulations", method=0x505554), error=106)
    raw = parameters("setUserPreference", choice)
    original = blob(json.dumps(choice).encode())
    assert raw.endswith(original)
    for bad in (
        json.dumps(choice)
        .replace('"value": true', '"value": true, "value": false')
        .encode(),
        json.dumps(choice).encode() + b"{}",
    ):
        client.task(255, 10, raw[: -len(original)] + blob(bad), error=106)
    assert preferences.read_bytes() == baseline[0]
    checks.append(
        "Complete regulation request layout rejects duplicate/trailing JSON, floats, malformed booleans, long names, account/path/query ambiguity and unsupported methods without mutating choices"
    )

    saved = json.loads(baseline[0])
    for target, document, mutations in (
        (
            publication,
            policy,
            (
                lambda value: value.update(title=title + 1),
                lambda value: value.update(regulations=value["regulations"] * 2),
                lambda value: value.update(
                    regulations=[{"name": f"p{i}", "version": 0} for i in range(16)]
                ),
                lambda value: value["regulations"][0].update(version=1.0),
            ),
        ),
        (
            preferences,
            saved,
            (
                lambda value: value.update(owner=owner + 1),
                lambda value: value.update(optouts=value["optouts"] * 2),
                lambda value: value["optouts"][0].update(value=1),
                lambda value: value["optouts"][0].update(updated="bad"),
                lambda value: value["optouts"][0].update(
                    updatedTimestamp=(1 << 64) - 1
                ),
            ),
        ),
    ):
        original_bytes = target.read_bytes()
        for mutate in mutations:
            damaged = copy.deepcopy(document)
            mutate(damaged)
            target.write_text(json.dumps(damaged))
            before = target.read_bytes()
            operation = (
                "fetchRegulations" if target == publication else "getUserPreference"
            )
            client.task(255, 10, parameters(operation), error=102)
            assert target.read_bytes() == before
        target.write_bytes(original_bytes)
    blocker = preferences.with_suffix(".json.pending")
    blocker.mkdir()
    changed = dict(choice, value=False)
    try:
        client.task(255, 10, parameters("setUserPreference", changed), error=102)
        assert preferences.read_bytes() == baseline[0]
    finally:
        blocker.rmdir()
    assert call("setUserPreference", changed) == (200, {"success": True})
    expected = call("getUserPreference")
    assert expected[1]["optouts"][0]["value"] is False
    assert call("getUserPreference", route=wrong)[0] == 403
    checks.append(
        "Whole persisted regulation publications/preferences reject corrupt ownership, duplicate/overflowing records, invalid numeric/time/boolean layouts; failed atomic writes publish no success and an owned retry saves the real changed preference"
    )

    def after_restart(connection):
        assert (
            response(connection.task(255, 10, parameters("getUserPreference")))
            == expected
        )
        before = preferences.read_bytes()
        assert response(
            connection.task(255, 10, parameters("setUserPreference", changed))
        ) == (200, {"success": True})
        assert preferences.read_bytes() == before
        checks.append(
            "Account-owned regulation preference and its native UTC/UInt64 DTO survive backend process restart with exact retry idempotence"
        )

    return after_restart
