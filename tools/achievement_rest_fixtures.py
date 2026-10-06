"""Exercise the two Replay REST writers' complete shared batch envelope."""

import copy
import json


def exercise(client, path, title, owner, request, response, checks):
    body = dict(
        titleID=title,
        idempotentRequestID="00000000-0000-0000-0000-000000000001",
        userEvents=[
            dict(
                accountType="bnet",
                userID=owner,
                events=[
                    dict(name="frontend_login", timestamp=123, values=dict(count=1))
                ],
            )
        ],
    )
    query = f"context={title}&client=replaylocal&titleID={title}"
    uri = "/v2/user-events/$batch/?" + query

    def packet(value=body, url=uri, method=0x504F5354):
        return request(
            "ae.demonware.net",
            "user_events",
            "report_user_events_batch",
            method,
            value,
            uri=url,
        )

    before = path.read_bytes()
    # Same owned event/retry identity, including an encoded native query value.
    assert response(
        client.task(255, 10, packet(url=uri.replace("replaylocal", "%72eplaylocal")))
    ) == (200, {"allSucceeded": True})
    assert response(
        client.task(
            255,
            10,
            packet(
                url=f"/v2/user-events/$batch/?titleID={title}&client=iw8&context={title}"
            ),
        )
    ) == (200, {"allSucceeded": True})
    assert path.read_bytes() == before
    for bad in (
        "/v2/user-events/$batch/other/?" + query,
        "/v2/user-events/$batch/?context=" + str(title),
        uri + "&context=iw8",
        uri + "&unknown=1",
        uri + "&",
        uri + "#fragment",
        uri.replace("titleID=" + str(title), "titleID=" + str(title + 1)),
        uri.replace("context=" + str(title), "context=../other"),
        uri.replace("replaylocal", "%00replaylocal"),
        uri.replace("replaylocal", "%GG"),
    ):
        client.task(255, 10, packet(url=bad), error=106)
        assert path.read_bytes() == before
    client.task(255, 10, packet(method=0x474554), error=106)
    assert path.read_bytes() == before
    checks.append(
        "Shared Replay achievement REST envelope binds the exact batch path, JSON acceptance and context/client/titleID query; aliases, foreign query titles, duplicate keys and malformed encoding cannot publish events"
    )

    encoded = json.dumps(body, separators=(",", ":")).encode()
    duplicate_bodies = (
        encoded.replace(b'"titleID":', b'"titleID":0,"titleID":', 1),
        encoded.replace(b'"userID":', b'"userID":0,"userID":', 1),
        encoded.replace(b'"count":1', b'"count":0,"count":1', 1),
    )
    for bad in duplicate_bodies:
        client.task(255, 10, packet(bad), error=106)
        assert path.read_bytes() == before
    for change in (
        lambda b: b.update(extra=True),
        lambda b: b["userEvents"][0].update(extra=True),
        lambda b: b["userEvents"][0]["events"][0].update(extra=True),
    ):
        bad = copy.deepcopy(body)
        change(bad)
        client.task(255, 10, packet(bad), error=106)
        assert path.read_bytes() == before
    checks.append(
        "Achievement REST root, single-user/multi-user account fields and event/value objects reject ambiguous JSON and unknown layout fields before durable retry or event mutation"
    )
