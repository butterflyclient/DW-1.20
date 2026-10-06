"""Replay bulk username hydration over the real encrypted REST task envelope."""

import struct


def exercise(client, title, owner, peer, request, response, blob, checks):
    route = f"/v1/users/?context={title}&client=iw8&titleID={title}&users="

    def packet(users, **options):
        return request(
            "social-service", "Users", "get_usernames", uri=route + users, **options
        )

    def call(users):
        return response(client.task(255, 10, packet(users)))

    own = {"userID": owner, "accountType": "uno", "username": "DWPlayer#0"}
    other = {"userID": peer, "accountType": "bnet", "username": "Fixture Peer#0"}
    status, body = call(f"bnet-{peer}%2Cuno-{owner},bnet-{peer}")
    assert status == 200 and body == {"users": [other, own, other]}
    # Real long IDs also consume the 4 KiB whole-URI budget. Exercise a large
    # positive result below that budget, then the 200-entry count with short IDs.
    assert call(",".join([f"uno-{owner}"] * 150)) == (200, {"users": [own] * 150})
    assert call(",".join(["uno-1"] * 200)) == (200, {"users": []})
    assert call(f"uno-{(1 << 64) - 2},psn-{owner}") == (200, {"users": []})
    assert call(f"bnet-{owner}") == (200, {"users": [dict(own, accountType="bnet")]})
    checks.append(
        "Native bulk username DTO: registered UNO/Battle.net aliases, requested order/duplicates, 200-record capacity and genuine empty unknown/provider results"
    )

    for users in (
        "",
        f"uno-{owner},",
        f",uno-{owner}",
        f"uno-{owner},,bnet-{peer}",
        f"uno-{owner}%00",
        f"uno-{owner}%2Fextra",
        f"uno--{owner}",
        "uno-0",
        f"uno-{(1 << 64) - 1}",
        f"uno-{1 << 64}",
        f"tenletters-{owner}",
        ",".join(["uno-1"] * 201),
        ",".join([f"uno-{owner}"] * 200),
    ):
        client.task(255, 10, packet(users), error=106)
    good = f"uno-{owner}"
    for uri in (
        route.replace(f"context={title}", f"context={title + 1}") + good,
        route.replace(f"titleID={title}", f"titleID={title + 1}") + good,
        route.replace("client=iw8", "client=") + good,
        route.replace("/v1/users/", "/v2/users/") + good,
        route + good + "&users=" + good,
        route + good + "&extra=1",
    ):
        client.task(
            255,
            10,
            request("social-service", "Users", "get_usernames", uri=uri),
            error=106,
        )
    client.task(255, 10, packet(good, method=0x504F5354), error=106)
    client.task(255, 10, packet(good, body={}), error=106)
    checks.append(
        "Bulk username ownership scope and native URI limits: mismatched title/context, duplicate query, malformed account ID, excess count, body and method rejected"
    )

    # Duplicate singleton fields used to overwrite routing facts silently.
    # Keep SDK repeated Accept/header/unknown-extension fields valid.
    raw = packet(good)
    length = struct.unpack_from("<I", raw, 7)[0]
    message = raw[11 : 11 + length]
    tail = raw[11 + length :]

    def integer(tag, value):
        from native_wire_client import integer as encode

        return encode(tag, value)

    def text(tag, value):
        from native_wire_client import text as encode

        return encode(tag, value)

    def binary(tag, value):
        from native_wire_client import binary as encode

        return encode(tag, value)

    def envelope(value):
        return raw[:5] + blob(value) + tail

    for duplicate in (
        integer(2, 1),
        integer(10, 0x474554),
        text(11, route + good),
        text(101, "social-service"),
        integer(302, 1),
    ):
        client.task(255, 10, envelope(message + duplicate), error=106)
    # The request helper's first field is the nested parameter message.
    assert message[0] == 10
    position, value, shift = 1, 0, 0
    while True:
        byte = message[position]
        position += 1
        value |= (byte & 127) << shift
        if byte < 128:
            break
        shift += 7
    params = message[position : position + value]
    rest = message[position + value :]
    for duplicate in (
        integer(1, 1),
        integer(2, 0),
        integer(3, 1),
        integer(100, 10000),
        binary(200, bytes(256)),
        text(300, "Users"),
        text(301, "get_usernames"),
    ):
        client.task(255, 10, envelope(binary(1, params + duplicate) + rest), error=106)
    for field in (1, 2):
        header = text(1, "Fixture") + text(2, "value") + text(field, "duplicate")
        client.task(255, 10, envelope(message + binary(14, header)), error=106)
    extra = (
        integer(102, 1)
        + integer(102, 2)
        + binary(14, text(1, "Fixture-A") + text(2, "one"))
        + binary(14, text(1, "Fixture-B") + text(2, "two"))
        + integer(777, 1)
        + integer(777, 2)
    )
    assert response(client.task(255, 10, envelope(message + extra))) == (
        200,
        {"users": [own]},
    )
    checks.append(
        "REST singleton routing/header fields reject duplicates while native repeated accepts/headers and unknown extensions remain compatible"
    )
