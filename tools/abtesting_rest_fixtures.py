"""Check Replay AB transports share bounded, durable account-owned enrollments."""

from copy import deepcopy
import json
import math
import struct
import time


def exercise(
    client,
    peer,
    directory,
    title,
    user,
    peer_user,
    rest_request,
    rest_response,
    legacy_request,
    helpers,
    checks,
):
    blob, structure, text, binary, integer, fields = helpers
    context = "ab_rest"
    catalog = directory / "ab-testing" / str(title) / context / "catalog.json"
    state = directory / "ab-enrollments" / str(title) / context / f"{user}.json"
    assert not catalog.exists() and not state.exists()
    catalog.parent.mkdir(parents=True)
    clock = int(time.time())
    publication = dict(
        schema=1,
        title=title,
        context=context,
        revision=1,
        tests=[
            dict(
                testID=101,
                enabled=True,
                cohorts=[
                    dict(
                        cohortID=201,
                        weight=1,
                        clientTreatments=[
                            dict(
                                starts=clock - 10,
                                ends=clock + 7200,
                                modifiers="{}",
                            )
                        ],
                    )
                ],
            )
        ],
    )

    def packet(account="uno", owner=user, selected=context, **options):
        uri = f"abtesting/v2/users/{account}-{owner}/enrollments/"
        if selected is not None:
            uri += f"?client=iw8&context={selected}"
        uri = options.pop("uri", uri)
        raw = rest_request(
            options.pop("service", "abtesting"),
            "abtesting",
            "enroll",
            method=options.pop("method", 0x504F5354),
            uri=uri,
            body=options.pop("body", None),
        )
        assert not options
        size = struct.unpack_from("<I", raw, 7)[0]
        # The native bodyless writer sets no Content-Type (tag 302).
        message = b"".join(
            binary(tag, value) if kind == 2 else integer(tag, value)
            for tag, kind, value in fields(raw[11 : 11 + size])
            if tag != 302
        )
        return raw[:5] + blob(message) + raw[11 + size :]

    def enroll(payload=None, actor=client):
        status, result = rest_response(actor.task(255, 10, payload or packet()))
        assert status == 200
        return result

    def legacy(selected=context):
        raw = fields(
            client.task(194, 1, legacy_request(user, context=selected), structured=True)
        )
        body = next(value for tag, kind, value in raw if tag == 3)
        assert len(body) < 8096
        return json.loads(body), body

    original = directory / "ab-enrollments" / str(title) / f"{user}.json"
    default_token = json.loads(original.read_bytes())["token"]
    assert enroll(packet(selected=None))["ABToken"] == default_token
    catalog.write_text(json.dumps(publication))
    result = enroll()
    assert result["enrollments"][0]["cohortID"] == 201
    assert result["enrollments"][0]["clientTreatments"][0]["modifiers"] == "{}"
    assert legacy()[0]["ABToken"] == result["ABToken"]
    assert enroll(packet(account="bnet"))["ABToken"] == result["ABToken"]
    other = enroll(packet(owner=peer_user), actor=peer)
    assert other["ABToken"] != result["ABToken"]
    client.task(255, 10, packet(owner=peer_user), error=101)
    checks.append(
        "AB REST explicitly addressed bodyless POST shares native IDs, cohorts, schedules and durable tokens with task 194/1; UNO/Battle.net aliases preserve signed ownership"
    )

    saved = state.read_bytes()
    for bad in (
        packet(service=""),
        packet(method=0x474554),
        packet(body={}),
        packet(uri=f"/abtesting/v2/users/uno-{user}/enrollments/"),
        packet(uri=f"abtesting/v2/users/uno-{user}/enrollments/?context=../bad"),
        packet(
            uri=f"abtesting/v2/users/uno-{user}/enrollments/?context={context}&context={context}"
        ),
        packet(uri=f"abtesting/v2/users/uno-{user}/enrollments/?unknown=1"),
    ):
        client.task(255, 10, bad, error=106)
        assert state.read_bytes() == saved
    checks.append(
        "AB REST rejects the original SDK's empty service, malformed/body-bearing requests, foreign namespaces and duplicate query fields before persistence"
    )

    # Populate the complete engine capacity, then exercise the legacy body's
    # exact 8095-byte boundary and one-byte overflow before either transport
    # can rotate a token or acknowledge a larger durable enrollment.
    full = deepcopy(publication)
    full["revision"] = 2
    full["tests"] = []
    native = []
    for index in range(8):
        full["tests"].append(
            dict(
                testID=101 + index,
                enabled=True,
                cohorts=[
                    dict(
                        cohortID=201 + index,
                        weight=1,
                        clientTreatments=[
                            dict(
                                starts=clock - 10,
                                ends=clock + 7200,
                                modifiers="x",
                            )
                        ],
                    )
                ],
            )
        )
        native.append(
            dict(
                testID=101 + index,
                cohortID=201 + index,
                clientTreatments=[dict(startsIn=0, endsIn=7200, modifiers="x")],
            )
        )
    minimum = len(
        json.dumps(
            dict(expiresIn=3600, ABToken="x" * 64, enrollments=native),
            separators=(",", ":"),
        )
    )
    remaining = 8095 - minimum
    for row in full["tests"]:
        add = min(remaining, 1022)
        row["cohorts"][0]["clientTreatments"][0]["modifiers"] += "x" * add
        remaining -= add
    assert remaining == 0
    catalog.write_text(json.dumps(full))
    bounded = enroll()
    value, raw = legacy()
    assert len(raw) == 8095 and len(value["enrollments"]) == 8
    assert bounded["ABToken"] == value["ABToken"]
    boundary_state = state.read_bytes()
    overflow = deepcopy(full)
    overflow["revision"] = 3
    row = next(
        row
        for row in overflow["tests"]
        if len(row["cohorts"][0]["clientTreatments"][0]["modifiers"]) < 1023
    )
    row["cohorts"][0]["clientTreatments"][0]["modifiers"] += "x"
    catalog.write_text(json.dumps(overflow))
    client.task(255, 10, packet(), error=102)
    client.task(194, 1, legacy_request(user, context=context), error=102)
    assert state.read_bytes() == boundary_state
    checks.append(
        "Both AB transports accept eight enrollments at exactly 8095 JSON bytes and reject one-byte legacy buffer overflow without publishing a new token or enrollment"
    )

    publication["revision"] = 3
    catalog.write_text(json.dumps(publication))
    pending = state.with_name(state.name + ".pending")
    assert not pending.exists()
    pending.mkdir()
    try:
        client.task(255, 10, packet(), error=102)
        assert state.read_bytes() == boundary_state
    finally:
        pending.rmdir()
    result = enroll()
    checks.append(
        "AB REST failed atomic publication preserves the prior complete enrollment; successful retry replaces it through the shared legacy journal"
    )
    return packet(), legacy_request(user, context=context), result["ABToken"]


def after_restart(client, fixture, rest_response, fields, checks):
    rest_packet, legacy_packet, token = fixture
    started = time.monotonic()
    status, result = rest_response(client.task(255, 10, rest_packet))
    assert status == 200 and result["ABToken"] == token
    legacy = fields(client.task(194, 1, legacy_packet, structured=True))
    value = json.loads(next(body for tag, kind, body in legacy if tag == 3))
    assert value["ABToken"] == token
    first, second = result["enrollments"], deepcopy(value["enrollments"])
    assert len(first) == len(second)
    for rest_row, native_row in zip(first, second):
        assert len(rest_row["clientTreatments"]) == len(native_row["clientTreatments"])
        for rest_treatment, native_treatment in zip(
                rest_row["clientTreatments"], native_row["clientTreatments"]):
            # These are independently timed requests. Crossing a wall-clock
            # second legitimately decreases the remaining treatment lifetime.
            elapsed = rest_treatment["endsIn"] - native_treatment["endsIn"]
            assert 0 <= elapsed <= math.ceil(time.monotonic() - started) + 1
            native_treatment["endsIn"] = rest_treatment["endsIn"]
    assert second == first
    checks.append(
        "AB REST/legacy shared cohort and owner token survive actual backend process restart"
    )
