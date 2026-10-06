"""Exercise published Replay AB cohorts, native capacities and durable token scope."""

from copy import deepcopy
import json
import time


def exercise(client, directory, title, user, request, fields, checks):
    state = directory / "ab-enrollments" / str(title) / f"{user}.json"
    original = state.read_bytes()
    catalog = directory / "ab-testing" / str(title) / "iw8" / "catalog.json"
    assert not catalog.exists()
    catalog.parent.mkdir(parents=True)
    clock = int(time.time())
    treatment = {
        "starts": clock - 10,
        "ends": clock + 7200,
        "modifiers": '{"type":"dvar","data":[{"key":"ui_serverFrameDuration","value":"16"}]}',
    }
    publication = dict(
        schema=1,
        title=title,
        context="iw8",
        revision=1,
        tests=[
            dict(
                testID=17,
                enabled=True,
                cohorts=[dict(cohortID=31, weight=1, clientTreatments=[treatment])],
            )
        ],
    )

    def write(data):
        catalog.write_text(json.dumps(data))

    def enroll(packet=None):
        data = fields(client.task(194, 1, packet or request(user), structured=True))
        assert (2, 0, 200) in data
        return json.loads(next(v for tag, kind, v in data if tag == 3))

    try:
        write(publication)
        result = enroll()
        assert len(result["ABToken"]) == 64 and 0 < result["expiresIn"] <= 3600
        row = result["enrollments"][0]
        assert (row["testID"], row["cohortID"]) == (17, 31)
        assert row["clientTreatments"][0]["startsIn"] == 0
        assert 7100 < row["clientTreatments"][0]["endsIn"] <= 7200
        assert row["clientTreatments"][0]["modifiers"] == treatment["modifiers"]
        assert enroll()["ABToken"] == result["ABToken"]
        checks.append(
            "Published AB cohort delivers exact native IDs, active treatment schedule and modifier string with a stable owner token"
        )

        saved = state.read_bytes()
        cases = []

        def broken(change):
            data = deepcopy(publication)
            change(data)
            cases.append(data)

        broken(lambda d: d.update(schema=True))
        broken(lambda d: d.update(title=title + 1))
        broken(lambda d: d.update(context="foreign"))
        broken(lambda d: d.update(extra=True))
        broken(lambda d: d.update(revision=0))
        broken(lambda d: d.update(tests=d["tests"] * 2))
        broken(lambda d: d["tests"][0].update(enabled=1))
        broken(lambda d: d["tests"][0]["cohorts"][0].update(weight=0))
        broken(lambda d: d["tests"][0]["cohorts"][0].update(cohortID=0))
        broken(lambda d: d["tests"][0].update(cohorts=d["tests"][0]["cohorts"] * 2))
        broken(
            lambda d: d["tests"][0]["cohorts"][0].update(
                clientTreatments=[treatment] * 2
            )
        )
        for modifiers in ("a" * 1024, "bad\0text", ""):
            broken(
                lambda d, value=modifiers: d["tests"][0]["cohorts"][0][
                    "clientTreatments"
                ][0].update(modifiers=value)
            )
        for case in cases:
            write(case)
            client.task(194, 1, request(user), error=102)
            assert state.read_bytes() == saved
        duplicate = json.dumps(publication).replace(
            '"schema": 1', '"schema": 1, "schema": 1'
        )
        catalog.write_text(duplicate)
        client.task(194, 1, request(user), error=102)
        assert state.read_bytes() == saved
        write(publication)
        for change in (
            lambda d: d.update(user=user + 1),
            lambda d: d.update(publicationHash="invalid"),
            lambda d: d.update(enrollments=[d["enrollments"][0]] * 9),
        ):
            damaged = json.loads(saved)
            change(damaged)
            payload = json.dumps(damaged).encode()
            state.write_bytes(payload)
            client.task(194, 1, request(user), error=102)
            assert state.read_bytes() == payload
        state.write_bytes(saved)
        checks.append(
            "Complete AB publication and persisted enrollment layouts reject bad scope, duplicate IDs/keys, invalid cohort weights and native treatment/modifier/count overflows before writing"
        )

        changed = deepcopy(publication)
        changed["tests"][0]["cohorts"][0]["clientTreatments"][0]["modifiers"] = "{}"
        write(changed)
        client.task(194, 1, request(user), error=102)
        assert state.read_bytes() == saved
        changed["revision"] = 2
        write(changed)
        pending = state.with_name(state.name + ".pending")
        assert not pending.exists()
        pending.mkdir()
        try:
            client.task(194, 1, request(user), error=102)
            assert state.read_bytes() == saved
        finally:
            pending.rmdir()
        new = enroll()
        assert new["ABToken"] != result["ABToken"]
        write(publication)
        client.task(194, 1, request(user), error=102)
        checks.append(
            "AB revision reuse/rollback and real failed atomic publication preserve the prior token; a valid newer revision renews the owned enrollment"
        )

        future = deepcopy(publication)
        future["revision"] = 3
        future["tests"][0]["cohorts"][0]["clientTreatments"][0].update(
            starts=clock + 120, ends=clock + 600
        )
        write(future)
        inactive = enroll()
        assert inactive["enrollments"] == [] and 0 < inactive["expiresIn"] <= 120
        future["revision"] = 4
        future["tests"][0]["cohorts"][0]["clientTreatments"][0].update(
            starts=clock - 300, ends=clock - 10
        )
        write(future)
        assert enroll()["enrollments"] == []
        checks.append(
            "Future and expired AB treatments are withheld from Replay's immediate modifier consumer and token lifetime stops at the next activation boundary"
        )
    finally:
        state.write_bytes(original)
        if catalog.exists():
            catalog.unlink()

    # Retain a separate context's positive enrollment for the suite's real
    # process restart. The original iw8 token above remains unchanged.
    context = "ab_fixture"
    other = directory / "ab-testing" / str(title) / context / "catalog.json"
    other.parent.mkdir(parents=True)
    publication["context"] = context
    other.write_text(json.dumps(publication))
    packet = request(user, context=context)
    result = enroll(packet)
    assert result["enrollments"][0]["cohortID"] == 31
    assert result["ABToken"] != json.loads(original)["token"]
    checks.append(
        "AB contexts isolate tokens and cohorts while preserving legacy iw8 enrollment retries"
    )
    return packet, result["ABToken"]


def after_restart(client, fixture, fields, checks):
    packet, token = fixture
    response = fields(client.task(194, 1, packet, structured=True))
    result = json.loads(next(v for tag, kind, v in response if tag == 3))
    assert result["ABToken"] == token
    assert result["enrollments"][0]["cohortID"] == 31
    checks.append(
        "Published AB cohort and its scoped token survive the actual backend process restart"
    )
