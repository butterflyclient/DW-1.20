"""Original account REST DTOs, durable credentials and interrupted publication."""

import base64
import hashlib
import json
import os
import struct


def exercise(
    default,
    foreign_token,
    default_owner,
    directory,
    title,
    seed,
    post,
    Client,
    request,
    response,
    blob,
    checks,
):
    profile = directory / "platform-profiles/account.bin"
    original_name = "Account Original"
    email = "account-owner@example.invalid"
    password = "Fixture-password-1!"

    def login():
        nonce = os.urandom(32)
        with post("/platform/login/account", nonce) as reply:
            platform = reply.read()
        assert len(platform) == 512 and platform[8:40] == nonce
        owner = struct.unpack_from("<Q", platform, 56)[0]
        name = platform[72:108].split(b"\0", 1)[0].decode()
        with post(
            "/auth/",
            dict(
                auth_task="84",
                iv_seed=str(seed),
                title_id=str(title),
                extra_data=json.dumps(
                    dict(
                        session_token=platform[112:176].decode(),
                        account_token=platform[177:241].decode(),
                    )
                ),
            ),
        ) as reply:
            auth = json.load(reply)
        with post(
            "/v1.0/tokens/lsg/?client=replaylocal",
            dict(
                ticket=auth["server_ticket"],
                initialVectorSeed=base64.b64encode(str(seed).encode()).decode(),
                titleID=title,
            ),
        ) as reply:
            legacy = json.load(reply)["accessToken"]
        client = Client(
            auth_identity=(
                base64.b64decode(auth["server_ticket"]),
                base64.b64decode(auth["client_ticket"])[97:121],
            )
        )
        return client, legacy, owner, name

    client, legacy, owner, name = login()
    assert name == original_name
    baseline = profile.read_bytes()
    record_path = directory / "platform-accounts" / f"{owner}.json"
    intent_path = directory / "platform-accounts/intents" / f"{owner}.json"
    routes = {
        "updatesecuredfields": (
            "uno",
            "UnoRes",
            0x505554,
            f"/v1.0/users/{owner}/securedfields/?client=replaylocal",
        ),
        "authenticateUser": (
            "uno",
            "UserResource",
            0x504F5354,
            "/v1.0/auth/?client=replaylocal",
        ),
        "linkUser": (
            "umbrella",
            "UserResource",
            0x505554,
            f"/v1.0/users/crossplatform/{owner}/?client=replaylocal",
        ),
        "updateUmbrellaAccount": (
            "umbrella",
            "Umbrella",
            0x504F5354,
            "/v1.0/tokens/uno/?client=replaylocal",
        ),
    }

    def packet(operation, body, *, access=None, uri=None, method=None):
        service, resource, native_method, native_uri = routes[operation]
        return request(
            service,
            resource,
            operation,
            body=body,
            method=native_method if method is None else method,
            uri=native_uri if uri is None else uri,
            headers={
                "Authorization": "Bearer  " + (legacy if access is None else access)
            },
        )

    def call(operation, body, *, connection=None, **options):
        return response(
            (connection or client).task(255, 10, packet(operation, body, **options))
        )

    def authenticate(secret=password, address=email, connection=None):
        return call(
            "authenticateUser",
            dict(email=address, password=secret, grantType="password"),
            connection=connection,
        )

    fields = dict(
        userName="Account Changed",
        email=email,
        password=password,
        accountType="full",
        firstName="Test",
        lastName="Player",
        dateOfBirth="2000-02-29",
        country="US",
        subscriptionOptIn=False,
    )
    assert authenticate()[0] == 403 and not record_path.exists()
    assert call("updatesecuredfields", fields, access=foreign_token)[0] == 403
    assert call("updatesecuredfields", fields, connection=default)[0] == 403
    for change in (
        dict(accountType=1),
        dict(subscriptionOptIn=1),
        dict(dateOfBirth="1900-02-29"),
        dict(dateOfBirth="2020-01-1-"),
        dict(email="bad"),
        dict(password=""),
        dict(userName="x" * 36),
    ):
        assert call("updatesecuredfields", fields | change)[0] == 400
    for operation, values in (
        ("updatesecuredfields", fields),
        (
            "authenticateUser",
            dict(email=email, password=password, grantType="password"),
        ),
    ):
        raw = packet(operation, values)
        suffix = blob(json.dumps(values).encode())
        assert raw.endswith(suffix)
        ambiguous = (
            b'{"accountType":"full","accountType":"full","subscriptionOptIn":false}'
        )
        client.task(255, 10, raw[: -len(suffix)] + blob(ambiguous), error=106)
        client.task(
            255,
            10,
            packet(operation, values, uri=routes[operation][3] + "&client=replaylocal"),
            error=106,
        )
        client.task(255, 10, packet(operation, values, method=0x474554), error=106)
    assert profile.read_bytes() == baseline and not record_path.exists()
    checks.append(
        "Four native account routes bind exact Replay methods/paths/body layouts; foreign sessions and invalid or ambiguous credential fields cannot mutate existing player identities"
    )

    status, upgraded = call("updatesecuredfields", fields)
    assert status == 200 and upgraded["success"] and len(upgraded["IDToken"]) == 64
    status, authenticated = authenticate(address=email.upper())
    assert status == 200 and authenticated["unoID"] == owner
    tokens = authenticated["tokens"]
    assert tokens["IDToken"] == upgraded["IDToken"] and all(
        len(value) == 64 for value in tokens.values()
    )
    document = json.loads(record_path.read_text())
    verifier = document["password"]
    assert verifier["algorithm"] == "pbkdf2-sha256" and verifier["rounds"] == 200000
    assert bytes.fromhex(verifier["digest"]) == hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(verifier["salt"]), 200000
    )
    assert (
        password not in record_path.read_text()
        and profile.read_bytes()[:20] == baseline[:20]
    )
    retry = (
        record_path.read_bytes(),
        record_path.stat().st_mtime_ns,
        profile.stat().st_mtime_ns,
    )
    assert call("updatesecuredfields", fields) == (200, upgraded)
    assert (
        record_path.read_bytes(),
        record_path.stat().st_mtime_ns,
        profile.stat().st_mtime_ns,
    ) == retry
    assert authenticate(secret="wrong")[0] == authenticate(connection=default)[0] == 403
    checks.append(
        "Optional email credentials attach to the stable signed player without provisioning; salted PBKDF2-SHA256 matches an independent implementation and exact upgrade retries preserve durable files and grants"
    )

    def link_body(grants):
        return dict(
            unoIDToken=grants["IDToken"],
            accessToken=grants["accessToken"],
            refreshToken=grants["refreshToken"],
        )

    assert call("linkUser", link_body(tokens)) == (200, {"umbrellaID": owner})
    assert call(
        "updateUmbrellaAccount",
        dict(
            accountID=owner,
            tokens={key: tokens[key] for key in ("accessToken", "refreshToken")},
        ),
    ) == (200, {"umbrellaID": owner})
    saved = json.loads(record_path.read_text())
    assert (
        saved["link"]["userID"] == saved["link"]["umbrellaID"] == owner
        and saved["umbrellaUpgraded"]
    )
    second, second_legacy, second_owner, second_name = login()
    assert second_owner == owner and second_name == fields["userName"]
    status, second_auth = authenticate(connection=second)
    assert status == 200 and second_auth["tokens"] != tokens
    assert call("linkUser", link_body(second_auth["tokens"]))[0] == 403
    assert call("linkUser", link_body(tokens), access=second_legacy)[0] == 403
    assert (
        call(
            "updateUmbrellaAccount",
            dict(
                accountID=owner + 1,
                tokens={key: tokens[key] for key in ("accessToken", "refreshToken")},
            ),
        )[0]
        == 403
    )
    changed_password = "Fixture-password-2!"
    assert (
        call("updatesecuredfields", fields | dict(password=changed_password))[0] == 200
    )
    assert call("linkUser", link_body(tokens))[0] == 403
    assert (
        call(
            "linkUser",
            link_body(second_auth["tokens"]),
            connection=second,
            access=second_legacy,
        )[0]
        == 403
    )
    assert authenticate()[0] == 403 and authenticate(secret=changed_password)[0] == 200
    second.close()
    checks.append(
        "Native UNO ID/access/refresh token triples are distinct per live session; link and Umbrella updates persist owner-bound state and credential changes revoke grants across all sessions without changing account IDs"
    )

    blocker = intent_path.with_suffix(".json.creating")
    blocker.mkdir()
    previous = record_path.read_bytes(), profile.read_bytes()
    try:
        client.task(
            255,
            10,
            packet(
                "updatesecuredfields", fields | dict(password="Fixture-password-3!")
            ),
            error=102,
        )
        assert (record_path.read_bytes(), profile.read_bytes()) == previous
    finally:
        blocker.rmdir()
    checks.append(
        "Failed intent publication changes neither the account document nor the platform profile and cannot issue success or new grants"
    )

    profile_blocker = profile.with_suffix(".bin.creating")
    status, old_grant = authenticate(secret=changed_password)
    assert status == 200
    same_process_fields = fields | dict(
        userName="Account SameProc", password="Fixture-password-3!"
    )
    profile_blocker.mkdir()
    try:
        client.task(
            255, 10, packet("updatesecuredfields", same_process_fields), error=102
        )
        assert intent_path.exists()
        # A pending write for this account cannot block another player's lookup.
        lookup = request(
            "social-service",
            "Users",
            "get_usernames",
            uri=f"/v1/users/?context={title}&client=iw8&titleID={title}&users=uno-{default_owner}",
        )
        status, unrelated = response(default.task(255, 10, lookup))
        assert status == 200 and unrelated["users"][0]["userID"] == default_owner
    finally:
        profile_blocker.rmdir()
    assert (
        call(
            "updatesecuredfields",
            fields | dict(password="unaccepted-change"),
            access=old_grant["tokens"]["accessToken"],
        )[0]
        == 403
    )
    assert (
        not intent_path.exists()
        and authenticate(secret=same_process_fields["password"])[0] == 200
    )
    assert authenticate(secret="unaccepted-change")[0] == 403
    checks.append(
        "Same-process publication recovery revokes the old grant before authorization is checked; a stale token cannot overwrite recovered credentials and another owner's username lookup remains available"
    )
    recovered_fields = fields | dict(
        userName="Account Recovered", password="Fixture-password-4!"
    )

    def prepare_restart():
        before_interruption = profile.read_bytes()
        profile_blocker.mkdir()
        client.task(255, 10, packet("updatesecuredfields", recovered_fields), error=102)
        assert intent_path.exists() and profile.read_bytes() == before_interruption
        assert recovered_fields["password"] not in intent_path.read_text()
        client.close()

    def stopped():
        profile_blocker.rmdir()

    def after_restart():
        nonlocal client, legacy
        client, legacy, restarted_owner, restarted_name = login()
        try:
            assert (
                restarted_owner == owner
                and restarted_name == recovered_fields["userName"]
            )
            assert (
                not intent_path.exists() and profile.read_bytes()[:20] == baseline[:20]
            )
            assert authenticate(secret=changed_password)[0] == 403
            status, renewed = authenticate(secret=recovered_fields["password"])
            assert status == 200 and renewed["tokens"] != tokens
            assert call("linkUser", link_body(tokens))[0] == 403
            assert call("linkUser", link_body(renewed["tokens"]))[0] == 200
            # Preserve the owned fixture's original display name for later checks.
            uri = f"/v1.0/users/{owner}/securedfields/?client=replaylocal"
            rename = request(
                "uno",
                "UserResource",
                "renameUsername",
                method=0x505554,
                uri=uri,
                body={"userName": original_name},
                headers={"Authorization": "Bearer " + renewed["tokens"]["accessToken"]},
            )
            assert response(client.task(255, 10, rename)) == (200, {"success": True})
            assert profile.read_bytes() == baseline
            checks.append(
                "A real account-document/profile split interruption recovers through server initialization; credential hashes, name and stable IDs survive restart, old grants expire and current UNO access tokens authorize native rename"
            )
        finally:
            client.close()

    return prepare_restart, stopped, after_restart
