"""Exact Replay rename DTO, live-token ownership and durable identity publication."""

import base64
import json
import os
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def exercise(
    default,
    foreign_token,
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
    profile = directory / "platform-profiles/rename.bin"
    original, changed = "Rename Original", "Rename Changed"

    def login():
        nonce = os.urandom(32)
        with post("/platform/login/rename", nonce) as reply:
            platform = reply.read()
        assert len(platform) == 512 and platform[8:40] == nonce
        public = (directory / "platform-public.blob").read_bytes()
        magic, bits, exponent_size, modulus_size, _, _ = struct.unpack_from(
            "<6I", public
        )
        assert magic == 0x31415352 and bits == 2048
        exponent = int.from_bytes(public[24 : 24 + exponent_size], "big")
        modulus = int.from_bytes(
            public[24 + exponent_size : 24 + exponent_size + modulus_size], "big"
        )
        rsa.RSAPublicNumbers(exponent, modulus).public_key().verify(
            platform[256:],
            platform[:256],
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        owner = struct.unpack_from("<Q", platform, 56)[0]
        name = platform[72:108].split(b"\0", 1)[0].decode()
        credentials = {
            "session_token": platform[112:176].decode(),
            "account_token": platform[177:241].decode(),
        }
        with post(
            "/auth/",
            {
                "auth_task": "84",
                "iv_seed": str(seed),
                "title_id": str(title),
                "extra_data": json.dumps(credentials),
            },
        ) as reply:
            auth = json.load(reply)
        with post(
            "/v1.0/tokens/lsg/?client=replaylocal",
            {
                "ticket": auth["server_ticket"],
                "initialVectorSeed": base64.b64encode(str(seed).encode()).decode(),
                "titleID": title,
            },
        ) as reply:
            access = json.load(reply)
        assert access["umbrellaID"] == owner
        connection = Client(
            auth_identity=(
                base64.b64decode(auth["server_ticket"]),
                base64.b64decode(auth["client_ticket"])[97:121],
            )
        )
        return connection, access["accessToken"], owner, name

    client, token, owner, name = login()
    assert name == original
    uri = f"/v1.0/users/{owner}/securedfields/?client=replaylocal"

    def packet(name, *, route=uri, access=token, method=0x505554, body=None):
        return request(
            "uno",
            "UserResource",
            "renameUsername",
            method=method,
            body={"userName": name} if body is None else body,
            uri=route,
            headers={"Authorization": "Bearer  " + access},
        )

    def call(name, **options):
        return response(client.task(255, 10, packet(name, **options)))

    def lookup():
        status, data = response(
            client.task(
                255,
                10,
                request(
                    "social-service",
                    "Users",
                    "get_usernames",
                    uri=f"/v1/users/?context={title}&client=iw8&titleID={title}&users=uno-{owner}",
                ),
            )
        )
        assert status == 200 and data["users"][0]["userID"] == owner
        return data["users"][0]["username"]

    baseline = profile.read_bytes(), profile.stat().st_mtime_ns
    assert call(original) == (200, {"success": True})
    assert (profile.read_bytes(), profile.stat().st_mtime_ns) == baseline
    for decorated in ("^3" + original, "^'" + original, "^>" + original,
                      "[{" + original + "}]", "^^" + original):
        assert call(decorated) == (200, {"success": True})
        assert (profile.read_bytes(), profile.stat().st_mtime_ns) == baseline
    assert call("^3Fixture Peer")[0] == 409
    assert call(changed, access=foreign_token)[0] == 403
    assert response(default.task(255, 10, packet(changed)))[0] == 403
    assert call(changed, route=uri.replace(str(owner), str(owner + 1)))[0] == 403
    for invalid in (
        "",
        " leading",
        "trailing ",
        "a#b",
        "a%b",
        "a\0b",
        "a\nb",
        "é",
        "x" * 36,
        "^3",
        "[{}]",
        "a ^3",
    ):
        assert call(invalid)[0] == 400
    assert call("Fixture Peer")[0] == 409
    for invalid in (
        uri + "&client=replaylocal",
        uri.replace("replaylocal", "iw8"),
        uri.replace(str(owner), "0" + str(owner)),
        uri.replace("/securedfields/", "/../"),
        uri.replace("/v1.0/", "/v2/"),
    ):
        client.task(255, 10, packet(changed, route=invalid), error=106)
    client.task(255, 10, packet(changed, method=0x504F5354), error=106)
    for invalid in ({"userName": 1}, {"userName": changed, "extra": True}, {}):
        client.task(255, 10, packet(changed, body=invalid), error=106)
    raw = packet(changed)
    suffix = blob(json.dumps({"userName": changed}).encode())
    assert raw.endswith(suffix)
    for invalid in (b'{"userName":"a","userName":"b"}', b'{"userName":"a"}{}'):
        client.task(255, 10, raw[: -len(suffix)] + blob(invalid), error=106)
    assert (profile.read_bytes(), profile.stat().st_mtime_ns) == baseline
    checks.append(
        "UNO rename binds the exact target PUT/body/path, owner and live issued access token; foreign-session tokens, name collisions, malformed names and ambiguous request layouts cannot mutate an identity"
    )

    damaged = bytearray(baseline[0])
    damaged[8] ^= 1  # A different persisted owner must never be overwritten.
    profile.write_bytes(damaged)
    try:
        client.task(255, 10, packet(changed), error=102)
        assert profile.read_bytes() == damaged and lookup() == original + "#0"
    finally:
        profile.write_bytes(baseline[0])

    blocker = profile.with_suffix(".bin.creating")
    blocker.mkdir()
    try:
        client.task(255, 10, packet(changed), error=102)
        assert profile.read_bytes() == baseline[0] and lookup() == original + "#0"
    finally:
        blocker.rmdir()
    assert call("^3" + changed) == (200, {"success": True})
    assert lookup() == changed + "#0"
    saved = profile.read_bytes(), profile.stat().st_mtime_ns
    assert saved[0][:20] == baseline[0][:20] and len(saved[0]) == len(baseline[0]) == 56
    assert call(changed) == (200, {"success": True})
    assert (profile.read_bytes(), profile.stat().st_mtime_ns) == saved
    client.close()
    checks.append(
        "A failed atomic rename leaves both disk and canonical lookup unchanged; successful rename updates the same stable player identity and exact retries do not rewrite its file"
    )

    def after_restart():
        nonlocal client
        client, renewed, renewed_owner, renewed_name = login()
        try:
            assert (
                renewed_owner == owner
                and renewed_name == changed
                and lookup() == changed + "#0"
            )
            assert call(original)[0] == 403  # Previous process's token is expired.
            assert call(original, access=renewed) == (200, {"success": True})
            assert profile.read_bytes() == baseline[0] and lookup() == original + "#0"
            checks.append(
                "Renamed identity survives a backend process restart and is returned by the signed login and native username DTO; old tokens are rejected and the owned fixture name is restored"
            )
        finally:
            client.close()

    return after_restart
