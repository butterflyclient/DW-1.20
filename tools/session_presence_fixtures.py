"""Revoked lobby leases, native presence pushes and independent live sessions.

Uses only the isolated fixture's existing peer account. No game identity or
production account is rotated, and no timer or authentication bypass is added.
"""

import base64
import json
import os
import time


def expect_disconnect(socket):
    """An owned socket must close promptly by FIN or Windows' unread-data RST."""
    begin = time.monotonic()
    socket.settimeout(3)
    try:
        assert socket.recv(1) == b""
    except ConnectionResetError:
        # Closing a revoked connection with unread bytes can produce WSAECONNRESET.
        # That is a disconnected socket, not a successful native record/echo.
        pass
    assert time.monotonic() - begin < 3


def exercise(
    observer,
    peer,
    peer_auth,
    peer_credentials,
    request,
    post,
    Client,
    native_rest,
    rest_response,
    user,
    peer_user,
    u32,
    text,
    checks,
):
    users = [{"userID": peer_user, "accountType": "uno"}]
    subscription = f"/v2/users/uno-{user}/subscriptions/presence/?context=iw8"
    prefix = (
        u32(199)
        + text("presence")
        + text("UserPresenceUpdatedPushMessage")
        + text("application/json")
    )
    sockets = [peer]

    def authenticate(credentials):
        with post(
            "/auth/", dict(request, extra_data=json.dumps(credentials))
        ) as response:
            return json.load(response)

    def connect(auth):
        connection = Client(
            auth_identity=(
                base64.b64decode(auth["server_ticket"]),
                base64.b64decode(auth["client_ticket"])[97:121],
            )
        )
        sockets.append(connection)
        return connection

    def presence():
        status, body = rest_response(
            observer.task(
                255,
                10,
                native_rest(
                    "social-service",
                    "UsersPresence",
                    "get_users_presence",
                    uri=f"/v1/users/presence/?context=iw8&users=uno-{peer_user}",
                ),
            )
        )
        assert status == 200 and body["users"][0]["userID"] == peer_user
        return body["users"][0]["presence"]

    def publish(connection, online=True, platform="bnet", lease=1):
        connection.task(
            255,
            10,
            native_rest(
                "presence",
                "UserPresence",
                "set_user_presence",
                0x505554,
                {"online": online, "platform": platform, "data": {"lease": lease}},
                uri=f"/v2/users/uno-{peer_user}/presence/?context=iw8",
            ),
        )

    def notification(online, platform="bnet", lease=1):
        kind, packet = observer.receive()
        assert kind == 2 and packet.startswith(prefix)
        changed = json.loads(packet[len(prefix) + 6 :])
        assert (
            changed["userID"] == peer_user
            and changed["context"] == "iw8"
            and changed["presence"]["online"] is online
            and changed["presence"]["platform"] == platform
            and changed["presence"]["data"] == {"lease": lease}
        )

    def retired(connection):
        # No task is sent to prod the idle reader. A partial header or a ping
        # also cannot keep a superseded issuer lease alive.
        expect_disconnect(connection.s)
        connection.close()

    def no_notification():
        # Client.task rejects unsolicited records before its own task result.
        assert observer.task(12, 6).startswith(b"\x08")

    try:
        publish(peer)
        status, body = rest_response(
            observer.task(
                255,
                10,
                native_rest(
                    "presence",
                    "UsersPresence",
                    "subscribe_to_users",
                    0x504F5354,
                    {"users": users},
                    uri=subscription,
                ),
            )
        )
        assert status == 200 and body["users"][0]["presence"]["online"] is True
        publish(peer)
        no_notification()
        publish(peer, lease=2)
        publish(peer, lease=2)
        notification(True, lease=2)
        no_notification()
        publish(peer, platform="other", lease=2)
        notification(True, platform="other", lease=2)
        publish(peer, online=False, platform="other", lease=2)
        notification(False, platform="other", lease=2)
        publish(peer, online=False, platform="other", lease=2)
        no_notification()
        publish(peer)
        notification(True)
        no_notification()
        checks.append(
            "identical presence repeats emit no native push or stale a queued transition; data, platform and online changes each notify once"
        )
        duplicate = connect(peer_auth)
        duplicate.close()
        assert presence()["online"] is True
        no_notification()
        checks.append(
            "closing one of two same-key lobby connections preserves peer presence and emits no offline push"
        )

        idle = connect(peer_auth)
        peer.s.sendall(b"\x00\x00")  # Leave an incomplete keepalive header.
        rotated = authenticate(peer_credentials)
        assert presence()["online"] is False
        retired(peer)
        retired(idle)
        notification(False)
        no_notification()
        checks.append(
            "revoked idle and partial-header lobby leases retire without a task, report offline immediately and emit exactly one native presence push"
        )

        fresh = connect(rotated)
        publish(fresh)
        notification(True)
        assert presence()["online"] is True

        # A second signed platform session for this same existing account stays
        # valid when the first credential pair is reauthenticated. The account
        # remains online while at least one of its independent leases is live.
        with post("/platform/login/peer", os.urandom(32)) as response:
            platform_reply = response.read()
        assert len(platform_reply) == 512
        alternate_credentials = {
            "session_token": platform_reply[112:176].decode(),
            "account_token": platform_reply[177:241].decode(),
        }
        alternate = connect(authenticate(alternate_credentials))
        latest = authenticate(peer_credentials)
        assert presence()["online"] is True
        fresh.s.sendall(bytes(4))
        retired(fresh)
        assert alternate.task(12, 6).startswith(b"\x08")
        assert presence()["online"] is True
        no_notification()
        checks.append(
            "a revoked keepalive cannot be echoed; another independently signed session keeps the same account online without a false offline push"
        )

        replacement = connect(latest)
        alternate.close()
        assert presence()["online"] is True
        no_notification()
        replacement.close()
        notification(False)
        assert presence()["online"] is False
        no_notification()
        checks.append(
            "replacement connection survives old-session retirement and only its last valid disconnect publishes offline"
        )
        observer.task(
            255,
            10,
            native_rest(
                "presence",
                "UsersPresence",
                "unsubscribe_from_users",
                0x44454C45,
                uri=subscription + "&users=uno-" + str(peer_user),
            ),
        )
    finally:
        for connection in sockets:
            connection.close()
