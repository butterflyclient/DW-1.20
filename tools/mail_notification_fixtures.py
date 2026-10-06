"""Native bare new-mail events, live recipients and idle/offline mailbox lifecycle."""

import base64
import json
import select
import struct
import time


def exercise(
    sender, peer, peer_auth, Client, directory, title, user, peer_user, helpers, checks
):
    u32, u64, text, boolean, blob = helpers
    name = "mail_notify"
    path = directory / "mail" / str(title) / name / "messages.json"
    marker = (2, u32(18))

    def send(
        recipient,
        body=b"native-mail-fixture",
        duration=0,
        bounce=False,
        error=0,
        context_name=name,
    ):
        return sender.task(
            29,
            9,
            text(context_name)
            + blob(body)
            + b"\x06\x07\x00"
            + u32(1)
            + u64(recipient)
            + text("uno")
            + u32(duration)
            + boolean(bounce),
            error=error,
        )

    def headers(client):
        return client.task(29, 10, text(name) + u32(0) + u32(64) + boolean(False))

    def ids(values):
        return (
            bytes([110, 8])
            + struct.pack("<II", len(values) * 8, len(values))
            + b"".join(struct.pack("<Q", v) for v in values)
        )

    def remove(client, values):
        return client.task(29, 5, text(name) + ids(values))

    def no_notification(client, seconds=1.3):
        assert not client.mail_notifications
        assert not select.select([client.s], [], [], seconds)[0]

    def reconnect():
        return Client(
            auth_identity=(
                base64.b64decode(peer_auth["server_ticket"]),
                base64.b64decode(peer_auth["client_ticket"])[97:121],
            )
        )

    # Drain already received wakeups from the earlier DTO fixture without changing
    # its mailbox; that fixture verifies identical durable headers after restart.
    sender.task(12, 6)
    sender.mail_notifications.clear()
    peer.mail_notifications.clear()

    send(peer_user)
    assert peer.receive_mail() == marker
    assert headers(peer)[0] == 10
    no_notification(peer)
    assert remove(peer, [1]) == []
    no_notification(sender, 0.1)
    checks.append(
        "native mail notifications deliver the exact bare event 18 to the recipient after persistence and suppress duplicate idle scans without notifying the sender"
    )

    # Delay is intentional: normal consumers can retrieve/delete a message before
    # its queued event. Queue validation must consult the current durable row.
    send(peer_user, b"already-read")
    assert peer.task(29, 4, text(name) + boolean(False) + ids([2])) == u64(2) + blob(
        b"already-read"
    )
    no_notification(peer)
    send(peer_user, b"already-deleted")
    remove(peer, [3])
    no_notification(peer)
    checks.append(
        "native mail notifications revalidate queued rows and suppress messages already read or deleted before delivery"
    )

    # Retry/disk failure does not constitute accepted delivery or alter watermarks.
    original = path.read_bytes()
    blocked = path.with_name("messages.json.pending")
    blocked.mkdir()
    try:
        send(peer_user, b"not-published", error=102)
        assert path.read_bytes() == original
        no_notification(peer)
    finally:
        blocked.rmdir()
    send(peer_user, b"durable-retry")
    assert peer.receive_mail() == marker
    remove(peer, [4])
    checks.append(
        "native mail notifications follow successful durable publication only; a real failed pending-file write emits nothing and a later accepted retry notifies"
    )

    peer.close()
    send(peer_user, b"offline-mail")
    reopened = reconnect()
    try:
        assert reopened.receive_mail() == marker
        assert headers(reopened)[0] == 10
        no_notification(reopened)
        # A second native socket gets its own catch-up, while the existing one
        # retains its notification watermark.
        duplicate = reconnect()
        try:
            assert duplicate.receive_mail() == marker
            no_notification(reopened)
        finally:
            duplicate.close()
        remove(reopened, [5])
        checks.append(
            "native mail notifications catch up unread offline mail on reconnect and on each independent connection without repeatedly notifying an established lease"
        )

        send(peer_user, b"expiration-return", duration=30, bounce=True)
        assert reopened.receive_mail() == marker
        # No subsequent mail task is issued. The existing idle publication worker
        # must expire and return the message, persist it, and notify the sender.
        stored = json.loads(path.read_bytes())
        stored["messages"][-1]["created"] = int(time.time()) - 31
        path.write_text(json.dumps(stored))
        assert sender.receive_mail() == marker
        returned = json.loads(path.read_bytes())
        last = returned["messages"][-1]
        assert (
            last["id"] == 7
            and last["recipient"] == user
            and last["sender"] == peer_user
        )
        assert last["undelivered"] is True and last["duration"] == 0
        assert last["name"] == "Fixture Peer"
        assert last["return_on_expiration"] is False
        assert not any(row["id"] == 6 for row in returned["messages"])
        assert sender.task(29, 4, text(name) + boolean(True) + ids([7])) == u64(
            7
        ) + blob(b"expiration-return")
        no_notification(sender)
        checks.append(
            "native mail notifications expire and return timed mail during idle connections, persist one non-recursive return and notify its sender without requiring a mailbox task"
        )

        original = path.read_bytes()
        path.write_text('{"schema":1,"messages":')
        try:
            no_notification(reopened)
            headers_result = reopened.task(
                29, 10, text(name) + u32(0) + u32(64) + boolean(False), error=102
            )
            assert headers_result == []
            send(peer_user, b"healthy-context", context_name="mail_other")
            assert reopened.receive_mail() == marker
            assert reopened.task(29, 5, text("mail_other") + ids([1])) == []
        finally:
            path.write_bytes(original)
        send(peer_user, b"after-repair")
        assert reopened.receive_mail() == marker
        remove(reopened, [8])
        checks.append(
            "native mail notifications isolate malformed contexts without blocking another valid mailbox, report storage failure and resume normal delivery after repair"
        )
        contexts = path.parent.parent
        temporary = []
        try:
            for number in range(128 - len(list(contexts.iterdir()))):
                folder = contexts / f"capacity_{number}"
                folder.mkdir()
                temporary.append(folder)
            send(peer_user, b"over-capacity", error=106, context_name="mail_extra")
            assert not (contexts / "mail_extra").exists()
            send(peer_user, b"existing-context")
            assert reopened.receive_mail() == marker
            remove(reopened, [9])
            checks.append(
                "native mail notifications enforce context capacity before accepting new mailbox writes while existing contexts continue to notify"
            )
        finally:
            for folder in temporary:
                folder.rmdir()
        return reopened
    except BaseException:
        reopened.close()
        raise
