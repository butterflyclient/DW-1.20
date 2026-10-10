"""Exercise real interrupted matchmaking publications using isolated fixture files."""

import copy
import json
import struct
import time


def strings(raw):
    values = []
    while raw:
        assert raw[0] == 16
        end = raw.index(0, 1)
        values.append(raw[1:end].decode())
        raw = raw[end + 1 :]
    return values


def load(path):
    return json.loads(path.read_bytes())


def exercise(client, directory, title, user, query, helpers, checks):
    u32, u64, text, boolean = helpers
    root = directory / "matchmaking" / str(title)
    journal_path = root / "transaction.json"
    index_path = root / "current-lobbies.json"
    block = root / "current-lobbies.json.pending"
    assert root.resolve().is_relative_to(directory.resolve())
    before_index = index_path.read_bytes()
    token = struct.unpack_from("<Q", client.task(145, 3), 1)[0]
    create = {**query, "members": [user], "tokens": [token]}

    # This is an actual CreateFile failure, without a server fault-injection
    # switch. The first two replacements can finish; the index cannot publish.
    block.mkdir()
    client.task(145, 18, text(json.dumps(create)), error=102)
    pending_bytes = journal_path.read_bytes()
    pending = json.loads(pending_bytes)
    assert pending["phase"] == "prepared" and len(pending["writes"]) == 3
    snapshots = {entry["path"]: entry["document"] for entry in pending["writes"]}
    lobby_name = next(name for name in snapshots if name.startswith("lobbies/"))
    search_name = next(name for name in snapshots if name.startswith("searches/"))
    lobby = snapshots[lobby_name]["id"]
    assert load(root / lobby_name) == snapshots[lobby_name]
    assert load(root / search_name) == snapshots[search_name]
    assert index_path.read_bytes() == before_index
    client.task(145, 13, u64(lobby), error=102)
    client.task(145, 3, error=102)
    assert journal_path.read_bytes() == pending_bytes
    checks.append(
        "a real blocked index publication leaves a prepared complete transaction; matchmaking reads and token operations reject partial state without a successful assignment"
    )

    # Change the first otherwise-valid snapshot, then poison a later entry.
    # If recovery validates and writes one entry at a time, the first file
    # changes here. Every bad journal must reject before any file replacement.
    original_lobby = (root / lobby_name).read_bytes()
    invalid = []
    for mode in (
        "outside-path",
        "duplicate-path",
        "foreign-title",
        "wrong-id",
        "bad-owner",
        "bad-capacity",
        "overflow-player",
        "wrong-phase",
        "too-many-entries",
        "duplicate-json-key",
        "missing-member-session",
        "missing-owner-session",
        "foreign-owner-session",
        "extra-member-session",
        "bad-member-session",
        "duplicate-search-member",
    ):
        changed = copy.deepcopy(pending)
        changed["writes"][0]["document"]["host_doc"]["game_state"]["state"] = "fixture-invalid"
        if mode == "outside-path":
            changed["writes"][-1]["path"] = "../outside.json"
        elif mode == "duplicate-path":
            changed["writes"].append(copy.deepcopy(changed["writes"][0]))
        elif mode == "foreign-title":
            changed["writes"][-1]["document"]["title"] = title + 1
        elif mode == "wrong-id":
            changed["writes"][1]["document"]["id"] += 1
        elif mode == "bad-owner":
            changed["writes"][0]["document"]["owner"] += 1
        elif mode == "bad-capacity":
            changed["writes"][0]["document"]["maximum_members"] = 0
        elif mode == "overflow-player":
            changed["writes"][-1]["document"]["lobbies"][str(2**64)] = lobby
        elif mode == "wrong-phase":
            changed["phase"] = "applied"
        elif mode == "too-many-entries":
            changed["writes"] *= 68
        elif mode in ("missing-member-session", "missing-owner-session", "foreign-owner-session",
                      "extra-member-session", "bad-member-session", "duplicate-search-member"):
            search = next(entry["document"] for entry in changed["writes"]
                          if entry["path"] == search_name)
            if mode == "missing-member-session":
                del search["member_sessions"][str(user)]
            elif mode == "missing-owner-session":
                del search["owner_session"]
            elif mode == "foreign-owner-session":
                search["owner_session"] = "A" * 44
            elif mode == "extra-member-session":
                search["member_sessions"][str(user + 1)] = "A" * 44
            elif mode == "bad-member-session":
                search["member_sessions"][str(user)] = 123
            elif mode == "duplicate-search-member":
                search["query"]["members"] *= 2
                search["query"]["tokens"] *= 2
                search["member_sessions"][str(user + 1)] = "A" * 44
        encoded = json.dumps(changed)
        if mode == "duplicate-json-key":
            encoded = '{"schema":1,' + encoded[1:]
        invalid.append(encoded)
    for encoded in invalid:
        journal_path.write_text(encoded)
        client.task(145, 13, u64(lobby), error=102)
        assert (root / lobby_name).read_bytes() == original_lobby
        assert index_path.read_bytes() == before_index
        assert not (root.parent / "outside.json").exists()
    journal_path.write_bytes(pending_bytes)
    checks.append(
        "transaction recovery preflights every snapshot and rejects escaping/duplicate paths, foreign titles, invalid identities/capacity, overflowing index IDs, duplicate JSON keys, malformed completion markers and incomplete/foreign/duplicate member-session bindings before mutation"
    )

    block.rmdir()
    result = list(map(json.loads, strings(client.task(145, 13, u64(lobby)))))
    # This fixture forms an ordinary MP lobby. Its wire document adds the
    # native No Fill defaults; those derived fields do not rewrite the journal.
    assert not snapshots[lobby_name]["match_selection"].get("squad_size", 0)
    expected_backend = copy.deepcopy(snapshots[lobby_name]["backend_doc"])
    expected_backend["ruleset_payload"]["dvar_overrides"].update(
        replay_dw_squadSize=0, replay_dw_reservedSquads="0" * 50
    )
    assert result == [snapshots[lobby_name]["host_doc"], expected_backend]
    for name, snapshot in snapshots.items():
        assert load(root / name) == snapshot
    completed = load(journal_path)
    assert completed == {**pending, "phase": "applied", "writes": []}
    # No success reply was sent for the failed request, so no native callback
    # may be invented during a later read/recovery.
    time.sleep(0.35)
    assert client.task(12, 6).startswith(b"\x08")
    checks.append(
        "live recovery rolls forward the same lobby/search/index snapshots once, retains a flushed completion marker, and does not replay an unacknowledged assignment callback"
    )

    # A newer assignment must survive disbanding an older lobby for this user.
    raw = client.task(145, 18, text(json.dumps(create)))
    mm_id = json.loads(strings(raw)[0])["mm_id"]
    kind, packet = client.receive()
    assert kind == 2 and packet.startswith(u32(2005) + u64(mm_id))
    newer_lobby = struct.unpack_from("<Q", packet, 15)[0]
    assert client.task(145, 10, u64(lobby)) == []
    assert client.receive() == (2, u32(2002) + u64(lobby) + u64(0))
    assert load(root / search_name)["active"] is False
    assert load(index_path)["lobbies"][str(user)] == newer_lobby
    checks.append(
        "disband journals the lobby/search/index together, deduplicates shared searches and preserves a member's newer current-lobby assignment"
    )
    # This spare lobby is deliberately disbanded before other domain checks.
    assert client.task(145, 10, u64(newer_lobby)) == []
    assert client.receive() == (2, u32(2002) + u64(newer_lobby) + u64(0))
    return dict(root=root, user=user, query=query)


def prepare_restart(client, fixture, helpers, checks):
    u32, u64, text, boolean = helpers
    root = fixture["root"]
    token = struct.unpack_from("<Q", client.task(145, 3), 1)[0]
    create = {**fixture["query"], "members": [fixture["user"]], "tokens": [token]}
    raw = client.task(145, 18, text(json.dumps(create)))
    mm_id = json.loads(strings(raw)[0])["mm_id"]
    kind, packet = client.receive()
    assert kind == 2 and packet.startswith(u32(2005) + u64(mm_id))
    lobby = struct.unpack_from("<Q", packet, 15)[0]
    fixture["lobby"], fixture["search"] = lobby, mm_id
    block = root / "searches" / f'{fixture["search"]}.json.pending'
    block.mkdir()
    client.task(145, 10, u64(lobby), error=102)
    fixture["block"] = block
    fixture["journal"] = load(root / "transaction.json")
    assert fixture["journal"]["phase"] == "prepared"
    assert load(root / "lobbies" / f"{lobby}.json")["disbanded"] is True
    assert load(root / "searches" / f'{fixture["search"]}.json')["active"] is True
    assert load(root / "current-lobbies.json")["lobbies"][str(fixture["user"])] == lobby
    time.sleep(0.35)
    assert client.task(12, 6).startswith(b"\x08")
    checks.append(
        "a real blocked search publication interrupts disband after the lobby write without sending event 2002 or acknowledging a complete transaction"
    )


def before_restart(fixture):
    assert load(fixture["root"] / "transaction.json") == fixture["journal"]
    fixture["block"].rmdir()


def check_restart(client, fixture, helpers, checks):
    u32, u64, text, boolean = helpers
    root, pending = fixture["root"], fixture["journal"]
    # Startup completes recovery before any listener becomes ready. A rejected
    # native read is the expected state for the now fully disbanded lobby.
    assert load(root / "transaction.json") == {
        **pending,
        "phase": "applied",
        "writes": [],
    }
    for entry in pending["writes"]:
        assert load(root / entry["path"]) == entry["document"]
    client.task(145, 13, u64(fixture["lobby"]), error=108)
    assert client.task(12, 6).startswith(b"\x08")
    checks.append(
        "server startup recovers an interrupted disband before accepting connections; exact snapshots/revision survive restart without replaying old connection callbacks"
    )
