"""Live encrypted-client tests of public player, party and match snapshots."""

import argparse, base64, copy, hashlib, json, os, runpy, socket, struct, subprocess, sys, time, urllib.request
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--server", type=Path, required=True)
p.add_argument("--source", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
sys.path.insert(0, str(a.source / "tools"))
from native_wire_client import NativeClient, u64
import operator_match_start_fixtures

root = a.output.parent / ("activity-fixture-" + str(time.time_ns()))
data = root / "data"
data.mkdir(parents=True)
(data / "replay-traffic-kdf.bin").write_bytes(
    (a.source / "data/replay-traffic-kdf.bin").read_bytes()
)
for profile, name in [
    ("host", "Dashboard Host"),
    ("peer", "Dashboard Peer"),
    ("solo", "Dashboard Solo"),
]:
    subprocess.run(
        [str(a.server), str(data), "--provision-profile", profile, name],
        check=True,
        stdout=subprocess.DEVNULL,
    )
runpy.run_path(str(a.source / "tools/prepare-playlist-catalog.py"))["prepare"](
    data, ["mp_shipment"], 1
)
offset = 15000
base = "http://127.0.0.1:" + str(8085 + offset)
log = (root / "stdout.log").open("w")
server = subprocess.Popen(
    [str(a.server), str(data), "--port-offset", str(offset)], stdout=log, stderr=log
)
clients = []
checks = []


def stats():
    return json.load(urllib.request.urlopen(base + "/stats.json", timeout=3))


def activity():
    s = stats()
    assert s["online_players"] == len(s["activity"]["players"])
    return s["activity"]


def text(v):
    return b"\x10" + v.encode() + b"\0"


def strings(v):
    out = []
    while v:
        assert v[0] == 16
        end = v.index(0, 1)
        out.append(json.loads(v[1:end]))
        v = v[end + 1 :]
    return out


def call(c, t, v=b""):
    return c.task(145, t, v, structured=False)


def wait(check):
    for _ in range(50):
        snapshot = activity()
        if check(snapshot):
            return snapshot
        time.sleep(0.1)
    raise AssertionError(snapshot)


try:
    for _ in range(100):
        try:
            stats()
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("Fixture did not start")
    assert activity() == dict(available=True, players=[], parties=[], matches=[])
    for profile in ["host", "peer", "solo"]:
        clients.append(NativeClient(root, profile=profile, port_offset=offset))
    host, peer, solo = clients
    snap = activity()
    assert (
        {x["name"] for x in snap["players"]}
        == {"Dashboard Host", "Dashboard Peer", "Dashboard Solo"}
        and not snap["matches"]
        and not snap["parties"]
    )
    checks.append(
        "Only authenticated live display names appear; unassigned players do not become invented parties"
    )
    info = {
        "dedicated_server": {"build_name": "replay-local-fixture"},
        "listen_server": {
            "local_address": base64.b64encode(bytes(84)).decode(),
            "security_id": base64.b64encode(bytes(8)).decode(),
            "security_key": base64.b64encode(bytes(16)).decode(),
        },
        "game_state": {"map_packs": ["MP_ORIGINAL_MAPS"]},
        "hardware": "pc",
    }
    tokens = []
    for client in clients:
        call(client, 2, text(json.dumps(info)))
        tokens.append(struct.unpack_from("<Q", call(client, 3), 1)[0])
    catalog = json.loads((data / "playlists/5800/catalog.json").read_text())
    # The catalog receipt uses the publication's native version.
    version = runpy.run_path(str(a.source / "tools/prepare-playlist-catalog.py"))[
        "prepare"
    ](data, ["mp_shipment"], 1)["version"]
    query = {
        "members": [host.user, peer.user],
        "tokens": tokens[:2],
        "player_id_to_slots": {str(host.user): 0, str(peer.user): 0},
        "lobby_slots": {"min": 1, "max": 4},
        "team_balance": {"num_teams": 2, "lock_squad": False},
        "ruleset_payload": {
            "filter": {
                "playlist_id": 1,
                "netcode_version": 1,
                "playlist_version": version,
            },
            "join_in_progress": False,
            "only_join_existing_lobbies": False,
        },
    }
    search = strings(call(host, 18, text(json.dumps(query))))[0]
    kind, push = host.receive()
    assert kind == 2
    lobby_id = struct.unpack_from("<Q", push, 15)[0]
    docs = strings(push[32:])
    host_doc, backend = docs
    snap = activity()
    assert (
        snap["available"]
        and len(snap["parties"]) == 1
        and len(snap["parties"][0]["members"]) == 2
        and snap["matches"][0]["state"] == "forming"
    )
    assert snap["parties"][0]["leader"] == "Dashboard Host"
    checks.append(
        "One published two-player party retains its leader and lobby relationship"
    )
    assert (
        call(
            host,
            15,
            u64(lobby_id) + u64(backend["update_id"]) + text(json.dumps(host_doc)),
        )
        == b"\x01\x01"
    )
    host.receive()
    peer.receive()
    joined = copy.deepcopy(query)
    joined.update(
        members=[solo.user], tokens=[tokens[2]], player_id_to_slots={str(solo.user): 0}
    )
    joined["ruleset_payload"]["only_join_existing_lobbies"] = True
    strings(call(solo, 18, text(json.dumps(joined))))
    snap = wait(lambda s: len(s["parties"]) == 2)
    assert (
        len(snap["matches"]) == 1
        and len(snap["matches"][0]["members"]) == 3
        and len(snap["matches"][0]["teams"]) == 2
    )
    assert sorted(len(p["members"]) for p in snap["parties"]) == [1, 2]
    assert len({p["party"] for p in snap["matches"][0]["members"]}) == 2
    checks.append(
        "Two distinct matchmaking parties share one lobby and preserve team/party roster structure"
    )
    lobby_path = data / "matchmaking/5800/lobbies" / (str(lobby_id) + ".json")
    waiting = json.loads(lobby_path.read_bytes())
    waiting_host = copy.deepcopy(waiting["host_doc"])
    waiting_host["game_state"]["state"] = ""
    assert call(host, 15, u64(lobby_id) + u64(waiting["update_id"]) + text(json.dumps(waiting_host))) == b"\x01\x01"
    assert activity()["matches"][0]["state"] == "intermission"
    checks.append("Replay's empty native waiting phase exposes the same waiting-lobby start control")
    operator_fixture = operator_match_start_fixtures.before_match(
        base, data, clients, activity, lobby_path, strings, checks)
    state = json.loads(lobby_path.read_text())
    host_doc = copy.deepcopy(state["host_doc"])
    host_doc["game_state"]["state"] = "in_game"
    assert (
        call(
            host,
            15,
            u64(lobby_id) + u64(state["update_id"]) + text(json.dumps(host_doc)),
        )
        == b"\x01\x01"
    )
    snap = wait(lambda s: s["matches"][0]["state"] == "in_game")
    assert (
        snap["matches"][0]["maps"] == ["mp_shipment"]
        and snap["matches"][0]["host"] == "Dashboard Host"
    )
    checks.append("Actual host-update wire task changes the published match to in-game")
    operator_match_start_fixtures.after_match(
        base, clients, activity, lobby_path, operator_fixture, call, u64, text, checks)
    subprocess.run(
        [
            sys.executable,
            str(a.source / "tools/test-public-dashboard.py"),
            "--url",
            base,
            "--output",
            str(a.output.parent / "dashboard-contract.json"),
        ] + (["--windows-fixture"] if os.name == "nt" else []),
        check=True,
    )
    before = {
        str(path): path.read_bytes() for path in (data / "matchmaking").rglob("*.json")
    }
    for _ in range(3):
        activity()
    assert before == {
        str(path): path.read_bytes() for path in (data / "matchmaking").rglob("*.json")
    }
    checks.append("Public snapshots do not mutate matchmaking records")

    def mutate(check, change, path=lobby_path):
        original = path.read_bytes()
        value = json.loads(original)
        change(value)
        path.write_text(json.dumps(value))
        try:
            assert check(activity())
        finally:
            path.write_bytes(original)

    mutate(
        lambda s: not s["matches"] and not s["parties"], lambda s: s.update(expires=0)
    )
    mutate(
        lambda s: not s["matches"] and not s["parties"],
        lambda s: s.update(disbanded=True),
    )
    index_path = data / "matchmaking/5800/current-lobbies.json"
    mutate(
        lambda s: not s["matches"],
        lambda s: s["lobbies"].update({str(host.user): lobby_id + 1}),
        index_path,
    )
    checks.append(
        "Expired, disbanded and superseded host assignments cannot appear as current matches"
    )
    original = lobby_path.read_bytes()
    lobby_path.write_text("{broken")
    try:
        snap = activity()
        assert (
            not snap["available"]
            and not snap["matches"]
            and not snap["parties"]
            and len(snap["players"]) == 3
        )
    finally:
        lobby_path.write_bytes(original)
    checks.append(
        "Unreadable grouping is marked unavailable without publishing partial rosters"
    )
    solo.close()
    snap = wait(lambda s: len(s["players"]) == 2)
    assert len(snap["parties"]) == 1 and len(snap["matches"][0]["members"]) == 2
    checks.append(
        "Disconnected members retire immediately from player, party and match lists"
    )
    call(host, 10, u64(lobby_id))
    snap = wait(lambda s: not s["matches"])
    assert not snap["parties"] and len(snap["players"]) == 2
    checks.append(
        "Native disband task removes the entire published match/party structure"
    )
    host.close()
    peer.close()
    wait(lambda s: not s["players"])
    proof = dict(
        passed=True,
        checks=checks,
        server_sha256=hashlib.sha256(a.server.read_bytes()).hexdigest(),
        fixture_directory=str(root),
        native_game_verified=False,
    )
    a.output.write_text(json.dumps(proof, indent=2) + "\n")
    print("PASS:", len(checks), "live activity checks", flush=True)
finally:
    for client in clients:
        client.close()
    server.terminate()
    server.wait(timeout=10)
    log.close()
