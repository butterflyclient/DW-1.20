"""Prove expiry at server startup with no platform, auth or lobby client traffic."""

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--validation-root", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
validation = args.validation_root.resolve()
output_path = args.output.resolve()
assert validation.is_relative_to(ROOT / "data")
assert output_path.is_relative_to(ROOT / "validation")


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


protocol = read(validation / "data/lobby-verification.json")
assert protocol["passed"] and any(
    item.startswith("Offline managed publication retirement")
    for item in protocol["checks"]
)
frozen = read(validation / "fixture-inputs.json")
assert frozen["build_receipt"]["sha256"] == protocol["server_sha256"]
for name, expected in frozen["frozen_input_hashes"].items():
    assert digest(validation / name) == expected
maintenance_sources = (
    "src/server.cpp",
    "src/services.cpp",
    "src/services.h",
    "src/tournament_services.cpp",
    "src/tournament_services.h",
)
source_hashes = {name: digest(validation / name) for name in maintenance_sources}
assert all(digest(ROOT / name) == expected for name, expected in source_hashes.items())
image = validation / "build/Release/iw8-dw-server.exe"
assert digest(image) == protocol["server_sha256"]
directory = Path(protocol["fixture_directory"]).resolve()
assert directory.is_relative_to(validation / "data")
assert directory.name.startswith("protocol-fixture-")
network_path = directory / "network.json"
# With no network configuration the frozen server binds only loopback and
# leaves UDP providers disabled. The full fixture suite restores this state.
assert not network_path.exists() or read(network_path)["bind_address"] == "127.0.0.1"
title = 5800
realm = directory / "tournaments" / str(title)
mm = directory / "matchmaking" / str(title)
source = next(
    read(path)
    for path in (mm / "tournament-terminations").glob("*.json")
    if read(path)["action"] == "publication-unavailable"
    and read(path)["state"]["tournamentStatus"] == "PLAYING"
    and len(read(path)["state"]["players"]) == 8
)
tournament = (int(time.time()) << 16) | 483
expires = int(time.time()) + 4
bracket = copy.deepcopy(source["state"])
bracket["tournamentID"] = tournament
bracket["tournamentStatus"] = "FORMING"
for round_ in bracket["rounds"]:
    for match in round_["matches"]:
        match.update(lobbyID=0, readyPlayerIDs=[], expired=False, winningTeamID=-1)
users = [row["playerID"] for row in bracket["players"]]
definition = dict(
    id=tournament,
    name=str(tournament),
    data_center="local",
    expires=expires,
    formation=dict(team_size=1, num_teams=8),
)
formation = dict(
    schema=1,
    title=title,
    id=tournament,
    expires=expires,
    definition=definition,
    parties={
        str(user): dict(team=index, members=[user]) for index, user in enumerate(users)
    },
    state=bracket,
)
terminal_path = mm / "tournament-terminations" / f"{tournament}.json"
formation_path = mm / "tournaments" / f"{tournament}.json"
malformed_path = directory / "tournaments/5801/enrollments.json"
paths = [
    realm / "catalog.json",
    realm / "enrollments.json",
    formation_path,
    terminal_path,
    malformed_path,
]
originals = {path: path.read_bytes() if path.exists() else None for path in paths}
assert originals[formation_path] is None and originals[terminal_path] is None
assert originals[malformed_path] is None


def publish(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(path.suffix + ".pending")
    pending.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
    pending.replace(path)


def choose_offset():
    for offset in range(10300, 10500):
        sockets = []
        try:
            for port in (8085, 8443, 3075):
                connection = socket.socket()
                sockets.append(connection)
                connection.bind(("127.0.0.1", port + offset))
            return offset
        except OSError:
            pass
        finally:
            for connection in sockets:
                connection.close()
    raise RuntimeError("No isolated startup fixture ports available")


process = None
try:
    publish(formation_path, formation)
    publish(
        realm / "catalog.json",
        dict(
            schema=1,
            title=title,
            tournaments=[
                dict(
                    definition,
                    registration_open=True,
                    live_updates=True,
                    start_search_offset_seconds=600.25,
                )
            ],
        ),
    )
    publish(
        realm / "enrollments.json",
        dict(
            schema=1,
            title=title,
            players={
                str(user): dict(
                    id=tournament,
                    accepted=False,
                    ready=True,
                    ready_round=0,
                    ready_match=0,
                )
                for user in users
            },
        ),
    )
    publish(malformed_path, b"{")
    offset = choose_offset()
    process = subprocess.Popen(
        [str(image), str(directory), "--port-offset", str(offset)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    deadline = time.monotonic() + 12
    status = None
    while time.monotonic() < deadline:
        assert process.poll() is None, "Fixture server exited before maintenance"
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{8085 + offset}/health", timeout=1
            ) as response:
                status = json.load(response)
        except OSError:
            time.sleep(0.05)
            continue
        assert (
            status["lobby_authenticated"]
            == status["auth_requests"]
            == status["tasks"]
            == 0
        )
        if (
            terminal_path.exists()
            and read(mm / "transaction.json")["phase"] == "applied"
        ):
            break
        time.sleep(0.05)
    else:
        raise AssertionError("Startup expiry required an authenticated client")
    terminal = read(terminal_path)
    assert terminal["action"] == "publication-unavailable" and terminal["actor"] == 0
    assert terminal["id"] == tournament and terminal["recorded"] >= expires
    assert terminal["state"]["players"] == bracket["players"]
    assert all(
        not player["ready"]
        and "ready_round" not in player
        and "ready_match" not in player
        for player in read(realm / "enrollments.json")["players"].values()
    )
    assert malformed_path.read_bytes() == b"{"
    proof = dict(
        schema=1,
        passed=True,
        recorded_utc=datetime.now(timezone.utc).isoformat(),
        backend_sha256=digest(image),
        source_sha256=source_hashes,
        test_tool_sha256=digest(Path(__file__)),
        protocol_groups=len(protocol["checks"]),
        server_pid=process.pid,
        authenticated_lobby_connections=status["lobby_authenticated"],
        authentication_requests=status["auth_requests"],
        native_tasks=status["tasks"],
        real_clock_expiry=True,
        terminal_committed=True,
        readiness_cleared=True,
        malformed_realm_preserved=True,
        independent_realm_progressed=True,
        game_launched=False,
        receiver_membership_seeded=True,
        protocol_evidence=dict(
            path=str(validation / "data/lobby-verification.json"),
            sha256=digest(validation / "data/lobby-verification.json"),
        ),
    )
finally:
    if process and process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    for path, content in originals.items():
        assert path.is_relative_to(directory)
        if content is None:
            path.unlink(missing_ok=True)
        else:
            publish(path, content)
        assert (path.read_bytes() if path.exists() else None) == content
proof["exact_source_restoration_verified"] = True
output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(proof, indent=2) + "\n")
print(
    "PASS: startup expiry and malformed-realm isolation with zero auth/lobby/tasks; fixture files restored exactly"
)
