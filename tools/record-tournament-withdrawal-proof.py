"""Bind encrypted managed-tournament withdrawal checks to the compiled backend."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


suite = json.loads((ROOT / "data/lobby-verification.json").read_bytes())
server_hash = digest(ROOT / "build/Release/iw8-dw-server.exe")
assert suite["passed"] and suite["server_sha256"] == server_hash
prefixes = (
    "Authenticated departure after elimination or a completed final",
    "Managed PLAYING decline retires",
    "Managed PLAYING leave retires",
    "Withdrawal validates complete retirement/terminal snapshots",
)
checks = [item for item in suite["checks"] if item.startswith(prefixes)]
assert len(checks) == len(prefixes)
fixture = Path(suite["fixture_directory"]).resolve()
assert fixture.parent == (ROOT / "data").resolve()
assert fixture.name.startswith("protocol-fixture-")
mm = fixture / "matchmaking/5800"
first_id = (1 << 62) + 561
assert not (mm / "tournament-terminations" / f"{first_id}.json").exists()
records = []
for offset, action in enumerate(("decline", "leave"), 1):
    path = mm / "tournament-terminations" / f"{first_id + offset}.json"
    state = json.loads(path.read_bytes())
    assert state["schema"] == 1 and state["title"] == 5800
    assert state["id"] == first_id + offset and state["action"] == action
    assert state["state"]["tournamentStatus"] == "PLAYING"
    results_path = fixture / "tournaments/5800/results" / f"{state['id']}.json"
    if action == "leave":
        results = json.loads(results_path.read_bytes())["results"]
        assert (
            len(results) == 1
            and results[0]["winner"] == 0
            and results[0]["scores"] == [6, 3]
        )
    else:
        assert not results_path.exists()
    lobbies = {
        match["lobbyID"]
        for round_ in state["state"]["rounds"]
        for match in round_["matches"]
        if match["lobbyID"]
    }
    assert len(lobbies) == (2 if action == "leave" else 0)
    for lobby in lobbies:
        assert json.loads((mm / "lobbies" / f"{lobby}.json").read_bytes())["disbanded"]
    records.append({"id": state["id"], "action": action, "sha256": digest(path)})
sources = (
    "src/tournament_services.cpp",
    "src/tournament_services.h",
    "src/matchmaking_store.cpp",
    "tools/tournament_withdrawal_fixtures.py",
    "tools/tournament_round_fixtures.py",
    "tools/record-tournament-withdrawal-proof.py",
)
receipt = {
    "schema": 1,
    "verified_at": datetime.now(timezone.utc).isoformat(),
    "server_sha256": server_hash,
    "passed": True,
    "scope": "Authenticated explicit withdrawal cancels unfinished backend-managed tournaments",
    "checks": checks,
    "suite_checks": len(suite["checks"]),
    "terminal_records_retained_after_fixture_server_restart": records,
    "source_sha256": {name: digest(ROOT / name) for name in sources},
    "native_withdrawal_callback_verified": False,
    "native_tournament_playability_verified": False,
    "retail_forfeit_or_disconnect_timeout_implemented": False,
    "two_network_multiplayer_verified": False,
}
output = ROOT / "validation/20261006-tournament-withdrawal.json"
output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
print(
    f"PASS: {len(checks)} managed withdrawal groups; {len(suite['checks'])} suite groups"
)
