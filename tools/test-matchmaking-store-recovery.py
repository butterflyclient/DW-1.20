"""Check complete lobby invariants before isolated transaction recovery writes."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]


def snapshot():
    return {
        "schema": 1, "title": 5800, "id": 100, "owner": 1,
        "update_id": 1, "expires": int(time.time()) + 3600,
        "members": [1, 2], "maximum_members": 4,
        "host_doc": {
            "listen_server": {"host_player_id": 1, "host_address": ""},
            "player_state": {"1": 2, "2": 3},
            "lobby_open": True, "lobby_open_for_pres_join": True,
            "game_state": {"state": "intermission"},
        },
        "backend_doc": {
            "lobby_id": 100,
            "listen_server": {"lobby_host_order": [1, 2]},
            "players": {"1": "connected", "2": "connected"},
            "player_id_to_mm_id": {"1": 10, "2": 10},
            "player_id_to_service_level": {"1": "paid", "2": "paid"},
            "player_id_to_slots": {"1": 0, "2": 0},
            "team_balance": {"teams": {"0": [1], "1": [2]},
                             "squad_size": 1, "squads": {}},
        },
    }


def cases():
    result = []

    def add(name, valid, change):
        state = snapshot()
        change(state)
        result.append((name, valid, state))

    add("modern", True, lambda s: None)
    add("legacy-missing-reservations", True,
        lambda s: s["backend_doc"].pop("player_id_to_slots"))
    add("legacy-missing-capacity", True, lambda s: s.pop("maximum_members"))
    add("legacy-optional-host-fields", True,
        lambda s: [s["host_doc"].pop(k) for k in
                   ("game_state", "lobby_open", "lobby_open_for_pres_join")])
    add("empty-optional-game-state", True,
        lambda s: s["host_doc"].update(game_state={}))
    add("zero-bot-running", True,
        lambda s: (s.update(operator_bots_requested=True, operator_bot_count=0),
                   s["host_doc"].update(game_state={"state": "in_game"})))
    add("legacy-squads-without-fill", True,
        lambda s: (s.update(match_selection={"squad_size": 4}),
                   s["backend_doc"]["team_balance"].update(squad_size=4, squads={"0": [1, 2]})))
    add("modern-filled-squad", True,
        lambda s: (s.update(match_selection={"squad_size": 4}, squad_fill={"0": True}),
                   s["backend_doc"]["team_balance"].update(squad_size=4, squads={"0": [1, 2]})))
    add("partial-legacy-reservations", True,
        lambda s: s["backend_doc"].update(player_id_to_slots={"1": 1}))
    add("empty-retained-team", True,
        lambda s: s["backend_doc"]["team_balance"]["teams"].update({"2": []}))
    add("empty-retained-mp-squad", True,
        lambda s: s["backend_doc"]["team_balance"].update(squads={"0": []}))
    add("reservation-overflow", False,
        lambda s: (s.update(maximum_members=2),
                   s["backend_doc"]["player_id_to_slots"].update({"1": 1})))
    for name, slots in (("reservation-foreign-member", {"3": 0}),
                        ("reservation-noncanonical-key", {"01": 0}),
                        ("reservation-boolean", {"1": True}),
                        ("reservation-negative", {"1": -1}),
                        ("reservation-fraction", {"1": 0.5}),
                        ("reservation-too-large", {"1": 2}),
                        ("reservation-array", [])):
        add(name, False, lambda s, v=slots: s["backend_doc"].update(player_id_to_slots=v))
    add("bot-overflow", False,
        lambda s: s.update(maximum_members=2, operator_bots_requested=True, operator_bot_count=1))
    add("autofill-target-overflow", False,
        lambda s: s.update(maximum_members=2, operator_bots_requested=True,
                           operator_bot_count=0, auto_fill_bots=True, auto_fill_complete=False,
                           auto_fill_started_ms=0, auto_fill_target=1))
    for field in ("players", "player_id_to_mm_id", "player_id_to_service_level",
                  "player_id_to_performance"):
        add("foreign-" + field, False,
            lambda s, k=field: s["backend_doc"].update({k: {"1": 10, "3": 10}}))
    add("missing-player-map-member", False,
        lambda s: s["backend_doc"]["players"].pop("2"))
    add("foreign-host-state", False,
        lambda s: s["host_doc"]["player_state"].update({"3": 2}))
    add("retired-host-state", False,
        lambda s: s["host_doc"]["player_state"].update({"2": 4}))
    add("duplicate-team-member", False,
        lambda s: s["backend_doc"]["team_balance"]["teams"].update({"1": [1, 2]}))
    add("missing-team-member", False,
        lambda s: s["backend_doc"]["team_balance"]["teams"].update({"1": []}))
    add("foreign-team-member", False,
        lambda s: s["backend_doc"]["team_balance"]["teams"].update({"1": [3]}))
    add("noncanonical-team-index", False,
        lambda s: s["backend_doc"]["team_balance"].update(teams={"00": [1, 2]}))
    add("duplicate-host-order", False,
        lambda s: s["backend_doc"]["listen_server"].update(lobby_host_order=[1, 1]))
    add("foreign-host-order", False,
        lambda s: s["backend_doc"]["listen_server"].update(lobby_host_order=[1, 3]))
    add("missing-owner-host-order", False,
        lambda s: s["backend_doc"]["listen_server"].update(lobby_host_order=[2]))
    add("squad-guest-overflow", False,
        lambda s: (s["backend_doc"]["player_id_to_slots"].update({"1": 1}),
                   s["backend_doc"]["team_balance"].update(squad_size=2, squads={"0": [1, 2]})))
    add("legacy-duplicate-squad-member", False,
        lambda s: s["backend_doc"]["team_balance"].update(squad_size=4, squads={"0": [1, 2], "1": [2]}))
    add("native-squad-index-overflow", False,
        lambda s: (s.update(match_selection={"squad_size": 4}),
                   s["backend_doc"]["team_balance"].update(squad_size=4, squads={"63": [1, 2]})))
    add("protected-squad-bot-overflow", False,
        lambda s: (s.update(maximum_members=200, match_selection={"squad_size": 3},
                            operator_bots_requested=True, operator_bot_count=184),
                   s["backend_doc"]["team_balance"].update(squad_size=3, squads={"0": [1], "1": [2]})))
    add("native-solo-bot-overflow", False,
        lambda s: (s.update(maximum_members=200, match_selection={"squad_size": 1},
                            operator_bots_requested=True, operator_bot_count=151),
                   s["backend_doc"]["team_balance"].update(squad_size=1, squads={"0": [1], "1": [2]})))
    add("foreign-squad-fill", False,
        lambda s: s.update(squad_fill={"0": True}))
    for name, value in (("game-state-null", None), ("game-state-string", "in_game"),
                        ("game-state-array", []), ("game-state-status-number", {"state": 2})):
        add(name, False, lambda s, v=value: s["host_doc"].update(game_state=v))
    for field in ("lobby_open", "lobby_open_for_pres_join"):
        add("invalid-" + field, False, lambda s, k=field: s["host_doc"].update({k: "true"}))
    return result


def spare_offset():
    for offset in range(10400, 10600):
        sockets = []
        try:
            for port in (8085, 8443, 3075):
                sock = socket.socket()
                sockets.append(sock)
                sock.bind(("127.0.0.1", port + offset))
            return offset
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError("No isolated fixture ports available")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-baseline-gaps", action="store_true")
    args = parser.parse_args()
    exe = args.executable.resolve()
    fixture = ROOT / "data" / ("matchmaking-store-recovery-" + str(time.time_ns()))
    offset = spare_offset()
    results = []
    for name, valid, state in cases():
        directory = fixture / name
        store = directory / "matchmaking/5800"
        store.mkdir(parents=True)
        journal = {"schema": 1, "title": 5800, "revision": 1, "phase": "prepared", "writes": [
            {"path": "current-lobbies.json", "document": {
                "schema": 1, "title": 5800, "user": 0, "revision": 1, "lobbies": {"1": 100, "2": 100}}},
            {"path": "lobbies/100.json", "document": state},
        ]}
        journal_path = store / "transaction.json"
        original = json.dumps(journal).encode()
        journal_path.write_bytes(original)
        with (directory / "stdout.log").open("wb") as log:
            process = subprocess.Popen([str(exe), str(directory), "--port-offset", str(offset)],
                                       stdout=log, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            try:
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        break
                    try:
                        if json.loads(journal_path.read_bytes())["phase"] == "applied":
                            break
                    except OSError:
                        pass
                    time.sleep(0.025)
                index_written = (store / "current-lobbies.json").exists()
                lobby_written = (store / "lobbies/100.json").exists()
                applied = json.loads(journal_path.read_bytes())["phase"] == "applied"
                accepted = applied and index_written and lobby_written
                rejected = process.poll() is not None and not index_written and not lobby_written
                untouched = journal_path.read_bytes() == original
                passed = accepted if valid else rejected and untouched
                results.append(dict(case=name, valid=valid, accepted=accepted, rejected=rejected,
                                    first_snapshot_written=index_written, lobby_written=lobby_written,
                                    journal_unchanged=untouched, passed=passed))
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
    passed = all(row["passed"] for row in results)
    baseline = (all(row["passed"] for row in results if row["valid"]) and
                all(next(row for row in results if row["case"] == name)["accepted"]
                    for name in ("reservation-overflow", "duplicate-team-member", "foreign-players", "bot-overflow")))
    receipt = dict(schema=1, passed=passed, baseline_gaps_confirmed=baseline,
                   executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
                   fixture_directory=str(fixture), game_runs_performed=False,
                   production_restarts=False, checks=results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    failures = [row["case"] for row in results if not row["passed"]]
    print(f"{sum(row['passed'] for row in results)}/{len(results)} recovery cases passed; receipt {args.output}")
    if failures:
        print("Failed cases: " + ", ".join(failures))
    if args.expect_baseline_gaps:
        if not baseline:
            raise SystemExit("Expected baseline validation gaps were not reproduced")
    elif not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
