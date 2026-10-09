"""Exercise native purchase, activation, token debit, tier grants and restart persistence."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request

from native_wire_client import NativeClient, binary, fields, integer, structure, text
from progression_delivery_fixtures import decode_event67
from test_replay_store_helpers import buy

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--publication", required=True, type=Path)
    parser.add_argument("--store-publication", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    fixture = ROOT / "data" / ("battlepass-fixture-" + str(time.time_ns()))
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    offset = 13300
    for profile in ("battlepass", "unowned"):
        subprocess.run(
            [str(args.server), str(data), "--provision-profile", profile, profile],
            check=True,
            stdout=subprocess.DEVNULL,
            creationflags=flags,
        )
    subprocess.run(
        [
            os.sys.executable,
            str(ROOT / "tools/publish-replay-store-catalog.py"),
            str(args.store_publication),
            "--data",
            str(data),
            "--health-url",
            f"http://127.0.0.1:{8085 + offset}/health",
        ],
        check=True,
        creationflags=flags,
    )
    subprocess.run(
        [
            os.sys.executable,
            str(ROOT / "tools/publish-replay-battlepass.py"),
            str(args.publication),
            "--data",
            str(data),
        ],
        check=True,
        creationflags=flags,
    )
    checks = []
    log = (fixture / "server-output.log").open("wb")

    def start():
        process = subprocess.Popen(
            [str(args.server), str(data), "--port-offset", str(offset)],
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
        for _ in range(100):
            assert process.poll() is None
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{8085 + offset}/health", timeout=0.5
                ).close()
                return process
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Fixture backend did not start")

    activate = lambda selected: structure(
        text(1, "5800") + text(2, "") + integer(3, 1000) + integer(4, selected)
    )

    def send(name, request, values=None):
        values = {"version": 1, **(values or {})}
        event = text(1, name) + integer(2, 1000) + integer(4, 0)
        for key, value in values.items():
            event += binary(3, text(1, key) + integer(2, value))
        return structure(text(1, "5800") + binary(2, event) + text(3, request))

    def received(client):
        events = []
        while client.pushes:
            events.append(decode_event67(client.pushes.pop(0), client.user)[2])
        while not any(row["kind"] == 20 for row in events):
            kind, packet = client.receive()
            assert kind == 2
            events.append(decode_event67(packet, client.user)[2])
        return [row for row in events if row["kind"] == 20]

    config = json.loads((args.publication / "rules.json").read_bytes())
    thresholds = config["seasons"]["3"]

    def reject(client, request, expected):
        try:
            client.task(125, 5, request)
        except RuntimeError as error:
            assert str(error).endswith("returned " + str(expected)), error
        else:
            raise AssertionError("Activation unexpectedly succeeded")

    process = start()
    try:
        with NativeClient(fixture, profile="unowned", port_offset=offset) as client:
            user_state = json.loads(
                fields(client.task(125, 9, structure(text(1, "5800"))))[1][0]
            )
            assert "battlepass3_owned" not in user_state
            reject(client, activate(3002001), 101)
            reject(client, activate(3000006), 101)
            checks.append("Unowned premium packages and tokens cannot be activated")
            state_path = (
                data / "achievements/5800/5800" / str(client.user) / "states.json"
            )
            inventory_path = (
                data / "marketplace/5800" / str(client.user) / "inventory.json"
            )
            battlepass_state = lambda: next(
                row
                for row in json.loads(state_path.read_bytes())
                if row["id"] == 3002000
            )
            amount = thresholds[3]["xp"] + 1
            client.task(
                125, 1, send("mp_addxp", "earned-free", {"Param0": 0, "Param4": amount})
            )
            updates = received(client)
            assert updates[-1]["reason"] == "completed"
            state = battlepass_state()
            assert state["multiProgress"][0]["current"] == amount
            assert state["multiProgress"][1]["current"] == 3 and not state.get(
                "premium", False
            )
            for tier in thresholds[:4]:
                key = ("free:" if tier["free"] else "premium:") + str(tier["rank"])
                assert (key in state["claimed"]) == tier["free"]
            checks.append(
                "Native Param4 alone earns exact Battle Pass XP and free-track rewards without purchasing premium"
            )
            client.task(
                125, 1, send("mp_addxp", "earned-fraction", {"Param0": 0, "Param4": 1})
            )
            assert received(client)[-1]["reason"] == "inProgress"
            snapshot = (state_path.read_bytes(), inventory_path.read_bytes())
            client.task(
                125, 1, send("mp_addxp", "earned-fraction", {"Param0": 0, "Param4": 1})
            )
            refresh = received(client)[-1]
            assert refresh["reason"] == "inProgress" and not refresh.get("triggers")
            assert snapshot == (state_path.read_bytes(), inventory_path.read_bytes())
            checks.append(
                "Within-tier updates and exact retries refresh absolute XP without another tier-completion effect or reward"
            )
            client.task(80, 106, buy(432000, "earned-premium"), structured=False)
            client.task(125, 5, activate(3002001))
            client.task(
                125, 1, send("activate_battlepass_s3", "earned-premium-activation")
            )
            received(client)
            state = battlepass_state()
            assert (
                state["premium"] and state["multiProgress"][0]["current"] == amount + 1
            )
            assert all(
                ("free:" if tier["free"] else "premium:") + str(tier["rank"])
                in state["claimed"]
                for tier in thresholds[:4]
            )
            checks.append(
                "Later premium activation preserves earned fractional XP and backfills only previously unclaimed premium rewards"
            )
            target = thresholds[6]["xp"] + 7
            delta = target - state["multiProgress"][0]["current"]
            blocked = inventory_path.with_name(inventory_path.name + ".pending")
            blocked.mkdir()
            try:
                try:
                    client.task(
                        125,
                        1,
                        send(
                            "mp_addxp",
                            "earned-recovery",
                            {"Param0": 0, "Param4": delta},
                        ),
                    )
                except RuntimeError as failure:
                    assert str(failure).endswith("returned 102"), failure
                else:
                    raise AssertionError(
                        "Blocked earned-tier inventory write succeeded"
                    )
                assert (data / "achievements/5800/event-transaction.json").exists()
            finally:
                blocked.rmdir()
            client.task(
                125,
                1,
                send("mp_addxp", "earned-recovery", {"Param0": 0, "Param4": delta}),
            )
            assert received(client)[-1]["reason"] == "inProgress"
            assert battlepass_state()["multiProgress"][0]["current"] == target
            assert not (data / "achievements/5800/event-transaction.json").exists()
            checks.append(
                "A real earned-reward write interruption recovers its XP, grants and request receipt once"
            )
            earned_user = client.user
            earned_snapshot = (state_path.read_bytes(), inventory_path.read_bytes())
        with NativeClient(fixture, profile="battlepass", port_offset=offset) as client:
            inventory = data / "marketplace/5800" / str(client.user) / "inventory.json"
            states = data / "achievements/5800/5800" / str(client.user) / "states.json"
            get_inventory = lambda: json.loads(inventory.read_bytes())
            quantity = lambda item: next(
                (row["2"] for row in get_inventory()["items"] if row["1"] == item), 0
            )
            get_state = lambda identity: next(
                row for row in json.loads(states.read_bytes()) if row["id"] == identity
            )

            def event(name, request):
                client.task(125, 1, send(name, request))
                return received(client)

            client.task(80, 106, buy(432001, "premium-plus-tokens"), structured=False)
            assert quantity(432000) == 1 and quantity(430006) == 1
            checks.append(
                "Zero-price bundle grants the native premium and twenty-tier token items"
            )
            client.task(125, 5, activate(3002001))
            snapshot = states.read_bytes()
            client.task(125, 5, activate(3002001))
            assert states.read_bytes() == snapshot and quantity(432000) == 1
            event("activate_battlepass_s3", "premium-event")
            assert get_state(3002000)["premium"] and quantity(432000) == 0
            checks.append(
                "Premium activation retries are harmless and its claim debits exactly one item"
            )
            client.task(125, 5, activate(3000006))
            event("skip_tier", "twenty-tier-event")
            assert quantity(430006) == 0
            state = get_state(3002000)
            assert state["multiProgress"][0]["current"] == thresholds[20]["xp"]
            assert state["multiProgress"][1]["current"] == 20
            for row in thresholds[:21]:
                for item in row["items"]:
                    assert quantity(item) > 0
            checks.append(
                "Claiming a twenty-tier token advances exact native XP thresholds and grants earned tier items"
            )
            before = (inventory.read_bytes(), states.read_bytes())
            event("skip_tier", "twenty-tier-event")
            assert before == (inventory.read_bytes(), states.read_bytes())
            reject(client, activate(3000006), 101)
            checks.append(
                "Repeated events cannot consume another token or duplicate rewards; exhausted tokens are rejected"
            )
            client.task(80, 106, buy(430002, "single-tier-1"), structured=False)
            client.task(80, 106, buy(430002, "single-tier-2"), structured=False)
            for i in range(2):
                client.task(125, 5, activate(3000002))
                event("skip_tier", f"single-tier-event-{i}")
            assert (
                quantity(430002) == 0
                and get_state(3002000)["multiProgress"][1]["current"] == 22
            )
            checks.append(
                "Successive claims of the same token type remain usable even within one timestamp"
            )
            client.task(80, 106, buy(430003, "recovery-token"), structured=False)
            client.task(125, 5, activate(3000003))
            blocked = inventory.with_name(inventory.name + ".pending")
            blocked.mkdir()
            try:
                try:
                    client.task(125, 1, send("skip_tier", "recovered-token-event"))
                except RuntimeError as failure:
                    assert str(failure).endswith("returned 102"), failure
                else:
                    raise AssertionError(
                        "Blocked inventory publication unexpectedly succeeded"
                    )
                assert (data / "achievements/5800/event-transaction.json").exists()
            finally:
                blocked.rmdir()
            event("skip_tier", "recovered-token-event")
            assert (
                quantity(430003) == 0
                and get_state(3002000)["multiProgress"][1]["current"] == 24
            )
            assert not (data / "achievements/5800/event-transaction.json").exists()
            checks.append(
                "Interrupted publication recovers its receipt, token debit, rewards and tier state once"
            )
            user = client.user
        process.terminate()
        process.wait(timeout=10)
        process = start()
        with NativeClient(fixture, profile="unowned", port_offset=offset) as client:
            assert client.user == earned_user
            client.task(
                125,
                1,
                send("mp_addxp", "earned-recovery", {"Param0": 0, "Param4": delta}),
            )
            assert received(client)[-1]["reason"] == "inProgress"
            assert earned_snapshot == (
                state_path.read_bytes(),
                inventory_path.read_bytes(),
            )
            checks.append(
                "Earned Battle Pass progress and retry identity persist across an actual backend process restart"
            )
            before = battlepass_state()
            client.task(
                125, 1, send("mp_addxp", "player-only", {"Param0": 9000, "Param4": 0})
            )
            assert battlepass_state() == before
            checks.append("Player XP without Param4 does not create Battle Pass credit")
            client.task(
                125,
                1,
                send("mp_addxp", "earned-cap", {"Param0": 0, "Param4": 2**64 - 1}),
            )
            received(client)
            state = battlepass_state()
            assert state["multiProgress"][0]["current"] == thresholds[100]["xp"]
            assert state["multiProgress"][1]["current"] == 100
            snapshot = (state_path.read_bytes(), inventory_path.read_bytes())
            client.task(
                125,
                1,
                send("mp_addxp", "earned-cap", {"Param0": 0, "Param4": 2**64 - 1}),
            )
            assert received(client)[-1]["reason"] == "inProgress"
            assert snapshot == (state_path.read_bytes(), inventory_path.read_bytes())
            checks.append(
                "Unsigned 64-bit XP saturates at the native tier-100 threshold without overflow or duplicate rewards"
            )
        with NativeClient(fixture, profile="battlepass", port_offset=offset) as client:
            assert (
                client.user == user
                and get_state(3002000)["multiProgress"][1]["current"] == 24
            )
            user_state = json.loads(
                fields(client.task(125, 9, structure(text(1, "5800"))))[1][0]
            )
            assert (
                user_state["battlepass3_owned"] == 1
                and type(user_state["battlepass3_owned"]) is int
            )
            active = fields(
                client.task(
                    125,
                    3,
                    structure(
                        text(1, "5800")
                        + integer(2, 20)
                        + integer(3, 100)
                        + text(4, "")
                        + integer(5, 1)
                        + integer(5, 3)
                        + integer(5, 5)
                        + integer(8, 0)
                    ),
                )
            )
            returned = [fields(row)[11][0] for row in active.get(1, [])]
            assert 3002000 in returned and not {
                3002001,
                3000002,
                3000003,
                3000006,
            }.intersection(returned)
            checks.append(
                "The native login JSON restores integer ownership flags and excludes completed activations from the active query"
            )
            client.task(125, 5, activate(3002001))
            event("activate_battlepass_s3", "premium-restart-repair")
            assert quantity(432000) == 0 and get_state(3002000)["premium"]
            checks.append(
                "Restart restores ownership and tiers and supports the native premium cache repair without another debit"
            )
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        log.close()
    args.output.write_text(
        json.dumps(
            dict(
                passed=True,
                server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
                checks=checks,
                fixture=str(fixture),
                native_game_verified=False,
            ),
            indent=2,
        )
        + "\n"
    )
    for check in checks:
        print("PASS", check)


if __name__ == "__main__":
    main()
