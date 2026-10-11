"""Focused native-wire first-match tier-skip claims; isolated signed identities."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from native_wire_client import NativeClient, binary, fields, integer, structure, text
from progression_delivery_fixtures import decode_event67
from achievement_transaction_fixtures import assert_applied

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = ROOT / "data" / ("first-match-reward-wire-" + str(time.time_ns()))
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copyfile(
        ROOT / "data/replay-traffic-kdf.bin", data / "replay-traffic-kdf.bin"
    )
    rules_path = data / "battlepass/5800/rules.json"
    rules_path.parent.mkdir(parents=True)
    shutil.copyfile(args.rules, rules_path)
    config = json.loads(rules_path.read_bytes())
    (definition,) = [
        row for row in config["activations"] if row["season"] == 0 and row["skips"] == 1
    ]
    token = definition["item"]
    assert token == 430002  # Independent stock BATTLEPASS.SINGLE_TIER_SKIP_ID.
    offset = 14200
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    log = (fixture / "server.log").open("wb")

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
                    f"http://127.0.0.1:{8085+offset}/health", timeout=0.3
                ).close()
                return process
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Fixture backend startup timed out")

    def stop(process):
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)

    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_numbers()
    blob = (
        struct.pack("<II", 0x31534345, 32)
        + public.x.to_bytes(32, "big")
        + public.y.to_bytes(32, "big")
    )
    name = b"First Match Reward Fixture".ljust(36, b"\0")

    def post(path, body):
        request = urllib.request.Request(f"http://127.0.0.1:{8085+offset}" + path, body)
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.read()

    def login(user=0, reset=False):
        nonce = os.urandom(32)
        challenge = post("/platform/client/challenge", blob + nonce)
        prefix = struct.pack("<II", 0x31494452, 2) + nonce + challenge + blob + name
        prefix += struct.pack("<IQQII", 3 if reset else 0, user, 0, 0, 0)
        r, s = utils.decode_dss_signature(key.sign(prefix, ec.ECDSA(hashes.SHA256())))
        return post(
            "/platform/client/login",
            prefix + r.to_bytes(32, "big") + s.to_bytes(32, "big"),
        )

    def claim(request, context="5800", reward=1, count=1):
        event = text(1, "br_tutorial_complete") + integer(2, 1000) + integer(4, 0)
        for name, value in (("version", 1), ("gamemode", 2), ("Param0", reward)):
            event += binary(3, text(1, name) + integer(2, value))
        return structure(text(1, context) + binary(2, event) * count + text(3, request))

    def user_state(client, context="5800"):
        return json.loads(
            fields(client.task(125, 9, structure(text(1, context))))[1][0]
        )

    def receive_reward(client):
        while True:
            if client.pushes:
                packet = client.pushes.pop(0)
            else:
                kind, packet = client.receive()
                assert kind == 2
            event = decode_event67(packet, client.user)[2]
            if event["kind"] == 20:
                return event

    def expect_grant(client, quantity):
        event = receive_reward(client)
        grants = event["triggers"][0]["inventory"]["granted_items"]
        assert grants == [{"id": token, "quantity": quantity}], grants
        assert event["multiProgress"]["xp"]["value"] == 0
        assert event["multiProgress"]["rank"]["value"] == 0

    process = start()
    checks = []
    try:
        with NativeClient(
            fixture, port_offset=offset, platform_reply=login()
        ) as client:
            user = client.user
            inventory_path = data / "marketplace/5800" / str(user) / "inventory.json"
            state_path = (
                data / "achievement-user-state/5800/5800" / (str(user) + ".json")
            )
            user_state(client)
            state = json.loads(state_path.read_bytes())
            state.update(
                br_tutorial_rewarded={"0": True, "3": False}, player_xp_end_time=42
            )
            state_path.write_text(json.dumps(state))
            inventory_path.parent.mkdir(parents=True, exist_ok=True)
            inventory_path.write_text(
                json.dumps({"items": [{"1": token, "2": 2}], "balances": []})
            )

            def quantity():
                if not inventory_path.exists():
                    return 0
                return next(
                    (
                        row["2"]
                        for row in json.loads(inventory_path.read_bytes())["items"]
                        if row["1"] == token
                    ),
                    0,
                )

            client.task(125, 1, claim("unimplemented-training", reward=0))
            assert quantity() == 2
            client.task(125, 1, claim("first-match", count=2))
            assert quantity() == 3
            expect_grant(client, 3)
            current = user_state(client)
            assert current["br_tutorial_rewarded"] == {"0": True, "1": True, "3": False}
            assert current["player_xp_end_time"] == 42
            checks.append(
                "Exact native first-match event grants one stock token and keyed boolean flag; duplicate rows do not multiply it, other rewards/state and season XP stay unchanged"
            )
            client.task(125, 1, claim("first-match", count=2))
            expect_grant(client, 3)
            client.task(125, 1, claim("first-match-new-request"))
            expect_grant(client, 3)
            client.task(125, 1, claim("first-match-iw8", context="iw8"))
            expect_grant(client, 3)
            assert (
                quantity() == 3
                and user_state(client, "iw8")["br_tutorial_rewarded"]["1"] is True
            )
            checks.append(
                "Exact retry, fresh claim UUID and alternate context all deliver current inventory without another consumable"
            )
        stop(process)
        process = start()
        with NativeClient(
            fixture, port_offset=offset, platform_reply=login()
        ) as client:
            assert client.user == user
            assert user_state(client)["br_tutorial_rewarded"]["1"] is True
            client.task(125, 1, claim("after-process-restart"))
            expect_grant(client, 3)
            assert quantity() == 3
        checks.append(
            "Machine identity, one-time claim and inventory survive a real backend restart"
        )
        with NativeClient(
            fixture, port_offset=offset, platform_reply=login(user, reset=True)
        ) as client:
            assert quantity() == 0 and "br_tutorial_rewarded" not in user_state(client)
            client.task(125, 1, claim("first-match", count=2))
            assert quantity() == 0 and "br_tutorial_rewarded" not in user_state(client)
            client.task(125, 1, claim("after-full-reset"))
            assert quantity() == 1
            expect_grant(client, 1)
        checks.append(
            "Full reset clears the reward in both namespaces; old receipt replay cannot undo reset and a fresh claim may earn it again"
        )
        with NativeClient(
            fixture, port_offset=offset, platform_reply=login(user, reset=True)
        ) as client:
            blocked = state_path.with_name(state_path.name + ".pending")
            blocked.mkdir()
            try:
                try:
                    client.task(125, 1, claim("interrupted-reward"))
                except RuntimeError as failure:
                    assert str(failure).endswith("returned 102"), failure
                else:
                    raise AssertionError("Blocked claim reported success")
                assert (data / "achievements/5800/event-transaction.json").exists()
                # The roll-forward store may already replace one file before
                # another pending path fails. Native reads must stay blocked,
                # rather than expose that partial flag/inventory snapshot.
                assert quantity() in (0, 1)
                try:
                    user_state(client)
                except RuntimeError as failure:
                    assert str(failure).endswith("returned 102"), failure
                else:
                    raise AssertionError("Partial reward was visible to native reads")
            finally:
                blocked.rmdir()
            client.task(125, 1, claim("interrupted-reward"))
            assert quantity() == 1
            expect_grant(client, 1)
            assert user_state(client)["br_tutorial_rewarded"]["1"] is True
            assert_applied(data / "achievements/5800/event-transaction.json")
            activation = structure(
                text(1, "5800")
                + text(2, "")
                + integer(3, 1000)
                + integer(4, definition["id"])
            )
            client.task(125, 5, activation)
            event = text(1, "skip_tier") + integer(2, 1000) + integer(4, 0)
            event += binary(3, text(1, "version") + integer(2, 1))
            client.task(
                125,
                1,
                structure(
                    text(1, "5800") + binary(2, event) + text(3, "consume-earned-token")
                ),
            )
            update = receive_reward(client)
            assert update["multiProgress"]["rank"]["value"] == 1 and quantity() == 0
            assert user_state(client)["br_tutorial_rewarded"]["1"] is True
        checks.append(
            "Interrupted flag/inventory publication fails without success, then rolls forward as one reward on exact retry"
        )
    finally:
        stop(process)
        log.close()
    result = dict(
        passed=True,
        server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
        rules_sha256=hashlib.sha256(args.rules.read_bytes()).hexdigest(),
        checks=checks,
        native_token=token,
        native_event="br_tutorial_complete",
        reward_parameter=1,
        fixture=str(fixture),
        game_runs_performed=False,
        primary_player_modified=False,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        "PASS",
        len(checks),
        "native first-match reward groups; no game or primary account used",
    )


if __name__ == "__main__":
    main()
