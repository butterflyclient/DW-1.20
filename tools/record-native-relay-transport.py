"""Bind actual Replay relay completion and decrypted SDK join data to UDP events."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
observation = json.loads((DATA / "runtime-relay-transport-menu.json").read_bytes())
stability_start = json.loads(
    (DATA / "runtime-relay-transport-stability-start.json").read_bytes()
)
deployment = json.loads((DATA / "deployment.json").read_bytes())
fixture = json.loads((DATA / "lobby-verification.json").read_bytes())
server = observation["server_process_verified"]
transport = observation["native_relay_transport"]
credential = observation["native_relay_server_auth"]
association = observation["native_relay_association"]
assert server["verified_live_process"] and server["connection_receipt_matches"]
assert (
    server["sha256"]
    == deployment["server_sha256"]
    == fixture["server_sha256"]
    == digest(Path(server["executable"]))
)
assert (
    observation["sha256"]
    == deployment["sha256"]
    == digest(Path(observation["executable"]))
)
assert (
    fixture["passed"]
    and transport["state"] == 6
    and transport["native_connected_callback_observed"]
)
assert credential["relay_id"] == transport["relay_id"] == association["relay_id"]
assert (
    association["state"] == 3
    and association["type"] == 1
    and association["title"] == 5800
    and association["route"]
    and association["join_id"]
)
assert (
    association["ipv4"] == credential["ipv4"] == "127.0.0.1"
    and association["port"] == credential["port"]
)
connection = observation["connection_receipt"]
started = int(
    datetime.fromisoformat(
        connection.get("requested_utc", connection.get("launched_utc")).replace(
            "Z", "+00:00"
        )
    ).timestamp()
)
events = [
    json.loads(line)
    for line in (DATA / "relay/transport-events.jsonl").read_text().splitlines()
]
matching = [
    row
    for row in events
    if row["time"] >= started
    and row["action"] == "established"
    and row["relay_id"] == association["relay_id"]
    and row["route"] == association["route"]
    and row["user"] == association["user"]
    and row["title"] == association["title"]
    and row["port"] == association["port"]
    and row["verification_sha256"] == association["verification_sha256"]
]
assert matching and matching[-1]["expires"] > datetime.now(timezone.utc).timestamp()
native = observation["native_relay_client_auth"]
assert native["state"] == 2 and observation["native_dw_hsm_connected_state_33"]
assert len(observation["native_fences_controller_0"]) == 27 and all(
    r["passing"] and not r["failed"] for r in observation["native_fences_controller_0"]
)
assert (
    observation["native_game_connection"]["state"] == 9
    and observation["native_game_connection"]["frontend_scene"]
)
requests = [
    line
    for line in observation["server_log_since_launch"]
    if "service=145 task=24 operation=dcqos-local-relay-read error=0 results=1" in line
]
assert requests
elapsed = (
    datetime.fromisoformat(observation["observed_utc"])
    - datetime.fromisoformat(stability_start["observed_utc"])
).total_seconds()
assert (
    elapsed >= 60
    and stability_start["pid"] == observation["pid"]
    and stability_start["sha256"] == observation["sha256"]
)
assert (
    stability_start["server_process_verified"]["pid"] == server["pid"]
    and stability_start["server_process_verified"]["sha256"] == server["sha256"]
)
assert stability_start["native_relay_transport"]["state"] == 6
assert stability_start["native_relay_association"] == association
start_health = stability_start["server"]["relay"]
health = observation["server"]["relay"]
assert health["active_associations"] == start_health["active_associations"] == 1
assert health["verified_associations"] == start_health["verified_associations"] == 1
assert health["rejected_packets"] == start_health["rejected_packets"] == 0
assert health["ping_replies"] > start_health["ping_replies"]
proof = dict(
    schema=2,
    passed=True,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    server_sha256=server["sha256"],
    game_sha256=observation["sha256"],
    game_pid=observation["pid"],
    server_pid=server["pid"],
    service=145,
    task=24,
    native_server_credential_deserialization_verified=True,
    native_init_ack_key_derivation_and_join_decryption_verified=True,
    native_bind_verify_established_verified=True,
    native_client_auth_state=native["state"],
    native_relay_state=6,
    native_association_state=3,
    relay_id=association["relay_id"],
    route=association["route"],
    title=association["title"],
    user=association["user"],
    endpoint_port=association["port"],
    verification_sha256=association["verification_sha256"],
    native_connection_stability_verified=True,
    stable_seconds=elapsed,
    keepalive_replies_during_observation=health["ping_replies"]
    - start_health["ping_replies"],
    native_udp_join_data_forwarding_verified=False,
    independent_udp_join_data_forwarding_verified=True,
    udp_transport_verified=True,
    full_backend_verified=False,
    map_tests_performed=False,
    independent_grouped_checks=len(fixture["checks"]),
    events=matching,
    requests=requests,
    method="read-only ASLR native NetRelay state 6, bound SDK association state 3, decrypted join-data route/relay/endpoint/verification hash match real authenticated UDP event",
    evidence=[
        dict(file=str(path.relative_to(ROOT)), sha256=digest(path))
        for path in (
            DATA / "runtime-relay-transport-menu.json",
            DATA / "runtime-relay-transport-stability-start.json",
            DATA / "relay/transport-events.jsonl",
            DATA / "lobby-verification.json",
            DATA / "native-server-token-vtable.json",
            DATA / "native-relay-udp-functions.json",
            DATA / "native-relay-routing-bind.json",
            DATA / "native-relay-udp-key-contract.json",
            DATA / "native-relay-sequence-contract.json",
        )
    ],
    source_sha256={
        str(path.relative_to(ROOT)): digest(path)
        for path in (
            ROOT / "src/relay_services.cpp",
            ROOT / "src/relay_provider.cpp",
            ROOT / "src/qos_services.cpp",
            ROOT / "src/crypto.cpp",
            ROOT / "src/platform.cpp",
        )
    },
)
(DATA / "native-relay-transport-verification.json").write_text(
    json.dumps(proof, indent=2) + "\n"
)
print(
    f'PASS: native Replay BIND/VERIFY/ESTABLISHED stable {elapsed:.1f}s with {health["ping_replies"]-start_health["ping_replies"]} keepalive replies; 27 menu fences; JOIN/forwarding independently verified; no map tests'
)
