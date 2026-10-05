"""Require exact native token bytes and real completion state, never a server ACK alone."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
observation = json.loads((DATA / "runtime-relay-client-menu.json").read_bytes())
deployment = json.loads((DATA / "deployment.json").read_bytes())
fixtures = json.loads((DATA / "lobby-verification.json").read_bytes())
server = observation["server_process_verified"]
native = observation["native_relay_client_auth"]
user = struct.unpack_from("<Q", (DATA / "platform-profile.bin").read_bytes(), 8)[0]
audit = DATA / f"relay/5800/clients/{user}.json"
issued = json.loads(audit.read_bytes())
hash_file = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert server["verified_live_process"] and server["connection_receipt_matches"]
assert (
    server["sha256"]
    == deployment["server_sha256"]
    == fixtures["server_sha256"]
    == hash_file(Path(server["executable"]))
)
assert (
    observation["sha256"]
    == deployment["sha256"]
    == hash_file(Path(observation["executable"]))
)
assert (
    fixtures["passed"]
    and native["state"] == 2
    and native["native_completion_callback_observed"]
)
assert native["version"] == 1 and 0 < native["expiry_delta"] <= 3600
assert (
    issued["title"] == 5800
    and issued["user"] == user
    and issued["udp_transport_advertised"] is False
)
assert native["native_wire_sha256"] == issued["native_wire_sha256"]
assert (
    native["opaque_sha256"] == issued["opaque_sha256"]
    and native["expiry_delta"] == issued["expiry_delta"]
)
connection = observation["connection_receipt"]
started = int(
    datetime.fromisoformat(
        connection.get("requested_utc", connection.get("launched_utc")).replace(
            "Z", "+00:00"
        )
    ).timestamp()
)
assert (
    issued["issued"] >= started
    and issued["expires"] > datetime.now(timezone.utc).timestamp()
)
requests = [
    line
    for line in observation["server_log_since_launch"]
    if "service=145 task=26 operation=relay-client-auth-token-issued error=0 results=1"
    in line
]
assert requests and observation["native_dw_hsm_connected_state_33"]
assert len(observation["native_fences_controller_0"]) == 27
assert all(
    f["passing"] and not f["failed"] for f in observation["native_fences_controller_0"]
)
assert (
    observation["native_game_connection"]["state"] == 9
    and observation["native_game_connection"]["frontend_scene"]
)
proof = dict(
    schema=1,
    passed=True,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    server_sha256=server["sha256"],
    game_sha256=observation["sha256"],
    game_pid=observation["pid"],
    server_pid=server["pid"],
    service=145,
    task=26,
    native_token_deserializer_and_completion_callback_verified=True,
    native_task_state=2,
    native_wire_sha256=native["native_wire_sha256"],
    expiry_delta=native["expiry_delta"],
    issuer_title=issued["title"],
    issuer_user=issued["user"],
    issuer_expires=issued["expires"],
    udp_transport_verified=False,
    full_backend_verified=False,
    map_tests_performed=False,
    method="ASLR-resolved native NetRelay token fields reconstructed as exact 77-byte wire blob; hash and expiry match issuer; native callback state 2 and Multiplayer frontend state 9",
    native_request_decoder="0x1421358F0",
    native_result_decoder="0x142149720",
    native_token_decoder="0x142193110",
    native_completion_callback="0x1412BF7C0",
    native_result_vtable="0x1426A4098",
    native_token_vtable="0x1426AB438",
    requests=requests,
    evidence=[
        dict(file=str(path.relative_to(ROOT)), sha256=hash_file(path))
        for path in (
            DATA / "runtime-relay-client-menu.json",
            audit,
            DATA / "lobby-verification.json",
            DATA / "native-client-token-result-vtable.json",
            DATA / "native-client-token-vtable.json",
            DATA / "native-relay-engine-state.json",
        )
    ],
    source_sha256={
        str(path.relative_to(ROOT)): hash_file(path)
        for path in (
            ROOT / "src/relay_services.cpp",
            ROOT / "src/relay_services.h",
            ROOT / "src/services.cpp",
        )
    },
)
(DATA / "native-relay-client-verification.json").write_text(
    json.dumps(proof, indent=2) + "\n"
)
print(
    "PASS: native Replay 145/26 deserialization + completion state 2; token/expiry match issuer; all 27 fences and Multiplayer frontend pass; no UDP transport claim"
)
