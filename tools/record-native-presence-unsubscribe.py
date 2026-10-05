"""Hash-bound queue and real request evidence; no game writes or service fixtures."""

import hashlib
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = root / "data"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--before", default="runtime-presence-unsubscribe-before.json")
parser.add_argument("--after", default="runtime-final-clan-cleaned.json")
parser.add_argument(
    "--output", default="native-presence-unsubscribe-latest-verification.json"
)
args = parser.parse_args()
names = [args.before, args.after]
for name in names + [args.output]:
    if Path(name).name != name or not name.endswith(".json"):
        raise ValueError("Use an observation basename within data")
observations = [json.loads((data / name).read_bytes()) for name in names]
before, after = observations
game = Path(after["executable"])
game_hash = hashlib.sha256(game.read_bytes()).hexdigest()
verified_server = after["server_process_verified"]
assert verified_server["verified_live_process"]
server_hash = verified_server["sha256"]
assert all(row["sha256"] == game_hash for row in observations)
assert before["native_presence_subscriptions"]["pending_unsubscribe"] == 1
assert before["native_presence_subscriptions"]["batch_count"] == 1
for row in (after,):
    assert (
        row["native_dw_hsm_connected_state_33"]
        and row["native_profile_sign_in_state"] == 2
    )
    queue = row["native_presence_subscriptions"]
    assert (
        queue["pending_unsubscribe"]
        == queue["batch_count"]
        == queue["unsubscribe_error_count"]
        == 0
    )
requests = [
    line
    for line in after["server_log_since_launch"]
    if "operation_name=unsubscribe_from_users" in line
]
assert requests and all("error=0" in line for line in requests)
assert not after["native_active_clans"]
proof = dict(
    schema=2,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    game_sha256=game_hash,
    server_sha256=server_hash,
    native_game_verified=True,
    full_backend_verified=False,
    before_queue=before["native_presence_subscriptions"],
    after_queue=after["native_presence_subscriptions"],
    successful_native_requests=requests,
    observations=[
        dict(
            file=name,
            sha256=hashlib.sha256((data / name).read_bytes()).hexdigest(),
            observed_utc=row["observed_utc"],
        )
        for name, row in zip(names, observations)
    ],
    scope="Hash-bound historical live-process snapshot: actual native unsubscribe requests and completion queue; no map tests or forced game states",
)
(data / args.output).write_text(json.dumps(proof, indent=2) + "\n")
print(
    "Native presence unsubscribe completion and cleared queue recorded under deployed image hashes"
)
