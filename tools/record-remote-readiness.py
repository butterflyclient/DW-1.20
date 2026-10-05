"""Record bounded native-startup evidence without claiming remote gameplay."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(name):
    return json.loads((ROOT / "data" / name).read_text(encoding="utf-8-sig"))


deployment = read("deployment.json")
host = read("native-host-ready.json")
guest = read("native-guest-standalone.json")
router = read("host-network-receipt.json")
cases = []
for role, observation in (("host", host), ("guest", guest)):
    assert observation["sha256"] == deployment["sha256"]
    assert (
        observation["server_process_verified"]["sha256"] == deployment["server_sha256"]
    )
    assert observation["server_process_verified"]["verified_live_process"]
    assert observation["platform_auth_state"] == 2
    fences = observation["native_fences_controller_0"]
    assert len(fences) == 27 and all(
        row["passing"] and not row["failed"] for row in fences
    )
    assert observation["native_relay_client_auth"]["state"] == 2
    assert observation["native_relay_association"]["state"] == 3
    cases.append(
        {
            "role": role,
            "user": observation["native_user_xuid_text"],
            "observed_utc": observation["observed_utc"],
            "passing_fences": len(fences),
            "native_relay_established": True,
        }
    )
assert cases[0]["user"] != cases[1]["user"]
public = host["native_common_address"]["public"]
assert public["ipv4"] == router["public_address"] and public["port"] == 3074
assert host["native_common_address"]["nat_type"] == 1
assert host["native_common_address"]["hash"] != 0
modules = read("native-guest-xinput-modules.json")
for module in modules:
    assert "\\windows\\system32\\" in module["FileName"].lower()
assert not (Path(deployment["executable"]).parent / "XInput9_1_0.dll").exists()
for name in ("external-tcp-8085.json", "external-tcp-3075.json"):
    results = read(name)
    assert len(results) >= 2
    for values in results.values():
        assert values and values[0]["address"] == router["public_address"]
        assert "error" not in values[0] and values[0]["time"] > 0
health = read("external-http-health.json")
assert len(health) >= 2
assert all(values[0][0] == 1 and int(values[0][3]) == 200 for values in health.values())
assert (
    read("network-publication-verification.json")["server_sha256"]
    == deployment["server_sha256"]
)
image = Path(deployment["executable"])
assert hashlib.sha256(image.read_bytes()).hexdigest() == deployment["sha256"]
receipt = {
    "schema": 1,
    "created_utc": datetime.now(timezone.utc).isoformat(),
    "game_sha256": deployment["sha256"],
    "server_sha256": deployment["server_sha256"],
    "compiler_job": deployment["job_id"],
    "proxy_free_native_startup_verified": True,
    "cases": cases,
    "native_host_public_address_verified": True,
    "public_tcp_8085_and_3075_reachable": True,
    "public_http_health_200": True,
    "concurrent_local_public_endpoint_publication_verified": True,
    "simultaneous_same_folder_native_games": "blocked by native toc1.dcache exclusive lock",
    "native_party_join_verified": False,
    "second_network_gameplay_verified": False,
    "scope": "Separate native startups and public backend reachability; owner/guest party and match test remains.",
}
(ROOT / "data/remote-readiness.json").write_text(json.dumps(receipt, indent=2) + "\n")
folder = ROOT / "validation"
folder.mkdir(exist_ok=True)
(folder / "20261005-proxy-free-host-guest.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print(
    "PASS: distinct native host/guest startup, public endpoints and proxy-free dependency checks"
)
