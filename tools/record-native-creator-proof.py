"""Bind the actual publisher download callback evidence to this deployment."""

import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = root / "data"
deployment = json.loads((data / "deployment.json").read_text())
names = [
    "runtime-creator-before-publication.json",
    "runtime-creator-after-publication.json",
]
before, after = [json.loads((data / name).read_text()) for name in names]
assert before["sha256"] == after["sha256"] == deployment["sha256"]
assert not before["native_content_creator_list"]["loaded"]
assert after["native_content_creator_list"] == {"loaded": True, "in_flight": False}
assert (
    after["native_dw_hsm_connected_state_33"]
    and after["native_profile_sign_in_state"] == 2
)
lines = after["server_log_since_launch"]
assert any(
    "names=contentCreatorList.txt" in line and "available=1 missing=0" in line
    for line in lines
)
assert any("immutable content download completed bytes=1" in line for line in lines)
image = root / "build/Release/iw8-dw-server.exe"
assert hashlib.sha256(image.read_bytes()).hexdigest() == deployment["server_sha256"]
receipt = {
    "schema": 1,
    "game_sha256": deployment["sha256"],
    "server_sha256": deployment["server_sha256"],
    "native_game_verified": True,
    "observations": names,
    "native_completion_callback": "0x141B3CD00",
    "evidence": "Real metadata and HTTP download completed; native callback set loaded=true and in_flight=false. The local list authorizes no creator codes.",
    "publisher_provenance": "local-publisher-sources/contentCreatorList.provenance.json",
    "observed_utc": after["observed_utc"],
}
(data / "native-content-creator-proof.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print(
    "Native publisher object/HTTP/callback completion recorded with deployment hashes."
)
