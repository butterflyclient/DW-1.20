"""Prepare the native Replay text list for explicit local publisher upload.

The native consumer 0x141B3C7F0 passes the buffer to q_I_strstr at
0x142036EF0. This is a NUL-terminated text list, not a JSON object. An empty
local publication contains a sole NUL and authorizes no creator code. Existing
source publications are preserved; no game assets or profiles are changed.
"""

import json
from pathlib import Path
import hashlib

root = Path(__file__).resolve().parents[1]
folder = root / "data/local-publisher-sources"
folder.mkdir(exist_ok=True)
target = folder / "contentCreatorList.txt"
if not target.exists():
    target.write_bytes(b"\0")
body = target.read_bytes()
if not 1 <= len(body) <= 4096 or body[-1:] != b"\0" or b"\0" in body[:-1]:
    raise ValueError("Native list must fit 4096 bytes and have one trailing NUL")
receipt = {
    "schema": 1,
    "source": str(target),
    "bytes": len(body),
    "sha256": hashlib.sha256(body).hexdigest(),
    "download_constructor": "0x141B3BE10",
    "completion_callback": "0x141B3CD00",
    "native_consumer": "0x141B3C7F0",
    "native_text_search": "0x142036EF0",
    "empty_local_list": body == b"\0",
}
(folder / "contentCreatorList.provenance.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print(
    "Native creator text list prepared for explicit publisher upload; "
    + str(len(body))
    + " bytes."
)
