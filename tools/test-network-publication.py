"""Check endpoint publication through real loopback and LAN lobby connections.

Run before either game signs in: issuing these identities supersedes their
previous native sessions. This verifies DTOs, not Internet reachability.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import socket
import struct
import urllib.request

from native_wire_client import NativeClient, binary, fields, structure, text

ROOT = Path(__file__).resolve().parents[1]
network = json.loads((ROOT / "data/network.json").read_text())
router = json.loads((ROOT / "data/host-network-receipt.json").read_text())


def ordinary_text(value):
    return b"\x10" + value.encode() + b"\0"


def check(client, expected_host):
    qos = json.loads(
        client.task(
            145,
            25,
            ordinary_text('{"qos_build_name":"replay","qos_build_name_context":"iw8"}'),
            structured=False,
        )[1:-1]
    )
    address = base64.b64decode(qos["hosts"][0]["address"], validate=True)
    assert len(address) == 84 and socket.inet_ntoa(address[:4]) == expected_host
    assert struct.unpack_from("<H", address, 4)[0] == network["qos_port"]
    document = json.loads(
        client.task(
            145, 24, ordinary_text("replay") + ordinary_text("pc"), structured=False
        )[1:-1]
    )
    relay = base64.b64decode(
        json.loads(document["server_info"])["relay_auth_token"], validate=True
    )
    assert len(relay) == 83 and socket.inet_ntoa(relay[69:73]) == expected_host
    assert struct.unpack_from("<H", relay, 73)[0] == network["relay_port"]
    object_ids = [{"owner": "infinityward", "name": "1_manifest_patch_pc_8.19.txt"}]
    request = structure(
        text(1, "GET")
        + text(2, "/v2/core/publishers/objects/?context=5800")
        + binary(
            4, text(1, "DW-Objectstore-ObjectIDs") + text(2, json.dumps(object_ids))
        )
    )
    response = fields(client.task(193, 16, request))
    metadata = json.loads(response[3][0])["objects"][0]["metadata"]
    url = metadata["contentURL"]
    assert url.startswith(f"http://{expected_host}:8085/objectstore/content/")
    if expected_host == "127.0.0.1":
        with urllib.request.urlopen(url, timeout=5) as content:
            assert len(content.read()) == metadata["contentLength"]
    return {
        "user": client.user,
        "endpoint": expected_host,
        "native_dtos_verified": True,
    }


with ExitStack() as stack:
    host = stack.enter_context(NativeClient(ROOT))
    guest = stack.enter_context(
        NativeClient(
            ROOT,
            profile="remote-test-1",
            host=router["lan_address"],
            access_key=network["clients"]["remote-test-1"],
        )
    )
    assert host.user != guest.user
    # Exercise both connection threads together to detect shared global state.
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(check, host, "127.0.0.1"),
            executor.submit(check, guest, network["advertised_address"]),
        ]
        results = [future.result() for future in futures]

receipt = {
    "schema": 1,
    "passed": True,
    "cases": results,
    "server_sha256": hashlib.sha256(
        (ROOT / "build/Release/iw8-dw-server.exe").read_bytes()
    ).hexdigest(),
    "independent_remote_network_verified": False,
}
(ROOT / "data/network-publication-verification.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print(
    "PASS: concurrent local/public QoS, relay credential and publisher-content publication"
)
