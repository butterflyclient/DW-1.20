"""Small live transport checks: status, fragmented HTTP, bounded lobby frames."""

import json
import socket
import struct
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:8085/health", timeout=3) as response:
    status = json.load(response)
assert status["server"] == "iw8-dw" and status["stage"] == "transport-ready"
assert status["native_auth"] is True and status["native_tasks"] is True
assert status["capability_stage"] == "encrypted-lobby-profiles"
assert status["profiles"] is True and status["storage"] is True
assert status["native_game_verified"] is False
with socket.create_connection(("127.0.0.1", 8085), timeout=3) as connection:
    for part in [b"GET /sta", b"tus HTTP/1.1\r\nHost: 127.0.", b"0.1\r\n\r\n"]:
        connection.sendall(part)
    chunks = []
    while chunk := connection.recv(4096):
        chunks.append(chunk)
    assert b"HTTP/1.1 200 OK" in b"".join(chunks)
with socket.create_connection(("127.0.0.1", 3075), timeout=3) as connection:
    connection.sendall(b"\0\0")
    connection.sendall(b"\0\0")
    assert connection.recv(4) == bytes(4)
    connection.sendall(struct.pack("<I", 0x40001))
    assert connection.recv(1) == b""
with socket.create_connection(("127.0.0.1", 8443), timeout=3) as connection:
    connection.sendall(b"\x16\x03\x01\x00\x00")
    assert connection.recv(7) == b"\x15\x03\x03\x00\x02\x02\x28"
print(
    "PASS: loopback status, fragmented HTTP, lobby keepalive/length limit, explicit unsupported TLS response"
)
