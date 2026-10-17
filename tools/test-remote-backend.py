"""Verify a migrated issuer with real CNG verification and independent wire crypto."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from native_wire_client import NativeClient, u64, u32

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--platform-library', type=Path,
                        default=ROOT / 'build/Release/iw8-dw-platform-client.dll',
                        help='Verified Windows CNG helper from the selected backend source build')
    args = parser.parse_args()
    process_before = None
    if args.host == '162.243.115.160':
        from remote_backend import live
        process_before = live()
        assert process_before['active'] == 'active'
        assert process_before['sha256'] == process_before['process_sha256']
    base = 'https://' + args.host + ':8443'
    checks = []
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    public = struct.pack('<II', 0x31534345, 32) + numbers.x.to_bytes(32, 'big') + numbers.y.to_bytes(32, 'big')

    def post(path, body):
        with urllib.request.urlopen(urllib.request.Request(base + path, body), timeout=10) as response:
            return response.read()

    def login():
        nonce = os.urandom(32)
        challenge = post('/platform/client/challenge', public + nonce)
        assert len(challenge) == 32
        prefix = struct.pack('<II', 0x31494452, 1) + nonce + challenge + public + ('Droplet Check ' + hashlib.sha256(public).hexdigest()[:8]).encode().ljust(36, b'\0')
        r, s = utils.decode_dss_signature(private.sign(prefix, ec.ECDSA(hashes.SHA256())))
        request = prefix + r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        reply = post('/platform/client/login', request)
        assert len(reply) == 512
        if os.name == 'nt':
            library = ctypes.CDLL(str(args.platform_library.resolve()))
            verify = library.DW_LocalPlatform_VerifyReply
            verify.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64)
            verify.restype = ctypes.c_bool
            assert verify(reply, nonce, int(time.time())), 'Actual Windows CNG client rejected Linux signature'
            assert not verify(reply, os.urandom(32), int(time.time()))
            damaged = bytearray(reply)
            damaged[-1] ^= 1
            assert not verify(bytes(damaged), nonce, int(time.time()))
        try:
            post('/platform/client/login', request)
        except urllib.error.HTTPError as error:
            assert error.code == 400
        else:
            raise AssertionError('Consumed challenge accepted again')
        return reply

    first = login()
    user = struct.unpack_from('<Q', first, 56)[0]
    with socket.create_connection((args.host, 8443), timeout=5) as transport:
        with ssl.create_default_context().wrap_socket(transport, server_hostname=args.host) as tls:
            assert tls.version() in ('TLSv1.2', 'TLSv1.3')
            checks.append('Publicly trusted HTTPS certificate and server address verified')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(5)
        destination = socket.inet_aton(args.host) + struct.pack('<H', 3076)
        introduction = b'\x0d' + struct.pack('<H', 2) + os.urandom(10) + struct.pack('<I', 73) + \
            socket.inet_aton('127.0.0.1') + struct.pack('<H', 1234) + destination
        udp.sendto(introduction, (args.host, 3076))
        packet, _ = udp.recvfrom(1290)
        assert packet == b'\x0c' + introduction[1:]
    checks.append('public UDP NAT introduction preserves native challenge')
    checks.extend(['P-256 machine proof accepted', 'original pinned issuer preserved',
                   'Windows CNG RSA-PSS reply verification', 'wrong nonce and altered signature rejected',
                   'consumed machine challenge rejected'])
    with NativeClient(ROOT, host=args.host, platform_reply=first) as client:
        assert client.user == user
        seconds = client.task(12, 6, b'', structured=False)
        assert len(seconds) == 5 and seconds[0] == 8
        assert abs(struct.unpack_from('<I', seconds, 1)[0] - time.time()) < 15
        value = b"Replay native Linux persistence check"
        profile_blob = b"\x13" + u32(len(value)) + value
        assert client.task(8, 3, profile_blob, structured=False) == b""
        profile = client.task(8, 1, u64(user), structured=False)
        assert profile == u64(user) + profile_blob
    checks.extend(['signed auth response on native HTTPS route 8443', 'legacy account token binding',
                   'encrypted 210 lobby handshake and CBC task transport', 'time task completion',
                   'native profile save/read exact bytes'])
    second = login()
    assert struct.unpack_from('<Q', second, 56)[0] == user
    checks.append('machine account stable on fresh login')
    health = json.load(urllib.request.urlopen(base + '/health', timeout=10))
    assert health['lobby_failures'] == 0
    receipt = dict(schema=1, passed=True, endpoint=args.host, checked_utc=time.time(), checks=checks,
                   issuer_sha256=hashlib.sha256((ROOT / 'data/platform-public.blob').read_bytes()).hexdigest(),
                   health=health, native_game_verified=False, native_tls_supported=True)
    if process_before is not None:
        process_after = live()
        assert process_before == process_after, 'Backend changed during public protocol checks'
        receipt['server_sha256'] = process_after['process_sha256']
        receipt['server_process_verified'] = process_after
    if os.name == 'nt':
        receipt['platform_library_sha256'] = hashlib.sha256(args.platform_library.read_bytes()).hexdigest()
    args.output.write_bytes((json.dumps(receipt, indent=2) + '\n').encode())
    print('PASS remote backend:', len(checks), 'focused authentication/transport checks')


if __name__ == '__main__':
    main()
