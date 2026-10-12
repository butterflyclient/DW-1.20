"""Compiled updater with isolated signed HTTP fixtures; no game or live service."""
import argparse
import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dw_update_assets import ROOT, prepare, decode, sha

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-proof', required=True, type=Path)
    parser.add_argument('--frozen-source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    checks = []
    with tempfile.TemporaryDirectory(prefix='update-assets-helper-', dir=ROOT / 'data') as temporary:
        root = Path(temporary).resolve()
        assert root.parent == (ROOT / 'data').resolve()
        snapshot = root / 'source'; package = snapshot / 'generated/bot-style-scripts'
        package.mkdir(parents=True); (snapshot / 'src').mkdir()
        proof = json.loads(args.package_proof.read_bytes()); copied = {}
        for item in proof['installation_manifest']:
            original = Path(item['source']); target = package / original.name
            if str(original) not in copied:
                shutil.copyfile(original, target); copied[str(original)] = str(target)
            item['source'] = str(target)
        proof['output_fastfile'] = copied[proof['output_fastfile']]
        proof['empty_companion']['output_fastfile'] = copied[proof['empty_companion']['output_fastfile']]
        (package / 'package-proof.json').write_text(json.dumps(proof) + '\n')
        record = prepare(snapshot)
        for filename in ('DW_LocalPlatformCrypto.cpp', 'dw_platform_protocol.h', 'dw_local_trust.h', 'dw_update_protocol.h'):
            shutil.copyfile(args.frozen_source / filename, snapshot / 'src' / filename)
        shutil.copyfile(ROOT / 'integration/replay/dw_update_assets_protocol.h', snapshot / 'src/dw_update_assets_protocol.h')
        # The real shipping crypto implementation uses an isolated fixture key.
        # No production private key, identity, authentication token or game data.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = key.public_key().public_numbers()
        exponent = public.e.to_bytes(3, 'big'); modulus = public.n.to_bytes(256, 'big')
        blob = struct.pack('<6I', 0x31415352, 2048, 3, 256, 0, 0) + exponent + modulus
        trust = snapshot / 'src/dw_local_trust.h'
        text = trust.read_text()
        text = re.sub(r'(s_dwLocalPlatformPublicKey\[\]\s*=\s*\{).*?(\};)',
                      lambda match: match[1] + ','.join(f'0x{x:02x}' for x in blob) + match[2], text, flags=re.S)
        trust.write_text(text)
        spec = importlib.util.spec_from_file_location('embed', ROOT / 'tools/embed-update-helper.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        helper = module.build(snapshot / 'src', root / 'DW_UpdateHelper.h')
        manifest = (snapshot / 'generated/update-assets.bin').read_bytes()
        target_bytes = b'MZ' + bytes(62) + manifest
        target_hash = hashlib.sha256(target_bytes).digest()
        payloads = {digest: Path(item['source']).read_bytes() for digest, item in record['payloads'].items()}
        corrupt = False
        requests = []
        class Server(http.server.BaseHTTPRequestHandler):
            def log_message(self, *unused): pass
            def respond(self, body):
                self.send_response(200); self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                request = self.rfile.read(int(self.headers['Content-Length']))
                magic, version, reserved, nonce, base = struct.unpack('<QII32s32s', request)
                assert self.path == '/updates/v2/check' and version == 2 and reserved == 0
                current = base == target_hash; now = int(time.time())
                plan = struct.pack('<QIIQQ32s32s32s32sQQQQ', magic, 2, 0 if current else 1,
                    now, now + 300, nonce, base, target_hash, bytes(32) if current else target_hash,
                    0, len(target_bytes), 0 if current else len(target_bytes), 27)
                signature = key.sign(plan, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
                requests.append(('check', current)); self.respond(plan + signature)
            def do_GET(self):
                if self.path == '/updates/v2/image/' + target_hash.hex():
                    requests.append(('image',)); self.respond(target_bytes)
                else:
                    prefix = '/updates/v2/asset/'
                    assert self.path.startswith(prefix)
                    digest = self.path[len(prefix):]; data = payloads[digest]
                    requests.append(('asset', digest))
                    self.respond(bytes([data[0] ^ 1]) + data[1:] if corrupt else data)
        # A busy port fails before changing any live process or service.
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 8085), Server)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            def run(image, expected):
                result = subprocess.run([str(helper), '--prepare', str(image), '127.0.0.1'],
                    capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=90)
                assert result.returncode == expected, (result.returncode, expected, result.stdout, result.stderr,
                    (Path(str(image) + '.update') / 'result.log').read_text())
            older = root / 'old.exe'; old_bytes = b'MZprevious signed-release fixture'; older.write_bytes(old_bytes)
            run(older, 20)
            assert older.read_bytes() == old_bytes and (Path(str(older) + '.update') / 'next.exe').read_bytes() == target_bytes
            assert len([x for x in requests if x[0] == 'asset']) == 4
            checks.append('Actual compiled helper stages signed full EXE and all four separately downloaded target-bound native payloads')
            current = root / 'current.exe'; current.write_bytes(target_bytes); before = len(requests)
            run(current, 20)
            assert current.read_bytes() == target_bytes and not (Path(str(current) + '.update') / 'next.exe').exists()
            assert len([x for x in requests[before:] if x[0] == 'asset']) == 4 and not (root / 'zone').exists()
            checks.append('Current signed EXE repairs missing assets by staging for clean exit without staging another EXE or writing zone files')
            (root / 'zone').mkdir()
            for item in decode(manifest):
                destination = root / 'zone' / record['relative_paths'][item['name']]
                destination.parent.mkdir(exist_ok=True)
                destination.write_bytes(payloads[item['sha256']])
            before = len(requests); run(current, 10)
            assert requests[before:] == [('check', True)]
            checks.append('Current EXE with exact owned assets receives current status and downloads nothing')
            for release in (3, 11, 24):
                skipped = root / ('release-' + str(release) + '.exe')
                prior = b'MZskipped-release fixture ' + str(release).encode('ascii')
                skipped.write_bytes(prior); before = len(requests)
                run(skipped, 20)
                assert skipped.read_bytes() == prior
                assert (Path(str(skipped) + '.update') / 'next.exe').read_bytes() == target_bytes
                assert requests[before:] == [('check', False), ('image',)]
            checks.append('Three distinct older release hashes reach the same signed latest full image and exact asset inventory without intermediate updates')
            corrupt = True
            failure = root / 'bad' / 'game.exe'; failure.parent.mkdir(); failure.write_bytes(old_bytes)
            run(failure, 40)
            assert failure.read_bytes() == old_bytes and not (Path(str(failure) + '.update') / 'next.exe').exists()
            assert not (failure.parent / 'zone').exists()
            checks.append('Corrupted asset under a valid signed EXE plan aborts staging and preserves original executable and zone files')
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(passed=True, checks=checks, compiled_shipping_crypto=True,
        fixture_signing_key_only=True, game_launched=False, production_identity_used=False,
        production_server_restarted=False, installed_game_modified=False, private_fixture_removed=True), indent=2) + '\n')
    print('PASS', len(checks), 'compiled signed helper asset download/current-version gates')

if __name__ == '__main__': main()
