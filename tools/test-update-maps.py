"""Actual bounded Cabinet map transactions and signed asset-only helper; no game."""
import argparse
import copy
import ctypes
from ctypes import wintypes
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
import dw_update_maps as maps
from dw_update_assets import ROOT, prepare, sha


def unchecked(files, chunks, total=None):
    table = b''.join(maps.FILE.pack(item['path'].encode(), bytes.fromhex(item['sha256']), item['size'],
                    item['first_chunk'], item['chunk_count']) for item in files)
    payload = table + b''.join(maps.CHUNK.pack(bytes.fromhex(item['sha256']),
              bytes.fromhex(item['payload_sha256']), item['size'], item['payload_size']) for item in chunks)
    package = hashlib.sha256(table).digest()
    return maps.HEADER.pack(maps.MAGIC, 1, maps.HEADER.size + len(payload), len(files), len(chunks),
        sum(item['size'] for item in files) if total is None else total,
        hashlib.sha256(package + payload).digest(), package) + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--package-proof', type=Path)
    parser.add_argument('--frozen-source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    checks = []
    build_proof = None
    if args.build:
        build_proof = json.loads((args.build / 'build-report.json').read_bytes())
        source = Path(build_proof['source_root'])
        args.package_proof = args.package_proof or source / 'generated/bot-style-scripts/package-proof.json'
        args.frozen_source = args.frozen_source or source / 'src'
        frozen_helper = source / 'generated-updater/helper-source/tools'
        for name in ('replay-update-client.cpp', 'replay-update-assets.h', 'replay-update-maps.h'):
            assert maps.file_sha(frozen_helper / name) == maps.file_sha(ROOT / 'tools' / name), ('Helper source differs from compiled client', name)
        checks.append('Fixture helper sources match the exact frozen helper embedded in the compiled client')
    if args.package_proof is None or args.frozen_source is None:
        parser.error('Pass --build or both --package-proof and --frozen-source')
    with tempfile.TemporaryDirectory(prefix='update-maps-fixture-', dir=ROOT / 'data') as temporary:
        root = Path(temporary).resolve()
        assert root.parent == (ROOT / "data").resolve()
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
        (package / 'package-proof.json').write_text(json.dumps(proof))
        overlays = prepare(snapshot)
        overlay_blob = (snapshot / 'generated/update-assets.bin').read_bytes()
        payload_folder = root / 'payloads'; payload_folder.mkdir()
        for digest, item in overlays['payloads'].items():
            shutil.copyfile(item['source'], payload_folder / (digest + '.bin'))

        files, chunks, cabinet = [], [], maps.Cabinet()
        # Synthetic native headers are fixture inputs, not playable-map claims.
        ff = b'IWffc100' + struct.pack('<II', 11, 0xFF7) + bytes(156)
        raw_files = {name: ff for name in maps.filenames('mp_fixture')}
        raw_files['map.json'] = b'{"id":"mp_fixture","title":"Fixture"}'
        raw_files['mp_fixture.ff'] = ff + (b'bounded map chunk regression\0' * 160000)
        raw_files['techsets_mp_fixture.ff'] = ff + bytes(range(256)) * 25
        try:
            for name, raw in sorted(raw_files.items()):
                first = len(chunks)
                for at in range(0, len(raw), maps.CHUNK_BYTES):
                    section = raw[at:at + maps.CHUNK_BYTES]
                    transport = cabinet.compress(section); digest = sha(transport)
                    (payload_folder / (digest + '.bin')).write_bytes(transport)
                    chunks.append(dict(sha256=sha(section), payload_sha256=digest,
                                       size=len(section), payload_size=len(transport)))
                files.append(dict(path='mods/mw120r/maps/mp_fixture/' + name, sha256=sha(raw),
                                  size=len(raw), first_chunk=first, chunk_count=len(chunks) - first))
        finally:
            cabinet.close()
        map_blob = maps.encode(files, chunks)
        image = root / 'target.exe'; image.write_bytes(b'MZ' + bytes(62) + overlay_blob + map_blob)
        header = snapshot / 'src/DW_UpdateMapManifest.h'
        header.write_text('#pragma once\nstatic const unsigned char s_dwUpdateMapManifest[]={' +
                          ','.join(str(value) for value in map_blob) + '};\n')

        cmake = root / 'CMakeLists.txt'
        cmake.write_text('cmake_minimum_required(VERSION 3.24)\nproject(update_maps_fixture LANGUAGES CXX)\n'
            f'add_executable(update-maps "{(ROOT / "tools/update_maps_harness.cpp").as_posix()}")\n'
            'target_compile_features(update-maps PRIVATE cxx_std_20)\n'
            f'target_include_directories(update-maps PRIVATE "{(snapshot / "src").as_posix()}")\n'
            'target_compile_definitions(update-maps PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)\n'
            'target_compile_options(update-maps PRIVATE /W4 /WX /EHsc)\n'
            'target_link_libraries(update-maps PRIVATE bcrypt cabinet)\n')
        flags = subprocess.CREATE_NO_WINDOW
        subprocess.run(['cmake', '-S', str(root), '-B', str(root / 'build'), '-G', 'Visual Studio 18 2026', '-A', 'x64'], check=True, creationflags=flags)
        subprocess.run(['cmake', '--build', str(root / 'build'), '--config', 'Release', '--parallel', '2'], check=True, creationflags=flags)
        harness = root / 'build/Release/update-maps.exe'
        subprocess.run([str(harness), str(root / 'installations'), str(image), str(payload_folder)], check=True, creationflags=flags)
        long_root = root / ('t' * (125 - len(str(root)) - 1))
        long_root.mkdir()
        subprocess.run([str(harness), str(long_root), str(image), str(payload_folder)], check=True, creationflags=flags)
        checks.append('Actual extended-path map staging, backups, install and rollback succeed beyond MAX_PATH without registry or manifest changes')
        checks.append('Six actual Windows transactions cover bounded chunk decoding, no decode before transport authentication, corrupt staging, shared overlay/map atomic rollback, new-file rollback and commit')
        for issue in ('traversal', 'stock', 'psob', 'long-id', 'missing', 'duplicate', 'over-file', 'over-chunk', 'coverage', 'total', 'table-hash', 'multiple'):
            bad_files, bad_chunks = copy.deepcopy(files), copy.deepcopy(chunks)
            if issue == 'traversal': bad_files[0]['path'] = 'mods/mw120r/maps/mp_fixture/../game.exe'
            elif issue == 'stock': bad_files[0]['path'] = 'zone/common_base_mp.ff'
            elif issue == 'psob': bad_files[0]['path'] = 'mods/mw120r/maps/mp_fixture/mp_fixture.psob'
            elif issue == 'long-id': bad_files[0]['path'] = 'mods/mw120r/maps/mp_abcdefghijklmnop/map.json'
            elif issue == 'missing': bad_files.pop()
            elif issue == 'duplicate': bad_files[1]['path'] = bad_files[0]['path']
            elif issue == 'over-file': bad_files[0]['size'] = maps.MAX_FILE + 1
            elif issue == 'over-chunk': bad_chunks[0]['payload_size'] = maps.MAX_TRANSPORT + 1
            elif issue == 'coverage': bad_files[0]['first_chunk'] = 1
            blob = unchecked(bad_files, bad_chunks, 1 if issue == 'total' else None)
            if issue == 'table-hash': blob = blob[:-1] + bytes([blob[-1] ^ 1])
            if issue == 'multiple': blob += blob
            bad = root / ('bad-' + issue + '.exe'); bad.write_bytes(b'MZ' + blob)
            result = subprocess.run([str(harness), '--parse', str(bad), str(payload_folder)], capture_output=True, creationflags=flags)
            assert result.returncode != 0, (issue, result.stdout, result.stderr)
            checks.append('Compiled parser rejected ' + issue)

        for name in ('dw_local_trust.h', 'dw_update_protocol.h'):
            shutil.copyfile(args.frozen_source / name, snapshot / 'src' / name)
        shutil.copyfile(ROOT / 'integration/replay/dw_update_assets_protocol.h', snapshot / 'src/dw_update_assets_protocol.h')
        shutil.copyfile(ROOT / 'integration/replay/dw_update_maps_protocol.h', snapshot / 'src/dw_update_maps_protocol.h')
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = key.public_key().public_numbers()
        trust_blob = struct.pack('<6I', 0x31415352, 2048, 3, 256, 0, 0) + public.e.to_bytes(3, 'big') + public.n.to_bytes(256, 'big')
        trust = snapshot / 'src/dw_local_trust.h'
        trust.write_text(re.sub(r'(s_dwLocalPlatformPublicKey\[\]\s*=\s*\{).*?(\};)',
            lambda match: match[1] + ','.join(str(value) for value in trust_blob) + match[2], trust.read_text(), flags=re.S))
        spec = importlib.util.spec_from_file_location('embed_maps', ROOT / 'tools/embed-update-helper.py')
        embed = importlib.util.module_from_spec(spec); spec.loader.exec_module(embed)
        helper = embed.build(snapshot / 'src', root / 'DW_UpdateHelper.h')
        target = image.read_bytes(); requests = []; slow = False
        class Server(http.server.BaseHTTPRequestHandler):
            def log_message(self, *unused): pass
            def respond(self, body):
                self.send_response(200); self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                request = self.rfile.read(int(self.headers['Content-Length']))
                magic, version, reserved, nonce, base = struct.unpack('<QII32s32s', request)
                assert self.path == '/updates/v2/check' and version == 2 and reserved == 0
                current = base == hashlib.sha256(target).digest(); now = int(time.time())
                expires = now + (2 if slow and not requests else 300)
                digest = hashlib.sha256(target).digest()
                plan = struct.pack('<QIIQQ32s32s32s32sQQQQ', magic, 2, 0 if current else 1,
                    now, expires, nonce, base, digest, bytes(32) if current else digest,
                    0, len(target), 0 if current else len(target), 30)
                signature = key.sign(plan, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
                requests.append(('check', nonce.hex(), expires)); self.respond(plan + signature)
            def do_GET(self):
                if self.path == '/updates/v2/image/' + sha(target):
                    requests.append(('image',)); self.respond(target)
                else:
                    prefix = '/updates/v2/asset/'; assert self.path.startswith(prefix)
                    digest = self.path[len(prefix):]; data = (payload_folder / (digest + '.bin')).read_bytes()
                    if slow and digest == chunks[0]['payload_sha256']: time.sleep(3)
                    requests.append(('asset', digest)); self.respond(data)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 8085), Server)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            def run(exe, mode, expected):
                result = subprocess.run([str(helper), mode, str(exe), '127.0.0.1'], capture_output=True,
                                        creationflags=flags, timeout=120)
                log = Path(str(exe) + '.update') / 'result.log'
                assert result.returncode == expected, (result.returncode, expected, log.read_text() if log.exists() else result.stderr)
            custom = root / 'custom/game.exe'; custom.parent.mkdir(); custom.write_bytes(b'MZcustom-owned-client')
            requests.clear(); slow = True
            run(custom, '--prepare-assets', 20); slow = False
            assert custom.read_bytes() == b'MZcustom-owned-client'
            stage = Path(str(custom) + '.update')
            assert not (stage / 'next.exe').exists() and (stage / 'verified-target.exe').read_bytes() == target
            assert not (custom.parent / 'mods').exists() and not (custom.parent / 'zone').exists()
            plans = [item for item in requests if item[0] == 'check']
            assert len(plans) == 2 and plans[0][1] != plans[1][1] and plans[0][2] <= int(time.time()) < plans[1][2]
            checks.append('Actual CNG helper authenticates custom-client asset-only staging, preserves EXE, stages no destination files and refreshes expired transfer plan with a new signed nonce')
            for item in files:
                staged = stage / 'asset-staging' / sha(target) / ('map-' + item['sha256'] + '.bin')
                assert maps.file_sha(staged) == item['sha256'] and staged.stat().st_size == item['size']
            staging_root = stage / 'asset-staging' / sha(target)
            assert not list(staging_root.glob('chunk-*.bin')) and not list(staging_root.glob('partial-*.bin'))
            checks.append('Actual XPRESS_HUFF helper restores every exact streamed file hash and size and deletes the downloaded chunks')
            unicode_prefix = 'deep_é_地图_'
            deep_folder = root / (unicode_prefix + 'd' * (125 - len(str(root)) - 1 - len(unicode_prefix)))
            deep_folder.mkdir()
            deep_exe = deep_folder / 'game_dx12_ship_replay_dw.exe'
            deep_exe.write_bytes(b'MZcustom-owned-client')
            run(deep_exe, '--prepare-assets', 20)
            deep_stage = Path(str(deep_exe) + '.update')
            for item in files:
                staged = deep_stage / 'asset-staging' / sha(target) / ('map-' + item['sha256'] + '.bin')
                assert len(str(staged)) > 260 and maps.file_sha(staged) == item['sha256']
            assert deep_exe.read_bytes() == b'MZcustom-owned-client' and not (deep_exe.parent / 'mods').exists()
            checks.append('Actual signed helper stages every exact map and overlay under a deep Unicode game folder with staging paths exceeding 317 characters')
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                          wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
            kernel.SetFileAttributesW.restype = wintypes.BOOL
            for problem, code in (('locked', 32), ('readonly', 5)):
                blocked = root / problem / 'game_dx12_ship_replay_dw.exe'
                blocked.parent.mkdir(); blocked.write_bytes(b'MZcustom-owned-client')
                for item in overlays['entries']:
                    destination = blocked.parent / 'zone' / overlays['relative_paths'][item['name']]
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(payload_folder / (item['sha256'] + '.bin'), destination)
                partial = Path(str(blocked) + '.update') / 'asset-staging' / sha(target) / ('partial-' + files[0]['sha256'] + '.bin')
                partial.parent.mkdir(parents=True); partial.write_bytes(b'')
                native = '\\\\?\\' + str(partial.resolve())
                handle = None
                if problem == 'locked':
                    handle = kernel.CreateFileW(native, 0x80000000, 0, None, 3, 0x80, None)
                    assert handle != wintypes.HANDLE(-1).value
                else:
                    assert kernel.SetFileAttributesW(native, 1)
                try:
                    run(blocked, '--prepare-assets', 40)
                    log = (Path(str(blocked) + '.update') / 'result.log').read_text()
                    assert 'Cannot stage map (Windows error ' + str(code) + ')' in log, log
                    assert 'check free space' not in log
                    assert blocked.read_bytes() == b'MZcustom-owned-client' and not (blocked.parent / 'mods').exists()
                finally:
                    if handle: kernel.CloseHandle(handle)
                    if problem == 'readonly': assert kernel.SetFileAttributesW(native, 0x80)
                run(blocked, '--prepare-assets', 20)
                checks.append('Actual helper reports ' + problem + ' cache Windows error ' + str(code) + ' precisely and reuses the same staging location on retry')

            # A new signed target is still insufficient if its owned manifest differs
            # from the frozen helper which will run with the custom installed EXE.
            bad_files = copy.deepcopy(files); bad_files[0]['sha256'] = 'a' * 64
            target = b'MZ' + bytes(62) + overlay_blob + unchecked(bad_files, chunks)
            other = root / 'other/game.exe'; other.parent.mkdir(); other.write_bytes(b'MZcustom-owned-client')
            run(other, '--prepare-assets', 40)
            assert other.read_bytes() == b'MZcustom-owned-client' and not (other.parent / 'mods').exists()
            checks.append('Asset-only custom client rejects a signed latest target whose frozen map manifest differs')
            for failure in ('raw-hash', 'decompress', 'whole-file-hash'):
                altered_files, altered_chunks = copy.deepcopy(files), copy.deepcopy(chunks)
                if failure == 'raw-hash': altered_chunks[0]['sha256'] = 'b' * 64
                elif failure == 'whole-file-hash': altered_files[0]['sha256'] = 'c' * 64
                else:
                    broken = b'not-a-Cabinet-buffer'
                    digest = sha(broken); (payload_folder / (digest + '.bin')).write_bytes(broken)
                    altered_chunks[0]['payload_sha256'] = digest
                    altered_chunks[0]['payload_size'] = len(broken)
                target = b'MZ' + bytes(62) + overlay_blob + unchecked(altered_files, altered_chunks)
                failure_exe = root / failure / 'game.exe'; failure_exe.parent.mkdir()
                failure_exe.write_bytes(b'MZprior-release-fixture')
                before = len(requests)
                run(failure_exe, '--prepare', 20)
                # Executable first: an outdated client stages only the signed EXE
                # and downloads no asset or map data.
                assert failure_exe.read_bytes() == b'MZprior-release-fixture'
                assert (Path(str(failure_exe) + '.update') / 'next.exe').read_bytes() == target
                assert not any(item[0] == 'asset' for item in requests[before:])
                assert not (failure_exe.parent / 'mods').exists() and not (failure_exe.parent / 'zone').exists()
                # Once that EXE is the one running, its own data staging rejects the map.
                failure_exe.write_bytes(target)
                run(failure_exe, '--prepare', 40)
                assert failure_exe.read_bytes() == target
                assert not (failure_exe.parent / 'mods').exists() and not (failure_exe.parent / 'zone').exists()
                checks.append('Outdated client stages only the signed EXE; the latest EXE then rejects ' + failure +
                              ' before writing any installed destination')

        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(passed=True, checks=checks, fixture_signing_key_only=True,
        compiled_client_sha256=build_proof["sha256"] if build_proof else None,
        bounded_chunk_bytes=maps.CHUNK_BYTES, game_launched=False, installed_game_modified=False,
        production_server_restarted=False, private_fixture_removed=True), indent=2) + '\n')
    print('PASS', len(checks), 'native compressed-map helper gates')


if __name__ == '__main__': main()
