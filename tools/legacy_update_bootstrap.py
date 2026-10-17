"""Bridge every retained version-1 updater identity to a published full image.

A size-specific RAW delta uses a periodic source with no matches in the target.
The Windows decoder requires the original source length. Complementary sources
verify that its contents are unused. Old helpers retain their signed plan,
base hash/size, delta hash and restored EXE checks without a protocol change.
"""
import ctypes
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import time
import urllib.request

import remote_backend

ROOT = Path(__file__).resolve().parents[1]
REMOTE = '/var/lib/replay-dw/updates'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def publish(image, catalog, output):
    output = Path(output).resolve()
    if not output.is_relative_to(ROOT / 'data'):
        raise ValueError('Legacy bootstrap output must stay in the DW data workspace')
    target = Path(image).read_bytes()
    if sha(target) != catalog['latest'] or len(target) != catalog['target_size']:
        raise ValueError('Legacy bootstrap target differs from the published full image')
    with remote_backend.connect() as client, client.open_sftp() as sftp:
        try:
            with sftp.file(REMOTE + '/catalog.json', 'rb') as stream:
                previous_bytes = stream.read(4 * 1024 * 1024 + 1)
        except FileNotFoundError:
            return dict(required=False)
        if len(previous_bytes) > 4 * 1024 * 1024:
            raise ValueError('Legacy catalog exceeds bounds')
        previous = json.loads(previous_bytes)
        if (previous['schema'] != 1 or previous['format'] != 'msdelta-raw-v1'
                or previous['release'] > catalog['release']):
            raise ValueError('Unexpected legacy catalog or release rollback')
        sizes = {digest: entry['base_size'] for digest, entry in previous['patches'].items()}
        sizes[previous['latest']] = previous['target_size']
        sizes.pop(catalog['latest'], None)
        if any(not re.fullmatch('[0-9a-f]{64}', h) or type(n) is not int
               or not 0 < n <= 512 * 1024 * 1024 for h, n in sizes.items()):
            raise ValueError('Legacy base identities exceed bounds')
        spec = importlib.util.spec_from_file_location('raw_bootstrap_delta', ROOT / 'tools/publish-executable-update.py')
        delta = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(delta)
        output.mkdir(parents=True, exist_ok=True)
        pattern = None
        for index in range(4096):
            candidate = bytes([(index * 73 + 17) % 256, (index * 151 + 31 + index // 256) % 256])
            if candidate[0] != candidate[1] and candidate + candidate[:1] not in target and candidate[1:] + candidate not in target:
                pattern = candidate
                break
        if pattern is None:
            raise ValueError('No source pattern without target matches was found')

        def prepare_patch(size):
            cache = output / ('size-' + str(size) + '.delta')
            original = (pattern * ((size + 1) // 2))[:size]
            patch = cache.read_bytes() if cache.exists() else delta.make_patch(original, target)
            if not 0 < len(patch) <= delta.MAX_IMAGE:
                raise ValueError('Legacy delta exceeds bounds')
            encoded = ctypes.create_string_buffer(patch)
            restored = ctypes.create_string_buffer(len(target))
            api = delta.delta_api().ApplyDeltaProvidedB
            api.argtypes = [ctypes.c_int64, delta.Input, delta.Input, ctypes.c_void_p, ctypes.c_size_t]
            api.restype = ctypes.c_int
            for sample in (pattern, bytes(value ^ 255 for value in pattern)):
                source = ctypes.create_string_buffer((sample * ((size + 1) // 2))[:size])
                if not api(0, delta.Input(ctypes.addressof(source), size, False),
                           delta.Input(ctypes.addressof(encoded), len(patch), False),
                           ctypes.addressof(restored), len(target)):
                    raise ctypes.WinError(ctypes.get_last_error())
                if sha(restored.raw) != catalog['latest']:
                    raise ValueError('Legacy delta depends on source contents')
            cache.write_bytes(patch)
            digest = sha(patch)
            payload = output / (digest + '.delta')
            if not payload.exists():
                payload.hardlink_to(cache)
            print('Verified legacy source size', size, 'with complementary source contents', flush=True)
            return size, dict(sha256=digest, size=len(patch), source=str(payload))

        with ThreadPoolExecutor(max_workers=3) as workers:
            prepared = dict(workers.map(prepare_patch, sorted(set(sizes.values()))))
        payloads = {entry['sha256']: entry for entry in prepared.values()}
        bridge = dict(schema=1, format='msdelta-raw-v1', release=catalog['release'],
                      latest=catalog['latest'], target_size=len(target),
                      patches={h: dict(base_size=n, size=prepared[n]['size'], sha256=prepared[n]['sha256']) for h, n in sizes.items()})
        document = (json.dumps(bridge, indent=2) + '\n').encode()
        (output / 'catalog.json').write_bytes(document)
        incoming = REMOTE + '/legacy-incoming-' + str(time.time_ns())
        _, stdout, stderr = client.exec_command('install -d -m 0755 ' + incoming, timeout=20)
        if stdout.channel.recv_exit_status():
            raise RuntimeError(stderr.read().decode())
        scp = shutil.which('scp')
        if scp:
            subprocess.run([scp, '-B', '-i', str(ROOT / '.toolchains/deploy_ed25519'),
                '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(ROOT / 'data/droplet-known-hosts'),
                *[item['source'] for item in payloads.values()], 'root@162.243.115.160:' + incoming + '/'], check=True)
        else:
            for h, item in payloads.items():
                sftp.put(item['source'], incoming + '/' + h + '.delta')
        sftp.put(str(output / 'catalog.json'), incoming + '/catalog.json')
        code = f'''
import pathlib,json,hashlib,fcntl,os,time
root=pathlib.Path({REMOTE!r});incoming=pathlib.Path({incoming!r})
def digest(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
with (root/'publication.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 assert json.loads((root/'full-image-catalog.json').read_bytes())=={catalog!r}
 assert digest(root/'catalog.json')=={sha(previous_bytes)!r},'Legacy catalog changed concurrently'
 assert digest(incoming/'catalog.json')=={sha(document)!r}
 new=json.loads((incoming/'catalog.json').read_bytes())
 patches=root/'patches';patches.mkdir(exist_ok=True)
 for h,size in { {h:item['size'] for h,item in payloads.items()}!r}.items():
  payload=incoming/(h+'.delta')
  assert payload.stat().st_size==size and digest(payload)==h
  final=patches/payload.name
  if final.exists():
   assert digest(final)==h;payload.unlink()
  else:os.chmod(payload,0o644);os.replace(payload,final)
  with final.open('rb') as f:os.fsync(f.fileno())
 fd=os.open(patches,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 backups=root/'legacy-catalog-backups';backups.mkdir(exist_ok=True)
 backup=backups/(str(time.time_ns())+'-'+{sha(previous_bytes)!r}+'.json')
 with backup.open('xb') as f:f.write((root/'catalog.json').read_bytes());f.flush();os.fsync(f.fileno())
 fd=os.open(backups,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 os.chmod(incoming/'catalog.json',0o644)
 with (incoming/'catalog.json').open('rb') as f:os.fsync(f.fileno())
 os.replace(incoming/'catalog.json',root/'catalog.json')
 fd=os.open(root,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 incoming.rmdir()
 print(json.dumps(dict(published=True,release=new['release'],latest=new['latest'],bases=len(new['patches']),backup=str(backup))))
'''
        _, stdout, stderr = client.exec_command("python3 - <<'PY'\n" + code + 'PY', timeout=60)
        raw = stdout.read()
        if stdout.channel.recv_exit_status():
            raise RuntimeError(stderr.read().decode())
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    trust = (ROOT / 'data/platform-public.blob').read_bytes()
    magic, bits, exponent_bytes, modulus_bytes, p1, p2 = struct.unpack_from('<6I', trust)
    if magic != 0x31415352 or bits != 2048 or p1 or p2:
        raise ValueError('Unexpected public signing key')
    public = rsa.RSAPublicNumbers(int.from_bytes(trust[24:24 + exponent_bytes], 'big'),
        int.from_bytes(trust[24 + exponent_bytes:24 + exponent_bytes + modulus_bytes], 'big')).public_key()
    plan_format = struct.Struct('<QIIQQ32s32s32s32sQQQQ')
    for base, size in [*sizes.items(), (catalog['latest'], len(target))]:
        nonce = secrets.token_bytes(32)
        before = int(time.time())
        request = struct.pack('<QII32s32s', 0x3155505744594C50, 1, 0, nonce, bytes.fromhex(base))
        with urllib.request.urlopen(urllib.request.Request(
                'http://162.243.115.160:8085/updates/v1/check', request), timeout=30) as response:
            signed = response.read(449)
        if len(signed) != 448:
            raise ValueError('Incomplete signed legacy update plan')
        public.verify(signed[192:], signed[:192], padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        values = plan_format.unpack(signed[:192])
        expected_status = 0 if base == catalog['latest'] else 1
        if (values[0:3] != (0x3155505744594C50, 1, expected_status)
                or not before - 5 <= values[3] <= int(time.time()) + 5 or values[4] <= values[3]
                or values[5] != nonce or values[6].hex() != base or values[7].hex() != catalog['latest']
                or values[9:11] != (size, len(target)) or values[12] != catalog['release']
                or (expected_status and (values[8].hex() != prepared[size]['sha256'] or values[11] != prepared[size]['size']))):
            raise ValueError('Legacy update plan does not bind its retained base and target')
    result = dict(json.loads(raw), passed=True, source_contents_independent=True, apply_delta_provided_verified=True,
                  signed_legacy_plans_verified=len(sizes) + 1,
                  source_sizes=len(prepared), complementary_source_checks=2 * len(prepared),
                  payloads={h:item['size'] for h,item in payloads.items()}, catalog_sha256=sha(document))
    (output / 'publication.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
