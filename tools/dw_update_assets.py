"""Bounded owned overlay manifest, authenticated inside the signed full EXE."""
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
MAGIC = b'REPLAYDWASSET01\0'
HEADER = struct.Struct('<16sIIII32s32s')
ENTRY = struct.Struct('<96s32sQ')
MAX_FILES, MAX_BYTES = 256, 64 * 1024 * 1024
OWNED = re.compile(r'^(?:[a-z0-9_]{0,16}_)?dw_bot_styles_mp_([0-9a-f]{16})\.(ff|fp)$')

def native_folder_policy(proof):
    """Freeze the target-derived filename prefix policy into the helper.

    The wire manifest retains flat owned names for older helpers. Native folder
    rules are reusable across bundle hashes and authenticated inside the EXE.
    """
    rules = proof['native_folder_rules']
    prefixes = set()
    for rule in rules:
        prefix, directory = rule['name_prefix'], rule['directory']
        if (not re.fullmatch(r'(?:[a-z0-9]{1,16}_|_|)', prefix)
                or not re.fullmatch(r'[a-z0-9_]{0,32}', directory)
                or directory in ('.', '..') or prefix in prefixes):
            raise ValueError('Invalid target native folder policy')
        prefixes.add(prefix)
    if not rules or len(rules) > 128 or '' not in prefixes:
        raise ValueError('Incomplete native folder policy')
    directories = {rule['name_prefix']: rule['directory'] for rule in rules}
    for item in proof['installation_manifest']:
        name = item['name']
        if not OWNED.fullmatch(name):
            raise ValueError('Native folder policy contains a non-owned asset')
        prefix = name[:name.index('dw_bot_styles_mp_')]
        if prefix not in directories:
            raise ValueError('Owned asset has no target native folder')
        directory = directories[prefix]
        relative = (directory + '/' if directory else '') + name
        if item['relative_path'] != relative:
            raise ValueError('Native package destination differs from its folder policy')
    return rules

def folder_header(rules):
    lines = [
        '#pragma once',
        '// Replay 1.20 folder rules recovered from its native locale tables.',
        '// Prefixes remain valid when a future content-addressed bundle changes.',
        'struct DWUpdateAssetFolderRule { const char *prefix; const char *directory; };',
        'inline constexpr DWUpdateAssetFolderRule s_dwUpdateAssetFolderRules[] = {',
    ]
    lines.extend('    {' + json.dumps(rule['name_prefix']) + ', '
                 + json.dumps(rule['directory']) + '},' for rule in rules)
    return ('\n'.join(lines + ['};', ''])).encode('ascii')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def decode(blob):
    if len(blob) < HEADER.size:
        raise ValueError('Incomplete asset manifest')
    magic, version, size, count, reserved, expected, bundle = HEADER.unpack_from(blob)
    if magic != MAGIC or version != 1 or reserved or not 0 < count <= MAX_FILES or size != len(blob) or size != HEADER.size + ENTRY.size * count:
        raise ValueError('Invalid owned asset manifest bounds')
    payload = blob[HEADER.size:]
    if hashlib.sha256(bundle + payload).digest() != expected:
        raise ValueError('Asset manifest entries failed SHA256')
    entries, names = [], set()
    for at in range(0, len(payload), ENTRY.size):
        name_bytes, digest, size = ENTRY.unpack_from(payload, at)
        name, nul, tail = name_bytes.partition(b'\0')
        if not nul or any(tail):
            raise ValueError('Invalid owned asset name padding')
        name = name.decode('ascii')
        match = OWNED.fullmatch(name)
        if not match or name in names or not 0 < size <= MAX_BYTES:
            raise ValueError('Unsafe, duplicate or oversized owned asset')
        names.add(name)
        entries.append(dict(name=name, sha256=digest.hex(), size=size))
    primary = [x for x in entries if x['name'].startswith('dw_bot_styles_mp_') and x['name'].endswith('.ff')]
    if len(primary) != 1:
        raise ValueError('Manifest needs exactly one owned primary fastfile')
    zone = primary[0]['name'][:-3]
    if zone[-16:] != bundle.hex()[:16]:
        raise ValueError('Owned zone name is not bound to the complete resource bundle')
    for entry in entries:
        match = OWNED.fullmatch(entry['name'])
        if match.group(1) != zone[-16:] or entry['name'][:-3] + ('.fp' if entry['name'].endswith('.ff') else '.ff') not in names:
            raise ValueError('Mismatched or incomplete FF/FP companion pair')
    unique = {x['sha256']: x['size'] for x in entries}
    if any(unique[x['sha256']] != x['size'] for x in entries) or len(unique) > 4:
        raise ValueError('Owned overlay has inconsistent payloads')
    return entries

def extract(image):
    records, at = [], 0
    while True:
        at = image.find(MAGIC, at)
        if at < 0:
            break
        if len(image) - at >= HEADER.size:
            _, version, size, count, reserved, _, _ = HEADER.unpack_from(image, at)
            if version == 1 and not reserved and 0 < count <= MAX_FILES and size == HEADER.size + ENTRY.size * count and size <= len(image) - at:
                blob = image[at:at + size]
                decode(blob)
                records.append(blob)
        at += len(MAGIC)
    if len(records) > 1:
        raise ValueError('Multiple owned asset records in target executable')
    return records[0] if records else None

def encode(entries, bundle_hash):
    if not re.fullmatch('[0-9a-f]{64}', bundle_hash):
        raise ValueError('Invalid owned resource bundle identity')
    bundle = bytes.fromhex(bundle_hash)
    payload = bytearray()
    for entry in entries:
        name = entry['name'].encode('ascii')
        if len(name) >= 96 or not re.fullmatch('[0-9a-f]{64}', entry['sha256']):
            raise ValueError('Invalid asset manifest input')
        payload += ENTRY.pack(name, bytes.fromhex(entry['sha256']), entry['size'])
    result = HEADER.pack(MAGIC, 1, HEADER.size + len(payload), len(entries), 0, hashlib.sha256(bundle + payload).digest(), bundle) + payload
    decode(result)
    return result

def prepare(snapshot):
    snapshot = Path(snapshot).resolve()
    if not snapshot.is_relative_to((ROOT / 'data').resolve()):
        raise ValueError('Asset manifests require a private source snapshot')
    path = snapshot / 'generated/bot-style-scripts/package-proof.json'
    original = path.read_bytes()
    proof = json.loads(original)
    if proof.get('schema') != 'replay120-bot-style-native-overlay-v1' or not proof.get('packaged') or proof.get('direct_static_bytecode_delivery'):
        raise ValueError('Native owned overlay proof is missing')
    folder_rules = native_folder_policy(proof)
    entries, payloads = [], {}
    for item in proof['installation_manifest']:
        source = Path(item['source']).resolve()
        if not source.is_relative_to(snapshot / 'generated/bot-style-scripts'):
            raise ValueError('Owned asset input escaped its private native package')
        data = source.read_bytes()
        digest = sha(data)
        if digest != item['sha256'] or len(data) != item['size']:
            raise ValueError('Native package asset changed after verification')
        entries.append(dict(name=item['name'], sha256=digest, size=len(data)))
        payloads[digest] = dict(source=str(source), size=len(data))
    entries.sort(key=lambda item: item['name'])
    main = Path(proof['output_fastfile'])
    empty = Path(proof['empty_companion']['output_fastfile'])
    resources = (main, main.with_suffix('.fp'), empty, empty.with_suffix('.fp'))
    if any(not path.resolve().is_relative_to(snapshot / 'generated/bot-style-scripts') for path in resources):
        raise ValueError('Native bundle input escaped its private package')
    bundle = sha(b''.join(path.read_bytes() for path in resources))
    if bundle != proof['resource_bundle_sha256']:
        raise ValueError('Native resource bundle changed after verification')
    manifest = encode(entries, bundle)
    header = snapshot / 'src/DW_UpdateAssetManifest.h'
    lines = ['#pragma once', '// Hash-bound owned overlay manifest, embedded in the update helper.',
             'inline const unsigned char s_dwUpdateAssetManifest[] = {']
    lines.extend('    ' + ','.join(f'0x{x:02x}' for x in manifest[at:at + 24]) + ',' for at in range(0, len(manifest), 24))
    header.write_bytes(('\n'.join(lines + ['};', ''])).encode('ascii'))
    paths_header = snapshot / 'src/DW_UpdateAssetPaths.h'
    paths_header.write_bytes(folder_header(folder_rules))
    record = dict(schema=1, manifest_sha256=sha(manifest), manifest_size=len(manifest), bundle_sha256=bundle,
                  package_proof_sha256=sha(original), package_proof=str(path), entries=entries,
                  payloads=payloads, embedded_header=str(header),
                  native_folder_rules=folder_rules, native_folder_header=str(paths_header),
                  native_folder_header_sha256=sha(paths_header.read_bytes()),
                  relative_paths={item['name']: item['relative_path']
                                  for item in proof['installation_manifest']})
    (snapshot / 'generated/update-assets.bin').write_bytes(manifest)
    (snapshot / 'generated/update-assets.json').write_text(json.dumps(record, indent=2) + '\n')
    return record

def publication(image, source, output):
    source, output = Path(source).resolve(), Path(output)
    record = json.loads((source / 'generated/update-assets.json').read_bytes())
    embedded = extract(Path(image).read_bytes())
    if embedded is None or sha(embedded) != record['manifest_sha256'] or decode(embedded) != record['entries']:
        raise ValueError('Full EXE does not contain its exact frozen asset manifest')
    package = source / 'generated/bot-style-scripts'
    proof = Path(record['package_proof']).resolve()
    if proof != package / 'package-proof.json' or sha(proof.read_bytes()) != record['package_proof_sha256']:
        raise ValueError('Native package proof changed before publication')
    folder_rules = native_folder_policy(json.loads(proof.read_bytes()))
    paths_header = source / 'src/DW_UpdateAssetPaths.h'
    if (folder_rules != record['native_folder_rules']
            or paths_header.read_bytes() != folder_header(folder_rules)
            or sha(paths_header.read_bytes()) != record['native_folder_header_sha256']):
        raise ValueError('Target native folder policy changed before publication')
    expected = {item['sha256']: item['size'] for item in record['entries']}
    if expected != {digest: item['size'] for digest, item in record['payloads'].items()}:
        raise ValueError('Publication payload inventory does not match its embedded manifest')
    output.joinpath('assets').mkdir(exist_ok=True)
    for digest, payload in record['payloads'].items():
        path = Path(payload['source']).resolve()
        if not path.is_relative_to(package):
            raise ValueError('Publication payload escaped its frozen native package')
        data = path.read_bytes()
        if sha(data) != digest or len(data) != payload['size']:
            raise ValueError('Owned asset changed before publication')
        output.joinpath('assets', digest + '.bin').write_bytes(data)
    output.joinpath('update-assets.bin').write_bytes(embedded)
    output.joinpath('update-assets.json').write_text(json.dumps(record, indent=2) + '\n')
    return record
