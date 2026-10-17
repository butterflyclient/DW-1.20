"""Bounded owned overlay manifest, authenticated inside the signed full EXE."""
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
MAGIC = b'REPLAYDWASSET01\0'
MAGIC_V2 = b'REPLAYDWASSET02\0'
HEADER = struct.Struct('<16sIIII32s32s')
ENTRY = struct.Struct('<96s32sQ')
GROUP = struct.Struct('<II32s')
MAX_FILES, MAX_BYTES = 256, 64 * 1024 * 1024
OWNED = re.compile(r'^(?:[a-z0-9_]{0,16}_)?dw_bot_styles_mp_([0-9a-f]{16})\.(ff|fp)$')
OWNERS = {1: 'dw_bot_styles_mp_', 2: 'dw_weapon_inspect_mp_'}

def owned_name(name, owner):
    return re.fullmatch(r'(?:[a-z0-9_]{0,16}_)?' + OWNERS[owner] + r'([0-9a-f]{16})\.(ff|fp)', name)

def native_folder_policy(proof, owner=1):
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
        if not owned_name(name, owner):
            raise ValueError('Native folder policy contains a non-owned asset')
        prefix = name[:name.index(OWNERS[owner])]
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

def decode_group(payload, count, bundle, owner):
    if owner not in OWNERS or not 0 < count <= MAX_FILES or len(payload) != ENTRY.size * count:
        raise ValueError('Invalid owned group bounds')
    entries, names = [], set()
    for at in range(0, len(payload), ENTRY.size):
        name_bytes, digest, size = ENTRY.unpack_from(payload, at)
        name, nul, tail = name_bytes.partition(b'\0')
        if not nul or any(tail):
            raise ValueError('Invalid owned asset name padding')
        name = name.decode('ascii')
        match = owned_name(name, owner)
        if not match or name in names or not 0 < size <= MAX_BYTES:
            raise ValueError('Unsafe, duplicate or oversized owned asset')
        names.add(name)
        entries.append(dict(name=name, sha256=digest.hex(), size=size))
    primary = [x for x in entries if x['name'].startswith(OWNERS[owner]) and x['name'].endswith('.ff')]
    if len(primary) != 1:
        raise ValueError('Manifest needs exactly one owned primary fastfile per group')
    zone = primary[0]['name'][:-3]
    if zone[-16:] != bundle.hex()[:16]:
        raise ValueError('Owned zone name is not bound to the complete resource bundle')
    for entry in entries:
        match = owned_name(entry['name'], owner)
        if match.group(1) != zone[-16:] or entry['name'][:-3] + ('.fp' if entry['name'].endswith('.ff') else '.ff') not in names:
            raise ValueError('Mismatched or incomplete FF/FP companion pair')
    unique = {x['sha256']: x['size'] for x in entries}
    if any(unique[x['sha256']] != x['size'] for x in entries) or len(unique) > 4:
        raise ValueError('Owned overlay has inconsistent payloads')
    return entries

def decode_groups(blob):
    if len(blob) < HEADER.size:
        raise ValueError('Incomplete asset manifest')
    magic, version, size, count, reserved, expected, bundle = HEADER.unpack_from(blob)
    legacy = magic == MAGIC and version == 1 and reserved == 0
    aggregate = magic == MAGIC_V2 and version == 2 and reserved == 2
    if (not (legacy or aggregate) or not 0 < count <= MAX_FILES or size != len(blob)
            or size != HEADER.size + ENTRY.size * count + (GROUP.size * reserved if aggregate else 0)):
        raise ValueError('Invalid owned asset manifest bounds')
    payload = blob[HEADER.size:]
    if hashlib.sha256(bundle + payload).digest() != expected:
        raise ValueError('Asset manifest entries failed SHA256')
    if legacy:
        return [dict(owner=1, bundle_sha256=bundle.hex(), entries=decode_group(payload, count, bundle, 1))]
    groups, descriptors, at, total = [], bytearray(), 0, 0
    for expected_owner in (1, 2):
        if len(payload) - at < GROUP.size:
            raise ValueError('Truncated owned group')
        descriptor = payload[at:at + GROUP.size]
        owner, group_count, identity = GROUP.unpack(descriptor)
        if owner != expected_owner or group_count > count - total:
            raise ValueError('Duplicate, unknown or unordered owned group')
        at += GROUP.size
        end = at + ENTRY.size * group_count
        entries = decode_group(payload[at:end], group_count, identity, owner)
        groups.append(dict(owner=owner, bundle_sha256=identity.hex(), entries=entries))
        descriptors += descriptor
        total += group_count
        at = end
    if at != len(payload) or total != count or hashlib.sha256(descriptors).digest() != bundle:
        raise ValueError('Invalid aggregate owned group identity')
    sizes = {}
    for group in groups:
        for entry in group['entries']:
            if sizes.setdefault(entry['sha256'], entry['size']) != entry['size']:
                raise ValueError('Inconsistent cross-group payload size')
    return groups

def decode(blob):
    return [entry for group in decode_groups(blob) for entry in group['entries']]

def extract(image):
    records = {}
    for magic, version in ((MAGIC, 1), (MAGIC_V2, 2)):
        at = 0
        while True:
            at = image.find(magic, at)
            if at < 0:
                break
            if len(image) - at >= HEADER.size:
                _, wire_version, size, count, reserved, _, _ = HEADER.unpack_from(image, at)
                groups = 0 if version == 1 else 2
                if (wire_version == version and reserved == groups and 0 < count <= MAX_FILES
                        and size == HEADER.size + ENTRY.size * count + GROUP.size * groups and size <= len(image) - at):
                    blob = image[at:at + size]
                    decode(blob)
                    if version in records:
                        raise ValueError('Multiple owned asset records in target executable')
                    records[version] = blob
            at += len(magic)
    if 2 in records:
        if 1 not in records or decode_groups(records[1]) != decode_groups(records[2])[:1]:
            raise ValueError('Aggregate manifest lacks its exact legacy catch-up group')
    return records.get(2, records.get(1))

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

def encode_groups(groups):
    if [group['owner'] for group in groups] != [1, 2]:
        raise ValueError('Aggregate requires bot and inspection groups')
    payload, descriptors, count = bytearray(), bytearray(), 0
    for group in groups:
        # Reuse the entry framing, then validate against the explicit owner below.
        entries = group['entries']
        identity = bytes.fromhex(group['bundle_sha256'])
        if len(identity) != 32:
            raise ValueError('Invalid owned resource bundle identity')
        descriptor = GROUP.pack(group['owner'], len(entries), identity)
        descriptors += descriptor
        payload += descriptor
        for entry in entries:
            name = entry['name'].encode('ascii')
            if len(name) >= 96 or not re.fullmatch('[0-9a-f]{64}', entry['sha256']):
                raise ValueError('Invalid asset manifest input')
            payload += ENTRY.pack(name, bytes.fromhex(entry['sha256']), entry['size'])
        count += len(entries)
    identity = hashlib.sha256(descriptors).digest()
    result = HEADER.pack(MAGIC_V2, 2, HEADER.size + len(payload), count, 2,
                         hashlib.sha256(identity + payload).digest(), identity) + payload
    decode(result)
    return result

def package_group(snapshot, owner):
    package = snapshot / ('generated/bot-style-scripts' if owner == 1 else 'generated/weapon-inspect-assets')
    path = package / 'package-proof.json'
    original = path.read_bytes()
    proof = json.loads(original)
    if owner == 1:
        if proof.get('schema') != 'replay120-bot-style-native-overlay-v1' or not proof.get('packaged') or proof.get('direct_static_bytecode_delivery'):
            raise ValueError('Native owned overlay proof is missing')
    else:
        if (proof.get('schema') != 'replay120-weapon-inspect-native-package-v1'
                or proof.get('gates', {}).get('native_reader_validated') is not True
                or not proof.get('source_inputs')):
            raise ValueError('Native inspection package proof is missing')
        for receipt in proof['source_inputs']:
            source = Path(receipt['path']).resolve()
            if source.suffix.lower() in ('.py', '.h', '.cpp') and not source.is_relative_to(snapshot):
                raise ValueError('Inspection package source is outside its frozen snapshot')
            with source.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if source.stat().st_size != receipt['bytes'] or digest != receipt['sha256']:
                raise ValueError('Inspection package source changed after native verification')
        extraction = Path(proof['extraction_manifest']).resolve()
        if not extraction.is_relative_to(package) or sha(extraction.read_bytes()) != proof['extraction_manifest_sha256']:
            raise ValueError('Inspection extraction proof changed or escaped its package')
    folder_rules = native_folder_policy(proof, owner)
    entries, payloads = [], {}
    for item in proof['installation_manifest']:
        source = Path(item['source']).resolve()
        if not source.is_relative_to(package):
            raise ValueError('Owned asset input escaped its private native package')
        data = source.read_bytes()
        digest = sha(data)
        if digest != item['sha256'] or len(data) != item['size']:
            raise ValueError('Native package asset changed after verification')
        entries.append(dict(name=item['name'], sha256=digest, size=len(data)))
        payloads[digest] = dict(source=str(source), size=len(data))
    entries.sort(key=lambda item: item['name'])
    primary = [item for item in proof['installation_manifest']
               if item['name'].startswith(OWNERS[owner]) and item['name'].endswith('.ff')]
    empty_files = [item for item in proof['installation_manifest']
                   if not item['name'].startswith(OWNERS[owner]) and item['name'].endswith('.ff')]
    if len(primary) != 1 or not empty_files:
        raise ValueError('Native package lacks primary and empty companion resources')
    main = Path(primary[0]['source'])
    empty = Path(empty_files[0]['source'])
    resources = (main, main.with_suffix('.fp'), empty, empty.with_suffix('.fp'))
    if any(not path.resolve().is_relative_to(package) for path in resources):
        raise ValueError('Native bundle input escaped its private package')
    bundle = sha(b''.join(path.read_bytes() for path in resources))
    if bundle != proof['resource_bundle_sha256']:
        raise ValueError('Native resource bundle changed after verification')
    decode_group(b''.join(ENTRY.pack(item['name'].encode('ascii'), bytes.fromhex(item['sha256']), item['size'])
                          for item in entries), len(entries), bytes.fromhex(bundle), owner)
    for item in proof['installation_manifest']:
        primary_file = item['name'].startswith(OWNERS[owner])
        resource = resources[(0 if primary_file else 2) + (1 if item['name'].endswith('.fp') else 0)]
        if item['sha256'] != sha(resource.read_bytes()):
            raise ValueError('Owned companion payload does not match its complete bundle')
    return dict(owner=owner, bundle_sha256=bundle, entries=entries,
                package_proof=str(path), package_proof_sha256=sha(original), payloads=payloads,
                native_folder_rules=folder_rules,
                relative_paths={item['name']: item['relative_path'] for item in proof['installation_manifest']})

def prepare(snapshot):
    snapshot = Path(snapshot).resolve()
    if not snapshot.is_relative_to((ROOT / 'data').resolve()):
        raise ValueError('Asset manifests require a private source snapshot')
    bot = package_group(snapshot, 1)
    groups = [bot]
    if (snapshot / 'generated/weapon-inspect-assets/package-proof.json').exists():
        groups.append(package_group(snapshot, 2))
    folder_rules = bot['native_folder_rules']
    if any(group['native_folder_rules'] != folder_rules for group in groups):
        raise ValueError('Owned packages disagree on the target native folder policy')
    legacy = encode(bot['entries'], bot['bundle_sha256'])
    manifest = encode_groups(groups) if len(groups) == 2 else legacy
    entries = [entry for group in groups for entry in group['entries']]
    payloads = {}
    for group in groups:
        for digest, item in group['payloads'].items():
            if digest in payloads and payloads[digest]['size'] != item['size']:
                raise ValueError('Conflicting cross-group payload size')
            payloads[digest] = item
    header = snapshot / 'src/DW_UpdateAssetManifest.h'
    lines = ['#pragma once', '// Hash-bound owned overlay manifest, embedded in the update helper.',
             'inline const unsigned char s_dwUpdateAssetManifest[] = {']
    # One referenced array keeps the legacy record alive through optimization.
    embedded = legacy + manifest if len(groups) == 2 else manifest
    lines.extend('    ' + ','.join(f'0x{x:02x}' for x in embedded[at:at + 24]) + ',' for at in range(0, len(embedded), 24))
    header.write_bytes(('\n'.join(lines + ['};', ''])).encode('ascii'))
    paths_header = snapshot / 'src/DW_UpdateAssetPaths.h'
    paths_header.write_bytes(folder_header(folder_rules))
    record = dict(schema=len(groups), manifest_sha256=sha(manifest), manifest_size=len(manifest),
                  bundle_sha256=HEADER.unpack_from(manifest)[-1].hex(),
                  package_proof_sha256=bot['package_proof_sha256'], package_proof=bot['package_proof'], entries=entries,
                  payloads=payloads, embedded_header=str(header),
                  groups=[{key: group[key] for key in ('owner', 'bundle_sha256', 'entries', 'package_proof', 'package_proof_sha256')}
                          for group in groups],
                  legacy_manifest_sha256=sha(legacy),
                  native_folder_rules=folder_rules, native_folder_header=str(paths_header),
                  native_folder_header_sha256=sha(paths_header.read_bytes()),
                  relative_paths={name: path for group in groups for name, path in group['relative_paths'].items()})
    (snapshot / 'generated/update-assets.bin').write_bytes(manifest)
    (snapshot / 'generated/update-assets.json').write_text(json.dumps(record, indent=2) + '\n')
    return record

def publication(image, source, output):
    source, output = Path(source).resolve(), Path(output)
    if not source.is_relative_to((ROOT / 'data').resolve()):
        raise ValueError('Asset publication requires a private source snapshot')
    record = json.loads((source / 'generated/update-assets.json').read_bytes())
    embedded = extract(Path(image).read_bytes())
    if embedded is None or sha(embedded) != record['manifest_sha256'] or decode(embedded) != record['entries']:
        raise ValueError('Full EXE does not contain its exact frozen asset manifest')
    groups = [package_group(source, group['owner']) for group in decode_groups(embedded)]
    if [dict(owner=group['owner'], bundle_sha256=group['bundle_sha256'], entries=group['entries']) for group in groups] != decode_groups(embedded):
        raise ValueError('Native packages differ from the signed manifest')
    proof_records = record.get('groups', [dict(owner=1, package_proof=record['package_proof'],
                                               package_proof_sha256=record['package_proof_sha256'])])
    if len(proof_records) != len(groups) or any(
            old['owner'] != group['owner'] or old['package_proof'] != group['package_proof']
            or old['package_proof_sha256'] != group['package_proof_sha256']
            for old, group in zip(proof_records, groups)):
        raise ValueError('Native package proof changed before publication')
    folder_rules = groups[0]['native_folder_rules']
    if any(group['native_folder_rules'] != folder_rules for group in groups):
        raise ValueError('Native package folder policies differ')
    paths_header = source / 'src/DW_UpdateAssetPaths.h'
    if (folder_rules != record['native_folder_rules']
            or paths_header.read_bytes() != folder_header(folder_rules)
            or sha(paths_header.read_bytes()) != record['native_folder_header_sha256']):
        raise ValueError('Target native folder policy changed before publication')
    expected = {item['sha256']: item['size'] for item in record['entries']}
    if expected != {digest: item['size'] for digest, item in record['payloads'].items()}:
        raise ValueError('Publication payload inventory does not match its embedded manifest')
    frozen_payloads = {digest: payload for group in groups for digest, payload in group['payloads'].items()}
    if record['payloads'] != frozen_payloads:
        raise ValueError('Publication payload paths differ from their frozen native packages')
    output.joinpath('assets').mkdir(exist_ok=True)
    for digest, payload in record['payloads'].items():
        path = Path(payload['source']).resolve()
        if not any(path.is_relative_to(Path(group['package_proof']).parent) for group in groups):
            raise ValueError('Publication payload escaped its frozen native package')
        data = path.read_bytes()
        if sha(data) != digest or len(data) != payload['size']:
            raise ValueError('Owned asset changed before publication')
        output.joinpath('assets', digest + '.bin').write_bytes(data)
    output.joinpath('update-assets.bin').write_bytes(embedded)
    output.joinpath('update-assets.json').write_text(json.dumps(record, indent=2) + '\n')
    return record
