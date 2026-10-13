"""Freeze explicitly published native maps; ordinary EXE builds never select new map data."""

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct

ROOT = Path(__file__).resolve().parents[1]
MAGIC = b'REPLAYDWMAP01\0\0\0'
HEADER = struct.Struct('<16sIIIIQ32s32s')
FILE = struct.Struct('<128s32sQII')
CHUNK = struct.Struct('<32s32sII')
CHUNK_BYTES = 4 * 1024 * 1024
MAX_TRANSPORT = 8 * 1024 * 1024
MAX_FILES, MAX_CHUNKS = 256, 4096
MAX_FILE, MAX_TOTAL = 2 * 1024**3, 4 * 1024**3
MAP_ID = re.compile(r'mp_[a-z0-9_]{1,12}')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def filenames(map_id):
    if not MAP_ID.fullmatch(map_id):
        raise ValueError('Invalid custom map identifier')
    return {prefix + map_id + '.ff' for prefix in ('', 'srv_', 'eng_', 'ww_', 'techsets_')} | {'map.json'}


def checked_path(value):
    path = PurePosixPath(value)
    if (path.as_posix() != value or len(path.parts) != 5
            or path.parts[:3] != ('mods', 'mw120r', 'maps')
            or path.name not in filenames(path.parts[3])):
        raise ValueError('Map update escaped its six native package files')
    return path


def encode(files, chunks):
    table = bytearray()
    for item in files:
        name = item['path'].encode('ascii')
        if len(name) >= 128:
            raise ValueError('Custom map path is too long')
        table += FILE.pack(name, bytes.fromhex(item['sha256']), item['size'],
                           item['first_chunk'], item['chunk_count'])
    package = hashlib.sha256(table).digest()
    payload = bytes(table) + b''.join(CHUNK.pack(bytes.fromhex(item['sha256']),
        bytes.fromhex(item['payload_sha256']), item['size'], item['payload_size']) for item in chunks)
    blob = HEADER.pack(MAGIC, 1, HEADER.size + len(payload), len(files), len(chunks),
                       sum(item['size'] for item in files),
                       hashlib.sha256(package + payload).digest(), package) + payload
    decode(blob)
    return blob


def decode(blob):
    if len(blob) < HEADER.size:
        raise ValueError('Incomplete custom map manifest')
    magic, version, length, count, chunk_count, total, expected, package = HEADER.unpack_from(blob)
    if (magic != MAGIC or version != 1 or not 0 < count <= MAX_FILES
            or not 0 < chunk_count <= MAX_CHUNKS or not 0 < total <= MAX_TOTAL
            or length != len(blob) or length != HEADER.size + FILE.size * count + CHUNK.size * chunk_count):
        raise ValueError('Invalid custom map manifest bounds')
    payload = blob[HEADER.size:]
    file_table = payload[:FILE.size * count]
    if hashlib.sha256(file_table).digest() != package or hashlib.sha256(package + payload).digest() != expected:
        raise ValueError('Custom map manifest hash failed')
    files, chunks, maps, seen = [], [], {}, set()
    for at in range(count):
        name, digest, size, first, number = FILE.unpack_from(file_table, at * FILE.size)
        name, separator, tail = name.partition(b'\0')
        if not separator or any(tail):
            raise ValueError('Invalid custom map path padding')
        name = name.decode('ascii')
        path = checked_path(name)
        if name in seen or not 0 < size <= MAX_FILE or not number:
            raise ValueError('Duplicate, empty or oversized native map file')
        seen.add(name)
        maps.setdefault(path.parts[3], set()).add(path.name)
        files.append(dict(path=name, sha256=digest.hex(), size=size, first_chunk=first, chunk_count=number))
    if files != sorted(files, key=lambda item: item['path']):
        raise ValueError('Native map file table is not canonical')
    if any(names != filenames(map_id) for map_id, names in maps.items()):
        raise ValueError('Incomplete six-file native map package')
    sizes = {}
    for at in range(chunk_count):
        raw, transport, size, compressed = CHUNK.unpack_from(payload, FILE.size * count + CHUNK.size * at)
        if not 0 < size <= CHUNK_BYTES or not 0 < compressed <= MAX_TRANSPORT:
            raise ValueError('Invalid compressed map chunk bounds')
        key = transport.hex()
        identity = (raw.hex(), size, compressed)
        if key in sizes and sizes[key] != identity:
            raise ValueError('Inconsistent compressed map payload identity')
        sizes[key] = identity
        chunks.append(dict(sha256=raw.hex(), payload_sha256=key, size=size, payload_size=compressed))
    cursor = 0
    for item in files:
        number = item['chunk_count']
        if (item['first_chunk'] != cursor or cursor + number > len(chunks)
                or number != (item['size'] + CHUNK_BYTES - 1) // CHUNK_BYTES):
            raise ValueError('Invalid native map chunk coverage')
        section = chunks[cursor:cursor + number]
        if (sum(part['size'] for part in section) != item['size']
                or any(part['size'] != CHUNK_BYTES for part in section[:-1])):
            raise ValueError('Native map chunks do not restore the declared file')
        cursor += number
    if cursor != len(chunks) or sum(item['size'] for item in files) != total:
        raise ValueError('Unused map chunks or inconsistent package size')
    return dict(package_hash=package.hex(), uncompressed_bytes=total, files=files, chunks=chunks)


def extract(image):
    found, at = None, 0
    while True:
        at = image.find(MAGIC, at)
        if at < 0:
            return found
        if len(image) - at >= HEADER.size:
            _, version, length, files, chunks, *_ = HEADER.unpack_from(image, at)
            if (version == 1 and 0 < files <= MAX_FILES and 0 < chunks <= MAX_CHUNKS
                    and length == HEADER.size + FILE.size * files + CHUNK.size * chunks
                    and length <= len(image) - at):
                blob = image[at:at + length]
                decode(blob)
                if found is not None:
                    raise ValueError('Multiple custom map manifests in executable')
                found = blob
        at += len(MAGIC)


class Cabinet:
    """The same Windows XPRESS_HUFF framing used by the shipping helper."""

    def __init__(self):
        if os.name != 'nt':
            raise RuntimeError('Publish compressed maps from the Windows DW workspace')
        self.api = ctypes.WinDLL('cabinet', use_last_error=True)
        self.compressor, self.decompressor = wintypes.HANDLE(), wintypes.HANDLE()
        for name in ('CreateCompressor', 'CreateDecompressor'):
            function = getattr(self.api, name)
            function.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE)]
            function.restype = wintypes.BOOL
        for name in ('Compress', 'Decompress'):
            function = getattr(self.api, name)
            function.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
            function.restype = wintypes.BOOL
        for name in ('ResetCompressor', 'ResetDecompressor', 'CloseCompressor', 'CloseDecompressor'):
            getattr(self.api, name).argtypes = [wintypes.HANDLE]
            getattr(self.api, name).restype = wintypes.BOOL
        if not self.api.CreateCompressor(4, None, ctypes.byref(self.compressor)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.api.CreateDecompressor(4, None, ctypes.byref(self.decompressor)):
            self.api.CloseCompressor(self.compressor)
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.compressor:
            self.api.CloseCompressor(self.compressor)
            self.compressor = wintypes.HANDLE()
        if self.decompressor:
            self.api.CloseDecompressor(self.decompressor)
            self.decompressor = wintypes.HANDLE()

    def compress(self, data):
        if not 0 < len(data) <= CHUNK_BYTES:
            raise ValueError('Native compression input exceeded chunk bounds')
        source = ctypes.create_string_buffer(data)
        length = ctypes.c_size_t()
        self.api.ResetCompressor(self.compressor)
        if self.api.Compress(self.compressor, source, len(data), None, 0, ctypes.byref(length)):
            raise ValueError('Unexpected native compression sizing result')
        if ctypes.get_last_error() != 122 or not 0 < length.value <= MAX_TRANSPORT:
            raise ctypes.WinError(ctypes.get_last_error())
        output = ctypes.create_string_buffer(length.value)
        if not self.api.Compress(self.compressor, source, len(data), output, len(output), ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        compressed = output.raw[:length.value]
        if self.decompress(compressed, len(data)) != data:
            raise ValueError('Native compressed map chunk did not round-trip')
        return compressed

    def decompress(self, data, size):
        if not 0 < len(data) <= MAX_TRANSPORT or not 0 < size <= CHUNK_BYTES:
            raise ValueError('Native decompression input exceeded chunk bounds')
        source, output = ctypes.create_string_buffer(data), ctypes.create_string_buffer(size)
        length = ctypes.c_size_t()
        self.api.ResetDecompressor(self.decompressor)
        if not self.api.Decompress(self.decompressor, source, len(data), output, size, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        if length.value != size:
            raise ValueError('Native map chunk decompressed to an unexpected size')
        return output.raw


def freeze_package(source_directory, output_directory):
    source, output = Path(source_directory).resolve(strict=True), Path(output_directory).resolve()
    if not output.is_relative_to(ROOT / 'data'):
        raise ValueError('Map publication output must remain in the DW data workspace')
    names = filenames(source.name)
    if any(not (source / name).is_file() or (source / name).is_symlink() for name in names):
        raise ValueError('Missing or redirected native custom map files')
    metadata = json.loads((source / 'map.json').read_bytes())
    if metadata.get('id', source.name) != source.name:
        raise ValueError('Map metadata identifies a different package')
    output.mkdir(parents=True, exist_ok=True)
    payload_folder = output / 'payloads'
    payload_folder.mkdir(exist_ok=True)
    files, chunks, payloads, source_files = [], [], {}, []
    cabinet = Cabinet()
    try:
        for name in sorted(names):
            path = source / name
            before = path.stat()
            if not 0 < before.st_size <= MAX_FILE:
                raise ValueError('Native map file exceeds publication bounds')
            first, whole = len(chunks), hashlib.sha256()
            with path.open('rb') as stream:
                if name.endswith('.ff') and stream.read(12) != b'IWffc100' + struct.pack('<I', 11):
                    raise ValueError('Custom map is not the validated Replay fastfile format')
                stream.seek(0)
                while data := stream.read(CHUNK_BYTES):
                    whole.update(data)
                    packed = cabinet.compress(data)
                    raw_hash, transport_hash = sha(data), sha(packed)
                    target = payload_folder / (transport_hash + '.bin')
                    if target.exists():
                        if target.stat().st_size != len(packed) or file_sha(target) != transport_hash:
                            raise ValueError('Existing compressed chunk changed')
                    else:
                        temporary = target.with_suffix('.partial')
                        with temporary.open('xb') as staging:
                            staging.write(packed)
                            staging.flush()
                            os.fsync(staging.fileno())
                        os.replace(temporary, target)
                    payloads[transport_hash] = dict(source=str(target), size=len(packed),
                                                   raw_sha256=raw_hash, raw_size=len(data))
                    chunks.append(dict(sha256=raw_hash, payload_sha256=transport_hash,
                                       size=len(data), payload_size=len(packed)))
            after = path.stat()
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError('Native map changed while publication was freezing it')
            digest = whole.hexdigest()
            files.append(dict(path='mods/mw120r/maps/' + source.name + '/' + name,
                              sha256=digest, size=before.st_size, first_chunk=first,
                              chunk_count=len(chunks) - first))
            source_files.append(dict(name=name, source=str(path), sha256=digest, size=before.st_size))
    finally:
        cabinet.close()
    blob = encode(files, chunks)
    manifest = output / 'map-manifest.bin'
    manifest.write_bytes(blob)
    record = dict(schema='replay120-custom-map-package-v1', **decode(blob),
                  manifest_sha256=sha(blob), manifest_size=len(blob), manifest_path=str(manifest),
                  payloads=payloads, source_files=source_files, map_ids=[source.name],
                  transport_bytes=sum(item['size'] for item in payloads.values()),
                  codec='xpress_huff', chunk_bytes=CHUNK_BYTES)
    (output / 'package.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def verify_record(record):
    blob = Path(record['manifest_path']).read_bytes()
    decoded = decode(blob)
    if (sha(blob) != record['manifest_sha256'] or len(blob) != record['manifest_size']
            or any(decoded[key] != record[key] for key in decoded)):
        raise ValueError('Published map declaration changed')
    expected = {item['payload_sha256']: item['payload_size'] for item in decoded['chunks']}
    if expected != {digest: item['size'] for digest, item in record['payloads'].items()}:
        raise ValueError('Compressed map payload inventory differs from its declaration')
    for digest, item in record['payloads'].items():
        path = Path(item['source']).resolve(strict=True)
        if not path.is_relative_to(ROOT / 'data') or path.stat().st_size != item['size'] or file_sha(path) != digest:
            raise ValueError('Published compressed map payload changed')
    return blob


def prepare(snapshot):
    snapshot = Path(snapshot).resolve()
    if not snapshot.is_relative_to(ROOT / 'data'):
        raise ValueError('Map manifests require a private source snapshot')
    declaration = ROOT / 'data/custom-map-publication.json'
    header = snapshot / 'src/DW_UpdateMapManifest.h'
    destination = snapshot / 'generated/custom-maps'
    destination.mkdir(parents=True, exist_ok=True)
    record = None
    if declaration.exists():
        record = json.loads(declaration.read_bytes())
        if not record.get('published'):
            raise ValueError('An unpublished map package cannot enter an ordinary EXE release')
        blob = verify_record(record)
        payload_folder = destination / 'payloads'
        payload_folder.mkdir(exist_ok=True)
        for digest, item in record['payloads'].items():
            path = payload_folder / (digest + '.bin')
            shutil.copyfile(item['source'], path)
            item['source'] = str(path)
        manifest = destination / 'map-manifest.bin'
        manifest.write_bytes(blob)
        record['manifest_path'] = str(manifest)
        record['publication_receipt_sha256'] = file_sha(declaration)
        (destination / 'package.json').write_text(json.dumps(record, indent=2) + '\n')
    else:
        blob = b'\0'
    lines = ['#pragma once', '// Last explicitly published custom map inventory; never captured from live map files.',
             'inline const unsigned char s_dwUpdateMapManifest[] = {']
    lines.extend('    ' + ','.join('0x%02x' % byte for byte in blob[at:at + 24]) + ','
                 for at in range(0, len(blob), 24))
    header.write_text('\n'.join(lines + ['};', '']), encoding='ascii')
    (snapshot / 'generated/update-maps.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def publication(image, source, output):
    source, output = Path(source).resolve(), Path(output)
    record = json.loads((source / 'generated/update-maps.json').read_bytes())
    embedded = extract(Path(image).read_bytes())
    if record is None:
        if embedded is not None:
            raise ValueError('Unexpected custom map inventory in executable')
        return None
    blob = verify_record(record)
    if embedded != blob:
        raise ValueError('EXE does not bind its last explicitly published map package')
    declaration = ROOT / 'data/custom-map-publication.json'
    current = json.loads(declaration.read_bytes())
    if file_sha(declaration) != record['publication_receipt_sha256'] or current['package_hash'] != record['package_hash']:
        raise ValueError('Explicit map publication changed during client compilation')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'update-maps.bin').write_bytes(blob)
    (output / 'update-maps.json').write_text(json.dumps(record, indent=2) + '\n')
    return record
