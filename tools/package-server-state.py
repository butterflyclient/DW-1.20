"""Curated, hash-inventoried runtime migration; never includes build/test archives."""
import argparse
import hashlib
import io
import json
import pathlib
import tarfile

DIRECTORIES = '''ab-enrollments ab-testing achievement-user-state achievements anti-cheat
auth-reports channels clans content-streaming counters event-log inventory-validation
leaderboard-definitions leaderboard-stats loot-generation mail marketing marketplace
matchmaking objectstore performance platform-accounts platform-client-profiles
platform-profiles playlists presence profiles publisher publisher-variables qos relay
regulations scheduled social storage teams tournaments validated-stats'''.split()
FILES = ['network.json', 'platform-private.blob', 'platform-public.blob',
         'platform-profile.bin', 'platform-word-filters.json']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--advertised-address', required=True)
    args = parser.parse_args()
    root = args.data.resolve()
    selected = [root / name for name in FILES if (root / name).is_file()]
    for name in DIRECTORIES:
        folder = root / name
        if not folder.exists():
            continue
        if folder.is_symlink():
            raise ValueError('Runtime tree contains a symlink')
        selected.extend(path for path in folder.rglob('*') if path.is_file())
    manifest = []
    with tarfile.open(args.output, 'w:gz') as archive:
        for path in sorted(selected):
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise ValueError('Runtime file escapes the data root')
            name = path.relative_to(root).as_posix()
            payload = path.read_bytes()
            if name == 'network.json':
                config = json.loads(payload)
                config['bind_address'] = '0.0.0.0'
                config['advertised_address'] = args.advertised_address
                config['bandwidth_port_count'] = 32
                payload = (json.dumps(config, indent=2) + '\n').encode()
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(payload))
            manifest.append(dict(path=name, size=len(payload),
                                 sha256=hashlib.sha256(payload).hexdigest()))
    receipt = dict(schema=1, files=manifest, source_root=str(root),
                   endpoint=args.advertised_address,
                   archive_sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
                   game_machine_private_keys_migrated=False)
    args.output.with_suffix('.manifest.json').write_bytes(
        (json.dumps(receipt, indent=2) + '\n').encode())
    print(json.dumps(dict(files=len(manifest), bytes=sum(x['size'] for x in manifest),
                          archive_sha256=receipt['archive_sha256'])))


if __name__ == '__main__':
    main()
