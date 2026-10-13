"""Verify explicit map pinning and actual Linux backup transactions; no game."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile

import dw_update_maps as maps
import remote_backend

ROOT = Path(__file__).resolve().parents[1]


def load_publisher():
    spec = importlib.util.spec_from_file_location('map_publisher_fixture', ROOT / 'tools/publish-custom-map.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def remote(client, script, success=True):
    _, output, error = client.exec_command("python3 - <<'PY'\n" + script + '\nPY', timeout=30)
    result, failure = output.read(), error.read()
    code = output.channel.recv_exit_status()
    if success:
        if code:
            raise AssertionError(failure.decode(errors='replace'))
        return json.loads(result)
    assert code, 'Invalid publication unexpectedly succeeded'


def server_transactions(publisher, records, local, checks):
    """The isolated fixture uses the same POSIX locks, fsync and hardlinks as publication."""
    with remote_backend.connect() as client:
        directory = remote(client, "import json,tempfile\nprint(json.dumps(tempfile.mkdtemp(prefix='replay-map-publication-')))\n")
        assert Path(directory).name.startswith('replay-map-publication-')
        try:
            def upload(record, release, label):
                catalog = publisher.catalog_for(record, release)
                path = local / (label + '.json')
                path.write_text(json.dumps(catalog, indent=2) + '\n')
                incoming = directory + '/map-incoming-' + label
                with client.open_sftp() as sftp:
                    sftp.mkdir(incoming)
                    sftp.mkdir(incoming + '/assets')
                    sftp.put(record['manifest_path'], incoming + '/manifest.bin')
                    sftp.put(str(path), incoming + '/catalog.json')
                    for digest, item in record['payloads'].items():
                        sftp.put(item['source'], incoming + '/assets/' + digest + '.bin')
                return publisher.transaction_script(incoming, publisher.sha(path)), catalog

            script, first_catalog = upload(records[0], 1, 'first')
            first = remote(client, script)
            assert first['published'] and first['previous'] is None and first['backup']
            checks.append('Initial server publication records that no previous map package exists')
            script, second_catalog = upload(records[1], 2, 'second')
            second = remote(client, script)
            assert second['published'] and second['previous'] == first_catalog
            assert second['catalog'] == second_catalog and second['backup']
            proof = remote(client, 'import hashlib,json,pathlib\n' +
                'root=pathlib.Path(' + repr(directory) + ')\n' +
                'backup=pathlib.Path(' + repr(second['backup']) + ')\n' +
                "catalog=json.loads((backup/'catalog.json').read_bytes())\n" +
                "assert catalog==" + repr(first_catalog) + '\n' +
                "assert hashlib.sha256((backup/'manifest.bin').read_bytes()).hexdigest()==catalog['manifest_sha256']\n" +
                "for digest,size in catalog['payloads'].items():\n" +
                " path=backup/'assets'/(digest+'.bin')\n" +
                " assert path.stat().st_size==size and hashlib.sha256(path.read_bytes()).hexdigest()==digest\n" +
                " assert path.stat().st_ino==(root/'assets'/path.name).stat().st_ino\n" +
                "print(json.dumps(dict(backup_verified=True,current=json.loads((root/'custom-map-catalog.json').read_bytes()),backups=len(list((root/'map-backups').iterdir())))))\n")
            assert proof['backup_verified'] and proof['current'] == second_catalog
            checks.append('Map replacement preserves exact prior catalog, manifest and all compressed payloads before atomic catalog advance')
            script, _ = upload(records[1], 2, 'retry')
            retry = remote(client, script)
            assert retry['already_current'] and retry['backup'] == second['backup']
            assert retry['previous'] == first_catalog
            checks.append('Exact publication retry keeps the catalog and does not create a duplicate backup')
            script, _ = upload(records[0], 1, 'rollback')
            remote(client, script, success=False)
            script, _ = upload(records[0], 3, 'corrupt')
            digest = next(iter(records[0]['payloads']))
            remote(client, 'import json,pathlib\npath=pathlib.Path(' +
                repr(directory + '/map-incoming-corrupt/assets/' + digest + '.bin') +
                ")\npath.write_bytes(b'corrupt')\nprint(json.dumps(True))")
            remote(client, script, success=False)
            after = remote(client, 'import json,pathlib\nroot=pathlib.Path(' + repr(directory) +
                ")\nprint(json.dumps(dict(catalog=json.loads((root/'custom-map-catalog.json').read_bytes()),backups=len(list((root/'map-backups').iterdir())))))")
            assert after['catalog'] == second_catalog and after['backups'] == proof['backups']
            checks.append('Older-release and damaged-payload publication failures leave the active map catalog and backup inventory unchanged')
        finally:
            remote(client, 'import json,pathlib,shutil\nroot=pathlib.Path(' + repr(directory) +
                ")\nassert root.parent==pathlib.Path('/tmp') and root.name.startswith('replay-map-publication-') and not root.is_symlink()\nshutil.rmtree(root)\nprint(json.dumps(True))")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    checks = []
    publisher = load_publisher()
    with tempfile.TemporaryDirectory(prefix='map-publication-fixture-', dir=ROOT / 'data') as temporary:
        local = Path(temporary).resolve()
        (local / 'data').mkdir()
        source = local / 'native/mp_fixture'
        source.mkdir(parents=True)
        header = b'IWffc100' + struct.pack('<II', 11, 0xFF7) + bytes(156)
        for name in maps.filenames(source.name):
            (source / name).write_bytes(header)
        (source / 'map.json').write_text('{"id":"mp_fixture","title":"Fixture"}')
        (source / 'mp_fixture.ff').write_bytes(header + b'bounded native map fixture\0' * 165000)
        original_root = maps.ROOT
        maps.ROOT = local
        try:
            first = maps.freeze_package(source, local / 'data/first')
            blob = maps.verify_record(first)
            assert maps.extract(b'MZ' + blob) == blob and len(first['chunks']) > 6
            checks.append('Windows Cabinet freezer round-trips a multi-chunk six-file native package with exact full-file and compressed transport hashes')
            pin = local / 'data/custom-map-publication.json'
            pin.write_text(json.dumps(dict(first, published=True)) + '\n')
            def snapshot(name):
                target = local / 'data' / name
                (target / 'src').mkdir(parents=True)
                return target
            before = maps.prepare(snapshot('before'))
            (source / 'mp_fixture.ff').write_bytes(header + b'new unpublished map data')
            after = maps.prepare(snapshot('after'))
            assert before['package_hash'] == after['package_hash'] == first['package_hash']
            assert maps.verify_record(after) == blob
            checks.append('Changing live map files alone cannot change the map inventory included by an ordinary EXE build')
            image = local / 'data/fixture.exe'
            image.write_bytes(b'MZ' + blob)
            maps.publication(image, local / 'data/after', local / 'data/publication')
            second = maps.freeze_package(source, local / 'data/second')
            pin.write_text(json.dumps(dict(second, published=True)) + '\n')
            try:
                maps.publication(image, local / 'data/after', local / 'data/refused')
            except ValueError:
                checks.append('An explicit map publication racing a compiled EXE blocks stale client publication')
            else:
                raise AssertionError('Stale map publication was accepted')
            payload = Path(next(iter(second['payloads'].values()))['source'])
            original = payload.read_bytes()
            payload.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            try:
                publisher.catalog_for(second, 2)
            except ValueError:
                checks.append('Damaged frozen compressed data is rejected before server upload')
            else:
                raise AssertionError('Damaged map data accepted')
            payload.write_bytes(original)
            server_transactions(publisher, (first, second), local, checks)
        finally:
            maps.ROOT = original_root
    if args.build:
        report = json.loads((args.build / 'build-report.json').read_bytes())
        frozen = Path(report['source_root'])
        record = json.loads((frozen / 'generated/update-maps.json').read_bytes())
        assert record and record['published']
        assert maps.extract(Path(report['executable']).read_bytes()) == maps.verify_record(record)
        assert maps.file_sha(ROOT / 'data/custom-map-publication.json') == record['publication_receipt_sha256']
        checks.append('Freshly compiled production EXE binds only the exact explicitly published map inventory')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(passed=True, checks=checks, game_launched=False,
        installed_game_modified=False, production_server_modified=False,
        isolated_linux_transaction_tested=True), indent=2) + '\n')
    print('PASS', len(checks), 'explicit map publication gates; no game or live catalog changed')


if __name__ == '__main__':
    main()
