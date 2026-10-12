"""Owned overlay manifests and real Windows backup/replace/rollback; no game."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from dw_update_assets import ROOT, prepare, decode, encode, extract, publication, sha

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-proof', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    checks = []
    with tempfile.TemporaryDirectory(prefix='update-assets-fixture-', dir=ROOT / 'data') as temporary:
        root = Path(temporary).resolve()
        assert root.parent == (ROOT / 'data').resolve()
        snapshot = root / 'source'
        package = snapshot / 'generated/bot-style-scripts'
        package.mkdir(parents=True); (snapshot / 'src').mkdir()
        proof = json.loads(args.package_proof.read_bytes())
        paths = {}
        for item in proof['installation_manifest']:
            original = Path(item['source'])
            destination = package / original.name
            if str(original) not in paths:
                shutil.copyfile(original, destination); paths[str(original)] = str(destination)
            item['source'] = str(destination)
        proof['output_fastfile'] = paths[proof['output_fastfile']]
        proof['empty_companion']['output_fastfile'] = paths[proof['empty_companion']['output_fastfile']]
        (package / 'package-proof.json').write_text(json.dumps(proof) + '\n')
        record = prepare(snapshot)
        blob = (snapshot / 'generated/update-assets.bin').read_bytes()
        assert proof['native_locale_codes']['supported_language_directories'] == {'eng': 'english'}
        assert decode(blob) == record['entries'] and len(record['entries']) == 20 and len(record['payloads']) == 4
        checks.append('English-only FF/FP list preserves native regional companions, four verified payloads and complete bundle identity')
        assert all(item['relative_path'] == record['relative_paths'][item['name']]
                   for item in proof['installation_manifest'])
        checks.append('Flat legacy-compatible manifest binds target-derived native folder rules in the signed helper')
        image = root / 'target.exe'; image.write_bytes(b'MZ' + bytes(62) + blob)
        assert extract(image.read_bytes()) == blob
        output = root / 'publication'; output.mkdir()
        publication(image, snapshot, output)
        assert len(list((output / 'assets').glob('*.bin'))) == 4
        checks.append('Published payloads match the exact manifest embedded in the target EXE')
        report = root / 'build-report.json'
        report.write_text(json.dumps(dict(sha256=sha(image.read_bytes()), cpp=['synthetic fixture'], fixture_only=True)))
        (root / 'verification-report.json').write_text(json.dumps(dict(sha256=sha(image.read_bytes()), unresolved_symbols=0, fixture_only=True)))
        (root / 'relocation-audit.json').write_text(json.dumps(dict(sha256=sha(image.read_bytes()), passed=True, fixture_only=True)))
        spec = importlib.util.spec_from_file_location('full_publisher', ROOT / 'tools/publish-full-executable.py')
        publisher = importlib.util.module_from_spec(spec); spec.loader.exec_module(publisher)
        full = root / 'full-publication'
        catalog = publisher.publish(image, report, 27, full, asset_source=snapshot)
        assert catalog['latest'] == sha(image.read_bytes()) and catalog['assets']['files'] == len(record['entries'])
        assert catalog['assets']['manifest_sha256'] == sha(blob) and len(catalog['assets']['payloads']) == 4
        assert len((full / 'full-image-catalog.json').read_bytes()) < 4096
        checks.append('Existing full-image publisher commits a bounded catalog binding exact target manifest and four owned payloads')
        for change in ('traversal', 'shipped', 'pair', 'duplicate', 'size', 'bundle', 'hash', 'multiple'):
            entries = [dict(item) for item in record['entries']]
            bundle = record['bundle_sha256']
            try:
                if change == 'traversal': entries[0]['name'] = '../common_base_mp.ff'
                elif change == 'shipped': entries[0]['name'] = 'common_base_mp.ff'
                elif change == 'pair': entries.pop()
                elif change == 'duplicate': entries.append(entries[0])
                elif change == 'size': entries[0]['size'] = 65 * 1024 * 1024
                elif change == 'bundle': bundle = '0' * 64
                elif change == 'hash':
                    bad = bytearray(blob); bad[-1] ^= 1; decode(bad)
                elif change == 'multiple': extract(image.read_bytes() + blob)
                if change not in ('hash', 'multiple'): encode(entries, bundle)
            except (ValueError, UnicodeError):
                checks.append('Rejected ' + change + ' manifest')
            else:
                raise AssertionError('Accepted ' + change)
        original = image.read_bytes(); image.write_bytes(original.replace(blob, blob[:-1] + bytes([blob[-1] ^ 1])))
        try: publication(image, snapshot, output)
        except ValueError: checks.append('Changed target-embedded manifest prevents publication')
        else: raise AssertionError('Changed target manifest published')
        image.write_bytes(original)
        cmake = root / 'CMakeLists.txt'
        cmake.write_text('cmake_minimum_required(VERSION 3.24)\nproject(update_assets_fixture LANGUAGES CXX)\n'
            f'add_executable(update-assets "{(ROOT / "tools/update_assets_harness.cpp").as_posix()}")\n'
            'target_compile_features(update-assets PRIVATE cxx_std_20)\n'
            f'target_include_directories(update-assets PRIVATE "{(snapshot / "src").as_posix()}")\n'
            'target_compile_definitions(update-assets PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)\n'
            'target_link_libraries(update-assets PRIVATE bcrypt)\n')
        flags = subprocess.CREATE_NO_WINDOW
        subprocess.run(['cmake', '-S', str(root), '-B', str(root / 'build'), '-G', 'Visual Studio 18 2026', '-A', 'x64'], check=True, creationflags=flags)
        subprocess.run(['cmake', '--build', str(root / 'build'), '--config', 'Release', '--parallel', '2'], check=True, creationflags=flags)
        fixture = root / 'installations'; fixture.mkdir()
        result = subprocess.run([str(root / 'build/Release/update-assets.exe'), str(fixture), str(image), str(output / 'assets')], capture_output=True, text=True, creationflags=flags)
        print(result.stdout + result.stderr, end='')
        result.check_returncode()
        checks.append('Five compiled Windows transactions use native language and regional folders, verified original backups and rollback')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(passed=True, checks=checks, game_launched=False,
        installed_game_modified=False, server_restarted=False, private_fixture_removed=True), indent=2) + '\n')
    print('PASS', len(checks), 'owned asset update gates; no game or production server touched')

if __name__ == '__main__':
    main()
