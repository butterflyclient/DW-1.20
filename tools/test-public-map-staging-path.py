"""Run old and corrected Windows helpers on real published maps in a deep folder."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-job', type=Path, required=True)
    parser.add_argument('--fixed-helper-receipt', type=Path, required=True)
    parser.add_argument('--candidate-build', type=Path, required=True)
    parser.add_argument('--host', default='162.243.115.160')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    baseline = json.loads((args.baseline_job / 'readiness.json').read_bytes())
    report = json.loads((args.candidate_build / 'build-report.json').read_bytes())
    candidate = Path(report['executable'])
    assert sha(candidate) == report['sha256'] and report['unresolved_symbols'] == 0
    old_source = Path(baseline['source_root'])
    new_source = Path(report['source_root'])
    helper = json.loads(args.fixed_helper_receipt.read_bytes())
    fixed = Path(helper['helper'])
    assert sha(fixed) == helper['sha256']
    assert candidate.read_bytes().count(fixed.read_bytes()) == 1
    for entry in helper['inputs']:
        assert sha(entry['source']) == entry['sha256']
    for name in ('replay-update-client.cpp', 'replay-update-assets.h', 'replay-update-maps.h'):
        assert sha(new_source / 'generated-updater/helper-source/tools' / name) == sha(ROOT / 'tools' / name)
    old_receipt = json.loads((old_source / 'generated-updater/DW_UpdateHelper.build.json').read_bytes())
    original = Path(old_receipt['helper'])
    assert sha(original) == old_receipt['sha256']
    assets = json.loads((old_source / 'generated/update-assets.json').read_bytes())
    maps = json.loads((old_source / 'generated/update-maps.json').read_bytes())
    current_maps = json.loads((new_source / 'generated/update-maps.json').read_bytes())
    assert maps['manifest_sha256'] == current_maps['manifest_sha256']
    checks = []
    with tempfile.TemporaryDirectory(prefix='public-map-path-', dir=ROOT / 'data') as temporary:
        folder = Path(temporary).resolve()
        prefix = 'deep_é_地图_'
        game = folder / (prefix + 'd' * (125 - len(str(folder)) - 1 - len(prefix)))
        game.mkdir()
        image = game / 'game_dx12_ship_replay_dw.exe'
        shutil.copyfile(baseline['executable'], image)
        assert sha(image) == baseline['sha256']
        # Match the observed failure: the game already staged its small native
        # overlays, leaving only custom maps for the update helper to acquire.
        for entry in assets['entries']:
            destination = game / 'zone' / assets['relative_paths'][entry['name']]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(assets['payloads'][entry['sha256']]['source'], destination)
        flags = subprocess.CREATE_NO_WINDOW
        failed = subprocess.run([str(original), '--prepare', str(image), args.host],
                                creationflags=flags, timeout=120)
        log = Path(str(image) + '.update') / 'result.log'
        original_log = log.read_text()
        assert failed.returncode == 40 and 'Cannot stage map; check free space' in original_log
        assert not (game / 'mods').exists() and sha(image) == baseline['sha256']
        checks.append('Release 30 helper reproduces the reported map-stage error against the actual public server in a 125-character folder')
        shutil.copyfile(candidate, image)
        repaired = subprocess.run([str(fixed), '--prepare-assets', str(image), args.host],
                                  creationflags=flags, timeout=900)
        assert repaired.returncode == 20, (repaired.returncode, log.read_text())
        assert sha(image) == report['sha256']
        staging = Path(str(image) + '.update') / 'asset-staging' / baseline['sha256']
        for entry in maps['files']:
            path = staging / ('map-' + entry['sha256'] + '.bin')
            assert len(str(path)) > 260 and path.stat().st_size == entry['size']
            assert sha(path) == entry['sha256']
        for digest, entry in maps['payloads'].items():
            path = staging / ('chunk-' + digest + '.bin')
            assert path.stat().st_size == entry['size'] and sha(path) == digest
        assert not (game / 'mods').exists()
        assert not (Path(str(image) + '.update') / 'next.exe').exists()
        checks.append('Exact freshly embedded candidate helper downloads and verifies every published compressed map chunk and complete native file beyond MAX_PATH')
        checks.append('Asset-only staging preserves candidate EXE and creates no installed map files')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(passed=True, checks=checks,
        baseline_executable_sha256=baseline['sha256'],candidate_executable_sha256=report['sha256'],
        original_helper_sha256=old_receipt['sha256'],fixed_helper_sha256=helper['sha256'],
        game_folder_characters=125,map_package_hash=maps['package_hash'],
        map_transport_bytes=maps['transport_bytes'],map_raw_bytes=maps['uncompressed_bytes'],
        original_log=original_log,host=args.host,game_executed=False,
        installed_game_modified=False,server_modified=False,temporary_fixture_removed=True), indent=2) + '\n')
    print('PASS actual public old/new helper map staging in a deep Unicode folder; no game launch')


if __name__ == '__main__':
    main()
