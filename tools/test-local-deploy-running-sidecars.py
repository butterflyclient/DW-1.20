"""Exercise the exact local-deployer running-game transaction in private fixtures."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'validation/local-deploy-running-sidecars.json')
    args = parser.parse_args()
    path = ROOT / 'tools/deploy-dw-client-local.py'
    text = path.read_text()
    start = text.index('    debug_paths = ')
    end = text.index('    evidence = dict(', start)
    # Execute the original guard, staging, recheck, apply, rollback and cleanup.
    fragment = '\n'.join(line[4:] if line.startswith('    ') else line for line in text[start:end].splitlines())
    outcomes = []
    with tempfile.TemporaryDirectory(prefix='deploy-sidecars-', dir=ROOT / 'tools/build') as tmp:
        base = Path(tmp)
        for case in ('matching-runtime', 'runtime-mismatch', 'game-started-during-staging'):
            directory = base / case
            game, sources = directory / 'game', directory / 'sources'
            game.mkdir(parents=True)
            sources.mkdir()
            target, ini = game / 'game.exe', game / 'game.ini'
            target.write_bytes(b'unchanged runtime image')
            ini.write_bytes(b'owner ini')
            records, debug_artifacts = [], []
            for name, content in [('game.exe', b'unchanged runtime image'), ('owned.ff', b'owned runtime file'), ('game.pdb', b'new matching pdb'), ('game.map', b'new matching map')]:
                source, destination = sources / name, game / name
                source.write_bytes(content)
                if name != 'game.exe':
                    destination.write_bytes(b'old sidecar' if name.endswith(('.pdb', '.map')) else content)
                records.append((source, destination, sha(source)))
                if name.endswith(('.pdb', '.map')):
                    debug_artifacts.append(dict(path=str(destination)))
            if case != 'matching-runtime':
                (game / 'owned.ff').write_bytes(b'other runtime version')
            original = {p.name:p.read_bytes() for p in game.iterdir()}
            calls = iter([False, True] if case == 'game-started-during-staging' else [True, True])
            namespace = dict(records=records, debug_artifacts=debug_artifacts,
                dw_client=SimpleNamespace(running_games=lambda:next(calls), require_current_sources=lambda receipt:None),
                sha=sha, Path=Path, datetime=datetime, timezone=timezone, os=os, shutil=shutil,
                game=game, target=target, ini=ini, ini_hash=sha(ini), before=sha(target), receipt={},
                ready=dict(sha256=sha(target)))
            error = None
            try:
                exec(compile(fragment, str(path), 'exec'), namespace)
            except RuntimeError as exc:
                error = str(exc)
            if case == 'matching-runtime':
                assert error is None
                assert namespace['running_debug_only']
                assert {Path(row['path']).suffix for row in namespace['changes']} == {'.pdb', '.map'}
                assert (game / 'game.pdb').read_bytes() == b'new matching pdb'
                assert (game / 'game.map').read_bytes() == b'new matching map'
                assert target.read_bytes() == original['game.exe']
                assert (game / 'owned.ff').read_bytes() == original['owned.ff']
                assert ini.read_bytes() == original['game.ini']
            else:
                assert error and ('runtime files differ' in error or 'runtime deployment deferred' in error)
                assert all((game / name).read_bytes() == content for name, content in original.items())
                assert not list(game.rglob('*.pending'))
            outcomes.append(dict(case=case, passed=True, error=error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(passed=True, deployer_sha256=sha(path), cases=outcomes,
        scope='Exact guard/transaction source slice; fixtures replace running-process detection and source gate. Full deployer provenance/package preconditions are outside this focused test.',
        live_game_writes=False, temporary_fixtures_cleaned=True), indent=2)+'\n')
    print(args.output)


if __name__ == '__main__':
    main()
