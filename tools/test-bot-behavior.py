"""Focused bot integration gates; compiled/native boundaries, no game launch."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    reports = []
    with tempfile.TemporaryDirectory(prefix='bot-behavior-', dir=ROOT / 'data') as temporary:
        folder = Path(temporary)
        for checker, name in (('test-bot-think.py', 'think.json'),
                              ('test-br-bot-loot.py', 'loot.json')):
            output = folder / name
            command = [sys.executable, '-B', str(ROOT / 'tools' / checker),
                       '--snapshot', str(args.snapshot), '--output', str(output)]
            if args.build and checker == 'test-bot-think.py':
                command += ['--build', str(args.build)]
            subprocess.run(command, cwd=ROOT, check=True)
            reports.append(dict(checker=checker, result=json.loads(output.read_bytes())))
        fixture = folder / 'equipment-test.exe'
        subprocess.run([r'C:\Program Files\LLVM\bin\clang++.exe', '-std=c++20',
                        '-Wall', '-Wextra', '-Werror', '-O2',
                        '-I' + str(args.snapshot / 'src'),
                        str(ROOT / 'tools/test-host-bot-equipment.cpp'),
                        '-o', str(fixture)], cwd=ROOT, check=True)
        subprocess.run([str(fixture)], cwd=folder, check=True)
        reports.append(dict(checker='test-host-bot-equipment.cpp', passed=True))
    linked = json.loads((args.build / 'build-report.json').read_bytes()) if args.build else None
    if linked:
        image = Path(linked['executable'])
        assert hashlib.sha256(image.read_bytes()).hexdigest() == linked['sha256']
        assert linked['unresolved_symbols'] == 0
        for symbol in ('Bot_Think', 'SV_HostBot_PrepareEquipment', 'SV_HostBot_UpdateLoot',
                       'SV_HostBot_GetLootGoal', 'SV_HostBot_FaceLoot', 'DW_BotPolicy_IsBattleRoyale'):
            assert symbol in linked['symbols'], symbol
    sources = [p for p in (ROOT / 'integration/host-scale').glob('*') if p.is_file()]
    result = dict(passed=True, reports=reports, game_run_performed=False,
                  native_boundaries_modeled=True,
                  executable_sha256=linked['sha256'] if linked else None,
                  source_hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in sources})
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: bot think, equipment and loot integration; no game launch', flush=True)

if __name__ == '__main__':
    main()
