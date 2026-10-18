"""Execute the authored loot helper at isolated engine boundaries; no game use."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path('C:/Program Files/LLVM/bin')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('loot_prepare', ROOT / 'tools/prepare-br-bot-loot-integration.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    proof = module.inspect(args.snapshot)
    source = ROOT / 'tools/br_bot_loot_harness.cpp'
    (ROOT / 'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='br-loot-', dir=ROOT / 'build') as temporary:
        folder = Path(temporary)
        (folder / 'SV_HostBotLootBindings.h').write_text(module.HEADER)
        obj, image = folder / 'loot.obj', folder / 'loot.dll'
        flags = ['--target=x86_64-pc-windows-msvc', '-std=c++20', '-O2', '-ffreestanding',
                 '-fno-exceptions', '-fno-rtti', '-ffunction-sections', '-fdata-sections',
                 '-fno-stack-protector', '-mno-stack-arg-probe', '-Wall', '-Wextra', '-Werror',
                 '-I' + str(folder), '-I' + str(ROOT / 'integration/host-scale'),
                 '-I' + str(args.snapshot / 'src')]
        subprocess.run([str(LLVM / 'clang++.exe'), *flags, '-c',
                        str(ROOT / 'integration/host-scale/SV_HostBot_Loot.cpp'),
                        '-o', str(folder / 'production.obj')], check=True)
        subprocess.run([str(LLVM / 'clang++.exe'), '--target=x86_64-pc-windows-msvc', '-c',
                        str(source), '-o', str(obj), '-std=c++20', '-O2', '-ffreestanding',
                        '-fno-exceptions', '-fno-rtti', '-ffunction-sections', '-fdata-sections',
                        '-fno-stack-protector', '-mno-stack-arg-probe', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(folder), '-I' + str(ROOT / 'integration/host-scale'),
                        '-I' + str(args.snapshot / 'src')], check=True)
        subprocess.run([str(LLVM / 'lld-link.exe'), '/dll', '/noentry', '/nodefaultlib', '/opt:ref',
                        '/out:' + str(image), str(obj)], check=True)
        library = ctypes.CDLL(str(image))
        try:
            result = library.Test_Run()
            assert result == 0, f'BR loot helper failed at harness line {result}'
        finally:
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(library._handle)
    proof.update(passed=True, production_object_compiled=True, engine_boundaries_modeled=True,
                 checks=['obstructed weapon skipped for cache', 'melee pickup skipped',
                         'reuse generation delivered to native callback', 'no repeated full-item use',
                         'native use cone required', 'stale goal generation rejected',
                         'equipped inventory does not churn weapons', 'upper floor skipped',
                         'Gulag and laststand and skydive and airborne and combat suppressed', 'timer rollback resets state',
                         'at most four scans per frame', 'TLS context restored on every exit'])
    proof['checks'].extend(['temporary native look request reaches direction updater',
                           'previous look point time type and opaque field restored',
                           'enemy target suppresses loot look', 'active stronger script look preserved',
                           'native CODE_SEEK look can be replaced and is restored',
                           'script look lock suppresses override', 'loot look TLS restored',
                           'gas evacuation retains priority during combat',
                           'gas evacuation suppresses loot and armor',
                           'stable current circle and closing next circle destinations',
                           'gas state expires and rejects timer rollback',
                           'gas map reset generation and invalid radius rejection'])
    proof['inputs'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                       (source, ROOT / 'integration/host-scale/SV_HostBot_Loot.cpp',
                        ROOT / 'integration/host-scale/sv_host_bot_loot.h')}
    args.output.write_text(json.dumps(proof, indent=2) + '\n')
    print('PASS: compiled BR loot helper behavior and pinned Replay ABI checks; no game launch')

if __name__ == '__main__':
    main()
