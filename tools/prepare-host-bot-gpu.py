"""Compile the fixed GPU planner shader into a private snapshot (no game build).

The production caller uses existing CreateDXGIFactory1 from dxgi.dll and
kernel32 loader imports. D3D12 entrypoints resolve from System32 at runtime. This does
not load helper DLLs, compile shaders at runtime, or change the render device.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'integration/host-scale/SV_HostBotGpu.hlsl'


def prepare(snapshot, fxc=None):
    snapshot = Path(snapshot).resolve()
    target = snapshot / 'src'
    if not target.is_dir():
        raise ValueError('Expected existing private snapshot src directory')
    source = target / SOURCE.name
    if not source.exists():
        source.write_bytes(SOURCE.read_bytes())
    if fxc is None:
        candidates = sorted(Path(r'C:\Program Files (x86)\Windows Kits\10\bin').glob('*/x64/fxc.exe'))
        if not candidates:
            raise FileNotFoundError('Windows SDK FXC is required; runtime compilation is forbidden')
        fxc = candidates[-1]
    fxc = Path(fxc).resolve()
    with tempfile.TemporaryDirectory(prefix='host-bot-gpu-') as directory:
        output = Path(directory) / 'planner.cso'
        subprocess.run([str(fxc), '/nologo', '/Ges', '/WX', '/O3', '/T', 'cs_5_0',
                        '/E', 'main', '/Fo', str(output), str(source)], check=True)
        bytecode = output.read_bytes()
    if bytecode[:4] != b'DXBC':
        raise ValueError('Unexpected shader container')
    header = '#pragma once\nstatic const unsigned char HostBotGpuShader[] = {\n'
    header += '\n'.join('    '+','.join(str(b) for b in bytecode[i:i+24])+',' for i in range(0,len(bytecode),24))
    header += '\n};\n'
    (target / 'SV_HostBotGpuShader.h').write_bytes(header.encode('ascii'))
    receipt = dict(schema=1, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                   bytecode_sha256=hashlib.sha256(bytecode).hexdigest(),
                   header_sha256=hashlib.sha256(header.encode('ascii')).hexdigest(),
                   compiler=str(fxc), compiler_sha256=hashlib.sha256(fxc.read_bytes()).hexdigest(),
                   profile='cs_5_0', entry='main', runtime_compilation=False,
                   required_native_imports={'dxgi.dll':['CreateDXGIFactory1'],
                                            'kernel32.dll':['GetTickCount64','LoadLibraryExW','GetProcAddress','GetLastError']},
                   system32_dynamic_entrypoints={'d3d12.dll':['D3D12CreateDevice','D3D12SerializeRootSignature']},
                   max_bots=200, max_nodes=2048, max_edges=16384, in_flight_batches=3)
    generated = snapshot / 'generated'
    generated.mkdir(exist_ok=True)
    # Freeze fixture metadata once here, alongside the fixed shader receipt.
    # Existing snapshot inputs always win over mutable canonical sources.
    fixtures = snapshot / 'tools'
    fixtures.mkdir(exist_ok=True)
    receipt['fixtures'] = {}
    for name in ('host_bot_gpu_planner_harness.cpp', 'host_bot_gpu_harness.cpp', 'test-host-bot-gpu.py', 'test-host-nav-graph.cpp'):
        path = fixtures / name
        if not path.exists():
            path.write_bytes((ROOT / 'tools' / name).read_bytes())
        receipt['fixtures'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
    receipt['sources'] = {}
    for name in ('SV_HostBotGpu.cpp', 'SV_HostBotGpu.h', 'SV_HostBotGpu.hlsl',
                 'SV_HostBotGpuPlanner.cpp', 'SV_HostBotGpuPlanner.h', 'SV_HostNavGraph.cpp', 'SV_HostNavGraph.h'):
        path = target / name
        if not path.exists():
            path.write_bytes((ROOT / 'integration/host-scale' / name).read_bytes())
        receipt['sources'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
    hardware = generated / 'host-bot-gpu-hardware-proof.json'
    if not hardware.exists():
        hardware.write_bytes((ROOT / 'validation/host-bot-gpu/hardware-proof.json').read_bytes())
    receipt['hardware_proof_sha256'] = hashlib.sha256(hardware.read_bytes()).hexdigest()
    (generated/'host-bot-gpu.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--fxc', type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, args.fxc), indent=2))
