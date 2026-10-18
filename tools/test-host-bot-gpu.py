"""Verify frozen GPU objects/image/imports and execute the actual coordinator.

Hardware evidence is explicitly reused only when its backend/shader hashes
match this frozen build. Coordinator boundaries are modeled, not hardware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import pefile


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(build, output):
    build = Path(build).resolve()
    report = json.loads((build/'build-report.json').read_bytes())
    snapshot = Path(report['source_root']).resolve()
    receipt = json.loads((snapshot/'generated/host-bot-gpu.json').read_bytes())
    image = Path(report['executable'])
    assert digest(image) == report['sha256'], 'Built executable hash changed'
    assert report['unresolved_symbols'] == 0
    for name, expected in receipt['sources'].items():
        assert digest(snapshot/'src'/name)==expected, ('Prepared source changed',name)
    native = json.loads((snapshot/'generated/host-scale-integration.json').read_bytes())['gpu_navigation_graph']
    expected_evidence = {
        0x1FC7250:(188,'3da0ae255a56d4dd0d2cca9eb541b2d3542107812b677c275f684b90fb0d2cb8'),
        0x1FC7FD0:(130,'8151d22b868155d4ca75dd0e880f00be3f1cac02921fa2fa16138844a4fa5469'),
        0x1FAA880:(152,'c3e9e6baf621f20c521e4e1d95801f1e71c0722ff778040b845f47fd33ec9fec'),
        0x1FC9660:(76,'c08030d3699efa5e1f9b4e15d5a64a7fac4f4a186174904cbdc1d89b3c965d8e'),
        0x1FDE130:(101,'3d21b2b2d1efeea7ad930874dc35c76d478d87a34719cfb08978756b5bcfac06'),
        0x1FDE030:(112,'700a1ab154582160fdf11e84c4addcc18fff8f3fdf1bbe5702db030e6a3b011a'),
    }
    actual_evidence = {row['original_rva']:(row['original_bytes'],row['original_sha256']) for row in native['evidence']}
    assert actual_evidence == expected_evidence, 'Six pinned native graph evidence hashes must match, including empty-child parent semantics'
    checked = []
    for name in ('SV_HostBotGpu.cpp','SV_HostBotGpuPlanner.cpp','SV_HostNavGraph.cpp'):
        source = snapshot/'src'/name
        rows = [row for row in report['cpp'] if Path(row['source']).as_posix() == 'src/'+name]
        assert len(rows)==1, ('Missing/duplicate frozen GPU object',name)
        row=rows[0]
        assert row['source_sha256']==digest(source), ('Source hash changed',name)
        assert row['object_sha256']==digest(row['object']), ('Object hash changed',name)
        for dependency in row['dependencies']:
            assert digest(dependency['path'])==dependency['sha256'], ('Dependency changed',dependency['path'])
        assert row['dependencies'], ('No tracked dependencies',name)
        checked.append(dict(source=name,sha256=row['source_sha256'],object_sha256=row['object_sha256'],dependencies=len(row['dependencies'])))
    header=snapshot/'src/SV_HostBotGpuShader.h'
    assert digest(header)==receipt['header_sha256']
    body=header.read_text().split('{',1)[1].split('}',1)[0]
    shader=bytes(int(value) for value in re.findall(r'\d+',body))
    assert shader[:4]==b'DXBC' and hashlib.sha256(shader).hexdigest()==receipt['bytecode_sha256']
    assert shader in image.read_bytes(), 'Fixed compiled shader absent from built executable'
    pe=pefile.PE(str(image),fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    imports={}
    for library in pe.DIRECTORY_ENTRY_IMPORT:
        imports[library.dll.decode().lower()]={entry.name.decode():entry.address-pe.OPTIONAL_HEADER.ImageBase for entry in library.imports if entry.name}
    resolved={}
    for library,names in receipt['required_native_imports'].items():
        for name in names:
            assert name in imports[library.lower()], ('Missing native import',library,name)
            rva=imports[library.lower()][name]
            assert report['symbols'].get('__imp_'+name)==rva, ('Native IAT resolution differs',name)
            resolved[name]=rva
    for name in receipt['system32_dynamic_entrypoints']['d3d12.dll']:
        assert all(name not in entries for entries in imports.values()), ('Unexpected new D3D12 IAT entry',name)
    for name,expected in receipt['fixtures'].items():
        assert digest(snapshot/'tools'/name)==expected, ('Frozen fixture changed',name)
    caller=(snapshot/'src/Bot_UpdateMove_OffPathGrid.cpp').read_text()
    guard=caller.split('bool CurrentMappedBot(',1)[1].split('bool Locked(',1)[0]
    for token in ('!bot || !bot->entity || !bot->playerState || !bot->sentient',
                  'slot >= 200 || slot >= SVHS_ClientCount', 'SVHS_Clients[slot]',
                  'static_cast<const uint8_t *>(client) + 1368',
                  'Field<int32_t>(client, 214756) == 2', 'Field<Entity *>(client, 280) == bot->entity',
                  'bot->entity->client == bot->playerState', 'bot->entity->sentient == bot->sentient',
                  'SVHS_IsBotEntity(bot->entity) && SVHS_IsBotPlaying(client)',
                  'DW_BotPolicy_ProfileSeed(slot, &profile)'):
        assert token in guard, ('Bot caller ownership guard missing',token)
    for token in ('const bool mapped = CurrentMappedBot(bot, &profile)',
                  'const auto gpu = mapped ? HostBotPlanner::Take(',
                  'if (projected && !gpuReady && mapped && HostBotPlanner::Enabled() && now >= state.gpuRetryAfter)',
                  'queued = HostBotPlanner::Queue(',
                  'if (projected && !queued && (gpuReady ? s_gpuCommits < 8 : s_cpuPlans < 2))',
                  'SVHS_BotPathToGoal(bot, &goal, 32.0f, "mesh fallback")',
                  'path = SVHS_NavHasPath(nav)'):
        assert token in caller, ('GPU caller/fallback flow missing',token)
    assert 'if (evacuating && !gpuReady && SV_HostBot_GetGasState(&gas))' in caller, 'GPU route detours must survive the CPU radial progress filter'
    destination=build/'host-bot-gpu-check'
    destination.mkdir(exist_ok=True)
    executable=destination/'host_bot_gpu_planner_harness.exe'
    compiler=next(row['compiler']['path'] for row in report['cpp'] if Path(row['source']).name=='SV_HostBotGpu.cpp')
    command=[compiler,'-std=c++20','-O2','-Wall','-Wextra','-Werror','-I',str(snapshot/'src'),str(snapshot/'tools/host_bot_gpu_planner_harness.cpp'),'-o',str(executable)]
    subprocess.run(command,check=True,capture_output=True,text=True)
    run=subprocess.run([str(executable)],check=True,capture_output=True,text=True,timeout=30)
    assert 'PASS actual coordinator:' in run.stdout
    # The frozen exporter fixture uses a repository-relative header include.
    # Stage exact frozen bytes in that shape; compile the real frozen exporter,
    # not a substituted implementation or a modified test source.
    nav_fixture=snapshot/'tools/test-host-nav-graph.cpp'
    nav_hash=receipt['fixtures']['test-host-nav-graph.cpp']
    assert digest(nav_fixture)==nav_hash
    nav_tools=destination/'nav-fixture/tools'
    nav_headers=destination/'nav-fixture/integration/host-scale'
    nav_tools.mkdir(parents=True,exist_ok=True);nav_headers.mkdir(parents=True,exist_ok=True)
    staged=nav_tools/nav_fixture.name;staged.write_bytes(nav_fixture.read_bytes())
    (nav_headers/'SV_HostNavGraph.h').write_bytes((snapshot/'src/SV_HostNavGraph.h').read_bytes())
    assert digest(staged)==nav_hash
    fixture_text=staged.read_text()
    assert 'childCount=0' in fixture_text and 'childCount=1' in fixture_text, 'Missing empty/nonempty child container regression'
    nav_executable=destination/'host_nav_graph_harness.exe'
    subprocess.run([compiler,'-std=c++20','-O2','-Wall','-Wextra','-Werror',
                    '-I',str(snapshot/'src'),str(snapshot/'src/SV_HostNavGraph.cpp'),str(staged),
                    '-o',str(nav_executable)],check=True,capture_output=True,text=True)
    nav_run=subprocess.run([str(nav_executable)],check=True,capture_output=True,text=True,timeout=30)
    assert '2048 nodes/4094 edges' in nav_run.stdout, 'Exporter capacity fixture did not finish'
    # Frozen evidence remains separate from newly executed modeled boundaries.
    hardware_path=snapshot/'generated/host-bot-gpu-hardware-proof.json'
    assert digest(hardware_path)==receipt['hardware_proof_sha256']
    hardware=json.loads(hardware_path.read_bytes())
    for name in ('SV_HostBotGpu.cpp','SV_HostBotGpu.h','SV_HostBotGpu.hlsl'):
        assert hardware['source_sha256']['integration/host-scale/'+name]==digest(snapshot/'src'/name), ('Hardware proof stale',name)
    assert hardware['shader_bytecode_sha256']==receipt['bytecode_sha256']
    assert hardware['hardware_execution'] is True and hardware['verified_stress_routes']>=200
    result=dict(schema=1,passed=True,build=str(build),image_sha256=report['sha256'],objects=checked,
                shader_bytecode_sha256=receipt['bytecode_sha256'],native_iat_rvas=resolved,
                navigation_graph=dict(actual_frozen_exporter=True,fixture_sha256=nav_hash,
                                      native_evidence=actual_evidence,stdout=nav_run.stdout,
                                      boundaries='synthetic owned native-layout buffers; no game execution'),
                coordinator=dict(actual_frozen_cpp=True,boundaries='modeled GPU and native graph; no game execution',stdout=run.stdout,
                                 human_boundary='in-range human/bot classification belongs to native caller; coordinator verifies slot bounds and owner identity'),
                hardware=dict(evidence='reused frozen hardware proof, not a new GPU execution during this build check',
                              proof_sha256=digest(hardware_path),verified_stress_routes=hardware['verified_stress_routes']),
                caller_static_guards=dict(ownership=True,native_fallback=True,gpu_gas_detour=True,execution=False),
                game_execution=False)
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(verify(args.build,args.output),indent=2))
