"""Build and independently reread the native custom operator zone."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'data/dw-client/compiler-base/tools'))
from roundtrip_replay_fastfile import verify_native
import workstation_native_references

# PhysicsAsset's native 88-byte root has the same proven root/name contract.
# The shared reference collector still checks its exact Load_Stream, string,
# callback bounds, pointer token, root link and full table/journal coverage.
workstation_native_references.REFERENCE_ROOT_NAME_TYPES = (
    workstation_native_references.REFERENCE_ROOT_NAME_TYPES | {3})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def patch(fastfile):
    # The native zero-payload patch repeats the exact previous/target header.
    prefix=bytearray(0x38)
    prefix[:8]=b'IWffd100'
    struct.pack_into('<II',prefix,8,6,4)
    return bytes(prefix)+fastfile[:0x88]+fastfile[:0x88]


def prepare(args):
    output=args.output.resolve(); output.mkdir(parents=True,exist_ok=True)
    merged={'schema':1,'models':[],'materials':[]}
    proofs=[]
    for source in args.model_input:
        source=source.resolve()
        value=json.loads(source.read_text())
        merged['models']+=value['models']
        for material in value['materials']:
            for image in material['images']:
                image['pixels']=str((source.parent/image['pixels']).resolve())
            merged['materials'].append(material)
        proofs.append({'path':str(source),'sha256':sha(source.read_bytes())})
    joined=output/'model-input.json'
    joined.write_text(json.dumps(merged,separators=(',',':'))+'\n')
    ff=output/'custom_operators.ff'
    subprocess.run([str(args.writer),str(joined),str(ff)],check=True)
    ff_bytes=ff.read_bytes(); empty=(output/'empty.ff').read_bytes()
    fp=patch(ff_bytes); empty_fp=patch(empty)
    ff.with_suffix('.fp').write_bytes(fp)
    (output/'empty.fp').write_bytes(empty_fp)
    evidence=output/f'native-{time.time_ns()}'
    result=verify_native(ff,ff.with_suffix('.raw').read_bytes(),ff,args.acts,args.replay,evidence,120,trace=True)
    empty_evidence=output/f'native-empty-{time.time_ns()}'
    empty_result=verify_native(output/'empty.ff',(output/'empty.raw').read_bytes(),output/'empty.ff',args.acts,args.replay,empty_evidence,60,trace=True)
    zone='dw_custom_operators_'+sha(ff_bytes+fp+empty+empty_fp)[:16]
    spec=importlib.util.spec_from_file_location('operator_native_paths',ROOT/'tools/bot_style_paths.py')
    paths=importlib.util.module_from_spec(spec); spec.loader.exec_module(paths)
    locale=paths.derive(ROOT/'data/dw-client/compiler-base')
    installations=[{'name':zone,'directory':''}]
    for prefix in sorted(set(['techsets','srv',*locale['regions'],*locale['supported_languages']])):
        installations.append({'name':prefix+'_'+zone,
                              'directory':locale['language_directories'].get(prefix,locale['region_directories'].get(prefix,''))})
    lines=['#pragma once','#include "DW_BotStyleScriptPackage.h"',
           'static_assert(sizeof(DWBotStyleScriptPackage)==96);','namespace DWCustomOperatorsPackage {']
    for name,data in [('Fastfile',ff_bytes),('Patch',fp),('EmptyFastfile',empty),('EmptyPatch',empty_fp)]:
        lines.append(f'inline const uint8_t {name}[] = {{')
        lines += ['    '+','.join(str(b) for b in data[i:i+24])+',' for i in range(0,len(data),24)]
        lines.append('};')
    for symbol,key in [('InstallationNames','name'),('InstallationDirectories','directory')]:
        lines.append(f'inline const char *const {symbol}[] = {{')
        lines += ['    '+json.dumps(row[key])+',' for row in installations]
        lines.append('};')
    lines += ['inline const DWBotStyleScriptPackage Package = {'+json.dumps(zone)+', Fastfile, sizeof(Fastfile), Patch, sizeof(Patch), EmptyFastfile, sizeof(EmptyFastfile), EmptyPatch, sizeof(EmptyPatch), InstallationNames, InstallationDirectories, sizeof(InstallationNames)/sizeof(*InstallationNames), 0};','}']
    header=output/'DW_CustomOperatorsPackage.h'
    header.write_text('\n'.join(lines)+'\n',encoding='ascii')
    manifest={'schema':1,'zone':zone,'operators':[
        {'id':'nicky','label':'Nicky','body':'dw_operator_nicky_body','head':'dw_operator_nicky_head'},
        {'id':'bo2','label':'BO2 SEAL Assault','body':'dw_operator_bo2_body','head':'dw_operator_bo2_head'}],
        'native_reader':result,'native_empty_reader':empty_result,'model_inputs':proofs,
        'header':str(header),'header_sha256':sha(header.read_bytes()),'fastfile_sha256':sha(ff_bytes),
        'patch_sha256':sha(fp),'installations':installations,
        'trace_checked_reference_types':[3],
        'writer_executable':str(args.writer.resolve()),'writer_sha256':sha(args.writer.read_bytes()),
        'importer_sha256':sha((ROOT/'tools/import-custom-operator-model.py').read_bytes()),
        'writer_source_sha256':sha((ROOT/'tools/custom-operator-model.cpp').read_bytes()),
        'runtime_animation_verified':False}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'header':str(header),'zone':zone,'ff_bytes':len(ff_bytes)},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--model-input',type=Path,action='append',required=True)
    p.add_argument('--output',type=Path,default=ROOT/'data/custom-operators/package')
    p.add_argument('--writer',type=Path,default=ROOT/'tools/build/custom-operator-model/out/Release/custom-operator-model.exe')
    p.add_argument('--acts',type=Path,default=Path(r'D:\mw124\atian-cod-tools\build-workstation\bin\Release\acts.exe'))
    p.add_argument('--replay',type=Path,default=Path(r'E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe'))
    prepare(p.parse_args())
