"""Run Replay's unchanged GPU skinning shader on serialized operator surfaces."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

import numpy as np


def unpack(data, middle, extent):
    values = np.frombuffer(data, dtype='<u8')
    quantized = np.stack([(values >> shift) & 0x1fffff for shift in (0,21,42)], axis=1)
    return (quantized.astype(float)/2097151*2-1)*extent+middle


def verify(args):
    manifest = json.loads(args.manifest.read_bytes())
    ff = args.manifest.parent/'custom_operators.ff'
    contents = ff.read_bytes()
    assert hashlib.sha256(contents).hexdigest() == manifest['fastfile_sha256']
    payload = contents[140:]
    reader = manifest['native_reader']
    trace = Path(reader['manifest_path']).parent/'stream-trace.jsonl'
    assert hashlib.sha256(trace.read_bytes()).hexdigest() == reader['trace_summary']['stream_trace_sha256']
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    models = {}
    for source in manifest['model_inputs']:
        data = Path(source['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == source['sha256']
        for model in json.loads(data)['models']:
            models[model['name']+'_surfs'] = model
    export = json.loads(args.shader_export.read_bytes())
    assert export['profile'] == 'replay-1.20'
    assert export['asset']['fields']['name']['string'] == 'cs_skinning_unified.hlsl/cs_skinning_unified_main'
    shader = bytes.fromhex(export['asset']['fields']['prog']['loadDef']['program']['bytes'])
    # Unified vertex storage separates 8-byte positions from 12-byte attributes.
    t0 = bytearray(0x2bc0000)
    t2 = bytearray()
    t5 = bytearray()
    t6 = bytearray()
    surfaces = []
    virtual_vertices = 0
    for root in events:
        if not (root.get('type_id') == 8 and root.get('kind') == 'load_stream_call'
                and root.get('at_start') and root.get('size') == 96
                and root.get('caller_rva') == 0xe2a806):
            continue
        at = root['serialized_input_cursor']
        name = payload[at+96:at+352].split(b'\0',1)[0].decode()
        model = models[name]
        loads = [e for e in events if e.get('type_id') == 8
                 and e.get('xasset_index') == root['xasset_index']
                 and e.get('kind') == 'load_stream_call' and e.get('at_start')]
        array = next(e for e in loads if e.get('caller_rva') == 0xe2a888)
        shared = next(e for e in loads if e.get('caller_rva') == 0xe2b056)
        blob = payload[shared['serialized_input_cursor']:shared['serialized_input_cursor']+shared['size']]
        blends = [e for e in loads if e.get('caller_rva') == 0xe2adb0]
        assert len(blends) == len(model['surfaces'])
        for i,(source,blend) in enumerate(zip(model['surfaces'],blends)):
            header = array['serialized_input_cursor']+i*192
            n = struct.unpack_from('<H',payload,header+2)[0]
            counts = struct.unpack_from('<8H',payload,header+16)
            vertex_offset = struct.unpack_from('<I',payload,header+36)[0]
            bounds = struct.unpack_from('<6f',payload,header+144)
            middle = np.array(bounds[:3]);extent = max(bounds[3:])
            assert n == sum(counts) == len(source['vertices'])
            virtual_vertices = (virtual_vertices+63)//64*64
            first = virtual_vertices
            virtual_vertices += n
            attribute_end = 0x2bc0000+12*virtual_vertices
            t0.extend(bytes(attribute_end-len(t0)))
            for v in range(n):
                vertex = blob[vertex_offset+20*v:vertex_offset+20*(v+1)]
                t0[8*(first+v):8*(first+v+1)] = vertex[:8]
                t0[0x2bc0000+12*(first+v):0x2bc0000+12*(first+v+1)] = vertex[8:]
            t2.extend(bytes((-len(t2))%1024))
            blend_page = len(t2)//1024
            t2.extend(payload[blend['serialized_input_cursor']:blend['serialized_input_cursor']+blend['size']])
            surface = len(surfaces)
            consts = bytearray(128)
            struct.pack_into('<4I4f4f4f',consts,0,0,first//64,blend_page,first,
                             *middle,extent,0,0,0,1,0,0,0,1)
            vertices_before = words_before = 0
            for tier,count in enumerate(counts):
                struct.pack_into('<2I',consts,64+tier*8,count,words_before-vertices_before)
                for v in range(0,count,64):
                    t5.extend(struct.pack('<4H',surface,min(64,count-v),tier+1,vertices_before+v))
                vertices_before += count
                words_before += count*(tier+1)
            t6.extend(consts)
            surfaces.append(dict(name=name,source=source,n=n,first=first,middle=middle,extent=extent))
    assert len(surfaces) == 16
    t1 = struct.pack('<'+'I'*((virtual_vertices+63)//64),*range((virtual_vertices+63)//64))
    t2.extend(bytes((-len(t2))%1024))
    t3 = struct.pack('<'+'I'*(len(t2)//1024),*range(len(t2)//1024))
    results = []
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='native-gpu-skin-',dir=args.output.parent) as temp:
        directory = Path(temp)
        for i,data in ((0,t0),(1,t1),(2,t2),(3,t3),(5,t5),(6,t6)):
            (directory/f't{i}.bin').write_bytes(data)
        (directory/'shader.cso').write_bytes(shader)
        for mode in ('identity','bone_translation','animation_envelope'):
            # This displacement exceeds the old tight per-material boxes.
            # Expected positions must fit without clamping, as animated feet
            # and hands must retain their shape outside their bind-pose box.
            def translation(bone):
                if mode == 'animation_envelope':
                    return np.array([12 if bone%2 else -12,8 if bone%3 else -8,-6],dtype=float)
                return np.array([bone*0.002 if mode!='identity' else 0,0,0])
            dq = b''.join(struct.pack('<8f',0,0,0,1,*(translation(b)*.5),0)
                          for b in range(256))
            (directory/'t4.bin').write_bytes(dq)
            native = subprocess.run([str(args.harness),str(directory/'shader.cso'),str(directory),
                                     str(directory/'output.bin')],capture_output=True,text=True,check=True,timeout=30)
            output = (directory/'output.bin').read_bytes()
            maximum = 0.0
            vertices = 0
            for s in surfaces:
                expected = np.array([v['position'] for v in s['source']['vertices']])
                source = s['source'];cursor = vertex = 0
                for tier,count in enumerate(source['blendCounts']):
                    for _ in range(count):
                        words = source['blendWords'][cursor:cursor+2*tier+1];cursor += len(words)
                        bones = [words[0]//64,*[words[k]//64 for k in range(1,len(words),2)]]
                        weights = [words[k]/65535 for k in range(2,len(words),2)]
                        weights = [1-sum(weights),*weights]
                        expected[vertex] += sum((translation(b)*w for b,w in zip(bones,weights)),np.zeros(3))
                        vertex += 1
                assert np.all(expected>=s['middle']-s['extent']) and np.all(expected<=s['middle']+s['extent']), (
                    'Animation clips against packed surface bounds',mode,s['name'])
                actual = unpack(output[8*s['first']:8*(s['first']+s['n'])],s['middle'],s['extent'])
                error = np.linalg.norm(expected-actual,axis=1)
                worst = float(max(error));maximum = max(maximum,worst);vertices += s['n']
                assert worst < 0.001, (mode,s['name'],worst,int(np.argmax(error)))
            results.append(dict(mode=mode,vertices=vertices,max_position_error=maximum,
                                native_output=native.stdout.strip()))
    return dict(passed=True,gpu_executed=True,game_launched=False,shader_modified=False,
                shader_sha256=hashlib.sha256(shader).hexdigest(),fastfile_sha256=manifest['fastfile_sha256'],
                harness_sha256=hashlib.sha256(args.harness.read_bytes()).hexdigest(),
                surfaces=len(surfaces),cases=results)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--shader-export',type=Path,required=True)
    parser.add_argument('--harness',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = verify(args)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
