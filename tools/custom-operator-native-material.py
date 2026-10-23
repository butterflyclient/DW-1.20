"""Preserve a Replay material's native packed constants and common technique."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def prepare(source,output):
    export=json.loads(source.read_text())
    if export['profile']!='replay-1.20' or export['asset']['issue_count']:
        raise ValueError('Native Replay material export is incomplete')
    f=export['asset']['fields']
    if f['packedAtlasData'] or f['subMaterials'] or f['decalVolumeMaterial']:
        raise ValueError('Choose a simple native common soldier material')
    info=bytearray(32)
    struct.pack_into('<IIfI',info,0,f['contents'],f['surfaceFlags'],f['maxDisplacement'],f['materialType']['value'])
    struct.pack_into('<BBHBBBBHBB',info,16,f['cameraRegion'],f['sortKey'],f['___u7']['flags'],
                     f['textureCount'],f['constantCount'],f['constantBufferCount'],f['layerCount'],
                     f['packedAtlasDataSize'],f['textureAtlasRowCount'],f['textureAtlasColumnCount'])
    constants=bytearray()
    for constant in f['constantTable']['values']:
        constants+=struct.pack('<I',constant['index'])
        for value in constant['literal']['v']:
            constants+=(struct.pack('<I',int(value['bits'],16)) if isinstance(value,dict)
                        else struct.pack('<f',value))
    buffers=[]
    for buffer in f['constantBufferTable']['values']:
        stages=[]
        for stage in ('vs','hs','ds','ps'):
            data=buffer[stage+'Data']
            payload=bytes.fromhex(data['bytes']) if data else b''
            if len(payload)!=buffer[stage+'DataSize']:
                raise ValueError('Native constant buffer bytes disagree with size')
            stages.append(payload.hex())
        buffers.append(stages)
    textures=[];color_slots=[]
    for index,texture in enumerate(f['textureTable']['values']):
        slot=texture['index']
        if slot not in (0,59):
            raise ValueError('Native donor must use base color and black emissive only')
        if slot==0: color_slots.append(index)
        textures.append({'header':struct.pack('<Q',slot).hex(),
                         'image':texture['image']['name'].lstrip(',') if slot==0 else '$black'})
    result={'name':'native_donor','info':info.hex(),'techset':f['techniqueSet']['name'].lstrip(','),
            'constants':constants.hex(),'bufferIndices':f['constantBufferIndex']['bytes'],
            'buffers':buffers,'textures':textures,'images':[],'colorSlots':color_slots,
            'provenance':{'source':str(source.resolve()),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                          'material':f['name']['string'],'profile':'replay-1.20'}}
    output.write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();prepare(a.source,a.output)
