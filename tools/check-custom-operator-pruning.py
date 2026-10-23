"""Compare imported operator skins by bone name before and after pruning."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def skin(surface,names):
    result=[]; cursor=0
    for tier,count in enumerate(surface['blendCounts']):
        for _ in range(count):
            words=surface['blendWords'][cursor:cursor+tier*2+1]
            if any(words[i]%64 for i in (0,*range(1,len(words),2))):
                raise ValueError('Misaligned blend bone index')
            influences=[(names[words[0]//64],65535-sum(words[2::2]))]
            influences += [(names[words[i]//64],words[i+1]) for i in range(1,len(words),2)]
            result.append(influences); cursor+=tier*2+1
    if cursor!=len(surface['blendWords']) or len(result)!=len(surface['vertices']):
        raise ValueError('Blend stream coverage differs from geometry')
    return result


def part_names(surface,names):
    return {name for index,name in enumerate(names)
            if surface['partBits'][index//32]&(0x80000000>>(index%32))}


def compare(old,new):
    if len(old['surfaces'])!=len(new['surfaces']):
        raise ValueError('Pruning changed surface count')
    vertices=triangles=0
    for before,after in zip(old['surfaces'],new['surfaces']):
        for key in ('material','vertices','indices','blendCounts'):
            if before[key]!=after[key]:
                raise ValueError('Pruning changed surface '+key)
        if skin(before,old['boneNames'])!=skin(after,new['boneNames']):
            raise ValueError('Pruning changed quantized skin influences by name')
        if part_names(before,old['boneNames'])!=part_names(after,new['boneNames']):
            raise ValueError('Pruning changed surface bone-mask identities')
        vertices+=len(after['vertices']); triangles+=len(after['indices'])//3
    for index,name in enumerate(new['boneNames']):
        original=old['boneNames'].index(name)
        for key in ('baseMat','boneInfo','partClassification'):
            if old['skeleton'][key][original]!=new['skeleton'][key][index]:
                raise ValueError('Pruning changed per-bone '+key)
        if index>=new['numRootBones']:
            child=index-new['numRootBones']; old_child=original-old['numRootBones']
            parent=index-new['skeleton']['parentList'][child]
            old_parent=original-old['skeleton']['parentList'][old_child]
            if new['boneNames'][parent]!=old['boneNames'][old_parent]:
                raise ValueError('Pruning changed native parent identity')
            for key in ('quats','trans'):
                if new['skeleton'][key][child]!=old['skeleton'][key][old_child]:
                    raise ValueError('Pruning changed native local '+key)
    return {'name':new['name'],'before_bones':len(old['boneNames']),
            'after_bones':len(new['boneNames']),'vertices':vertices,'triangles':triangles,
            'geometry_identical':True,'skin_names_and_quantized_weights_identical':True,
            'native_parent_names_and_bind_arrays_identical':True,'part_names_identical':True}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--model-input',type=Path,action='append',required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    originals={m['name']:m for m in json.loads(args.baseline.read_text())['models']}
    report={'schema':1,'baseline_sha256':sha(args.baseline),'model_inputs':[], 'models':[]}
    for source in args.model_input:
        models=json.loads(source.read_text())['models']
        total=sum(len(model['boneNames']) for model in models)
        if total>254: raise ValueError('Raw body/head bones exceed native DObj limit')
        report['model_inputs'].append({'path':str(source.resolve()),'sha256':sha(source),
                                       'raw_bones':total,'remaining_to_native_limit':254-total})
        for model in models:
            report['models'].append(compare(originals[model['name']],model))
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
