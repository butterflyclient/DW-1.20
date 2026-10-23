"""Preserve the regular and client skeleton from a Replay XModel export."""
import argparse
import hashlib
import json
from pathlib import Path


def prepare(source, strings, output):
    export = json.loads(source.read_bytes())
    if export['profile'] != 'replay-1.20' or export['asset']['issue_count']:
        raise ValueError('Incomplete Replay XModel export')
    f = export['asset']['fields']
    names = json.loads(strings.read_bytes())
    regular, client, roots = f['numBones'], f['numClientBones'], f['numRootBones']
    total = regular + client
    def grouped(key, width):
        values = f[key]['values']
        if len(values) != (total-roots)*width:
            raise ValueError('Wrong native array extent: '+key)
        return [values[i:i+width] for i in range(0,len(values),width)]
    skeleton = dict(parentList=list(bytes.fromhex(f['parentList']['bytes'])),
                    quats=grouped('quats',4), trans=grouped('trans',3),
                    partClassification=list(bytes.fromhex(f['partClassification']['bytes'])),
                    baseMat=[dict(quat=b['quat']['v'],trans=b['trans']['v'],
                                  transWeight=b['transWeight']) for b in f['baseMat']['values']],
                    boneInfo=[dict(midPoint=b['bounds']['midPoint']['v'],
                                   halfSize=b['bounds']['halfSize']['v'],
                                   radiusSquared=b['___u1']['radiusSquared']) for b in f['boneInfo']['values']])
    assert len(skeleton['parentList']) == total-roots
    assert len(skeleton['partClassification']) == regular
    assert len(skeleton['baseMat']) == len(skeleton['boneInfo']) == total
    result = dict(boneNames=[names[b['value']] for b in f['boneNames']['values']],
                  numBones=regular,numClientBones=client,numRootBones=roots,skeleton=skeleton,
                  boundsHalf=f['bounds']['halfSize']['v'],
                  physicsAssetName=f['physicsAsset']['name'].lstrip(','),
                  provenance=dict(source=str(source.resolve()),profile='replay-1.20',
                                  native_export_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                                  native_script_strings_sha256=hashlib.sha256(strings.read_bytes()).hexdigest()))
    assert len(result['boneNames']) == total
    output.write_text(json.dumps(result,indent=2)+'\n')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path)
    parser.add_argument('strings',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    prepare(args.source,args.strings,args.output)
