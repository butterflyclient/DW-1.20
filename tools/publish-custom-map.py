"""Explicitly publish one frozen custom map and back up its prior server release.

Ordinary EXE publication must never call this tool or select game map files.
Payloads are immutable SHA256-addressed XPRESS_HUFF chunks. The existing asset
route serves them unchanged; only this explicit tool advances the map catalog.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import textwrap
import time

import remote_backend

ROOT = Path(__file__).resolve().parents[1]
REMOTE = '/var/lib/replay-dw/updates'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def atomic_json(path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + '.pending')
    pending.write_bytes((json.dumps(document, indent=2) + '\n').encode('utf-8'))
    pending.replace(path)


def inventory():
    """Read the explicit map registry through the pinned SSH connection."""
    code = (
        'import json,pathlib\n'
        f'path=pathlib.Path({REMOTE!r})/"custom-map-catalog.json"\n'
        'print(json.dumps(json.loads(path.read_bytes()) if path.exists() else None))\n'
    )
    with remote_backend.connect() as client:
        _, out, error = client.exec_command("python3 - <<'PY'\n" + code + 'PY', timeout=20)
        raw = out.read()
        if out.channel.recv_exit_status():
            raise RuntimeError(error.read().decode())
    return json.loads(raw)


def catalog_for(record, release):
    from dw_update_maps import verify_record
    verify_record(record)
    if not isinstance(release, int) or isinstance(release, bool) or release <= 0:
        raise ValueError('Custom map release must be positive')
    manifest = Path(record['manifest_path'])
    if sha(manifest) != record['manifest_sha256']:
        raise ValueError('Frozen custom-map manifest changed')
    payloads = {}
    for digest, item in record['payloads'].items():
        if not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Invalid compressed map payload digest')
        path = Path(item['source'])
        size = item['size']
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= 64 * 1024 * 1024:
            raise ValueError('Compressed chunk exceeds the existing asset route')
        if path.stat().st_size != size or sha(path) != digest:
            raise ValueError('Frozen compressed map chunk changed')
        payloads[digest] = size
    return dict(schema=1, format='custom-map-package-v1', release=release,
                package_hash=record['package_hash'], manifest_sha256=record['manifest_sha256'],
                manifest_size=manifest.stat().st_size, files=len(record['files']),
                chunks=len(record['chunks']), uncompressed_bytes=record['uncompressed_bytes'],
                codec='xpress_huff', chunk_bytes=4 * 1024 * 1024, payloads=payloads)


def transaction_script(incoming, catalog_sha):
    """Server-side commit. The old catalog/payload backup precedes catalog advance."""
    code = r'''
import fcntl,hashlib,json,os,pathlib,re,struct,time
incoming=pathlib.Path(INCOMING);root=incoming.parent
sha=lambda path:hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
def sync_file(path):
    with path.open('rb') as stream:os.fsync(stream.fileno())
def sync_dir(path):
    handle=os.open(path,os.O_DIRECTORY);os.fsync(handle);os.close(handle)
def immutable(source,destination):
    if destination.exists():
        assert destination.is_file() and not destination.is_symlink()
        assert destination.stat().st_size==source.stat().st_size and sha(destination)==sha(source)
        source.unlink()
    else:
        os.chmod(source,0o444);os.replace(source,destination)
    sync_file(destination)
with (root/'publication.lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    catalog_file=incoming/'catalog.json'
    assert sha(catalog_file)==CATALOG_SHA
    new=json.loads(catalog_file.read_bytes())
    assert new['schema']==1 and new['format']=='custom-map-package-v1'
    assert type(new['release']) is int and new['release']>0
    assert re.fullmatch('[0-9a-f]{64}',new['package_hash']) and re.fullmatch('[0-9a-f]{64}',new['manifest_sha256'])
    blob=(incoming/'manifest.bin').read_bytes()
    assert len(blob)==new['manifest_size'] and hashlib.sha256(blob).hexdigest()==new['manifest_sha256']
    magic,version,total,file_count,chunk_count,raw_total,entries_hash,package_hash=struct.unpack_from('<16sIIIIQ32s32s',blob)
    assert magic==b'REPLAYDWMAP01\0\0\0' and version==1
    assert 0<file_count<=256 and 0<chunk_count<=4096 and 0<raw_total<=4*1024*1024*1024
    assert total==len(blob)==104+176*file_count+72*chunk_count
    assert new['files']==file_count and new['chunks']==chunk_count and new['package_hash']==package_hash.hex()
    assert new['uncompressed_bytes']==raw_total and new['codec']=='xpress_huff' and new['chunk_bytes']==4*1024*1024
    file_table=blob[104:104+176*file_count];chunk_table=blob[104+176*file_count:]
    assert hashlib.sha256(file_table).digest()==package_hash
    assert hashlib.sha256(package_hash+file_table+chunk_table).digest()==entries_hash
    paths=set();map_files={};ordered=[];next_chunk=0;raw_sum=0;payloads={};identities={}
    chunks=[struct.unpack_from('<32s32sII',chunk_table,72*i) for i in range(chunk_count)]
    for i in range(file_count):
        path_bytes,digest,size,first,count=struct.unpack_from('<128s32sQII',file_table,176*i)
        name,nul,padding=path_bytes.partition(b'\0');assert nul and not any(padding)
        path=name.decode('ascii')
        match=re.fullmatch(r'mods/mw120r/maps/(mp_[a-z0-9_]{1,12})/([a-z0-9_.]+)',path);assert match
        map_id,leaf=match.groups()
        allowed={prefix+map_id+'.ff' for prefix in ('','srv_','eng_','ww_','techsets_')}|{'map.json'}
        assert leaf in allowed;map_files.setdefault(map_id,set()).add(leaf);ordered.append(path)
        assert '..' not in path.split('/') and path not in paths;paths.add(path)
        assert 0<size<=2*1024*1024*1024 and first==next_chunk and 0<count<=chunk_count-first
        selected=chunks[first:first+count]
        assert sum(chunk[2] for chunk in selected)==size
        for at,(raw_hash,payload_hash,raw_size,payload_size) in enumerate(selected):
            assert 0<raw_size<=4*1024*1024 and (at==count-1 or raw_size==4*1024*1024)
            assert 0<payload_size<=8*1024*1024
            digest=payload_hash.hex()
            assert digest not in payloads or payloads[digest]==payload_size
            identity=(raw_hash.hex(),raw_size,payload_size)
            assert digest not in identities or identities[digest]==identity;identities[digest]=identity
            payloads[digest]=payload_size
        next_chunk+=count;raw_sum+=size
    assert next_chunk==chunk_count and raw_sum==raw_total and payloads==new['payloads']
    assert ordered==sorted(ordered)
    assert all(names=={prefix+map_id+'.ff' for prefix in ('','srv_','eng_','ww_','techsets_')}|{'map.json'} for map_id,names in map_files.items())
    for digest,size in payloads.items():
        source=incoming/'assets'/(digest+'.bin')
        assert source.is_file() and not source.is_symlink() and source.stat().st_size==size and sha(source)==digest
        sync_file(source)
    sync_file(incoming/'manifest.bin');sync_file(catalog_file)
    index=root/'custom-map-catalog.json'
    old=json.loads(index.read_bytes()) if index.exists() else None
    assert old==new or not old or new['release']>old['release'],'Map release rollback rejected'
    if old==new:
        # Exact retry verifies durable blobs but does not alter the registry.
        assert (root/'map-manifests'/(new['manifest_sha256']+'.bin')).read_bytes()==blob
        for digest,size in payloads.items():
            path=root/'assets'/(digest+'.bin');assert path.stat().st_size==size and sha(path)==digest
        prior_backup=None;previous=old
        for candidate in sorted((root/'map-backups').glob('*/backup.json'),reverse=True):
            metadata=json.loads(candidate.read_bytes())
            if metadata.get('new_catalog')==new:
                prior_backup=str(candidate.parent);previous=metadata['previous'];break
        result=dict(published=True,already_current=True,catalog=new,backup=prior_backup,previous=previous)
    else:
        backups=root/'map-backups';backups.mkdir(exist_ok=True)
        backup=backups/(str(time.time_ns())+'-'+new['package_hash'][:16]);backup.mkdir()
        backed_up={}
        if old:
            assert old['schema']==1 and old['format']=='custom-map-package-v1'
            (backup/'catalog.json').write_bytes(index.read_bytes());sync_file(backup/'catalog.json')
            old_manifest=root/'map-manifests'/(old['manifest_sha256']+'.bin')
            assert re.fullmatch('[0-9a-f]{64}',old['manifest_sha256'])
            assert old_manifest.is_file() and not old_manifest.is_symlink()
            assert old_manifest.stat().st_size==old['manifest_size'] and sha(old_manifest)==old['manifest_sha256']
            os.link(old_manifest,backup/'manifest.bin');sync_file(backup/'manifest.bin')
            (backup/'assets').mkdir()
            for digest,size in old['payloads'].items():
                assert re.fullmatch('[0-9a-f]{64}',digest) and 0<size<=64*1024*1024
                original=root/'assets'/(digest+'.bin')
                assert original.is_file() and not original.is_symlink() and original.stat().st_size==size and sha(original)==digest
                target=backup/'assets'/original.name;os.link(original,target)
                assert target.stat().st_size==size and sha(target)==digest;sync_file(target)
                backed_up[digest]=size
            sync_dir(backup/'assets')
        metadata=dict(previous_catalog_present=old is not None,previous=old,new_catalog=new,
                      payloads=backed_up,immutable_hash_verified_hardlinks=True)
        (backup/'backup.json').write_text(json.dumps(metadata,indent=2)+'\n');sync_file(backup/'backup.json')
        sync_dir(backup);sync_dir(backups)
        assets=root/'assets';assets.mkdir(exist_ok=True)
        for digest in payloads:immutable(incoming/'assets'/(digest+'.bin'),assets/(digest+'.bin'))
        sync_dir(assets)
        manifests=root/'map-manifests';manifests.mkdir(exist_ok=True)
        immutable(incoming/'manifest.bin',manifests/(new['manifest_sha256']+'.bin'));sync_dir(manifests)
        os.chmod(catalog_file,0o644);os.replace(catalog_file,index);sync_dir(root)
        result=dict(published=True,already_current=False,catalog=new,backup=str(backup),previous=old)
    # Delete only this transaction's known, verified temporary inputs.
    for digest in payloads:
        source=incoming/'assets'/(digest+'.bin')
        if source.exists():assert sha(source)==digest;source.unlink()
    (incoming/'assets').rmdir()
    source=incoming/'manifest.bin'
    if source.exists():assert source.read_bytes()==blob;source.unlink()
    if catalog_file.exists():assert sha(catalog_file)==CATALOG_SHA;catalog_file.unlink()
    incoming.rmdir()
    print(json.dumps(result))
'''
    return code.replace('INCOMING', repr(incoming)).replace('CATALOG_SHA', repr(catalog_sha))


def publish(record, output, upload=False):
    output = Path(output).resolve()
    if not output.is_relative_to((ROOT / 'data').resolve()):
        raise ValueError('Map publication evidence must stay in the DW data directory')
    output.mkdir(parents=True, exist_ok=True)
    old = inventory() if upload else None
    same = old and old['package_hash'] == record['package_hash'] and old['manifest_sha256'] == record['manifest_sha256']
    release = old['release'] if same else (old['release'] + 1 if old else 1)
    catalog = catalog_for(record, release)
    atomic_json(output / 'custom-map-catalog.json', catalog)
    if not upload:
        return dict(published=False, catalog=catalog)
    incoming = REMOTE + '/map-incoming-' + str(time.time_ns())
    with remote_backend.connect() as client:
        with client.open_sftp() as sftp:
            sftp.mkdir(incoming);sftp.mkdir(incoming + '/assets')
            sftp.put(record['manifest_path'], incoming + '/manifest.bin')
            sftp.put(str(output / 'custom-map-catalog.json'), incoming + '/catalog.json')
            for digest,item in record['payloads'].items():
                sftp.put(item['source'], incoming + '/assets/' + digest + '.bin')
        script = transaction_script(incoming, sha(output / 'custom-map-catalog.json'))
        _, out, error = client.exec_command("python3 - <<'PY'\n" + script + '\nPY', timeout=60)
        raw = out.read()
        if out.channel.recv_exit_status():
            raise RuntimeError(error.read().decode())
    receipt = json.loads(raw)
    receipt['frozen_record'] = record
    receipt['catalog_sha256'] = sha(output / 'custom-map-catalog.json')
    atomic_json(output / 'droplet-map-publication.json', receipt)
    pin = dict(record, published=True, server=receipt['catalog'],
               server_backup=receipt['backup'], server_catalog_sha256=receipt['catalog_sha256'])
    atomic_json(ROOT / 'data/custom-map-publication.json', pin)
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--source-directory', type=Path, help='Explicit current custom-map directory; never inferred by EXE publication')
    group.add_argument('--package-record', type=Path, help='Previously frozen immutable package record')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--upload', action='store_true')
    args=parser.parse_args()
    output=args.output.resolve()
    if not output.is_relative_to((ROOT/'data').resolve()):
        raise ValueError('Custom-map staging must stay in the DW data directory')
    if args.source_directory:
        from dw_update_maps import freeze_package
        record=freeze_package(args.source_directory, output/'package')
    else:
        record=json.loads(args.package_record.read_bytes())
    receipt=publish(record,output,args.upload)
    catalog=receipt['catalog']
    summary=dict(published=receipt['published'],release=catalog['release'],
                 package_hash=catalog['package_hash'],manifest_sha256=catalog['manifest_sha256'],
                 files=catalog['files'],chunks=catalog['chunks'],
                 uncompressed_bytes=catalog['uncompressed_bytes'],
                 transport_bytes=sum(catalog['payloads'].values()),
                 backup=receipt.get('backup'),already_current=receipt.get('already_current',False),
                 receipt=str(output/('droplet-map-publication.json' if args.upload else 'custom-map-catalog.json')))
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
