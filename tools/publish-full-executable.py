"""Publish one verified complete Replay EXE, with the catalog committed last."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time
import textwrap

import remote_backend

ROOT = Path(__file__).resolve().parents[1]


def verify_updater(path, target_hash):
    if path is None:
        raise ValueError("Uploading an EXE requires its compiled updater verification receipt")
    proof_bytes = path.read_bytes()
    proof = json.loads(proof_bytes)
    if not proof.get("passed") or proof.get("game_sha256") != target_hash:
        raise ValueError("Updater verification does not bind the published EXE")
    cases = proof.get("initial_update_checks", [])
    has_bypass = any("bypass_update_restart" in case for case in cases)
    checks = proof.get("checks", [])
    # bypass_skips_updater: bypass_update_restart=1 starts no worker and never
    # downloads; the worker (and its asset repair) runs only without it.
    skips = proof.get("bypass_skips_updater") is True
    repairs_under_bypass = not skips and ('worker_checks' in proof or any(
        'asset_repair_restart_under_bypass' in case or 'asset_failure_fence' in case
        for case in checks))
    expected = {
        (False, True, False): (0, 0),
        (True, True, False): (1, 1),
        (True, False, False): (1, 40),
    }
    if has_bypass:
        expected.update({(True, True, True): (1, 1), (True, False, True): (1, 40)}
                        if repairs_under_bypass else
                        {(True, True, True): (0, 50), (True, False, True): (0, 50)})
    observed = {}
    for case in cases:
        if case.get("compiled_initial_state") != 0 or case.get("frames") != 2:
            raise ValueError("The compiled updater is disabled or its first-frame check is missing")
        bypass = case.get("bypass_update_restart", False)
        key = (case["enabled"], case["thread_creation_succeeds"], bypass)
        if key in observed:
            raise ValueError("Duplicate compiled updater startup case")
        if has_bypass and case.get("bypass_logged") is not (bypass and not repairs_under_bypass and
                                                            (case["enabled"] or not skips)):
            raise ValueError("Compiled updater bypass logging does not verify")
        if repairs_under_bypass or skips:
            callback = case.get('worker_callback')
            runs = case['enabled'] and not (skips and bypass)
            if (runs and (type(callback) is not int or callback <= 0)
                    or not runs and callback is not None):
                raise ValueError('Compiled updater worker callback does not verify')
        observed[key] = (case["worker_starts"], case["final_state"])
    if observed != expected:
        raise ValueError("Compiled updater scheduling or failure handling does not verify")
    states = (1, 10, 20, 30, 40, 50) if has_bypass else (1, 10, 20, 30, 40)
    expected_fences = {(enabled, state, bypass)
                       for enabled in (False, True) for state in states
                       for bypass in ((False, True) if has_bypass else (False,))}
    observed_fences = set()
    for case in checks:
        bypass = case.get("bypass_update_restart", False)
        key = (case["enabled"], case["state"], bypass)
        if (key in observed_fences or not case.get("native_prerequisite_passes")
                or not case.get("restart_route_correct") or case.get("getter_cases") != 10
                or (has_bypass and case.get("native_data_restart_preserved") is not
                    (not (case['enabled'] and case['state'] == 20) if repairs_under_bypass or skips
                     else bypass))
                or (skips and case.get('asset_failure_fence') is not
                    (case['enabled'] and case['state'] == 40))
                or (repairs_under_bypass and
                    (case.get('asset_repair_restart_under_bypass') is not
                     (case['enabled'] and bypass and case['state'] == 20)
                     or case.get('asset_failure_fence') is not
                     (case['enabled'] and case['state'] == 40)))):
            raise ValueError("Compiled update fence and restart routing do not verify")
        observed_fences.add(key)
    if observed_fences != expected_fences:
        raise ValueError("Compiled update fence matrix is incomplete")
    if repairs_under_bypass or skips:
        if not has_bypass or not re.fullmatch('[0-9a-f]{64}', proof.get('embedded_helper_sha256', '')):
            raise ValueError('Compiled asset repair helper proof is missing')
        if len({case['worker_callback'] for case in cases
                if case['enabled'] and case['worker_callback'] is not None}) != 1:
            raise ValueError('Compiled startup cases disagree on the worker callback')
        expected_workers = {(bypass, helper, exit_code)
                            for bypass in ((False,) if skips else (False, True))
                            for helper, exit_code in (('exact', 10), ('older', 10),
                                                       ('older', 20), ('older', 40), ('trailing', 10))}
        observed_workers = set()
        for case in proof.get('worker_checks', []):
            bypass = case['bypass_update_restart']
            helper, exit_code = case['existing_helper'], case['helper_exit']
            key = (bypass, helper, exit_code)
            calls = ['open-existing'] + ([] if helper == 'exact' else ['rewrite-helper'])
            calls += ['--prepare-assets' if bypass else '--prepare', 'bounded-map-wait']
            state = 50 if bypass and exit_code == 10 else exit_code
            if key in observed_workers or case.get('state') != state or case.get('calls') != calls:
                raise ValueError('Compiled worker asset repair, helper refresh or failure routing does not verify')
            observed_workers.add(key)
        if observed_workers != expected_workers:
            raise ValueError('Compiled worker asset repair matrix is incomplete')
    return proof_bytes


def publish(image, report, release, output, upload=False, updater_verification=None, asset_source=None):
    spec = importlib.util.spec_from_file_location(
        "compiler_publication", ROOT / "tools/publish-executable-update.py"
    )
    verification = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verification)
    data, digest, report_bytes = verification.verify_image(image, report)
    if release <= 0:
        raise ValueError("Release number must be positive")
    updater_bytes = verify_updater(updater_verification, digest) if upload else None
    output.mkdir(parents=True, exist_ok=True)
    binary = output / (digest + ".exe")
    binary.write_bytes(data)
    (output / "build-report.json").write_bytes(report_bytes)
    if updater_bytes is not None:
        (output / "updater-verification.json").write_bytes(updater_bytes)
    assets = None
    maps = None
    from dw_update_maps import extract as extract_maps, publication as map_publication
    if asset_source is None and extract_maps(data) is not None:
        raise ValueError('Executable map manifest requires its frozen publication receipt')
    if asset_source is not None:
        from dw_update_assets import publication
        assets = publication(image, asset_source, output)
        if (Path(asset_source) / 'generated/update-maps.json').exists():
            maps = map_publication(image, asset_source, output)
        elif extract_maps(data) is not None:
            raise ValueError('Executable map manifest has no frozen publication receipt')
    catalog = dict(
        schema=1,
        format="full-executable-v1",
        release=release,
        latest=digest,
        target_size=len(data),
    )
    if assets is not None:
        catalog['assets'] = dict(manifest_sha256=assets['manifest_sha256'],
                                manifest_size=assets['manifest_size'], files=len(assets['entries']),
                                payloads={digest: item['size'] for digest, item in assets['payloads'].items()})
    if maps is not None:
        # Chunk inventories belong only to the explicitly published map catalog.
        # Keep this plan catalog below its existing 4096-byte protocol limit.
        catalog['maps'] = dict(package_hash=maps['package_hash'],
                               manifest_sha256=maps['manifest_sha256'],
                               manifest_size=maps['manifest_size'], files=len(maps['files']),
                               chunks=len(maps['chunks']))
    verification.atomic_json(output / "full-image-catalog.json", catalog)
    if (output / 'full-image-catalog.json').stat().st_size > 4096:
        raise ValueError('Full executable catalog exceeds its unchanged 4096-byte limit')
    if not upload:
        return catalog

    catalog_bytes = (output / "full-image-catalog.json").read_bytes()
    incoming = "/var/lib/replay-dw/updates/full-incoming-" + str(time.time_ns())
    with remote_backend.connect() as client:
        _, out, error = client.exec_command(
            "install -d -m 0755 " + incoming, timeout=20
        )
        if out.channel.recv_exit_status():
            raise RuntimeError(error.read().decode())
        with client.open_sftp() as sftp:
            sftp.put(str(binary), incoming + "/" + binary.name)
            if assets is not None:
                sftp.mkdir(incoming + '/assets')
                for digest in assets['payloads']:
                    sftp.put(str(output / 'assets' / (digest + '.bin')), incoming + '/assets/' + digest + '.bin')
                sftp.put(str(output / 'update-assets.bin'), incoming + '/update-assets.bin')
            if maps is not None:
                sftp.put(str(output / 'update-maps.bin'), incoming + '/update-maps.bin')
            with sftp.file(incoming + "/catalog.json", "wb") as file:
                file.write(catalog_bytes)
        script = r"""
import hashlib,json,os,pathlib,struct,mmap
incoming=pathlib.Path(INCOMING)
root=incoming.parent
new=json.loads((incoming/'catalog.json').read_bytes())
assert hashlib.sha256((incoming/'catalog.json').read_bytes()).hexdigest()==CATALOG_SHA
assert new['schema']==1 and new['format']=='full-executable-v1'
assert len((incoming/'catalog.json').read_bytes())<=4096
image=incoming/(new['latest']+'.exe')
with image.open('rb') as f:
    assert hashlib.file_digest(f,'sha256').hexdigest()==new['latest']
    os.fsync(f.fileno())
assert image.stat().st_size==new['target_size'] and 0<new['target_size']<=512*1024*1024
with image.open('rb') as f: assert f.read(2)==b'MZ'
map_index=root/'custom-map-catalog.json'
map_catalog_before=map_index.read_bytes() if map_index.exists() else None
assert map_catalog_before is None or 'maps' in new,'Published custom maps missing from frozen EXE'
if 'maps' in new:
    maps=new['maps'];manifest=(incoming/'update-maps.bin').read_bytes()
    assert len(manifest)==maps['manifest_size'] and hashlib.sha256(manifest).hexdigest()==maps['manifest_sha256']
    assert map_catalog_before is not None,'Custom map must be explicitly published first'
    published=json.loads(map_catalog_before)
    assert published['schema']==1 and published['format']=='custom-map-package-v1'
    assert all(published[key]==maps[key] for key in ('package_hash','manifest_sha256','manifest_size','files','chunks'))
    magic,version,total,files,chunks,raw_bytes,entries_hash,package_hash=struct.unpack_from('<16sIIIIQ32s32s',manifest)
    assert magic==b'REPLAYDWMAP01\0\0\0' and version==1 and 0<files<=256 and 0<chunks<=4096
    assert total==len(manifest)==104+176*files+72*chunks and files==maps['files'] and chunks==maps['chunks']
    assert 0<raw_bytes<=4*1024**3 and raw_bytes==published['uncompressed_bytes']
    table=manifest[104:104+176*files]
    assert hashlib.sha256(table).digest()==package_hash and package_hash.hex()==maps['package_hash']
    assert hashlib.sha256(package_hash+manifest[104:]).digest()==entries_hash
    expected={}
    for at in range(104+176*files,len(manifest),72):
        raw_hash,payload_hash,raw_size,payload_size=struct.unpack_from('<32s32sII',manifest,at)
        assert 0<raw_size<=4*1024**2 and 0<payload_size<=8*1024**2
        digest=payload_hash.hex()
        assert digest not in expected or expected[digest]==payload_size
        expected[digest]=payload_size
    assert expected==published['payloads'],'Published map transport inventory differs from frozen EXE'
    assert (root/'map-manifests'/(maps['manifest_sha256']+'.bin')).read_bytes()==manifest
    for digest,size in published['payloads'].items():
        assert len(digest)==64 and all(c in '0123456789abcdef' for c in digest) and 0<size<=64*1024*1024
        payload=root/'assets'/(digest+'.bin')
        assert payload.is_file() and not payload.is_symlink() and payload.stat().st_size==size
        with payload.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==digest
    with image.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mapped:
        at=mapped.find(manifest);assert at>=0 and mapped.find(manifest,at+len(manifest))<0
if 'assets' in new:
    assets=new['assets'];manifest=(incoming/'update-assets.bin').read_bytes()
    assert len(manifest)==assets['manifest_size'] and hashlib.sha256(manifest).hexdigest()==assets['manifest_sha256']
    magic,version,total,count,reserved,digest,bundle=struct.unpack_from('<16sIIII32s32s',manifest)
    assert magic==b'REPLAYDWASSET01\0' and version==1 and reserved==0 and 0<count<=256
    assert total==len(manifest)==96+136*count and count==assets['files']
    assert hashlib.sha256(bundle+manifest[96:]).digest()==digest
    with (incoming/'update-assets.bin').open('rb') as f: os.fsync(f.fileno())
    with image.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mapped:
        at=mapped.find(manifest);assert at>=0 and mapped.find(manifest,at+len(manifest))<0
    for digest,size in assets['payloads'].items():
        assert len(digest)==64 and all(c in '0123456789abcdef' for c in digest) and 0<size<=64*1024*1024
        payload=incoming/'assets'/(digest+'.bin')
        assert payload.stat().st_size==size
        with payload.open('rb') as f: assert hashlib.file_digest(f,'sha256').hexdigest()==digest;os.fsync(f.fileno())
index=root/'full-image-catalog.json'
if index.exists():
    old=json.loads(index.read_bytes())
    assert old==new or new['release']>old['release'],'Release rollback rejected'
legacy=root/'catalog.json'
if legacy.exists():
    assert new['release']>json.loads(legacy.read_bytes())['release'],'Release must follow legacy publication'
images=root/'images';images.mkdir(exist_ok=True)
if 'assets' in new:
    asset_folder=root/'assets';asset_folder.mkdir(exist_ok=True)
    for digest,size in new['assets']['payloads'].items():
        source=incoming/'assets'/(digest+'.bin');destination=asset_folder/source.name
        if destination.exists():
            assert destination.stat().st_size==size
            with destination.open('rb') as f: assert hashlib.file_digest(f,'sha256').hexdigest()==digest
            source.unlink()
        else: os.chmod(source,0o644);os.replace(source,destination)
    directory=os.open(asset_folder,os.O_DIRECTORY);os.fsync(directory);os.close(directory)
    manifests=root/'asset-manifests';manifests.mkdir(exist_ok=True)
    destination=manifests/(new['latest']+'.bin')
    if destination.exists():
        assert destination.read_bytes()==manifest
        (incoming/'update-assets.bin').unlink()
    else: os.chmod(incoming/'update-assets.bin',0o644);os.replace(incoming/'update-assets.bin',destination)
    directory=os.open(manifests,os.O_DIRECTORY);os.fsync(directory);os.close(directory)
    (incoming/'assets').rmdir()
destination=images/image.name
if destination.exists():
    with destination.open('rb') as f: assert hashlib.file_digest(f,'sha256').hexdigest()==new['latest']
    assert destination.stat().st_size==new['target_size']
    image.unlink()
else:
    os.chmod(image,0o644);os.replace(image,destination)
directory=os.open(images,os.O_DIRECTORY);os.fsync(directory);os.close(directory)
os.chmod(incoming/'catalog.json',0o644)
with (incoming/'catalog.json').open('rb') as f: os.fsync(f.fileno())
os.replace(incoming/'catalog.json',index)
assert (map_index.read_bytes() if map_index.exists() else None)==map_catalog_before,'EXE publication changed custom map registry'
directory=os.open(root,os.O_DIRECTORY);os.fsync(directory);os.close(directory)
if 'maps' in new:(incoming/'update-maps.bin').unlink()
incoming.rmdir()
print(json.dumps(dict(published=True,format=new['format'],release=new['release'],latest=new['latest'],bytes=new['target_size'])))
""".replace(
            "INCOMING", repr(incoming)
        ).replace(
            "CATALOG_SHA", repr(hashlib.sha256(catalog_bytes).hexdigest())
        )
        script = (
            "import fcntl,pathlib\n"
            "with (pathlib.Path('/var/lib/replay-dw/updates')/'publication.lock').open('a') as lock:\n"
            "    fcntl.flock(lock,fcntl.LOCK_EX)\n"
            + textwrap.indent(script, "    ")
        )
        _, out, error = client.exec_command(
            "python3 - <<'PY'\n" + script + "\nPY", timeout=60
        )
        response = out.read()
        if out.channel.recv_exit_status():
            raise RuntimeError(error.read().decode())
    result = json.loads(response)
    result["compiled_updater_verified"] = True
    result["updater_verification_sha256"] = hashlib.sha256(updater_bytes).hexdigest()
    verification.atomic_json(output / "droplet-publication.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--build-report", required=True, type=Path)
    parser.add_argument("--release", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--updater-verification", type=Path,
                        help="Hash-bound compiled initial scheduling, fence and restart proof; required for upload")
    parser.add_argument('--asset-source', type=Path, help='Frozen source snapshot containing target-embedded owned asset proof')
    args = parser.parse_args()
    print(
        json.dumps(
            publish(
                args.image, args.build_report, args.release, args.output, args.upload,
                args.updater_verification, args.asset_source
            ),
            indent=2,
        )
    )
