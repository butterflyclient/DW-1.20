"""Verify signed full-image updates and the embedded helper without launching a game."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import tempfile
import time
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dw_update_assets import decode as decode_assets, extract as extract_assets
from dw_update_maps import decode as decode_maps, extract as extract_maps, verify_record as verify_maps

ROOT = Path(__file__).resolve().parents[1]
MAGIC = 0x3155505744594C50
PLAN = struct.Struct("<QIIQQ32s32s32s32sQQQQ")


def array(header, name):
    match = re.search(r"\b" + re.escape(name) + r"\[\]\s*=\s*\{(.*?)\}",
                      header.read_text(), re.S)
    if not match:
        raise ValueError("Missing frozen helper/trust array: " + name)
    return bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})", match[1]))


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publication", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--base-exe", required=True, type=Path)
    parser.add_argument("--host", default="162.243.115.160")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--release-history", type=Path,
                        default=ROOT / "data/executable-releases/releases.json",
                        help="Older executable hashes retained locally or fetched from the pinned server")
    args = parser.parse_args()
    catalog = json.loads((args.publication / "full-image-catalog.json").read_bytes())
    image = args.publication / (catalog["latest"] + ".exe")
    assert sha(image) == catalog["latest"] and image.stat().st_size == catalog["target_size"]
    image_bytes = image.read_bytes()
    asset_manifest = extract_assets(image_bytes)
    map_manifest = extract_maps(image_bytes)
    maps = decode_maps(map_manifest) if map_manifest is not None else None
    map_files = [] if maps is None else maps['files']
    if maps is not None:
        record = json.loads((args.publication / 'update-maps.json').read_bytes())
        assert verify_maps(record) == map_manifest
        assert catalog['maps'] == dict(package_hash=maps['package_hash'],
                                       manifest_sha256=hashlib.sha256(map_manifest).hexdigest(),
                                       manifest_size=len(map_manifest), files=len(map_files),
                                       chunks=len(maps['chunks']))
        from dw_publication import inventory, require_maps
        require_maps(catalog, inventory()['maps'])
    assets = decode_assets(asset_manifest) if asset_manifest is not None else []
    native_paths = {}
    if assets:
        asset_record = json.loads((args.publication / 'update-assets.json').read_bytes())
        native_paths = asset_record['relative_paths']
        assert set(native_paths) == {item['name'] for item in assets}
        assert hashlib.sha256(asset_manifest).hexdigest() == catalog['assets']['manifest_sha256']
        assert len(assets) == catalog['assets']['files']
        for item in assets:
            payload = args.publication / 'assets' / (item['sha256'] + '.bin')
            assert sha(payload) == item['sha256'] and payload.stat().st_size == item['size']
    trust = array(args.source_root / "dw_local_trust.h", "s_dwLocalPlatformPublicKey")
    magic, bits, exponent_size, modulus_size, prime1, prime2 = struct.unpack_from("<6I", trust)
    assert magic == 0x31415352 and bits == 2048 and prime1 == prime2 == 0
    exponent = int.from_bytes(trust[24:24 + exponent_size], "big")
    modulus = int.from_bytes(trust[24 + exponent_size:24 + exponent_size + modulus_size], "big")
    public = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    checks = []
    history_bytes = args.release_history.read_bytes()
    history = json.loads(history_bytes)
    old = {row["sha256"] for row in history}
    assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in old)
    old.add(sha(args.base_exe))
    old.add("a" * 64)  # Full images do not require an inventory of prior builds.

    def check(base_hash, expected_status):
        nonce = secrets.token_bytes(32)
        request = struct.pack("<QII32s32s", MAGIC, 2, 0, nonce, bytes.fromhex(base_hash))
        before = int(time.time())
        with urllib.request.urlopen(urllib.request.Request(
            "http://" + args.host + ":8085/updates/v2/check", data=request,
            headers={"Content-Type": "application/octet-stream"}), timeout=30) as response:
            reply = response.read(449)
        assert len(reply) == 448
        public.verify(reply[192:], reply[:192],
                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        values = PLAN.unpack(reply[:192])
        identity, version, status, issued, expires, echoed, base, target, payload, base_size, target_size, size, release = values
        assert identity == MAGIC and version == 2 and status == expected_status
        assert before - 5 <= issued <= int(time.time()) + 5 and expires > issued
        assert echoed == nonce and base.hex() == base_hash and target.hex() == catalog["latest"]
        assert target_size == catalog["target_size"] and release == catalog["release"] and base_size == 0
        if expected_status == 1:
            assert payload == target and size == target_size
        else:
            assert size == 0

    for digest in sorted(old - {catalog["latest"]}):
        check(digest, 1)
    checks.append("Signed fresh-nonce full-image replies point all tested older hashes directly to the latest release")
    check(catalog["latest"], 0)
    checks.append("Latest executable receives current status without another download/update loop")

    helper = array(args.source_root / "DW_UpdateHelper.h", "s_dwUpdateHelper")
    helper_hash = hashlib.sha256(helper).hexdigest()
    assert image_bytes.count(helper) == 1, "Published PE must contain the exact helper that is exercised"
    assert b"/\x00u\x00p\x00d\x00a\x00t\x00e\x00s\x00/\x00v\x002\x00/\x00c\x00h\x00e\x00c\x00k\x00" in helper
    with tempfile.TemporaryDirectory(prefix="published-update-", dir=ROOT / "data") as name:
        folder = Path(name).resolve()
        assert folder.parent == (ROOT / "data").resolve()
        runner = folder / "replay-update-client.exe"
        runner.write_bytes(helper)
        base = folder / "old-release.exe"
        shutil.copyfile(args.base_exe, base)
        base_hash = sha(base)
        def staged_companions(executable):
            cache = Path(str(executable) + '.update') / 'asset-staging' / catalog['latest']
            paths = []
            for item in assets:
                paths.append((cache / (item['sha256'] + '.bin'), item))
            for item in map_files:
                paths.append((cache / ('map-' + item['sha256'] + '.bin'), item))
            for payload, item in paths:
                assert payload.resolve().is_relative_to(folder)
                assert sha(payload) == item['sha256'] and payload.stat().st_size == item['size']
            return paths

        result = subprocess.run([str(runner), "--prepare", str(base), args.host],
                                cwd=folder, creationflags=subprocess.CREATE_NO_WINDOW, timeout=900 if maps else 300)
        assert result.returncode == 20, "Embedded helper must stage the full update"
        staged = Path(str(base) + ".update") / "next.exe"
        assert sha(staged) == catalog["latest"] and sha(base) == base_hash
        # EXE first (owner rule 2026-10-13): an outdated EXE stages only the new
        # EXE; the new EXE's own helper stages companions (checked below).
        old_cache = Path(str(base) + '.update') / 'asset-staging' / catalog['latest']
        assert not old_cache.exists() or not any(old_cache.iterdir()),             'Outdated EXE staged companions before installing the latest EXE'
        old_payloads = []
        checks.append("Actual embedded Windows helper verifies and stages exact published EXE first, without companions; installed older bytes remain unchanged")
        current = folder / "current-release.exe"
        local_payloads = None
        if maps:
            # The helper deletes its transport chunks once every map file is staged.
            old_cache = Path(str(base) + '.update') / 'asset-staging' / catalog['latest']
            assert not list(old_cache.glob('chunk-*.bin')) and not list(old_cache.glob('partial-*.bin')),                 'Helper retained downloaded map chunks after staging'
            checks.append('Embedded helper deletes downloaded map transport chunks after staging')
            # One complete network download proves the public transport; later
            # cases are seeded from the explicitly frozen local package (same
            # immutable hashes) instead of redownloading a large map.
            for record in sorted((ROOT / 'data/custom-map-releases').glob('*/package/package.json')):
                if json.loads(record.read_bytes()).get('package_hash') == maps['package_hash']:
                    local_payloads = record.parent / 'payloads'
                    break

        def seed_chunks(executable):
            if not maps or local_payloads is None:
                return
            cache = Path(str(executable) + '.update') / 'asset-staging' / catalog['latest']
            cache.mkdir(parents=True, exist_ok=True)
            for chunk in {item['payload_sha256']: item for item in maps['chunks']}.values():
                payload = local_payloads / (chunk['payload_sha256'] + '.bin')
                assert sha(payload) == chunk['payload_sha256'] and payload.stat().st_size == chunk['payload_size']
                shutil.copyfile(payload, cache / ('chunk-' + chunk['payload_sha256'] + '.bin'))

        seed_chunks(current)
        # These isolated bytes are no longer needed after verification. Reclaim
        # them before the current-version check to bound fixture disk usage.
        assert staged.resolve().is_relative_to(folder) and base.resolve().parent == folder
        staged.unlink()
        # Full map staging can be large; only remove verified fixture-owned files.
        for payload, _ in old_payloads:
            payload.unlink(missing_ok=True)
        base.unlink()
        shutil.copyfile(image, current)
        if assets or maps:
            result = subprocess.run([str(runner), '--prepare', str(current), args.host],
                                    cwd=folder, creationflags=subprocess.CREATE_NO_WINDOW, timeout=900 if maps else 120)
            assert result.returncode == 20 and sha(current) == catalog['latest']
            assert not (Path(str(current) + '.update') / 'next.exe').exists()
            assert not (folder / 'zone').exists(), 'Preparation modified loaded zone assets'
            assert not (folder / 'mods').exists(), 'Preparation modified installed map assets'
            staged_companions(current)
            checks.append('Current signed EXE separately stages missing owned companions without changing installed files or requiring an EXE replacement')
        if assets:
            (folder / 'zone').mkdir()
            for item in assets:
                relative = Path(native_paths[item['name']])
                assert not relative.is_absolute() and '..' not in relative.parts and len(relative.parts) <= 2
                destination = folder / 'zone' / relative
                destination.parent.mkdir(exist_ok=True)
                shutil.copyfile(args.publication / 'assets' / (item['sha256'] + '.bin'), destination)
        if maps:
            # Legacy companions are now present while maps are still absent.
            # An EXE upgraded by an older helper must still repair the missing maps.
            seed_chunks(current)
            result = subprocess.run([str(runner), '--prepare', str(current), args.host],
                                    cwd=folder, creationflags=subprocess.CREATE_NO_WINDOW, timeout=900)
            assert result.returncode == 20 and sha(current) == catalog['latest']
            assert not (Path(str(current) + '.update') / 'next.exe').exists()
            assert not (folder / 'mods').exists()
            staged_companions(current)
            cache = Path(str(current) + '.update') / 'asset-staging' / catalog['latest']
            for item in map_files:
                relative = Path(item['path'])
                assert not relative.is_absolute() and '..' not in relative.parts
                destination = (folder / relative).resolve()
                assert destination.is_relative_to(folder / 'mods/mw120r/maps')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(cache / ('map-' + item['sha256'] + '.bin'), destination)
                assert sha(destination) == item['sha256']
            checks.append('Current EXE with legacy companions present stages missing maps; compressed downloads verify raw chunks and complete file hashes')
        result = subprocess.run([str(runner), "--prepare", str(current), args.host],
                                cwd=folder, creationflags=subprocess.CREATE_NO_WINDOW, timeout=300 if maps else 60)
        assert result.returncode == 10 and sha(current) == catalog["latest"]
        assert not (Path(str(current) + ".update") / "next.exe").exists()
        checks.append("Actual embedded helper recognizes the current release and stages no replacement")
    result = dict(passed=True, host=args.host, release=catalog["release"],
                  executable_sha256=catalog["latest"], bytes=catalog["target_size"],
                  tested_older_hashes=len(old - {catalog["latest"]}),
                  release_history_sha256=hashlib.sha256(history_bytes).hexdigest(),
                  helper_sha256=helper_hash, pinned_trust_sha256=hashlib.sha256(trust).hexdigest(),
                  owned_asset_manifest_sha256=hashlib.sha256(asset_manifest).hexdigest() if assets else None,
                  owned_asset_files=len(assets),
                  native_asset_folders_verified=bool(assets),
                  map_package_hash=maps['package_hash'] if maps else None,
                  map_manifest_sha256=hashlib.sha256(map_manifest).hexdigest() if maps else None,
                  map_files=len(map_files), map_chunks=len(maps['chunks']) if maps else 0,
                  missing_maps_on_current_executable_verified=bool(maps),
                  checks=checks, game_runs_performed=False, installed_game_modified=False,
                  apply_or_relaunch_invoked=False, temporary_fixture_removed=True,
                  legacy_delta_only_clients_require_bootstrap=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS: signed published full-image plans and actual embedded helper staging; no game launched")


if __name__ == "__main__":
    main()
