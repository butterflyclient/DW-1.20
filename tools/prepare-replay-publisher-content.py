"""Prepare explicit local Replay playlists and signed no-update manifests.

Run with the game and backend stopped, then publish the generated files with
publish-publisher-object.py. This never edits the game's fastfiles or cache.
The manifest ABI and PSS parameters come from this exact Replay executable.
"""

import hashlib
import json
from pathlib import Path
import struct
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

root = Path(__file__).resolve().parents[1]
source = root / "data" / "local-publisher-sources"
source.mkdir(parents=True, exist_ok=True)
blob = (root / "data" / "platform-private.blob").read_bytes()
magic, bits, exponent_size, modulus_size, p_size, q_size = struct.unpack_from(
    "<6I", blob
)
if (magic, bits, exponent_size, modulus_size, p_size, q_size) != (
    0x32415352,
    2048,
    3,
    256,
    128,
    128,
):
    raise RuntimeError("Unexpected local RSA private key format")
if len(blob) != 24 + exponent_size + modulus_size + p_size + q_size:
    raise RuntimeError("Truncated local RSA private key")
offset = 24
numbers = []
for size in (exponent_size, modulus_size, p_size, q_size):
    numbers.append(int.from_bytes(blob[offset : offset + size], "big"))
    offset += size
e, n, p, q = numbers
if p * q != n:
    raise RuntimeError("Local RSA key components are inconsistent")
d = pow(e, -1, (p - 1) * (q - 1))
key = rsa.RSAPrivateNumbers(
    p,
    q,
    d,
    rsa.rsa_crt_dmp1(d, p),
    rsa.rsa_crt_dmq1(d, q),
    rsa.rsa_crt_iqmp(p, q),
    rsa.RSAPublicNumbers(e, n),
).private_key()
manifest_body = bytearray(901132)
struct.pack_into("<IHHH", manifest_body, 901120, 0, 1, 4087, 0)
digest = hashlib.sha256(manifest_body).digest()
signature = key.sign(
    digest,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=8),
    utils.Prehashed(hashes.SHA256()),
)
key.public_key().verify(
    signature,
    digest,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=8),
    utils.Prehashed(hashes.SHA256()),
)
manifest = {
    "count": 0,
    "manifestver": 1,
    "dataverff": 4087,
    "purgeCache": 0,
    "signature": signature.hex(),
}
for name in ("1_manifest_patch_pc_8.19.txt", "1_manifest_comms_pc_8.19.txt"):
    (source / name).write_text(
        json.dumps(manifest, separators=(",", ":")) + "\n", encoding="utf-8"
    )
# One genuine, playable local playlist, with existing Replay map and script.
# No ownership, inventory, fence or matchmaking result is synthesized here.
playlist = {
    "global_dvars": {},
    "gametypes": [
        {
            "gametype": "tdm",
            "name": "#Team Deathmatch",
            "script": "tdm",
            "teamCount": 2,
            "teamSize": 6,
            "dvars": {"scr_tdm_scorelimit": 75, "scr_tdm_timelimit": 10},
        }
    ],
    "playlists": [
        {
            "playlist": 1,
            "name": "#Local Shipment",
            "description": "#Replay local multiplayer",
            "type": "mp",
            "minplayers": 1,
            "maxplayers": 12,
            "score_limit": 75,
            "time_limit": 10,
            "maps": [{"map": "mp_shipment", "gametype": "tdm", "weight": 1}],
        }
    ],
    "categories": [{"category": "Top", "name": "#Local Play", "bnet_include": [1]}],
}
downloaded = root / "data" / "unified_large_playlist_tu19.aggr"
if downloaded.is_file():
    packed = downloaded.read_bytes()
    decoder = zlib.decompressobj()
    raw = decoder.decompress(packed, 409601)
    if (
        not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
        or len(raw) > 409600
    ):
        raise RuntimeError(
            "Downloaded playlist does not fit the native decompression contract"
        )
    playlist = json.loads(raw.rstrip(b"\0"))
else:
    raw = json.dumps(playlist, separators=(",", ":")).encode()
    packed = zlib.compress(raw, 9)
if len(packed) > 40960 or not playlist.get("playlists"):
    raise RuntimeError("Playlist is empty or exceeds the native compressed capacity")
(source / "unified_large_playlist_tu19.json").write_bytes(raw + b"\n")
(source / "unified_large_playlist_tu19.aggr").write_bytes(packed)
receipt = {
    "schema": 1,
    "title": 5800,
    "context": "5800",
    "owner": "infinityward",
    "manifest_native_parser": "0x14107AB50",
    "manifest_native_consumer": "0x141052D10",
    "signature_native_verifier": "0x141038500",
    "manifest_digest_sha256": digest.hex(),
    "manifest_entry_count": 0,
    "manifest_dataverff": 4087,
    "playlist_native_parser": "0x1410CE1A0",
    "playlist_entries": len(playlist["playlists"]),
    "playlist_source": (
        str(downloaded) if downloaded.is_file() else "local Shipment definition"
    ),
    "files": {
        name: hashlib.sha256((source / name).read_bytes()).hexdigest()
        for name in (
            "1_manifest_patch_pc_8.19.txt",
            "1_manifest_comms_pc_8.19.txt",
            "unified_large_playlist_tu19.aggr",
        )
    },
}
(root / "data" / "replay-publisher-content-provenance.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print(
    "Prepared "
    + str(len(playlist["playlists"]))
    + " playlist entries and two genuinely signed no-update manifests."
)
