"""Check the served playlist menu offers only playlists matchmaking can start.

A disposable backend installs content/replay120. Replay's published policy has
13 maps and no Ground War map: matchmaking refuses those playlists (error 108)
and the native search waits forever, so the menu must not offer them. The rule
is recomputed here independently of src/playlist_catalog.cpp.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.request
import zlib

ROOT = Path(__file__).resolve().parents[1]
TITLE = "5800"
OFFSET = 24361


def servable(catalog, available=None, installed=None):
    out = set()
    for playlist in catalog["playlists"]:
        for entry in playlist["maps"][:20]:  # Replay's ChooseEntry weights the first 20
            if (entry["weight"] > 0 and (available is None or entry["map"] in available)
                    and (installed is None or entry["map"] in installed)):
                out.add(playlist["playlist"])
                break
    return out


def run(server, data, label):
    with (data.parent / (label + ".log")).open("wb") as log:
        process = subprocess.Popen(
            [str(server), str(data), "--port-offset", str(OFFSET), "--content-pack", str(ROOT / "content")],
            stdout=log, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    try:
        for _ in range(400):
            assert process.poll() is None, (data.parent / (label + ".log")).read_text(errors="replace")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{8085 + OFFSET}/health", timeout=.3):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("Disposable backend readiness timeout")
    finally:
        process.terminate()
        process.wait(10)
    lines = (data / "server.log").read_text(errors="replace").splitlines()
    (data / "server.log").unlink()
    return [line for line in lines if "playlist menu" in line]


def served(data):
    folder = data / "objectstore/publisher" / TITLE / TITLE / "infinityward"
    content = (folder / "unified_large_playlist_tu19.aggr.content.bin").read_bytes()
    metadata = json.loads((folder / "unified_large_playlist_tu19.aggr.metadata.json").read_bytes())
    # objectstore_services.cpp serves the object only with matching length and MD5.
    assert metadata["contentLength"] == len(content)
    assert metadata["checksum"] == base64.b64encode(hashlib.md5(content).digest()).decode()
    # Replay downloads the object into a 0xa000-byte buffer (0x1412D1B16); a larger
    # one never loads and the client stalls on "Fetching online profile".
    assert len(content) <= 0xA000, len(content)
    return content, json.loads(zlib.decompress(content))


def listed(menu):
    ids, letters = {}, {}
    for category in menu["categories"]:
        for key, value in category.items():
            if key.endswith("_include") and value:
                target = letters if isinstance(value[0], str) else ids
                target.setdefault(key, set()).update(value)
    return ids, letters


def check_menu(menu, catalog, expected):
    without = lambda value: {k: v for k, v in value.items() if k != "categories"}
    assert without(menu) == without(catalog), "only the menu categories may change"
    ids, letters = listed(menu)
    original_ids, _ = listed(catalog)
    for key, values in original_ids.items():
        assert ids.get(key, set()) == values & expected, key
    names = {category["category"]: category for category in menu["categories"]}
    for key, values in letters.items():
        for letter in values:
            assert names[letter].get(key), (key, letter, "an empty category stays listed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, default=ROOT / "build/Release/iw8-dw-server.exe")
    server = parser.parse_args().server.resolve()
    pack = ROOT / "content/replay120/files"
    catalog_bytes = (pack / "playlists" / TITLE / "catalog.json").read_bytes()
    catalog = json.loads(catalog_bytes)
    policy = json.loads((pack / "playlists" / TITLE / "policy.json").read_bytes())
    with tempfile.TemporaryDirectory(prefix="dw-playlist-menu-") as temporary:
        data = Path(temporary) / "data"
        data.mkdir()
        kdf = ROOT / "data/replay-traffic-kdf.bin"
        if kdf.exists():
            shutil.copy2(kdf, data / "replay-traffic-kdf.bin")

        # Published policy: Ground War (category K and playlist 40) is not offered.
        expected = servable(catalog, set(policy["available_maps"]))
        log = run(server, data, "policy")
        content, menu = served(data)
        check_menu(menu, catalog, expected)
        ids, letters = listed(menu)
        assert not {27, 28, 29, 31, 39, 40} & set().union(*ids.values())
        assert "K" not in letters["bnet_include"] and "B" in letters["bnet_include"]
        hidden = sorted(set().union(*listed(catalog)[0].values()) - expected)
        assert log == [f"{log[0].split(' CONTENT')[0]} CONTENT playlist menu title={TITLE} hides "
                       f"{len(hidden)} playlists this server cannot start: " + " ".join(map(str, hidden))], log
        print("PASS: menu hides", len(hidden), "unstartable playlists:", hidden)

        # A restart re-derives the same bytes and rewrites nothing.
        assert run(server, data, "restart") == []
        assert served(data)[0] == content
        state = json.loads((data / "content-packs/replay120.json").read_bytes())
        relative = "objectstore/publisher/5800/5800/infinityward/unified_large_playlist_tu19.aggr.content.bin"
        assert state["installed"][relative] == hashlib.sha256(content).hexdigest()
        assert state["derived"][relative] == json.loads(
            (ROOT / "content/replay120/manifest.json").read_bytes())["files"][relative]["sha256"]
        print("PASS: restart keeps the derived menu and its pack state")

        # Every map allowed: the original publication is served again.
        relaxed = dict(policy)
        relaxed.pop("available_maps")
        (data / "playlists" / TITLE / "policy.json").write_text(json.dumps(relaxed))
        full = servable(catalog)
        log = run(server, data, "relaxed")
        content, menu = served(data)
        assert zlib.decompress(content) == catalog_bytes or full != set(p["playlist"] for p in catalog["playlists"])
        check_menu(menu, catalog, full)
        print("PASS: an unrestricted policy serves", len(full), "playlists;", log or "no change")

        # A local installation narrows the menu further (packages.json).
        installed = {"mp_shipment", "mp_rust"}
        catalog_sha = hashlib.sha256(catalog_bytes).hexdigest()
        names = sorted({entry["map"] for playlist in catalog["playlists"] for entry in playlist["maps"]})
        body = {"schema": 1, "title": int(TITLE), "playlist_version": catalog["system"]["version"],
                "catalog_sha256": catalog_sha,
                "maps": [{"name": name, "available": name in installed} for name in names]}
        # playlist_catalog.cpp hashes nlohmann's compact, key-sorted dump.
        body["revision"] = hashlib.sha256(
            json.dumps(body, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
        (data / "playlists" / TITLE / "packages.json").write_text(json.dumps(body))
        log = run(server, data, "installed")
        content, menu = served(data)
        check_menu(menu, catalog, servable(catalog, None, installed))
        print("PASS: a two-map installation offers", len(servable(catalog, None, installed)), "playlists")


if __name__ == "__main__":
    main()
