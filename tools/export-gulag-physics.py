"""Export only identified Gulag PhysicsAssets through Replay's offline reader.

All source FF/FP/FC files remain read-only; output must be under this workspace.
Existing complete ACTS exports may be imported without parsing their FF again.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--geometry", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--acts", type=Path, default=Path("D:/mw124/atian-cod-tools/build-workstation/bin/Release/acts.exe"))
    ap.add_argument("--game", type=Path, default=Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe"))
    ap.add_argument("--existing", type=Path, action="append", default=[])
    ap.add_argument("--source", type=Path, action="append", default=[])
    ap.add_argument("--nav-export", type=Path)
    args = ap.parse_args()
    workspace = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if not output.is_relative_to(workspace / "data"):
        raise ValueError("all research output must remain under canonical workspace/data")
    output.mkdir(parents=True, exist_ok=True)
    wanted = {m["physics_asset"] for m in json.loads(args.geometry.read_text())["transient_static_model_candidates"]
              if m["physics_asset"]}
    items, runs = {}, []
    if args.nav_export:
        root = args.nav_export.resolve(strict=True)
        native_manifest = json.loads((root / "manifest.json").read_text())
        if not native_manifest.get("complete") or not native_manifest.get("success") or native_manifest.get("failed"):
            raise ValueError("canonical navmesh native export is incomplete")
        matches = [json.loads(line) for line in (root / native_manifest["journal"]).read_text().splitlines()
                   if json.loads(line).get("type") == "navmesh"]
        if len(matches) != 1 or matches[0].get("status") != "ok":
            raise ValueError("canonical navmesh export is ambiguous")
        path = root / matches[0]["file"]
        fields = json.loads(path.read_bytes())["asset"]["fields"]
        metadata = {"asset": fields["name"]["string"], "version": fields["version"],
            "hasExposureData": fields["hasExposureData"], "resource_count": fields["numNavResources"],
            "staticHalf": fields["miscData"]["m_StaticBoundsHalfSize"]["v"],
            "staticMid": fields["miscData"]["m_StaticBoundsMidPoint"]["v"],
            "export_sha256": sha(path), "native_export_complete": True,
            "native_export_failed": native_manifest.get("failed", 0),
            "source_hashes": [{"path": str(p), "sha256": sha(p)} for p in
                [Path(native_manifest["fastfile"])] + [Path(x) for x in native_manifest.get("applied_patches", [])]]}
        (output / "canonical-navmesh-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    def import_export(root):
        manifest = json.loads((root / "manifest.json").read_text())
        if not manifest.get("complete") or not manifest.get("success") or manifest.get("failed") or manifest.get("unavailable"):
            raise ValueError(f"native reader did not complete cleanly: {root}")
        sources = [Path(manifest["fastfile"])] + [Path(p) for p in manifest.get("applied_patches", [])]
        source_hashes = [{"path": str(p.resolve()), "sha256": sha(p)} for p in sources]
        for line in (root / manifest["journal"]).read_text().splitlines():
            row = json.loads(line)
            name = row.get("name")
            if row.get("type") != "physicsasset" or name not in wanted or row.get("status") != "ok":
                continue
            if any(row.get(key) for key in ("read_errors", "unresolved_pointers", "unresolved_unions", "field_issues")):
                raise ValueError(f"native export has unresolved fields: {name}")
            path = root / row["file"]
            obj = json.loads(path.read_bytes())
            fields = obj["asset"]["fields"]
            blob = bytes.fromhex(fields["havokData"]["bytes"])
            if len(blob) != fields["havokDataSize"] or blob[4:8] != b"TAG0":
                raise ValueError(f"native physics export has invalid TAG0: {name}")
            blob_hash = hashlib.sha256(blob).hexdigest()
            if name in items and items[name]["sha256"] != blob_hash:
                raise ValueError(f"conflicting owned PhysicsAsset payloads: {name}")
            destination = output / (name + ".tag0.bin")
            if destination.parent != output:
                raise ValueError("unexpected PhysicsAsset virtual directory")
            destination.write_bytes(blob)
            items[name] = {"name": name, "blob": str(destination), "sha256": blob_hash,
                "bytes": len(blob), "asset_export": str(path.resolve()),
                "asset_export_sha256": sha(path), "bodyContents": fields["bodyContents"],
                "numRigidBodies": fields["numRigidBodies"], "source_zone": root.name,
                "source_manifest": str((root / "manifest.json").resolve()),
                "source_hashes": source_hashes}
        return manifest
    def save():
        receipt = {"schema": 1, "items": list(items.values()),
            "missing": sorted(wanted - items.keys()), "runs": runs,
            "acts_sha256": sha(args.acts), "native_executable_sha256": sha(args.game),
            "geometry_sha256": sha(args.geometry)}
        (output / "manifest.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"found": len(items), "wanted": len(wanted),
            "missing_count": len(receipt["missing"]), "missing_sample": receipt["missing"][:8]}), flush=True)
    for root in args.existing:
        import_export(root)
    save()
    for source in args.source:
        missing = sorted(wanted - items.keys())
        if not missing:
            break
        source = source.resolve(strict=True)
        inputs = [source] + [p for extension in (".fp", ".fc") if (p := source.with_suffix(extension)).is_file()]
        before = {str(p): sha(p) for p in inputs}
        export_root = output / "native" / source.stem
        export_root.mkdir(parents=True, exist_ok=True)
        log = export_root / "acts.log"
        command = [str(args.acts), "--noUpdater", "fastfile", "-r", "mw19replay", "-g", str(args.game),
            "-o", str(export_root), "-a", "physicsasset", "-n", ",".join(missing), "-l", str(source)]
        with log.open("w") as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=600)
        after = {str(p): sha(p) for p in inputs}
        if result.returncode or before != after:
            raise RuntimeError(f"native export failed or source changed; see {log}")
        root = export_root / "mw19replay" / source.stem
        manifest = import_export(root)
        runs.append({"source": str(source), "source_hashes_before_after": before,
            "command": command, "complete": manifest["complete"], "log": str(log)})
        save()


if __name__ == "__main__":
    main()
