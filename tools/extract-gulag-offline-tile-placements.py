"""Retain every static model pose in all authored Gulag ROI collision tiles.

No instance origin or height cutoff is applied. The geometry assembler must
select by decoded, transformed shape bounds, not these instance origins.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--capture", required=True, type=Path)
    ap.add_argument("--tiles", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    source = json.loads(args.capture.read_text())
    centers = [m["position"] for m in source["markers"] if m["original_fields"].get("845") == "gulag_center"]
    required = set()
    for center in centers:
        for y in range(math.floor((center[1] - 2048) / 8192) + 16,
                       math.floor((center[1] + 2048) / 8192) + 17):
            for x in range(math.floor((center[0] - 2048) / 8192) + 16,
                           math.floor((center[0] + 2048) / 8192) + 17):
                required.add(x + 32 * y)
    rows, payloads, detail_only = [], [], []
    for tile in sorted(required):
        root = args.tiles / str(tile) / "mw19replay" / f"mp_donetsk_cg_{tile:05d}_tr"
        manifest = json.loads((root / "manifest.json").read_text())
        if not manifest.get("complete") or not manifest.get("success") or manifest.get("failed"):
            raise ValueError("incomplete native CollisionTile export")
        journal = [json.loads(line) for line in (root / "assets.jsonl").read_text().splitlines()]
        if len(journal) != 1 or journal[0].get("status") != "ok":
            raise ValueError("ambiguous native CollisionTile export")
        asset = root / journal[0]["file"]
        asset_bytes = asset.read_bytes()
        fields = json.loads(asset_bytes)["asset"]["fields"]
        if fields["index"] != tile:
            raise ValueError("unexpected CollisionTile index")
        origin = fields["origin"]["v"]
        world_blob = bytes.fromhex(fields["havokTileShapeData"]["bytes"])
        blob_path = args.tiles / f"{tile}-havokTileShapeData.bin"
        blob_path.write_bytes(world_blob)
        native_sources = [Path(manifest["fastfile"])] + [Path(x) for x in manifest.get("applied_patches", [])]
        payloads.append({"tile": tile, "blob": str(blob_path.resolve()),
            "sha256": hashlib.sha256(world_blob).hexdigest(), "bytes": len(world_blob),
            "asset_export": str(asset.resolve()), "asset_export_sha256": hashlib.sha256(asset_bytes).hexdigest(),
            "tile_origin": origin, "native_complete": True, "native_failed": 0,
            "source_hashes": [{"path": str(p), "sha256": hashlib.file_digest(p.open("rb"), "sha256").hexdigest()}
                              for p in native_sources]})
        for model_index, model in enumerate(fields["staticModelCollision"]["values"][0]["models"]["values"]):
            physics_name = (model.get("physicsAsset") or {}).get("name", "").lstrip(",") or None
            detail_name = (model.get("detailCollision") or {}).get("name", "").lstrip(",") or None
            instances = []
            for index, instance in enumerate(model["instances"]["values"]):
                raw = struct.pack("<7H", *(instance["origin"] + instance["angles"] + [instance["scale"]]))
                values = struct.unpack("<7e", raw)
                instances.append({"index": index, "raw14": raw.hex(), "tile_origin": origin,
                    "local_origin": list(values[:3]),
                    "origin": [values[a] + origin[a] for a in range(3)],
                    "angles": list(values[3:6]), "scale": values[6]})
            row = {"tile": tile, "model": model_index, "physics_asset": physics_name,
                "detail_collision": detail_name, "instances": instances,
                "source_asset_export": str(asset.resolve())}
            rows.append(row)
            if physics_name is None and detail_name is not None and instances:
                detail_only.append({"tile": tile, "model": model_index,
                    "detail_collision": detail_name, "instances": len(instances)})
    source["transient_static_model_candidates"] = rows
    source["provenance"]["offline_pose_scope"] = {
        "arena_xy_half_extent": 2048, "required_tiles": sorted(required),
        "selection": "All instances in every intersected collision tile; no instance origin/height filter",
        "detail_only_candidates": detail_only,
        "source_capture": str(args.capture.resolve()),
        "source_capture_sha256": hashlib.sha256(args.capture.read_bytes()).hexdigest()}
    source["collision_complete"] = False
    args.output.write_text(json.dumps(source, indent=2) + "\n")
    (args.tiles / "payloads.json").write_text(json.dumps(payloads, indent=2) + "\n")
    print(json.dumps({"tiles": len(required), "models": len(rows),
        "instances": sum(len(x["instances"]) for x in rows),
        "physics_assets": len({x["physics_asset"] for x in rows if x["physics_asset"]}),
        "detail_only_models": len(detail_only)}))


if __name__ == "__main__":
    main()
