"""Decode native serialized CollisionTile world shapes into bounded Gulag ROIs."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    path = Path(__file__).with_name("decode-gulag-offline-physics.py")
    spec = importlib.util.spec_from_file_location("physics", path)
    physics = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(physics)
    captured = json.loads(args.capture.read_bytes())
    centers = [marker["position"] for marker in captured["markers"]
               if marker["original_fields"].get("845") == "gulag_center"]
    result = dict(schema=1, coordinate_space="world", collision_complete=False,
                  hulls=[], triangles=[], unresolved_quads=[], blockers=[], tiles=[])
    proof_path = Path(__file__).resolve().parent.parent / "data" / "gpu-gulag-world-tile-native-proof.json"
    if not json.loads(proof_path.read_bytes()).get("passed"):
        raise ValueError("Native world tile identity-placement proof has not passed")
    result["provenance"] = dict(
        payload_manifest_sha256=hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        native_placement_proof_sha256=hashlib.sha256(proof_path.read_bytes()).hexdigest(),
    )
    for row in json.loads(args.manifest.read_bytes()):
        if not row["native_complete"] or row["native_failed"]:
            raise ValueError("World tile native export is incomplete")
        blob = Path(row["blob"]).read_bytes()
        if hashlib.sha256(blob).hexdigest() != row["sha256"]:
            raise ValueError("World tile SHA256 mismatch")
        decoded = physics.decode_asset(blob, world_root=True)
        counts = {}
        for kind, field in (("hulls", "points"), ("triangles", "corners"),
                            ("unresolved_quads", "corners")):
            count = 0
            for item in decoded[kind]:
                points = [[value * 32 for value in point] for point in item[field]]
                low = [min(point[axis] for point in points) for axis in range(3)]
                high = [max(point[axis] for point in points) for axis in range(3)]
                if not any(all(low[axis] <= center[axis] + extent
                               and high[axis] >= center[axis] - extent
                               for axis, extent in enumerate((2048, 2048, 512)))
                           for center in centers):
                    continue
                item[field] = points
                if kind == "hulls":
                    margin = item.get("native_margin_havok")
                    item["native_margin_world"] = margin * 32 if margin is not None else None
                item.setdefault("provenance", {}).update(
                    collision_tile=row["tile"], source_blob_sha256=row["sha256"],
                    native_world_translation="identity; no tile origin added")
                result[kind].append(item)
                count += 1
            counts[kind] = count
        result["blockers"].extend(dict(collision_tile=row["tile"], **item)
                                  for item in decoded["blockers"])
        result["tiles"].append(dict(tile=row["tile"], source_sha256=row["sha256"], **counts))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["tiles"], indent=2))


if __name__ == "__main__":
    main()
