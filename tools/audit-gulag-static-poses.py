"""Bind captured Gulag poses to original offline CollisionTile half records."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--capture", required=True, type=Path)
    ap.add_argument("--tiles", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    capture = json.loads(args.capture.read_text())
    examples, errors, verified = [], [], 0
    for directory in args.tiles.iterdir():
        if not directory.is_dir() or not directory.name.isdecimal():
            continue
        tile = int(directory.name)
        root = directory / "mw19replay" / f"mp_donetsk_cg_{tile:05d}_tr"
        manifest = json.loads((root / "manifest.json").read_text())
        if not manifest.get("complete") or not manifest.get("success") or manifest.get("failed"):
            raise ValueError("incomplete native tile export")
        row = json.loads((root / "assets.jsonl").read_text().splitlines()[0])
        path = root / row["file"]
        asset_bytes = path.read_bytes()
        source_sha = hashlib.sha256(asset_bytes).hexdigest()
        fields = json.loads(asset_bytes)["asset"]["fields"]
        models = fields["staticModelCollision"]["values"][0]["models"]["values"]
        origin = fields["origin"]["v"]
        for model in capture["transient_static_model_candidates"]:
            if model["tile"] != tile:
                continue
            original = models[model["model"]]
            original_name = (original.get("physicsAsset") or {}).get("name", "").lstrip(",")
            if original_name != (model["physics_asset"] or ""):
                errors.append({"tile": tile, "model": model["model"], "reason": "name mismatch"})
                continue
            for instance in model["instances"]:
                source = original["instances"]["values"][instance["index"]]
                words = source["origin"] + source["angles"] + [source["scale"]]
                raw = struct.pack("<7H", *words)
                values = struct.unpack("<7e", raw)
                world = [values[a] + origin[a] for a in range(3)]
                expected = instance["origin"] + instance["angles"] + [instance["scale"]]
                actual = world + list(values[3:])
                error = max(abs(a - b) for a, b in zip(actual, expected))
                if error:
                    errors.append({"tile": tile, "model": model["model"],
                        "instance": instance["index"], "max_error": error})
                verified += 1
                yaw_sample = values[4] in (315, 135) and not any(x["angles"][1] == values[4] for x in examples)
                tilted_sample = (values[3] != 0 or values[5] != 0) and not any(
                    x["angles"][0] != 0 or x["angles"][2] != 0 for x in examples)
                if yaw_sample or tilted_sample:
                    examples.append({"tile": tile, "model": model["model"],
                        "instance": instance["index"], "physics_asset": model["physics_asset"],
                        "raw14": raw.hex(), "tile_origin": origin,
                        "local_origin": list(values[:3]), "angles": list(values[3:6]),
                        "scale": values[6], "world_origin": world,
                        "captured_origin": instance["origin"], "source_asset_export": str(path.resolve()),
                        "source_asset_export_sha256": source_sha})
    result = {"status": "pass" if not errors else "fail", "verified_captured_instances": verified,
        "errors": errors, "samples": examples}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"verified": verified, "errors": len(errors), "samples": len(examples)}))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
