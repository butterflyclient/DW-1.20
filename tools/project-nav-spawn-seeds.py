"""Project authored navigation seeds onto audited source collision floors.

This transforms seed positions only. It neither creates collision geometry nor
changes collision-completeness status. Every seed must have an actual retained
Scene floor in the hash-matched source audit; partial projections are rejected.
"""

import argparse
import hashlib
import json
import math
from pathlib import Path


def project(geometry_bytes, audit_bytes):
    geometry = json.loads(geometry_bytes)
    audit = json.loads(audit_bytes)
    source_hash = hashlib.sha256(geometry_bytes).hexdigest()
    if audit.get("input_sha256") != source_hash:
        raise ValueError("Source audit does not match the geometry SHA256")
    results = audit["source_collision_audit"]["spawn_results"]
    original = geometry["spawns"]
    if not original or len(results) != len(original):
        raise ValueError("Source audit must cover every authored spawn")
    projected = []
    for spawn, result in zip(original, results):
        if result["spawn"] != spawn:
            raise ValueError("Source audit spawn order/coordinates differ")
        floor = result.get("nearest_floor")
        if (
            floor is None
            or not math.isfinite(floor)
            or result["walkable_floor_count"] < 1
            or floor > spawn[2]
        ):
            raise ValueError("Every authored spawn requires an actual floor beneath it")
        projected.append([spawn[0], spawn[1], floor])
    geometry["spawns"] = projected
    geometry["authored_spawns"] = original
    geometry.setdefault("provenance", {})["seed_projection"] = dict(
        method="same XY; actual nearest retained Scene walkable floor below authored marker",
        source_geometry_sha256=source_hash,
        source_audit_sha256=hashlib.sha256(audit_bytes).hexdigest(),
        authored_spawns=original,
        projected_spawns=projected,
        collision_geometry_changed=False,
        collision_completeness_changed=False,
    )
    return geometry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--source-audit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() in (args.input.resolve(), args.source_audit.resolve()):
        parser.error("Output must preserve both original geometry and source audit")
    geometry = project(args.input.read_bytes(), args.source_audit.read_bytes())
    args.output.write_text(json.dumps(geometry, indent=2) + "\n")
    print(json.dumps(geometry["provenance"]["seed_projection"], indent=2))


if __name__ == "__main__":
    main()
