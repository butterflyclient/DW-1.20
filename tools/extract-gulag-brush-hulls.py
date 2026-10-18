"""Decode actual authored Gulag brush hulls; preserve dynamic-state uncertainty."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--blob", required=True, type=Path)
    ap.add_argument("--bounds-audit", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    tools = Path(__file__).resolve().parent
    decoder = load("offline_physics", tools / "decode-gulag-offline-physics.py")
    assembler = load("offline_placement", tools / "assemble-gulag-offline-geometry.py")
    blob = args.blob.read_bytes()
    reader = decoder.TagReader(blob)
    root, count, typ = reader.item(1, 152)
    if count != 1 or typ != "HavokPhysicsShapeList":
        raise ValueError("unexpected MapEnts collision root")
    shapes, shape_count, _ = reader.pointer(root, 8)
    contents, contents_count, _ = reader.pointer(root + 120, 4)
    if contents_count != shape_count:
        raise ValueError("MapEnts shape/content arrays differ")
    audit = json.loads(args.bounds_audit.read_text())
    hulls = []
    for selected in audit["selected"]:
        index = selected["shape_override_index"]
        if not 0 <= index < shape_count:
            raise ValueError("brush shape index outside native shape list")
        shape, _, shape_type = reader.pointer(shapes + index * 8, 128)
        if shape_type != "hknpCompressedMeshShape":
            raise ValueError("unsupported brush root shape")
        instances, instance_count, _ = reader.pointer(shape + 112, 112)
        if instance_count != 1:
            raise ValueError("expected one actual convex brush child")
        child, _, child_type = reader.pointer(instances + 80, 96)
        if child_type not in ("hknpBoxShape", "hknpConvexPolytopeShape"):
            raise ValueError("unsupported brush child type")
        vertices, vertex_count, vertex_type = reader.item(reader.unpack("<I", child + 58)[0], 16)
        if vertex_count != 8 or vertex_type not in ("hkVector4", "hkVector4f"):
            raise ValueError("unexpected actual brush support vertex array")
        radius = reader.unpack("<f", child + 32)[0]
        if radius:
            raise ValueError("rounded brush needs explicit native radius handling")
        matrix = reader.unpack("<16f", instances)
        scale = reader.unpack("<3f", instances + 64)
        entity = selected["record"]
        pose = {"origin": list(map(float, entity.get("709", "0 0 0").split())),
            "angles": list(map(float, entity.get("80", "0 0 0").split())), "scale": 1.0}
        points = []
        for i in range(vertex_count):
            p = reader.unpack("<3f", vertices + i * 16)
            local = [matrix[12 + axis] + sum(matrix[j * 4 + axis] * p[j] * scale[j] for j in range(3))
                     for axis in range(3)]
            points.append(assembler.world_point(local, pose))
        body_contents = reader.unpack("<I", contents + index * 4)[0]
        hulls.append({"points": points, "flags": 1, "model": selected["model"],
            "shape_override_index": index, "arenas": selected["arenas"],
            "body_contents": body_contents, "player_mask_intersection": body_contents & 0x02014011,
            "native_radius_world": 0, "original_entity_fields": entity,
            "dynamic_state_verified": False})
    result = {"schema": 1, "coordinate_space": "world", "hulls": hulls,
        "collision_complete": False, "provenance": {"blob_sha256": hashlib.sha256(blob).hexdigest(),
            "brush_records_audited": audit["brush_records"], "actual_roi_hulls": len(hulls),
            "limitation": "Authored brush colliders decoded exactly; runtime GSC solid/not-solid state remains unverified"}}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"actual_brush_hulls": len(hulls), "rounded_radii": 0,
        "all_player_mask_intersections": sorted({x["player_mask_intersection"] for x in hulls})}))


if __name__ == "__main__":
    main()
