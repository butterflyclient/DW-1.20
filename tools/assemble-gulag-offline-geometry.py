"""Assemble six bounded world-space arena geometry candidates from actual assets.

Incomplete asset, collision-filter, radius and quad coverage remain explicit.
This command does not generate a navigation resource or access a live process.
"""

import argparse
import copy
import hashlib
import json
import math
from pathlib import Path


def world_point(point, instance):
    pitch, yaw, roll = [math.radians(value) for value in instance["angles"]]
    cp, sp = math.cos(pitch), math.sin(pitch)
    cy, sy = math.cos(yaw), math.sin(yaw)
    cr, sr = math.cos(roll), math.sin(roll)
    matrix = [
        [cp * cy, sr * sp * cy - cr * sy, cr * sp * cy + sr * sy],
        [cp * sy, sr * sp * sy + cr * cy, cr * sp * sy - sr * cy],
        [-sp, sr * cp, cr * cp],
    ]
    scale = instance["scale"] * 32.0
    result = [
        instance["origin"][axis]
        + sum(matrix[axis][column] * point[column] * scale for column in range(3))
        for axis in range(3)
    ]
    if not all(math.isfinite(value) and abs(value) < 1_000_000 for value in result):
        raise ValueError("Invalid placed geometry coordinate")
    return result


def overlaps(points, center):
    return all(
        max(point[axis] for point in points) >= center[axis] - extent
        and min(point[axis] for point in points) <= center[axis] + extent
        for axis, extent in enumerate((2048.0, 2048.0, 512.0))
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--decoded", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--world-tiles", type=Path)
    parser.add_argument("--brush-hulls", type=Path)
    parser.add_argument("--all-height-placements", type=Path)
    parser.add_argument("--installed-dependency-fallback-proof", type=Path)
    args = parser.parse_args()
    capture_bytes = args.capture.read_bytes()
    captured = json.loads(capture_bytes)
    decoded_manifest = json.loads(args.decoded.read_bytes())
    fallback = None
    if args.installed_dependency_fallback_proof:
        fallback = json.loads(args.installed_dependency_fallback_proof.read_bytes())
        if (
            fallback.get("missing_asset") != "cinderblock_wall_topper_01_16"
            or fallback.get("player_mask") != 0x02014011
            or fallback.get("mask_intersections") != [0]
        ):
            raise ValueError("Unexpected installed-dependency fallback disposition")
        default_export = Path(fallback["default_asset_export"])
        if hashlib.sha256(default_export.read_bytes()).hexdigest() != fallback["default_export_sha256"]:
            raise ValueError("Native default asset export SHA256 mismatch")
    proof_directory = Path(__file__).resolve().parent.parent / "data"
    rotation_proof = proof_directory / "gpu-gulag-native-instance-transform-proof.json"
    filter_proof = proof_directory / "gpu-gulag-player-collision-filter-proof.json"
    if not json.loads(rotation_proof.read_bytes()).get("passed"):
        raise ValueError("Native instance rotation proof has not passed")
    if json.loads(filter_proof.read_bytes()).get("default_player_trace_mask") != "0x2014011":
        raise ValueError("Unexpected native player collision filter proof")
    assets = {
        row["name"]: json.loads(Path(row["output"]).read_bytes())
        for row in decoded_manifest["decoded"]
    }
    markers = [
        marker
        for marker in captured["markers"]
        if marker["original_fields"].get("845") == "gulag_center"
    ]
    if len(markers) != 6:
        raise ValueError("Expected six original authored arena centers")
    arenas = []
    for index, marker in enumerate(markers):
        arenas.append(
            dict(
                schema=1,
                coordinate_space="world",
                collision_complete=False,
                provenance=dict(
                    synthetic=False,
                    collision_complete=False,
                    arena_index=index,
                    arena_center=marker["position"],
                    authored_center_fields=marker["original_fields"],
                    capture_sha256=hashlib.sha256(capture_bytes).hexdigest(),
                    collision_filter_verified=True,
                    instance_rotation_native_validation=True,
                    native_angle_oracle="original Replay AnglesToAxis RVA 0x20375e0; native instruction numeric proof passed",
                    rotation_proof_sha256=hashlib.sha256(rotation_proof.read_bytes()).hexdigest(),
                    filter_proof_sha256=hashlib.sha256(filter_proof.read_bytes()).hexdigest(),
                    native_player_trace_mask="0x02014011",
                    placement_selection="transformed geometry bounds; no origin filter" if args.all_height_placements else "legacy bounded origin candidates",
                    limitations=[
                        "World leaf tags conservatively retained where tag contents are unresolved",
                        "Playerclip brush dynamic state conservatively treated as blocking",
                    ],
                ),
                hulls=[],
                triangles=[],
                unresolved_quads=[],
                spawns=[],
                pathNodes=[],
                blockers=[],
                missing_assets=[],
            )
        )
    centers = [marker["position"] for marker in markers]
    for spawn in captured["spawns"]:
        nearest = min(
            range(6),
            key=lambda index: sum(
                (spawn[axis] - centers[index][axis]) ** 2 for axis in range(2)
            ),
        )
        arenas[nearest]["spawns"].append(spawn)
    for hull_index, hull in enumerate(captured["hulls"]):
        for arena, center in zip(arenas, centers):
            if overlaps(hull["points"], center):
                source = copy.deepcopy(hull)
                source["provenance"] = dict(
                    source="captured actual base-world convex", index=hull_index
                )
                arena["hulls"].append(source)
    rows = captured.get("static_model_collision_candidates", []) + captured.get(
        "transient_static_model_candidates", []
    )
    if args.all_height_placements:
        placements = json.loads(args.all_height_placements.read_bytes())
        rows = placements.get("transient_static_model_candidates", [])
        pose_hash = hashlib.sha256(args.all_height_placements.read_bytes()).hexdigest()
        detail_proof = proof_directory / "gulag-offline-detail-only-native-proof.json"
        detail_hash = hashlib.sha256(detail_proof.read_bytes()).hexdigest()
        for arena in arenas:
            arena["provenance"]["all_height_placement_sha256"] = pose_hash
            arena["provenance"]["all_height_model_rows"] = len(rows)
            arena["provenance"]["all_height_instances"] = sum(len(row["instances"]) for row in rows)
            arena["provenance"]["detail_only_simulation_exclusion_proof_sha256"] = detail_hash
    for row in rows:
        if row["physics_asset"] is None and row.get("simulation_shape", "0x0") == "0x0":
            continue
        asset = assets.get(row["physics_asset"])
        if asset is None and fallback and row["physics_asset"] == fallback["missing_asset"]:
            for arena in arenas:
                arena["provenance"]["installed_dependency_missing_reference"] = dict(
                    asset=row["physics_asset"],
                    disposition="native default contents exclude player mask; no geometry substituted",
                    proof_sha256=hashlib.sha256(args.installed_dependency_fallback_proof.read_bytes()).hexdigest(),
                    scope_limit=fallback["scope_limit"],
                )
            continue
        for instance in row["instances"]:
            selected = list(range(6)) if args.all_height_placements else [
                index
                for index, center in enumerate(centers)
                if abs(instance["origin"][0] - center[0]) < 2400
                and abs(instance["origin"][1] - center[1]) < 2400
            ]
            if not selected:
                continue
            if asset is None:
                for index in selected:
                    arenas[index]["missing_assets"].append(
                        row["physics_asset"] or "<unresolved asset name>"
                    )
                continue
            for kind, field in (
                ("hulls", "points"),
                ("triangles", "corners"),
                ("unresolved_quads", "corners"),
            ):
                for item in asset[kind]:
                    points = [world_point(point, instance) for point in item[field]]
                    for index in selected:
                        if not overlaps(points, centers[index]):
                            continue
                        body = item.get("provenance", {}).get("body")
                        if body is not None:
                            contents = int(asset["bodies"][body]["contents"], 0)
                            if not contents & 0x02014011:
                                continue
                        placed = copy.deepcopy(item)
                        placed[field] = points
                        if kind == "hulls":
                            margin = item.get("native_margin_havok", 0.0)
                            if margin is None:
                                arenas[index]["blockers"].append(
                                    dict(
                                        asset=row["physics_asset"],
                                        reason="Unresolved native convex margin transform",
                                    )
                                )
                            else:
                                placed["native_margin_world"] = (
                                    margin * 32 * abs(instance["scale"])
                                )
                        placed.setdefault("provenance", {}).update(
                            asset=row["physics_asset"],
                            instance=instance,
                            source_blob_sha256=asset["provenance"]["blob_sha256"],
                        )
                        arenas[index][kind].append(placed)
            for index in selected:
                for blocker in asset["blockers"]:
                    body = blocker.get("body")
                    if body is not None:
                        contents = int(asset["bodies"][body]["contents"], 0)
                        if not contents & 0x02014011:
                            continue
                    arenas[index]["blockers"].append(
                        dict(asset=row["physics_asset"], **blocker)
                    )
    for path, label in ((args.world_tiles, "offline CollisionTile world"),
                        (args.brush_hulls, "actual playerclip brush")):
        if path is None:
            continue
        source = json.loads(path.read_bytes())
        for kind, field in (("hulls", "points"), ("triangles", "corners"),
                            ("unresolved_quads", "corners")):
            for item in source.get(kind, []):
                for arena, center in zip(arenas, centers):
                    if overlaps(item[field], center):
                        placed = copy.deepcopy(item)
                        placed.setdefault("provenance", {})["source_category"] = label
                        arena[kind].append(placed)
        for arena in arenas:
            arena["provenance"][label] = dict(
                source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                source=str(path.resolve()),
            )
    args.output.mkdir(parents=True, exist_ok=True)
    summary = []
    for index, arena in enumerate(arenas):
        arena["missing_assets"] = sorted(set(arena["missing_assets"]))
        if arena["missing_assets"]:
            arena["provenance"]["limitations"].append(
                "Static PhysicsAsset exports missing"
            )
        if arena["blockers"]:
            arena["provenance"]["limitations"].append(
                "Rounded/unsupported native shapes not yet represented"
            )
        if arena["unresolved_quads"]:
            arena["provenance"]["limitations"].append(
                "Native mesh quad topology unresolved"
            )
        complete = bool(
            args.all_height_placements and args.world_tiles and args.brush_hulls
            and fallback and not decoded_manifest["errors"]
            and not arena["missing_assets"] and not arena["blockers"]
            and not arena["unresolved_quads"]
        )
        arena["collision_complete"] = complete
        arena["provenance"]["collision_complete"] = complete
        arena["provenance"]["coverage_scope"] = (
            "six authored Gulag ROIs, +/-2048 XY and +/-512 Z; inspected installed dependency set"
        )
        root_audit = proof_directory / "gulag-offline-all-world-convex.json"
        arena["provenance"]["all_root_custom_instances_audit_sha256"] = hashlib.sha256(root_audit.read_bytes()).hexdigest()
        tile_proof = proof_directory / "gpu-gulag-world-tile-native-proof.json"
        arena["provenance"]["native_world_tile_placement_proof_sha256"] = hashlib.sha256(tile_proof.read_bytes()).hexdigest()
        tile_manifest = proof_directory / "gulag-offline-collision-tiles" / "payloads.json"
        arena["provenance"]["world_tile_source_manifest_sha256"] = hashlib.sha256(tile_manifest.read_bytes()).hexdigest()
        if args.world_tiles:
            quad_proof = proof_directory / "gulag-native-quad-surface-proof.json"
            arena["provenance"]["native_quad_surface_proof_sha256"] = hashlib.sha256(quad_proof.read_bytes()).hexdigest()
        destination = args.output / f"arena-{index}.geometry.json"
        destination.write_text(json.dumps(arena, indent=2) + "\n")
        summary.append(
            dict(
                arena=index,
                output=str(destination),
                hulls=len(arena["hulls"]),
                triangles=len(arena["triangles"]),
                quads=len(arena["unresolved_quads"]),
                spawns=len(arena["spawns"]),
                missing_assets=arena["missing_assets"],
                blocker_count=len(arena["blockers"]),
                collision_complete=complete,
            )
        )
    (args.output / "manifest.json").write_text(
        json.dumps(dict(schema=1, arenas=summary), indent=2) + "\n"
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
