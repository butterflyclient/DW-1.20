"""Decode every convex instance in the saved native-fixed world TAG0 offline.

Selection uses transformed geometry bounds, never the instance origin. Output
is restricted to six authored Gulag regions and retains original native tags.
"""

import argparse
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path


def decode(blob, receipt, geometry):
    if hashlib.sha256(blob).hexdigest() != receipt["sha256"]:
        raise ValueError("Saved native TAG0 SHA256 mismatch")
    base = int(receipt["original_blob_base"], 0)
    path = Path("D:/mw124/mw120rproxy/iw8-zonetool/tools/audit_world_shape.py")
    specification = importlib.util.spec_from_file_location("tag", path)
    tag = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(tag)
    root = (0, len(blob))
    data_section = tag.section(blob, root, b"DATA")
    payload = data_section[0] + 8
    data_end = sum(data_section)
    types = tag.type_identities(blob, tag.section(blob, root, b"TYPE"))
    section = tag.section(blob, tag.section(blob, root, b"INDX"), b"ITEM")
    items = {
        payload + offset: (index, types[flags & 0xFFFFFF], count)
        for index, (flags, offset, count) in enumerate(
            struct.unpack_from("<III", blob, at)
            for at in range(section[0] + 8, sum(section), 12)
        )
        if flags & 0xFFFFFF
    }

    def unpack(fmt, at):
        if at < payload or at + struct.calcsize(fmt) > data_end:
            raise ValueError("World TAG0 read exceeds saved image")
        return struct.unpack_from(fmt, blob, at)

    def pointer(at):
        offset = unpack("<Q", at)[0] - base
        if offset not in items:
            raise ValueError("Native pointer does not resolve to a typed ITEM")
        return offset

    shapes = pointer(payload)
    shape = pointer(shapes)
    if items[shape][1] != "hknpCompressedMeshShape":
        raise ValueError("Unexpected root world shape")
    children = pointer(shape + 112)
    count = items[children][2]
    if not 1 <= count <= 100000:
        raise ValueError("World custom instance count outside bound")
    centers = [
        marker["position"]
        for marker in geometry["markers"]
        if marker["original_fields"].get("845") == "gulag_center"
    ]
    if len(centers) != 6:
        raise ValueError("Expected six authored Gulag centers")
    hulls, selected, cache = [], [], {}
    for index in range(count):
        instance = children + index * 112
        child = pointer(instance + 80)
        if child not in cache:
            item_id, name, _ = items[child]
            if name not in ("hknpConvexPolytopeShape", "hknpBoxShape"):
                raise ValueError(f"Unsupported world custom child {name}")
            vertices, relative = unpack("<HH", child + 58)
            if not 4 <= vertices <= 256:
                raise ValueError("Native fixed support vertex count outside bound")
            points = [
                unpack("<3f", child + 58 + relative + at * 16)
                for at in range(vertices)
            ]
            radius = unpack("<f", child + 32)[0]
            cache[child] = item_id, name, points, radius
        item_id, name, points, radius = cache[child]
        matrix = unpack("<16f", instance)
        scale = unpack("<3f", instance + 64)
        world = [
            [
                32 * (matrix[12 + axis] + sum(
                    matrix[column * 4 + axis] * point[column] * scale[column]
                    for column in range(3)
                ))
                for axis in range(3)
            ]
            for point in points
        ]
        if not all(math.isfinite(value) for point in world for value in point):
            raise ValueError("Invalid transformed world coordinate")
        low = [min(point[axis] for point in world) for axis in range(3)]
        high = [max(point[axis] for point in world) for axis in range(3)]
        arenas = [
            arena for arena, center in enumerate(centers)
            if all(low[axis] <= center[axis] + extent
                   and high[axis] >= center[axis] - extent
                   for axis, extent in enumerate((2048, 2048, 512)))
        ]
        if not arenas:
            continue
        metadata = dict(
            instance=index, shape_item=item_id, type=name, arenas=arenas,
            bounds=[low, high], transform=matrix, scale=scale,
            native_shape_tag=unpack("<H", instance + 88)[0],
            native_radius_world=radius * 32,
        )
        selected.append(metadata)
        hulls.append(dict(points=world, flags=3, provenance=metadata))
    return dict(
        schema=1, coordinate_space="world", collision_complete=False,
        provenance=dict(synthetic=False, source_sha256=receipt["sha256"],
                        selection="all custom instances decoded; transformed bounds overlap authored arena ROI"),
        root_custom_instances=count, unique_shapes=len(cache),
        hulls=hulls, selected_instances=selected,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--geometry", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = decode(args.blob.read_bytes(), json.loads(args.receipt.read_bytes()),
                    json.loads(args.geometry.read_bytes()))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("root_custom_instances", "unique_shapes")}))
    print("Selected", len(result["hulls"]), "actual hulls")


if __name__ == "__main__":
    main()
