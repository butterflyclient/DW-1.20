"""Offline decoder of captured Replay compressed mesh primitives; never opens a process.

Only vertices/layout demonstrated by original Replay 0x141E2CA20 are decoded.
Custom convex instances stay with extract-gulag-collision.py. Quad surfaces use
the target raycast/export diagonal verified at RVAs 0x1f21ac0 and 0x1f215f0.
"""

import argparse
import collections
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path

EVIDENCE = {
    "original_rva": "0x1e2ca20",
    "original_bytes": 4975,
    "original_sha256": "8e9aa82d59820353311925bf1abce768eadc0836743af120e49a14476e2cb188",
    "symbol_source": "native hknpCompressedMeshShape vtable slot 22",
    "local_quantization_bits": [11, 11, 10],
    "shared_quantization_bits": [21, 21, 22],
}


def float32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def capture_mesh_image(read, shape_address, max_bytes=16 * 1024 * 1024):
    """Copy a bounded contiguous native mesh image through an owner's read callback.

    This function does not open a process. Its caller owns identity verification,
    the read budget, and native lifetime stability. No native function is called.
    """
    header = read(shape_address, 128)
    if header[26] != 9:
        raise ValueError("Capture target is not native shape type 9")
    internals_address = struct.unpack_from("<Q", header, 72)[0]
    internals = read(internals_address, 264)
    ranges = [(shape_address, 128), (internals_address, 264)]
    for offset, stride in ((96, 96), (112, 4), (128, 2), (144, 4), (160, 8), (176, 4)):
        pointer, count = struct.unpack_from("<QI", internals, offset)
        if count > 2_000_000 or count * stride > max_bytes or (count and not pointer):
            raise ValueError("Native compressed mesh array exceeds capture bound")
        if count:
            ranges.append((pointer, count * stride))
    beginning = min(address for address, size in ranges)
    end = max(address + size for address, size in ranges)
    if end - beginning > max_bytes:
        raise ValueError(
            "Native compressed mesh image is not within contiguous capture bound"
        )
    image = read(beginning, end - beginning)
    return dict(
        image=image,
        original_base=beginning,
        native_shape_offset=shape_address - beginning,
        convex_radius=struct.unpack_from("<f", header, 32)[0],
        shape_address=shape_address,
    )


def decode_mesh_image(capture):
    """Return all mesh faces in LOCAL HAVOK units; caller applies instance poses."""
    result = decode(
        capture["image"],
        capture["original_base"],
        None,
        None,
        native_shape_offset=capture["native_shape_offset"],
    )
    result["native_convex_radius"] = capture["convex_radius"]
    result["minimum_decoded_local_z"] = result.pop("minimum_decoded_world_z")
    return result


def decode(data, original_base, geometry, schema, native_shape_offset=None):
    sections = (0, len(data))
    if native_shape_offset is None:
        data_section = schema.section(data, sections, b"DATA")
        type_names = schema.type_identities(
            data, schema.section(data, sections, b"TYPE")
        )
        index = schema.section(data, schema.section(data, sections, b"INDX"), b"ITEM")
        items = [
            struct.unpack_from("<III", data, at)
            for at in range(index[0] + 8, sum(index), 12)
        ]
        payload = data_section[0] + 8
        lookup = {
            payload + offset: (identity, type_names[flags & 0xFFFFFF], count)
            for identity, (flags, offset, count) in enumerate(items)
            if flags & 0xFFFFFF
        }
    else:
        data_section = (0, len(data))
        payload = 0
        lookup = None

    def unpack(fmt, at):
        if at < payload or at + struct.calcsize(fmt) > sum(data_section):
            raise ValueError("Compressed collision read leaves captured DATA")
        return struct.unpack_from(fmt, data, at)

    def item_pointer(at, expected, stride):
        pointer = unpack("<Q", at)[0] - original_base
        if lookup is not None:
            identity, name, count = lookup[pointer]
            if name != expected:
                raise ValueError(f"Unexpected ITEM {identity}: {name}")
        else:
            count = unpack("<I", at + 8)[0]
        if count and (
            pointer < payload or pointer + count * stride > sum(data_section)
        ):
            raise ValueError("Native compressed mesh array exceeds captured image")
        return pointer, count

    if native_shape_offset is None:
        root_shapes, _ = item_pointer(payload, "T*<hknpShape>", 8)
        shape, _ = item_pointer(root_shapes, "hknpCompressedMeshShape", 128)
        internals, _ = item_pointer(shape + 72, "hknpCompressedMeshShapeData", 264)
    else:
        shape = native_shape_offset
        if unpack("<B", shape + 26)[0] != 9:
            raise ValueError("Native shape image is not type 9")
        internals = unpack("<Q", shape + 72)[0] - original_base
        unpack("<264s", internals)
    section_array, section_count = item_pointer(
        internals + 96, "hkcdStaticMeshTree::Section", 96
    )
    primitives, primitive_count = item_pointer(
        internals + 112, "hkcdStaticMeshTree::Primitive", 4
    )
    shared_indices, shared_index_count = item_pointer(internals + 128, "hkUint16", 2)
    local_vertices, local_count = item_pointer(internals + 144, "unsigned int", 4)
    shared_vertices, shared_count = item_pointer(
        internals + 160, "unsigned long long", 8
    )
    runs, run_count = item_pointer(
        internals + 176, "hkcdDefaultStaticMeshTree::PrimitiveDataRun", 4
    )
    domain_min = unpack("<3f", internals + 48)
    domain_max = unpack("<3f", internals + 64)
    shared_scale = [
        float32(float32(domain_max[i] - domain_min[i]) * float32(1 / ((1 << bits) - 1)))
        for i, bits in enumerate((21, 21, 22))
    ]
    centers = [
        marker["position"]
        for marker in (geometry["markers"] if geometry is not None else [])
        if marker["original_fields"].get("845") == "gulag_center"
    ]
    if geometry is not None and len(centers) != 6:
        raise ValueError("Expected six authored Gulag centers")
    counts = collections.Counter()
    triangles, unresolved = [], []
    minimum_world_z = math.inf

    def overlaps_region(vertices):
        if geometry is None:
            return True
        for center in centers:
            if all(
                max(p[axis] for p in vertices) >= center[axis] - extent
                and min(p[axis] for p in vertices) <= center[axis] + extent
                for axis, extent in enumerate((2048, 2048, 512))
            ):
                return True
        return False

    for section_id in range(section_count):
        section = section_array + 96 * section_id
        offset = unpack("<3f", section + 48)
        scale = unpack("<3f", section + 60)
        local_start, shared_start, primitive_start, run_start = unpack(
            "<4I", section + 72
        )
        section_local_count, section_primitive_count, section_run_count, shared_page = (
            unpack("<4B", section + 88)
        )
        if (
            primitive_start + section_primitive_count > primitive_count
            or run_start + section_run_count > run_count
        ):
            raise ValueError("Compressed section arrays exceed typed ITEM bounds")

        def vertex(identity):
            if identity < section_local_count:
                index = local_start + identity
                if index >= local_count:
                    raise ValueError("Local packed vertex index outside ITEM")
                packed = unpack("<I", local_vertices + index * 4)[0]
                components = [packed & 0x7FF, (packed >> 11) & 0x7FF, packed >> 22]
                point = [
                    float32(float32(float32(components[i]) * scale[i]) + offset[i])
                    for i in range(3)
                ]
            else:
                index = shared_start - section_local_count + identity
                if not 0 <= index < shared_index_count:
                    raise ValueError("Shared packed vertex index outside ITEM")
                shared_id = unpack("<H", shared_indices + index * 2)[0]
                packed_at = shared_vertices + (shared_page << 19) + shared_id * 8
                if (
                    not shared_vertices
                    <= packed_at
                    < shared_vertices + shared_count * 8
                ):
                    raise ValueError("Shared vertex page outside ITEM")
                packed = unpack("<Q", packed_at)[0]
                components = [
                    packed & 0x1FFFFF,
                    (packed >> 21) & 0x1FFFFF,
                    packed >> 42,
                ]
                point = [
                    float32(
                        float32(float32(components[i]) * shared_scale[i])
                        + domain_min[i]
                    )
                    for i in range(3)
                ]
            point = [float32(x * (32 if geometry is not None else 1)) for x in point]
            if not all(math.isfinite(x) for x in point):
                raise ValueError("Nonfinite decoded vertex")
            return point

        for primitive_id in range(section_primitive_count):
            raw = unpack("<4B", primitives + (primitive_start + primitive_id) * 4)
            if raw == (0xDE, 0xAD, 0xDE, 0xAD):
                counts["dead_records"] += 1
                continue
            if raw[1] == raw[3]:
                counts[f"custom_type_{raw[2]}"] += 1
                continue
            corners = [vertex(identity) for identity in raw]
            minimum_world_z = min(minimum_world_z, min(p[2] for p in corners))
            kind = "triangle" if raw[2] == raw[3] else "quad"
            counts[kind] += 1
            if not overlaps_region(corners):
                continue
            tag = None
            for run_id in range(section_run_count):
                value, start, length = unpack("<HBB", runs + (run_start + run_id) * 4)
                if start <= primitive_id < start + length:
                    tag = value
                    break
            metadata = dict(
                section=section_id,
                primitive=primitive_id,
                shape_tag=tag,
                source_kind=kind,
                flags_provisional=True,
                native_primitive_indices=list(raw),
                native_quad_merge_mask=unpack("<B", internals + 92)[0],
            )
            if kind == "triangle":
                triangles.append(
                    dict(corners=corners[:3], flags=1, provenance=metadata)
                )
            else:
                # Target hknpTriangleShape raycast RVA 0x1f21ac0 tests
                # (0,1,2), then (0,2,3). Its native geometry export at
                # RVA 0x1f215f0 emits the same two triangles, including
                # nonplanar quads. Preserve this actual target diagonal.
                metadata["native_quad_surface_proof"] = (
                    "data/gulag-native-quad-surface-proof.json"
                )
                for indices in ((0, 1, 2), (0, 2, 3)):
                    provenance = dict(metadata, native_quad_triangle=list(indices))
                    triangles.append(dict(
                        corners=[corners[index] for index in indices],
                        flags=1,
                        provenance=provenance,
                    ))
    return dict(
        schema=1,
        coordinate_space="world" if geometry is not None else "local_havok",
        collision_complete=False,
        provenance=dict(
            blob_sha256=hashlib.sha256(data).hexdigest(),
            original_base=hex(original_base),
            native_evidence=EVIDENCE,
            contents_filter_verified=False,
            coordinate_scale=32 if geometry is not None else 1,
            region_half_extents=[2048, 2048, 512],
        ),
        section_count=section_count,
        primitive_count=primitive_count,
        counts=dict(counts),
        minimum_decoded_world_z=(
            None if minimum_world_z == math.inf else minimum_world_z
        ),
        triangles=triangles,
        unresolved_quads=unresolved,
        custom_instances_handled_by="extract-gulag-collision.py",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob", type=Path, required=True)
    parser.add_argument(
        "--original-base", type=lambda value: int(value, 0), required=True
    )
    parser.add_argument("--geometry", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("D:/mw124/mw120rproxy/iw8-zonetool/tools/audit_world_shape.py"),
    )
    args = parser.parse_args()
    specification = importlib.util.spec_from_file_location(
        "native_tag_schema", args.schema
    )
    schema = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(schema)
    result = decode(
        args.blob.read_bytes(),
        args.original_base,
        json.loads(args.geometry.read_bytes()),
        schema,
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: value
                for key, value in result.items()
                if key not in ("triangles", "unresolved_quads")
            },
            indent=2,
        )
    )
    print(
        f"Regional triangles: {len(result['triangles'])}; unresolved quads: {len(result['unresolved_quads'])}"
    )


if __name__ == "__main__":
    main()
