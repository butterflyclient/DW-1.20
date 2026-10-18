"""Decode actual serialized Replay PhysicsAsset TAG0 shapes without loading game code.

TAG0 pointer fields contain ITEM indexes. They are resolved through the type
table, never treated as fixed native pointers. Output retains unresolved rounded
radii and unsupported shapes as explicit coverage blockers. Quad surfaces follow
the verified target raycast/export triangle diagonal.
"""

import argparse
import hashlib
import importlib.util
import json
import math
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TAG_SCHEMA = Path("D:/mw124/mw120rproxy/iw8-zonetool/tools/audit_world_shape.py")
COMPENDIUM = Path(
    "D:/mw124/mw120rproxy/iw8-zonetool/src/zonetool/iw8/replay_type_compendium.inc"
)


def load_module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def identity_matrix():
    return [[float(i == j) for j in range(4)] for i in range(4)]


def multiply(a, b):
    return [
        [sum(a[i][k] * b[k][j] for k in range(4)) for j in range(4)] for i in range(4)
    ]


def transform(point, matrix):
    return [
        sum(matrix[i][j] * point[j] for j in range(3)) + matrix[i][3] for i in range(3)
    ]


def quaternion_matrix(quaternion, position):
    x, y, z, w = quaternion
    length = math.sqrt(sum(value * value for value in quaternion))
    if abs(length - 1) > 0.01:
        raise ValueError("Serialized body quaternion is not unit length")
    return [
        [
            1 - 2 * (y * y + z * z),
            2 * (x * y - z * w),
            2 * (x * z + y * w),
            position[0],
        ],
        [
            2 * (x * y + z * w),
            1 - 2 * (x * x + z * z),
            2 * (y * z - x * w),
            position[1],
        ],
        [
            2 * (x * z - y * w),
            2 * (y * z + x * w),
            1 - 2 * (x * x + y * y),
            position[2],
        ],
        [0, 0, 0, 1],
    ]


class TagReader:
    def __init__(self, data):
        self.data = data
        self.schema = load_module("replay_tag_schema", TAG_SCHEMA)
        root = (0, len(data))
        data_section = self.schema.section(data, root, b"DATA")
        self.payload = data_section[0] + 8
        self.end = sum(data_section)
        try:
            type_section = self.schema.section(data, root, b"TYPE")
        except ValueError:
            reference = self.schema.section(data, root, b"TCRF")
            if (
                struct.unpack_from("<Q", data, reference[0] + 8)[0]
                != 0xC16B2E49324C3540
            ):
                raise ValueError("Unknown Replay type compendium signature")
            pairs = re.findall(r'\{"([^\"]+)", (\d+)\}', COMPENDIUM.read_text())
            self.types = ["NULL"] * (1 + max(int(index) for _, index in pairs))
            for name, index in pairs:
                self.types[int(index)] = name
        else:
            self.types = self.schema.type_identities(data, type_section)
        index = self.schema.section(
            data, self.schema.section(data, root, b"INDX"), b"ITEM"
        )
        self.items = [
            struct.unpack_from("<III", data, at)
            for at in range(index[0] + 8, sum(index), 12)
        ]

    def unpack(self, fmt, offset):
        if offset < self.payload or offset + struct.calcsize(fmt) > self.end:
            raise ValueError("Serialized shape read exceeds DATA")
        return struct.unpack_from(fmt, self.data, offset)

    def item(self, identity, stride=1):
        if not 0 < identity < len(self.items):
            raise ValueError(f"Invalid TAG0 ITEM index {identity}")
        flags, offset, count = self.items[identity]
        if not flags & 0xFFFFFF or offset + count * stride > self.end - self.payload:
            raise ValueError(f"TAG0 ITEM {identity} exceeds DATA")
        return self.payload + offset, count, self.types[flags & 0xFFFFFF]

    def pointer(self, offset, stride=1):
        identity = self.unpack("<Q", offset)[0]
        return self.item(identity, stride) if identity else (0, 0, "NULL")

    def compressed(self, shape):
        """Relocate only verified mesh pointer fields in a private derived copy."""
        copied = bytearray(self.data)
        virtual_base = 0x100000000
        internals, _, name = self.pointer(shape + 72, 264)
        if name != "hknpCompressedMeshShapeData":
            raise ValueError(f"Unexpected compressed mesh internals: {name}")
        struct.pack_into("<Q", copied, shape + 72, virtual_base + internals)
        for offset, stride in (
            (96, 96),
            (112, 4),
            (128, 2),
            (144, 4),
            (160, 8),
            (176, 4),
        ):
            pointer, count, _ = self.pointer(internals + offset, stride)
            stored_count = self.unpack("<I", internals + offset + 8)[0]
            if stored_count not in (0, count):
                raise ValueError("Serialized hkArray count disagrees with typed ITEM")
            # The compact tagfile leaves runtime hkArray counts zero; the typed
            # ITEM extent supplies that count during native pointer fixup.
            struct.pack_into("<I", copied, internals + offset + 8, count)
            struct.pack_into(
                "<Q",
                copied,
                internals + offset,
                virtual_base + pointer if pointer else 0,
            )
        decoder = load_module(
            "native_compressed_decoder", ROOT / "decode-gulag-compressed-triangles.py"
        )
        capture = dict(
            image=bytes(copied),
            original_base=virtual_base,
            native_shape_offset=shape,
            convex_radius=self.unpack("<f", shape + 32)[0],
        )
        return decoder.decode_mesh_image(capture)


def asset_bodies(reader):
    roots = [
        reader.item(index)
        for index in range(1, len(reader.items))
        if reader.items[index][0] & 0xFFFFFF
        and reader.types[reader.items[index][0] & 0xFFFFFF] == "HavokPhysicsAsset"
    ]
    if len(roots) != 1:
        raise ValueError(f"Expected one HavokPhysicsAsset root, found {len(roots)}")
    root = roots[0][0]
    system, _, system_type = reader.pointer(root + 8, 104)
    if system_type != "hknpPhysicsSystemData":
        raise ValueError(f"Unexpected native physics system type {system_type}")
    bodies, body_count, body_type = reader.pointer(system + 56, 192)
    if body_type not in (
        "hknpBodyCinfoWithAttachment",
        "hknpPhysicsSystemData::bodyCinfoWithAttachment",
    ):
        raise ValueError(f"Unexpected native body array type {body_type}")
    return bodies, body_count


def decode_asset(data, world_root=False, world_shape_item=1):
    reader = TagReader(data)
    if world_root:
        shape, _, shape_type = reader.item(world_shape_item)
        if shape_type not in ("hknpCompressedMeshShape", "hknpCompoundShape"):
            raise ValueError(f"Unexpected world collision root {shape_type}")
        bodies, body_count = 0, 1
    else:
        bodies, body_count = asset_bodies(reader)
    hulls, triangles, quads, blockers, body_metadata = [], [], [], [], []

    def walk(shape, shape_type, matrix, body, chain):
        if len(chain) >= 32 or shape in chain:
            raise ValueError("Shape recursion depth/cycle")
        chain = chain + [shape]
        radius = reader.unpack("<f", shape + 32)[0]
        if not math.isfinite(radius) or radius < 0:
            raise ValueError("Invalid native convex radius")
        metadata = dict(
            body=body,
            type=shape_type,
            serialized_offset=shape,
            native_radius_havok=radius,
            shape_chain=chain,
        )
        if shape_type in ("hknpBoxShape", "hknpConvexPolytopeShape"):
            vertex_item = reader.unpack("<I", shape + 58)[0]
            vertices, count, vertex_type = reader.item(vertex_item, 16)
            if vertex_type not in ("hkVector4f", "hkVector4"):
                raise ValueError(f"Unexpected convex support vertex ITEM {vertex_type}")
            if not 4 <= count <= 256:
                raise ValueError("Convex support vertex count outside verified bound")
            points = [
                transform(reader.unpack("<3f", vertices + index * 16), matrix)
                for index in range(count)
            ]
            columns = [[matrix[row][column] for row in range(3)] for column in range(3)]
            orthogonal = all(
                abs(sum(columns[a][i] * columns[b][i] for i in range(3))) < 0.0001
                for a in range(3)
                for b in range(a)
            )
            maximum_scale = max(
                math.sqrt(sum(value * value for value in column)) for column in columns
            )
            hulls.append(
                dict(
                    points=points,
                    flags=1,
                    provenance=metadata,
                    native_margin_havok=radius * maximum_scale if orthogonal else None,
                    margin_representation="conservative shifted support-plane envelope",
                )
            )
            if radius:
                if not orthogonal:
                    blockers.append(
                        dict(
                            reason="Nonorthogonal native margin transform requires verification",
                            **metadata,
                        )
                    )
        elif shape_type in ("hknpScaledConvexShape", "hknpScaledConvexShapeBase"):
            child, _, child_type = reader.pointer(shape + 56)
            scale = reader.unpack("<3f", shape + 64)
            translation = reader.unpack("<3f", shape + 80)
            local = identity_matrix()
            for axis in range(3):
                local[axis][axis] = scale[axis]
                local[axis][3] = translation[axis]
            walk(child, child_type, multiply(matrix, local), body, chain)
            if radius:
                blockers.append(
                    dict(
                        reason="Scaled wrapper native radius requires separate verification",
                        **metadata,
                    )
                )
        elif shape_type in ("hknpCompoundShape", "hknpCompressedMeshShape"):
            if shape_type == "hknpCompressedMeshShape":
                mesh = reader.compressed(shape)
                for triangle in mesh["triangles"]:
                    triangle["corners"] = [
                        transform(point, matrix) for point in triangle["corners"]
                    ]
                    triangle["provenance"].update(metadata)
                    triangles.append(triangle)
                for quad in mesh["unresolved_quads"]:
                    quad["corners"] = [
                        transform(point, matrix) for point in quad["corners"]
                    ]
                    quad["provenance"].update(metadata)
                    quads.append(quad)
                child_field = 112
                if radius:
                    blockers.append(
                        dict(
                            reason="Compressed mesh native convex radius not represented",
                            **metadata,
                        )
                    )
            else:
                child_field = 72
            children, count, child_type = reader.pointer(shape + child_field, 112)
            if count and child_type not in (
                "hknpShapeInstance",
                "hkFreeListArrayElement<hknpShapeInstance>",
            ):
                raise ValueError(f"Unexpected compound children: {child_type}")
            for index in range(count):
                instance = children + index * 112
                child, _, child_type = reader.pointer(instance + 80)
                if not child:
                    continue
                values = reader.unpack("<16f", instance)
                scale = reader.unpack("<3f", instance + 64)
                local = identity_matrix()
                for row in range(3):
                    for column in range(3):
                        local[row][column] = values[column * 4 + row] * scale[column]
                    local[row][3] = values[12 + row]
                walk(child, child_type, multiply(matrix, local), body, chain)
        else:
            blockers.append(dict(reason="Unsupported serialized shape", **metadata))

    for body in range(body_count):
        if world_root:
            shape, _, shape_type = reader.item(world_shape_item)
            position = (0.0, 0.0, 0.0)
            orientation = (0.0, 0.0, 0.0, 1.0)
            contents = 0xFFFFFFFF
        else:
            offset = bodies + body * 192
            shape, _, shape_type = reader.pointer(offset)
            position = reader.unpack("<3f", offset + 48)
            orientation = reader.unpack("<4f", offset + 64)
            contents = reader.unpack("<I", offset + 16)[0]
        body_metadata.append(
            dict(
                body=body,
                contents=f"0x{contents:08x}",
                position=position,
                orientation=orientation,
                shape_type=shape_type,
            )
        )
        walk(shape, shape_type, quaternion_matrix(orientation, position), body, [])
    return dict(
        schema=1,
        coordinate_space="local_havok",
        collision_complete=False,
        provenance=dict(
            blob_sha256=hashlib.sha256(data).hexdigest(),
            serialized_pointer_mode="TAG0 ITEM indexes",
            contents_filter_verified=False,
            synthetic=False,
        ),
        hulls=hulls,
        triangles=triangles,
        unresolved_quads=quads,
        blockers=blockers,
        bodies=body_metadata,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.manifest:
        args.output.mkdir(parents=True, exist_ok=True)
        receipt = dict(schema=1, collision_complete=False, decoded=[], errors=[])
        for item in json.loads(args.manifest.read_bytes())["items"]:
            try:
                blob = Path(item["blob"]).read_bytes()
                if hashlib.sha256(blob).hexdigest() != item["sha256"]:
                    raise ValueError("Exported blob hash mismatch")
                result = decode_asset(blob)
                destination = args.output / (item["name"] + ".geometry.json")
                result["provenance"]["asset_export"] = item["asset_export"]
                result["provenance"]["source_zone"] = item["source_zone"]
                result["provenance"]["asset_name"] = item["name"]
                destination.write_text(json.dumps(result, indent=2) + "\n")
                receipt["decoded"].append(
                    dict(
                        name=item["name"],
                        output=str(destination),
                        hulls=len(result["hulls"]),
                        triangles=len(result["triangles"]),
                        quads=len(result["unresolved_quads"]),
                        blockers=len(result["blockers"]),
                    )
                )
            except (ValueError, KeyError, IndexError, struct.error) as error:
                receipt["errors"].append(dict(name=item["name"], error=str(error)))
        (args.output / "manifest.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, indent=2))
        return
    if not args.blob:
        parser.error("--blob or --manifest is required")
    result = decode_asset(args.blob.read_bytes())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            dict(
                hulls=len(result["hulls"]),
                triangles=len(result["triangles"]),
                unresolved_quads=len(result["unresolved_quads"]),
                blockers=len(result["blockers"]),
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
