"""Bounded, read-only Replay Gulag collision research capture.

Emits actual world-space convex support points, never fabricated geometry.
The result deliberately remains incomplete until compressed mesh triangles and
static-model physics coverage are independently established.
"""
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import struct


class Reader:
    def __init__(self, pid, budget):
        self.kernel = C.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.restype = C.c_void_p
        self.kernel.ReadProcessMemory.argtypes = [C.c_void_p, C.c_void_p,
            C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
        self.kernel.CloseHandle.argtypes = [C.c_void_p]
        self.handle = self.kernel.OpenProcess(0x410, False, pid)
        if not self.handle:
            raise OSError(C.get_last_error())
        self.bytes = 0
        self.budget = budget
        ps = C.WinDLL("psapi")
        ps.EnumProcessModulesEx.argtypes = [C.c_void_p, C.c_void_p,
            C.c_ulong, C.c_void_p, C.c_ulong]
        modules = (C.c_void_p * 2048)()
        needed = C.c_ulong()
        if not ps.EnumProcessModulesEx(self.handle, modules, C.sizeof(modules),
                                      C.byref(needed), 3):
            raise OSError(C.get_last_error())
        self.base = modules[0]
        ps.GetModuleFileNameExW.argtypes = [C.c_void_p, C.c_void_p, C.c_wchar_p, C.c_ulong]
        filename = C.create_unicode_buffer(32768)
        if not ps.GetModuleFileNameExW(self.handle, modules[0], filename, len(filename)):
            raise OSError(C.get_last_error())
        self.executable = Path(filename.value)

    def read(self, address, size):
        if not address or size < 0 or self.bytes + size > self.budget:
            raise ValueError("invalid read or process-read budget exceeded")
        result = bytearray()
        for offset in range(0, size, 65536):
            count = min(65536, size - offset)
            buf = C.create_string_buffer(count)
            got = C.c_size_t()
            if not self.kernel.ReadProcessMemory(self.handle, address + offset,
                    buf, count, C.byref(got)) or got.value != count:
                raise OSError(C.get_last_error())
            result.extend(buf.raw)
            self.bytes += count
        return bytes(result)

    def u64(self, address):
        return struct.unpack("<Q", self.read(address, 8))[0]

    def close(self):
        self.kernel.CloseHandle(self.handle)


def transformed(points, matrix, scale):
    # Native hknpShapeInstance: column-major hkTransform plus xyz scale.
    return [[32.0 * (sum(p[j] * scale[j] * matrix[j * 4 + axis]
                           for j in range(3)) + matrix[12 + axis])
             for axis in range(3)] for p in points]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pid", required=True, type=int)
    ap.add_argument("--build-report", required=True, type=Path)
    ap.add_argument("--tag-schema", type=Path, default=Path(
        "D:/mw124/mw120rproxy/iw8-zonetool/tools/audit_world_shape.py"))
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--max-read-mib", type=int, default=48)
    args = ap.parse_args()
    report_bytes = args.build_report.read_bytes()
    build_report = json.loads(report_bytes)
    symbols = build_report["symbols"]
    spec = importlib.util.spec_from_file_location("verified_tag_schema", args.tag_schema)
    schema = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(schema)
    reader = Reader(args.pid, args.max_read_mib * 1024 * 1024)
    try:
        with reader.executable.open("rb") as stream:
            executable_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        if executable_hash != build_report["sha256"]:
            raise ValueError("live executable does not match the supplied compiled build report")
        allocator = reader.u64(reader.base + symbols["gl_1423FC130"] + 23 * 8)
        code = reader.read(allocator, 15)
        if code[:6] != bytes.fromhex("4863c1488d0d") or code[10:15] != bytes.fromhex("488b04c1c3"):
            raise ValueError("unrecognized native singleton clipMap allocator")
        table = allocator + 10 + struct.unpack_from("<i", code, 6)[0]
        clip = reader.u64(table + 23 * 8)
        root = reader.read(clip, 248)
        name = reader.read(struct.unpack_from("<Q", root)[0], 128).split(b"\0")[0].decode()
        if name != "maps/mp/mp_donetsk.d3dbsp":
            raise ValueError("current map is not the verified Verdansk target")
        # Capture canonical world metadata before the larger geometry reads.
        # The singleton allocator's pointer table is the native asset-pool
        # base table, including the four-entry NavMeshData pool (type 27).
        nav_pool = reader.u64(table + 27 * 8)
        canonical_nav = None
        for index in range(4):
            nav = reader.read(nav_pool + index * 168, 168)
            nav_name_ptr = struct.unpack_from("<Q", nav)[0]
            if not nav_name_ptr:
                continue
            nav_name = reader.read(nav_name_ptr, 128).split(b"\0")[0]
            if nav_name == name.encode():
                canonical_nav = {"asset": name, "version": struct.unpack_from("<I", nav, 8)[0],
                    "hasExposureData": struct.unpack_from("<I", nav, 12)[0],
                    "staticHalf": list(struct.unpack_from("<3f", nav, 144)),
                    "staticMid": list(struct.unpack_from("<3f", nav, 156)),
                    "resource_count": struct.unpack_from("<I", nav, 16)[0],
                    "read_only": True, "pid": args.pid,
                    "source_build_report_sha256": hashlib.sha256(report_bytes).hexdigest()}
                break
        if canonical_nav is None:
            raise ValueError("canonical NavMeshData metadata not found")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.with_suffix(".canonical-nav.json").write_text(json.dumps(canonical_nav, indent=2) + "\n")
        size = struct.unpack_from("<I", root, 184)[0]
        blob = struct.unpack_from("<Q", root, 192)[0]
        if not 32 <= size <= 32 * 1024 * 1024:
            raise ValueError("world TAG0 size outside research bound")
        data = bytearray(size)
        def fill(offset, count):
            if offset < 0 or count < 0 or offset + count > size:
                raise ValueError("TAG0 read exceeds original serialized blob")
            data[offset:offset + count] = reader.read(blob + offset, count)
        fill(0, 32)
        if data[4:8] != b"TAG0":
            raise ValueError("world collision is not a TAG0")
        sections = {}
        offset = 8
        while offset + 8 <= size and len(sections) < 32:
            fill(offset, 8)
            count = struct.unpack_from(">I", data, offset)[0] & 0x0fffffff
            if count < 8 or offset + count > size:
                raise ValueError("invalid TAG0 section extent")
            sections[bytes(data[offset + 4:offset + 8])] = (offset, count)
            offset += count
        for tag in (b"TYPE", b"INDX"):
            fill(*sections[tag])
        names = schema.type_identities(data, sections[b"TYPE"])
        item_section = schema.section(data, sections[b"INDX"], b"ITEM")
        items = [struct.unpack_from("<III", data, p)
                 for p in range(item_section[0] + 8, sum(item_section), 12)]
        payload = sections[b"DATA"][0] + 8
        lookup = {payload + off: (idx, typ, count)
                  for idx, (typ, off, count) in enumerate(items) if typ & 0xffffff}
        def reference(offset):
            return struct.unpack_from("<Q", data, offset)[0]
        def item(pointer, stride):
            off = pointer - blob
            idx, typ, count = lookup[off]
            fill(off, count * stride)
            return off, count, names[typ & 0xffffff], idx
        fill(payload, 144)
        array, _, _, _ = item(reference(payload), 8)
        shape, _, root_type, _ = item(reference(array), 128)
        if root_type not in ("hknpCompressedMeshShape", "hknpCompoundShape"):
            raise ValueError("unsupported world shape type")
        child_off = 112 if root_type == "hknpCompressedMeshShape" else 72
        children, child_count, _, _ = item(reference(shape + child_off), 112)
        if child_count > 100000:
            raise ValueError("instance count outside research bound")
        ents = reader.read(struct.unpack_from("<Q", root, 24)[0], 24)
        text_size = struct.unpack_from("<i", ents, 16)[0]
        if not 0 < text_size <= 16 * 1024 * 1024:
            raise ValueError("entity text outside research bound")
        text = reader.read(struct.unpack_from("<Q", ents, 8)[0], text_size).decode("utf8")
        markers = []
        for block in re.findall(r"\{[^{}]*\}", text):
            if not any(t in block for t in ('"fight_spawn"', '"gulag_center"')):
                continue
            fields = dict(re.findall(r'(?m)^\s*(\d+)\s+"([^"\r\n]*)"', block))
            if "709" not in fields:
                raise ValueError("Gulag marker has no original numeric origin field")
            pos = [float(v) for v in fields["709"].split()]
            if len(pos) != 3 or not all(math.isfinite(v) for v in pos):
                raise ValueError("invalid Gulag marker origin")
            markers.append({"position": pos, "original_fields": fields})
        seeds = [m["position"] for m in markers if m["original_fields"].get("845") == "fight_spawn"]
        if not seeds:
            raise ValueError("no authored Gulag fight spawn markers")
        hulls, captured, cache = [], [], {}
        for index in range(child_count):
            off = children + index * 112
            pointer = reference(off + 80)
            if not pointer:
                continue
            if pointer not in cache:
                so, _, typ, item_id = item(pointer, 96)
                if typ not in ("hknpBoxShape", "hknpConvexPolytopeShape"):
                    raise ValueError("unsupported convex child; extraction must remain fail-closed")
                count, relative = struct.unpack_from("<HH", data, so + 58)
                if not 4 <= count <= 256:
                    raise ValueError("native support vertex count outside verified bound")
                vertex_off = so + 58 + relative
                fill(vertex_off, count * 16)
                points = [struct.unpack_from("<3f", data, vertex_off + j * 16)
                          for j in range(count)]
                radius = struct.unpack_from("<f", data, so + 32)[0]
                cache[pointer] = points, radius, typ, item_id
            points, radius, typ, item_id = cache[pointer]
            matrix = struct.unpack_from("<16f", data, off)
            scale = struct.unpack_from("<3f", data, off + 64)
            world = transformed(points, matrix, scale)
            lo = [min(v[a] for v in world) for a in range(3)]
            hi = [max(v[a] for v in world) for a in range(3)]
            if hi[2] < -1700 or lo[2] > -900:
                continue
            if not any(all(lo[a] - 1200 <= s[a] <= hi[a] + 1200 for a in (0, 1)) for s in seeds):
                continue
            # Raw points retained only. Contents and rounded convex radius need
            # independent native filtering/clearance proof before generation.
            hulls.append({"points": world, "flags": 3})
            captured.append({"instance": index, "shape_item": item_id,
                "type": typ, "native_radius_world": radius * 32,
                "native_shape_tag": struct.unpack_from("<H", data, off + 88)[0],
                "bounds": [lo, hi], "transform": list(matrix), "scale": list(scale)})
        static_models = []
        list_count = struct.unpack_from("<I", root, 12)[0]
        list_pointer = struct.unpack_from("<Q", root, 16)[0]
        if list_count > 4096:
            raise ValueError("static collision model list count outside bound")
        lists = reader.read(list_pointer, list_count * 24) if list_count else b""
        for list_index in range(list_count):
            count = struct.unpack_from("<I", lists, list_index * 24)[0]
            pointer = struct.unpack_from("<Q", lists, list_index * 24 + 8)[0]
            if count > 100000:
                raise ValueError("static collision model count outside bound")
            models = reader.read(pointer, count * 40) if count else b""
            for model_index in range(count):
                offset = model_index * 40
                instance_count = struct.unpack_from("<I", models, offset + 24)[0]
                instance_pointer = struct.unpack_from("<Q", models, offset + 32)[0]
                if instance_count > 1000000:
                    raise ValueError("static collision instance count outside bound")
                instances = reader.read(instance_pointer, instance_count * 28) if instance_count else b""
                selected = []
                for ii in range(instance_count):
                    values = struct.unpack_from("<7f", instances, ii * 28)
                    if values[2] <= -900 and any(
                            abs(values[0] - s[0]) < 2400 and abs(values[1] - s[1]) < 2400
                            for s in seeds):
                        selected.append({"index": ii, "origin": list(values[:3]),
                            "angles": list(values[3:6]), "scale": values[6]})
                if selected:
                    physics = struct.unpack_from("<Q", models, offset + 8)[0]
                    asset_name = reader.read(reader.u64(physics), 256).split(b"\0")[0].decode() if physics else None
                    static_models.append({"list": list_index, "model": model_index,
                        "physics_asset": asset_name, "physics_asset_pointer": hex(physics),
                        "instances": selected})
        # Native q_StaticModels_AddCollisionTile stores the current resident
        # tile pointer at qword_14E2B3D80[tile]. Compressed instances contain
        # seven IEEE binary16 values; 139DEF0 decodes origin and angles via
        # 13DCEB0, and 139DEC0 decodes scale via FloatFromHalf (13DD040).
        tile_models = []
        compressed_bounds = [[math.inf] * 3, [-math.inf] * 3]
        compressed_samples = []
        tile_array = reader.read(reader.base + symbols["gl_14E2B3D80"], 1024 * 8)
        tiles_read = 0
        for tile_index, tile_pointer in enumerate(struct.unpack("<1024Q", tile_array)):
            if not tile_pointer:
                continue
            tiles_read += 1
            tile = reader.read(tile_pointer, 72)
            if struct.unpack_from("<I", tile, 8)[0] != tile_index:
                raise ValueError("resident tile index changed during capture")
            # StaticModels_InstantiateCollisionForCollisionTile passes tile+16
            # as the parent body's world translation. Child half origins are
            # tile-local, unlike the base-world TAG0 instance transforms.
            tile_origin = struct.unpack_from("<3f", tile, 16)
            models_pointer = struct.unpack_from("<Q", tile, 32)[0]
            if not models_pointer:
                continue
            model_list = reader.read(models_pointer, 32)
            count = struct.unpack_from("<I", model_list)[0]
            pointer = struct.unpack_from("<Q", model_list, 8)[0]
            if count > 100000:
                raise ValueError("compressed static model count outside bound")
            models = reader.read(pointer, count * 56) if count else b""
            for model_index in range(count):
                offset = model_index * 56
                instance_count = struct.unpack_from("<I", models, offset + 44)[0]
                instance_pointer = struct.unpack_from("<Q", models, offset + 48)[0]
                if instance_count > 1000000:
                    raise ValueError("compressed instance count outside bound")
                instances = reader.read(instance_pointer, instance_count * 14) if instance_count else b""
                selected = []
                for ii in range(instance_count):
                    local_values = struct.unpack_from("<7e", instances, ii * 14)
                    values = tuple(local_values[a] + tile_origin[a] for a in range(3)) + local_values[3:]
                    for axis in range(3):
                        compressed_bounds[0][axis] = min(compressed_bounds[0][axis], values[axis])
                        compressed_bounds[1][axis] = max(compressed_bounds[1][axis], values[axis])
                    if len(compressed_samples) < 8:
                        compressed_samples.append({"tile": tile_index, "values": list(values),
                            "raw": instances[ii * 14:ii * 14 + 14].hex()})
                    if values[2] <= -900 and any(
                            abs(values[0] - s[0]) < 2400 and abs(values[1] - s[1]) < 2400
                            for s in seeds):
                        selected.append({"index": ii, "origin": list(values[:3]),
                            "angles": list(values[3:6]), "scale": values[6]})
                if selected:
                    physics = struct.unpack_from("<Q", models, offset + 8)[0]
                    asset_name = reader.read(reader.u64(physics), 256).split(b"\0")[0].decode() if physics else None
                    tile_models.append({"tile": tile_index, "model": model_index,
                        "physics_asset": asset_name, "physics_asset_pointer": hex(physics),
                        "simulation_shape": hex(struct.unpack_from("<Q", models, offset + 24)[0]),
                        "detail_shape": hex(struct.unpack_from("<Q", models, offset + 32)[0]),
                        "instances": selected})
        output = {"schema": 1, "coordinate_space": "world", "collision_complete": False,
            "provenance": {"pid": args.pid, "read_only": True, "map": name,
                "build_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
                "executable_sha256": executable_hash,
                "tag_schema_sha256": hashlib.sha256(args.tag_schema.read_bytes()).hexdigest(),
                "bytes_read": reader.bytes, "root_type": root_type,
                "root_static_model_lists": list_count, "resident_static_tiles": tiles_read,
                "compressed_instance_value_bounds": compressed_bounds,
                "compressed_instance_samples": compressed_samples,
                "support_vertex_native_rva": "0x1e82c00",
                "limitations": ["Compressed root triangles not decoded",
                    "Separate static-model PhysicsAsset coverage not established",
                    "Native rounded convex radius retained in capture metadata, not expanded",
                    "Movement/sight flags conservatively set; original shape tags retained",
                    "Numeric marker origin field 709 retained for independent token verification"]},
            "hulls": hulls, "triangles": [], "spawns": seeds, "pathNodes": [],
            "markers": markers, "captured_instances": captured,
            "static_model_collision_candidates": static_models,
            "transient_static_model_candidates": tile_models}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2) + "\n")
        print(json.dumps({"output": str(args.output), "hulls": len(hulls),
            "spawns": len(seeds), "bytes_read": reader.bytes, "collision_complete": False}))
    finally:
        reader.close()


if __name__ == "__main__":
    main()
