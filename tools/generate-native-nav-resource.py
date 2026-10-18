"""Generate only a Replay BFX navigation resource from supplied world collision JSON.

No native process access, asset registration, package modification or deployment.
Use --validate for independent structural checking of a stock/generated resource.
"""

import argparse
import hashlib
import json
import math
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "native-nav-resource"
BUILD = ROOT / "build" / "native-nav-resource"


def validate_resource(data):
    def u(at):
        return struct.unpack_from("<I", data, at)[0]

    def fail(message):
        raise ValueError(message)

    if len(data) < 416 or len(data) % 4:
        fail("Resource size/alignment")
    if (u(0), u(4), u(8), u(16), u(20)) != (0, 2, len(data) - 24, 0, 0x1000001):
        fail("Resource header differs from unused Replay resource")
    if sum(
        struct.unpack("<" + "I" * ((len(data) - 24) // 4), data[24:])
    ) & 0xFFFFFFFF != u(12):
        fail("Resource checksum")
    if (u(24), u(28), u(32), u(36), u(40), u(44)) != (
        0x10000,
        len(data) - 36,
        1,
        0,
        0x2E,
        1,
    ):
        fail("Section/image header")
    base = 48
    graphSize = u(base + 32)
    areaBytes = u(base + 8)
    kdBytes = u(base + 12)
    if graphSize != len(data) - base or 340 + areaBytes + kdBytes != graphSize:
        fail("Graph lengths")
    if (
        u(base),
        u(base + 4),
        u(base + 16),
        u(base + 20),
        u(base + 24),
        u(base + 28),
        u(base + 84),
    ) != (0x2E, 0, 0, 0, 56, 0, 2):
        fail("Unsupported graph/link layout")
    bounds = struct.unpack_from("<6f", data, base + 60)
    if not all(math.isfinite(v) for v in bounds) or any(
        bounds[i] > bounds[i + 3] for i in range(3)
    ):
        fail("Graph bounds")
    areas = {}
    at = 340
    while at < 340 + areaBytes:
        n = u(base + at + 56) & 127
        if n < 3 or base + at + 72 + 32 * n > base + 340 + areaBytes:
            fail("Area edge count/length")
        center = struct.unpack_from("<3f", data, base + at + 32)
        radius = struct.unpack_from("<f", data, base + at + 44)[0]
        vertices = []
        neighbors = []
        for e in range(n):
            off = base + at + 72 + 32 * e
            neighbors.append(struct.unpack_from("<Q", data, off)[0])
            vertices.append(struct.unpack_from("<3f", data, off + 8))
        if not all(math.isfinite(x) for v in vertices for x in v):
            fail("Nonfinite vertex")
        if (
            not all(math.isfinite(x) for x in center)
            or not math.isfinite(radius)
            or radius < 0
        ):
            fail("Invalid area sphere")
        for vertex in vertices:
            if math.dist(vertex, center) > radius + 0.1:
                fail("Area sphere does not enclose vertex")
            if any(
                vertex[i] < bounds[i] - 0.1 or vertex[i] > bounds[i + 3] + 0.1
                for i in range(3)
            ):
                fail("Vertex outside graph bounds")
        cross = []
        for i in range(n):
            a, b, c = vertices[i], vertices[(i + 1) % n], vertices[(i + 2) % n]
            cross.append((b[0] - a[0]) * (c[1] - b[1]) - (b[1] - a[1]) * (c[0] - b[0]))
        if min(cross) < -0.01 or max(cross) <= 0:
            fail("Nonconvex/non-CCW floor polygon")
        areas[at] = (vertices, neighbors)
        at += 72 + 32 * n
    if at != 340 + areaBytes or not areas:
        fail("Area array coverage")
    portalSides = 0
    for offset, (vertices, neighbors) in areas.items():
        for e, neighbor in enumerate(neighbors):
            if not neighbor:
                continue
            portalSides += 1
            if neighbor not in areas:
                fail("Portal points outside area array")
            other, back = areas[neighbor]
            a, b = vertices[e], vertices[(e + 1) % len(vertices)]
            if not any(
                x == offset and other[j] == b and other[(j + 1) % len(other)] == a
                for j, x in enumerate(back)
            ):
                fail("Nonreciprocal portal or mismatched shared vertices")
    kdStart = base + 340 + areaBytes
    kdEnd = kdStart + kdBytes
    if kdBytes < 32 or u(kdStart + 24) != kdBytes - 28:
        fail("KD lengths")
    stack = [kdStart + 28]
    seen = set()
    leaves = []
    ranges = []
    while stack:
        node = stack.pop()
        if node in seen or node < kdStart + 28 or node + 4 > kdEnd:
            fail("KD cycle/range")
        seen.add(node)
        word = u(node)
        if word & 0x80000000:
            leaf = word & 0x7FFFFFFF
            if leaf not in areas:
                fail("KD leaf not an area")
            leaves.append(leaf)
            ranges.append((node, node + 4))
        else:
            if (word >> 28) & 7 > 2 or node + 12 > kdEnd:
                fail("KD axis/range")
            right = node + (word & 0xFFFFFFF)
            if right <= node + 12:
                fail("KD right child")
            if not all(
                math.isfinite(x) for x in struct.unpack_from("<2f", data, node + 4)
            ):
                fail("KD split nonfinite")
            stack.extend([node + 12, right])
            ranges.append((node, node + 12))
    if len(leaves) != len(areas) or set(leaves) != set(areas):
        fail("KD area coverage")
    ranges.sort()
    cursor = kdStart + 28
    for begin, end in ranges:
        if begin != cursor:
            fail("KD unreachable/overlapping bytes")
        cursor = end
    if cursor != kdEnd:
        fail("KD trailing bytes")
    return dict(
        resource_bytes=len(data),
        resource_sha256=hashlib.sha256(data).hexdigest(),
        checksum=f"{u(12):08x}",
        resource_version=2,
        graph_version=46,
        layer=0,
        areas=len(areas),
        edges=sum(len(x[0]) for x in areas.values()),
        portal_sides=portalSides,
        kd_nodes=len(seen),
        bounds=list(bounds),
        structural_validation=True,
        live_native_load_test=False,
        live_gulag_navigation_test=False,
    )


def geometry_binary(document, allow_incomplete_audit=False):
    if not allow_incomplete_audit and (
        document.get("collision_complete") is False
        or document.get("provenance", {}).get("collision_complete") is False
    ):
        raise ValueError(
            "Collision coverage is explicitly incomplete; finish its audit before generating"
        )
    if document.get("schema") != 1 or document.get("coordinate_space") != "world":
        raise ValueError("Expected schema 1 and coordinate_space world")
    if not isinstance(document.get("provenance"), dict) or not document["provenance"]:
        raise ValueError("Geometry provenance is required")
    hulls = document.get("hulls", [])
    triangles = document.get("triangles", [])
    spawns = document.get("spawns", [])
    nodes = document.get("pathNodes", [])
    if (
        len(hulls) > 100000
        or len(triangles) > 2000000
        or len(spawns) > 10000
        or len(nodes) > 10000
    ):
        raise ValueError("Geometry count bound exceeded")
    if not hulls and not triangles:
        raise ValueError("No collision geometry")
    if not spawns and not nodes:
        raise ValueError("No reachability seeds")
    out = bytearray(
        struct.pack(
            "<5I", 0x3247564E, len(hulls), len(triangles), len(spawns), len(nodes)
        )
    )
    pointCount = 0

    def point(p):
        nonlocal pointCount
        if (
            not isinstance(p, (list, tuple))
            or len(p) != 3
            or not all(
                isinstance(x, (int, float)) and math.isfinite(x) and abs(x) <= 10000000
                for x in p
            )
        ):
            raise ValueError("Invalid coordinate")
        pointCount += 1
        if pointCount > 6000000:
            raise ValueError("Point budget exceeded")
        return struct.pack("<3f", *p)

    for h in hulls:
        vertices = h["points"]
        flags = h["flags"]
        if not 4 <= len(vertices) <= 4096 or flags not in (1, 2, 3):
            raise ValueError("Hull vertices/flags")
        margin = h.get("native_margin_world", 0.0)
        if (
            not isinstance(margin, (float, int))
            or not math.isfinite(margin)
            or not 0 <= margin <= 128
        ):
            raise ValueError("Invalid verified native convex margin")
        out += struct.pack("<IIf", flags, len(vertices), margin)
        for p in vertices:
            out += point(p)
    for t in triangles:
        if len(t["corners"]) != 3 or t["flags"] not in (1, 2, 3):
            raise ValueError("Triangle corners/flags")
        out += struct.pack("<I", t["flags"])
        for p in t["corners"]:
            out += point(p)
    for p in spawns + nodes:
        out += point(p)
    return out


def build_backend(compiler):
    import time

    BUILD.mkdir(parents=True, exist_ok=True)
    files = [
        SOURCE / "main.cpp",
        SOURCE / "replay_navigation.cpp",
        SOURCE / "replay_navigation.h",
        SOURCE / "nav_resource_log.h",
        SOURCE / "nav_resource_audit.inl",
        SOURCE / "nav_resource_surface.inl",
    ]
    provenance = json.loads((SOURCE / "source-provenance.json").read_bytes())
    if hashlib.sha256(files[1].read_bytes()).hexdigest() != provenance["output_sha256"]:
        raise ValueError(
            "Vendored generator source differs from its provenance receipt"
        )
    key = hashlib.sha256(
        b"".join(p.read_bytes() for p in files) + str(compiler).encode()
    ).hexdigest()
    exe = BUILD / ("native-nav-resource-" + key[:16] + ".exe")
    marker = exe.with_suffix(".build-key.txt")
    lock = exe.with_suffix(".build-lock")
    deadline = time.monotonic() + 30
    while True:
        if exe.exists() and marker.exists() and marker.read_text() == key:
            return exe
        try:
            lock.mkdir()
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise RuntimeError("Timed out waiting for the standalone compiler lock")
            time.sleep(0.1)
    try:
        subprocess.run(
            [
                str(compiler),
                "-std=c++20",
                "-O2",
                "-DNOMINMAX",
                str(files[0]),
                str(files[1]),
                "-o",
                str(exe),
            ],
            check=True,
        )
        marker.write_text(key)
    finally:
        lock.rmdir()
    return exe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--audit-source", action="store_true")
    parser.add_argument("--conservative-surface", action="store_true")
    parser.add_argument(
        "--research-candidate",
        action="store_true",
        help="Allow an incomplete source for offline diagnostics; production packaging remains blocked",
    )
    parser.add_argument(
        "--compiler", type=Path, default=Path(r"C:\Program Files\LLVM\bin\clang++.exe")
    )
    args = parser.parse_args()
    if args.validate:
        result = validate_resource(args.validate.read_bytes())
        result["validation_source"] = str(args.validate.resolve())
    else:
        if not args.input or (not args.output and not args.audit_source):
            parser.error("--input and --output required for generation")
        raw = args.input.read_bytes()
        if len(raw) > 256 * 1024 * 1024:
            raise ValueError("Geometry JSON exceeds size bound")
        document = json.loads(raw)
        binary = geometry_binary(
            document,
            allow_incomplete_audit=args.audit_source or args.research_candidate,
        )
        exe = build_backend(args.compiler)
        with tempfile.TemporaryDirectory(prefix="native-nav-", dir=BUILD) as directory:
            interchange = Path(directory) / "input.geom"
            resource = Path(directory) / "result.bfx"
            audit = Path(directory) / "audit.json"
            interchange.write_bytes(binary)
            if args.audit_source:
                subprocess.run(
                    [str(exe), str(interchange), "--audit-source", str(audit)],
                    check=True,
                    timeout=600,
                )
                result = dict(
                    source_collision_audit=json.loads(audit.read_bytes()),
                    collision_complete=document.get("collision_complete", False),
                    input_sha256=hashlib.sha256(raw).hexdigest(),
                    input=str(args.input.resolve()),
                )
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(result, indent=2) + "\n")
                print(json.dumps(result, indent=2))
                return
            command = [str(exe), str(interchange), str(resource), str(audit)]
            if args.conservative_surface:
                command.append("--conservative-surface")
            subprocess.run(
                command,
                check=True,
                timeout=600,
            )
            data = resource.read_bytes()
            result = validate_resource(data)
            result["collision_fidelity"] = json.loads(audit.read_bytes())
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(data)
        result.update(
            input=str(args.input.resolve()),
            input_sha256=hashlib.sha256(raw).hexdigest(),
            output=str(args.output.resolve()),
            geometry_provenance=document["provenance"],
            collision_complete=document.get("collision_complete", False),
            research_candidate=args.research_candidate,
            conservative_surface=args.conservative_surface,
            generator_provenance=json.loads(
                (SOURCE / "source-provenance.json").read_bytes()
            ),
            collision_hulls=len(document.get("hulls", [])),
            collision_triangles=len(document.get("triangles", [])),
            spawn_seeds=len(document.get("spawns", [])),
            pathnode_seeds=len(document.get("pathNodes", [])),
            backend_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
            backend_build_key=exe.with_suffix(".build-key.txt").read_text(),
            compiler=str(args.compiler.resolve()),
        )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
