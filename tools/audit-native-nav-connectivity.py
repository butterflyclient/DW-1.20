"""Verify all authored arena spawns share a reciprocal native BFX component."""

import argparse
import hashlib
import json
import struct
from pathlib import Path


def audit(resource, geometry):
    base = 48
    end = 340 + struct.unpack_from("<I", resource, base + 8)[0]
    areas = {}
    at = 340
    while at < end:
        count = struct.unpack_from("<I", resource, base + at + 56)[0] & 127
        vertices = [struct.unpack_from("<3f", resource, base + at + 80 + edge * 32)
                    for edge in range(count)]
        neighbors = [struct.unpack_from("<Q", resource, base + at + 72 + edge * 32)[0]
                     for edge in range(count)]
        areas[at] = (vertices, [neighbor for neighbor in neighbors if neighbor])
        at += 72 + count * 32
    components = {}
    sizes = []
    for area in areas:
        if area in components:
            continue
        component = len(sizes)
        queue = [area]
        components[area] = component
        for current in queue:
            for neighbor in areas[current][1]:
                if neighbor not in components:
                    components[neighbor] = component
                    queue.append(neighbor)
        sizes.append(len(queue))
    matches = []
    for spawn in geometry["spawns"]:
        candidates = []
        for area, (vertices, _) in areas.items():
            inside = all(
                (b[0] - a[0]) * (spawn[1] - a[1]) -
                (b[1] - a[1]) * (spawn[0] - a[0]) >= -0.01
                for a, b in zip(vertices, vertices[1:] + vertices[:1])
            )
            if inside and abs(sum(point[2] for point in vertices) / len(vertices) - spawn[2]) <= 2:
                candidates.append(area)
        matches.append(dict(spawn=spawn, areas=candidates,
                            components=sorted({components[area] for area in candidates})))
    common = set(matches[0]["components"]) if matches else set()
    for match in matches:
        common.intersection_update(match["components"])
    return dict(
        resource_sha256=hashlib.sha256(resource).hexdigest(),
        spawn_count=len(matches), spawn_matches=matches,
        component_sizes=sizes, shared_spawn_components=sorted(common),
        all_spawns_mutually_connected=bool(common),
        directed_spawn_pairs_reachable=len(matches) * (len(matches) - 1) if common else 0,
        native_runtime_path_query=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resource", type=Path, required=True)
    parser.add_argument("--geometry", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.resource.read_bytes(), json.loads(args.geometry.read_bytes()))
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(result["all_spawns_mutually_connected"], result["component_sizes"])
    if not result["all_spawns_mutually_connected"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
