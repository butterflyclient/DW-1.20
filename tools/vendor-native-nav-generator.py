"""Explicit read-only import of the owner's Replay generator geometry/serializer slice."""

import hashlib
import json
from pathlib import Path

SOURCE = Path(
    r"D:\mw124\mw120rproxy\iw8-zonetool\src\zonetool\iw8\replay_navigation.cpp"
)
TARGET = Path(__file__).resolve().parent / "native-nav-resource"


def main():
    original = SOURCE.read_bytes()
    source = original.decode("utf-8-sig")
    prefix = source[
        : source.index(
            "// ---------------------------------------------------------------------------\n// Path nodes."
        )
    ]
    body = source[
        source.index("Result Build(const Source &source)") : source.index(
            "    const float skyTop = scene.Bounds().hi[2] + 64.0f;"
        )
    ]
    body = body.replace(
        "Result Build(const Source &source)",
        "std::vector<std::uint8_t> BuildResource(const Source &source)",
    ).replace("    Result result;", "    std::vector<std::uint8_t> result;")
    # Preserve source algorithms verbatim; stop before unrelated PathData/TacGraph authoring.
    adapted = (
        prefix
        + '#include "nav_resource_surface.inl"\n'
        + "} // anonymous namespace\n\n"
        + body
        + '    Box graphBox;\n    return BuildNavGraph(mesh, graphBox);\n}\n} // iw8::navigation\n#include "nav_resource_audit.inl"\n'
    )
    adapted = adapted.replace(
        "    Mesh mesh = BuildMesh(grid);",
        "    if (source.conservativeSurface) ConstrainSurface(scene, source, grid);\n"
        "    Mesh mesh = BuildMesh(grid);",
    )
    adapted = adapted.replace(
        '#include "common/log.h"', '#include "nav_resource_log.h"'
    )
    adapted = adapted.replace(
        "            prim.planes = HullPlanes(hull.points);",
        "            prim.planes = HullPlanes(hull.points);\n"
        "            for (auto &plane : prim.planes) plane[3] += hull.nativeMargin;",
    )
    adapted = adapted.replace(
        "            prim.flags = hull.flags;",
        "            for (unsigned axis = 0; axis < 3; ++axis) {\n"
        "                prim.box.lo[axis] -= hull.nativeMargin;\n"
        "                prim.box.hi[axis] += hull.nativeMargin;\n"
        "            }\n            prim.flags = hull.flags;",
    )
    TARGET.mkdir(exist_ok=True)
    (TARGET / "replay_navigation.cpp").write_bytes(adapted.encode("utf-8"))
    receipt = dict(
        schema=1,
        original_source=str(SOURCE),
        original_sha256=hashlib.sha256(original).hexdigest(),
        output_sha256=hashlib.sha256(adapted.encode()).hexdigest(),
        retained=[
            "original source start through BuildNavGraph end",
            "Build geometry stage through BuildMesh",
        ],
        adaptations=[
            "standalone types header",
            "stderr logging header",
            "return serialized nav resource directly",
            "separate collision fidelity audit adapter included after retained source",
            "native convex radius represented by conservative shifted support-plane envelope and expanded AABB",
            "optional conservative Scene footprint/support refinement before polygon merging; prevents averaging distinct floor planes",
        ],
        excluded=[
            "ZoneWriter",
            "asset registration",
            "PathData generation",
            "TacticalGraph generation",
        ],
        provenance_note="Source reuse is not evidence that supplied geometry is correct or live Gulag navigation works.",
    )
    (TARGET / "source-provenance.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
