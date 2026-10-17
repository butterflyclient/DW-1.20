"""Extract real, rig-compatible inspect XAnims without building or deploying a zone.

The two supported decoded archives are immutable inputs. Package identities and
pointer slots select clips; filenames never select a weapon's animation. The
output is a recipe plus lossless native roots/arrays for the Replay zone writer.
"""

import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import sys
import importlib.util

sys.dont_write_bytecode = True
ROOT = Path("E:/DW/IW8")
DONOR = Path(
    "E:/replay-compiler/assets/mw131-common-mp-decoded/common_mp.fp.patched.dec"
)
REPLAY = (
    ROOT
    / "data/research/weapon-inspect-20261017/replay-common-mp-decoded/common_mp.fp.patched.dec"
)
# Actual shipped Replay4087 ncs_anm_common_mp, serialized offset0x4E414.
NCS_SOURCE = 1

INLINE = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE}
DONOR_SHA = "9a3ac5452fefff512f55bcf63d4919ecd1d4dde315c171675826096722e6ff68"
REPLAY_SHA = "992ae7441d54c1305c1a9b0b7b244d9347fec247911460ee62d9847c80994b26"
PROFILES = {
    DONOR_SHA: dict(version=4136, idle_alias=0x500044099, inspect_slot=433),
    REPLAY_SHA: dict(version=4087, idle_alias=0x500029531, inspect_slot=None),
}
ANCHOR = "vm_ar_akilo47_idle"
PACKAGE_ANCHOR = "iw8_ar_akilo47_animpackage"
BASE_PACKAGE = re.compile(rb"iw8_(?:[a-z0-9_]+_animpackage|fists_mp(?:_ls)?_package)\Z")
ANIMATION = re.compile(rb"vm_[a-z0-9_]+\Z")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strings(data):
    count, reserved, pointer = struct.unpack_from("<IIQ", data)
    require(
        not reserved and pointer in INLINE and count < 1000000,
        "Unsupported ScriptStringList root",
    )
    at = 32 + count * 8
    result = []
    for index in range(count):
        token = struct.unpack_from("<Q", data, 32 + index * 8)[0]
        if token in INLINE:
            end = data.find(b"\0", at)
            require(end >= at, "Unterminated script string")
            result.append(data[at:end].decode("utf-8"))
            at = end + 1
        else:
            require(token == 0, "Packed script-string pointer is unsupported")
            result.append("")
    return result


def packages(data):
    """Find version-pinned native roots, retaining the actual two idle aliases."""
    result = {}
    at = 0
    prefix = struct.pack("<Q", 0xFFFFFFFFFFFFFFFE) * 3
    while (at := data.find(b"iw8_", at)) >= 0:
        end = data.find(b"\0", at, at + 160)
        name = data[at:end] if end >= 0 else b""
        if (
            BASE_PACKAGE.fullmatch(name)
            and at >= 64
            and data[at - 64 : at - 40] == prefix
        ):
            label = name.decode("ascii")
            require(label not in result, "Duplicate native package root: " + label)
            result[label] = dict(
                root_offset=at - 64,
                name_offset=at,
                parts_offset=end + 1,
                idle_aliases=struct.unpack_from("<2Q", data, end + 1 + 236 * 8),
            )
        at += 4
    require(PACKAGE_ANCHOR in result, "Missing native package calibration anchor")
    return result


def vm_roots(data, first_package):
    """Enumerate the contiguous VM portion of this pinned top-level XAnim run.

    XAsset aliases advance 16 bytes per top-level record. A calibrated package
    pointer binds that ordered run to the original DB alias, preserving the
    source relationship rather than deriving animation names from weapon names.
    """
    result = []
    at = 0
    seen = set()
    while (at := data.find(b"vm_", at, first_package)) >= 0:
        end = data.find(b"\0", at, at + 192)
        name = data[at:end] if end >= 0 else b""
        root_at = at - 160
        if root_at >= 0 and ANIMATION.fullmatch(name):
            pointers = struct.unpack_from("<11Q", data, root_at)
            fps = struct.unpack_from("<f", data, root_at + 0x64)[0]
            if (
                pointers[0] in INLINE
                and all(p == 0 or p in INLINE for p in pointers)
                and 0 <= fps <= 1000
            ):
                label = name.decode("ascii")
                require(label not in seen, "Duplicate inline VM XAnim: " + label)
                seen.add(label)
                result.append(dict(name=label, root_offset=root_at, name_offset=at))
        at += 3
    names = [row["name"] for row in result]
    require(
        names == sorted(names), "Top-level VM XAnim sequence is not strictly ordered"
    )
    require(ANCHOR in names, "Missing native XAnim alias calibration anchor")
    for row, following in zip(result, result[1:]):
        row["next_root_offset"] = following["root_offset"]
    return result


def archive(data, expected_hash):
    require(
        sha(data) == expected_hash,
        "Decoded archive SHA-256 differs from its pinned profile",
    )
    profile = PROFILES[expected_hash]
    strings_table = strings(data)
    package_rows = packages(data)
    rows = vm_roots(data, min(p["root_offset"] for p in package_rows.values()))
    anchor = next(i for i, row in enumerate(rows) if row["name"] == ANCHOR)
    by_alias = {
        profile["idle_alias"] + (i - anchor) * 16: row for i, row in enumerate(rows)
    }
    require(
        package_rows[PACKAGE_ANCHOR]["idle_aliases"] == (profile["idle_alias"],) * 2,
        "Native primary idle calibration aliases changed",
    )
    for package in package_rows.values():
        for token in package["idle_aliases"]:
            require(
                not token or token in by_alias,
                "Unresolved native package primary idle alias",
            )
            if token:
                require(
                    "_idle" in by_alias[token]["name"],
                    "Package primary idle resolved to a different animation state",
                )
    return dict(
        profile=profile,
        strings=strings_table,
        packages=package_rows,
        by_alias=by_alias,
        vm_roots=rows,
        sha256=expected_hash,
    )


def bone_names(data, row, table):
    at = row["name_offset"] + len(row["name"]) + 1
    count = data[row["root_offset"] + 0x82]
    pointer = struct.unpack_from("<Q", data, row["root_offset"] + 8)[0]
    require(
        (not count and not pointer) or pointer in INLINE,
        "Unsupported bone-name array pointer",
    )
    ids = struct.unpack_from("<" + "I" * count, data, at)
    require(all(i < len(table) for i in ids), "Bone-name script string is out of range")
    return [table[i] for i in ids]


def clip(data, row, table):
    start, name_at = row["root_offset"], row["name_offset"]
    root = data[start:name_at]
    pointers = struct.unpack_from("<11Q", root)
    random_short, random_byte, indices, fps, frequency, data_byte = struct.unpack_from(
        "<IIIffI", root, 0x58
    )
    data_short, data_int, random_int, frames = struct.unpack_from("<4H", root, 0x70)
    bones, notify_count = list(root[0x79:0x83]), root[0x83]
    blend_count = struct.unpack_from("<H", root, 0x88)[0]
    require(
        frames and fps > 0 and bones[9], "Inspect clip has no animated frames/bones"
    )
    require(
        not pointers[10] and not blend_count and not any(root[0x90:0xA0]),
        "Inspect root-motion/blendshape payload requires another verified reader",
    )
    at = name_at + len(row["name"]) + 1
    arrays = {}
    spans = {}

    def take(field, count, width, pointer):
        nonlocal at
        token = pointers[pointer]
        require(
            (not count and not token) or token in INLINE,
            "Inspect array is not inline: " + field,
        )
        length = count * width
        arrays[field] = data[at : at + length]
        require(len(arrays[field]) == length, "Truncated inspect array: " + field)
        spans[field] = dict(offset=at, bytes=length, sha256=sha(arrays[field]))
        at += length
        return arrays[field]

    names_data = take("names", bones[9], 4, 1)
    names_ids = struct.unpack("<" + "I" * bones[9], names_data)
    require(all(i < len(table) for i in names_ids), "Inspect bone ID is out of range")
    names = [table[i] for i in names_ids]
    notes = take("notify", notify_count, 8, 9)
    notifies = []
    for index, time in struct.iter_unpack("<If", notes):
        require(
            index < len(table) and 0 <= time <= 1,
            "Inspect notify ID/time is out of range",
        )
        notifies.append(dict(name=table[index], time=time))
    take("dataByte", data_byte, 1, 2)
    take("dataShort", data_short, 2, 3)
    take("dataInt", data_int, 4, 4)
    take("randomDataShort", random_short, 2, 5)
    take("randomDataByte", random_byte, 1, 6)
    take("randomDataInt", random_int, 4, 7)
    take("indices", indices, 1 if frames < 256 else 2, 8)
    require(
        at == start + 160 + len(row["name"]) + 1 + sum(len(v) for v in arrays.values()),
        "Inspect serialized span accounting differs",
    )
    require(
        at == row.get("next_root_offset"),
        "Inspect key payload does not end exactly at the next native XAnim root",
    )
    return (
        dict(
            schema="replay120-native-xanim-v1",
            source_name=row["name"],
            name="dw_inspect_" + row["name"],
            source_root_offset=start,
            source_name_offset=name_at,
            source_end_offset=at,
            serialized_bytes=at - start,
            serialized_sha256=sha(data[start:at]),
            numframes=frames,
            framerate=fps,
            frequency=frequency,
            duration_ms=round(1000 * frames / fps),
            flags=root[0x78],
            bone_count=bones,
            asset_type=root[0x84],
            ik_type=root[0x85],
            finger_pose_type=root[0x86],
            delta_part=None,
            blendshape_count=0,
            names=names,
            notify=notifies,
            source_array_spans=spans,
        ),
        root,
        arrays,
    )


def extract_assets(donor_path, replay_path, output):
    output = Path(output).resolve()
    require(
        not output.exists(),
        "Use a fresh output directory to preserve prior review artifacts",
    )
    with Path(donor_path).open("rb") as df, Path(replay_path).open(
        "rb"
    ) as rf, mmap.mmap(df.fileno(), 0, access=mmap.ACCESS_READ) as donor, mmap.mmap(
        rf.fileno(), 0, access=mmap.ACCESS_READ
    ) as replay:
        da, ra = archive(donor, DONOR_SHA), archive(replay, REPLAY_SHA)
        selected, excluded, clips = [], [], {}
        for package_name, rp in sorted(ra["packages"].items()):
            dp = da["packages"].get(package_name)
            if not dp:
                excluded.append(
                    dict(package=package_name, reason="No exact donor package identity")
                )
                continue
            token = struct.unpack_from("<Q", donor, dp["parts_offset"] + 433 * 8)[0]
            source = da["by_alias"].get(token)
            if not source or "inspect" not in source["name"]:
                excluded.append(
                    dict(
                        package=package_name,
                        reason="Native donor slot433 has no resolved inspect clip",
                        donor_pointer_token=hex(token),
                    )
                )
                continue
            metadata, raw_root, arrays = clip(donor, source, da["strings"])
            idle = [ra["by_alias"][v] for v in rp["idle_aliases"] if v]
            idle_names = set().union(
                *(set(bone_names(replay, row, ra["strings"])) for row in idle)
            )
            # A bone absent from idle can still be part of the stock weapon rig.
            # Require an actual animation pointer in this same native package to
            # prove those additional bindings, instead of borrowing another gun.
            native_tokens = struct.unpack_from("<614Q", replay, rp["parts_offset"])
            rig_names = set(idle_names)
            evidence = []
            remaining = set(metadata["names"]) - rig_names
            if remaining:
                for slot, alias in enumerate(native_tokens):
                    row = ra["by_alias"].get(alias)
                    if not row:
                        continue
                    names = set(bone_names(replay, row, ra["strings"]))
                    if remaining & names:
                        evidence.append(
                            dict(
                                slot=slot,
                                alias=hex(alias),
                                name=row["name"],
                                root_offset=row["root_offset"],
                            )
                        )
                        rig_names.update(names)
                        remaining -= names
                    if not remaining:
                        break
            if remaining:
                excluded.append(
                    dict(
                        package=package_name,
                        reason="Donor bones absent from all resolved native package animations",
                        missing_bones=sorted(remaining),
                        source_clip=source["name"],
                    )
                )
                continue
            clips.setdefault(metadata["name"], (metadata, raw_root, arrays))
            selected.append(
                dict(
                    package=package_name,
                    animation=metadata["name"],
                    source_animation=source["name"],
                    duration_ms=metadata["duration_ms"],
                    replay_package_root=rp["root_offset"],
                    donor_package_root=dp["root_offset"],
                    donor_inspect_slot=433,
                    donor_inspect_alias=hex(token),
                    replay_primary_idle=[
                        dict(name=row["name"], root_offset=row["root_offset"])
                        for row in idle
                    ],
                    additional_bone_evidence=evidence,
                    compatibility="All donor bone names occur in animations already referenced by this Replay package; rendered pose remains untested",
                )
            )
        require(
            selected, "No native package has a proven compatible donor inspect clip"
        )
        output.mkdir(parents=True)
        artifacts = []
        for name, (metadata, raw_root, arrays) in sorted(clips.items()):
            folder = output / "xanim" / name
            folder.mkdir(parents=True)
            (folder / "root.bin").write_bytes(raw_root)
            for field, value in arrays.items():
                (folder / (field + ".bin")).write_bytes(value)
            (folder / "asset.json").write_text(
                json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
            )
        header = [
            "#pragma once",
            "// Generated from pinned native package pointers; no weapon-name inference.",
            "struct DWWeaponInspectAsset { const char *package; const char *animation; unsigned durationMs; };",
            "inline constexpr DWWeaponInspectAsset kDWWeaponInspectAssets[] = {",
        ]
        header += [
            "    {"
            + json.dumps(r["package"])
            + ", "
            + json.dumps(r["animation"])
            + ", "
            + str(r["duration_ms"])
            + "},"
            for r in selected
        ]
        header += ["};", ""]
        (output / "weapon-inspect-assets.h").write_text(
            "\n".join(header), encoding="utf-8"
        )
        for path in sorted(output.rglob("*")):
            if path.is_file():
                data = path.read_bytes()
                artifacts.append(
                    dict(
                        path=path.relative_to(output).as_posix(),
                        bytes=len(data),
                        sha256=sha(data),
                    )
                )
        report = dict(
            schema="replay120-weapon-inspect-assets-v1",
            donor=dict(
                path=str(Path(donor_path).resolve()),
                sha256=DONOR_SHA,
                xfile_version=4136,
            ),
            replay=dict(
                path=str(Path(replay_path).resolve()),
                sha256=REPLAY_SHA,
                xfile_version=4087,
            ),
            packages=selected,
            excluded_packages=excluded,
            animations=len(clips),
            netconststrings=dict(type=16, names=sorted(clips)),
            artifacts=artifacts,
            serializer_requirements=[
                "Intern resolved bone and notify names in the output zone script-string table",
                "Preserve the complete root scalar tail including flags, assetType, ikType and fingerPoseType",
                "Write arrays in source_array_spans order; preserve all numeric key bytes",
                "Register output animation names and type16 NetConstStrings in a companion native zone",
            ],
            gates=dict(
                extracted=True,
                built_fastfile=False,
                native_reader_validated=False,
                compiled_executable=False,
                deployed=False,
                live_game_tested=False,
            ),
        )
        (output / "manifest.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        return report


def serialize_zone(recipe):
    """Replay ZoneWriter's stream order, including alignment-only reservations.

    This deliberately preserves native weapon XAnim scalar fields rather than
    using the IW3 prop writer, which sets assetType7 and discards hand metadata.
    It is called only by prepare(snapshot), after the owner approves a build.
    """
    recipe = Path(recipe)
    report = json.loads((recipe / "manifest.json").read_bytes())
    for artifact in report["artifacts"]:
        data = (recipe / artifact["path"]).read_bytes()
        require(
            len(data) == artifact["bytes"] and sha(data) == artifact["sha256"],
            "Prepared inspect artifact changed: " + artifact["path"],
        )
    labels = report["netconststrings"]["names"]
    assets = []
    script_strings = []
    ids = {}
    for label in labels:
        folder = recipe / "xanim" / label
        metadata = json.loads((folder / "asset.json").read_bytes())
        for value in metadata["names"] + [n["name"] for n in metadata["notify"]]:
            require(
                value and "\0" not in value, "Empty/invalid native XAnim script string"
            )
            if value not in ids:
                ids[value] = len(script_strings) + 1
                script_strings.append(value)
        assets.append((folder, metadata))
    body = bytearray()
    streams = [0] * 11

    def align(stream, mask):
        streams[stream] = (streams[stream] + mask) & ~mask

    def write(stream, data):
        body.extend(data)
        streams[stream] += len(data)

    def write_scratch_root(stream, data):
        body.extend(data)
        # The XAssetList is read into the caller's root, outside TEMP0.
        # Load_*Ptr pushes TEMP1, and native DB_PopStreamPos restores its
        # saved cursor: separate top-level roots reuse this scratch address.
        if stream == 1:
            streams[1] = max(streams[1], len(data))
        else:
            require(stream == 0, "Unexpected scratch root stream")

    def reserve(stream, count):
        streams[stream] += count

    def text(stream, value):
        write(stream, value.encode("ascii") + b"\0")

    # XAssetList consumes physical input but no TEMP0 reservation. Its script
    # strings and XAsset array live in virtual stream5.
    count = len(assets) + 1
    write_scratch_root(
        0,
        struct.pack(
            "<IIQIIQ",
            len(script_strings) + 1,
            0,
            0xFFFFFFFFFFFFFFFE,
            count,
            0,
            0xFFFFFFFFFFFFFFFE,
        ),
    )
    align(5, 7)
    write(
        5,
        struct.pack("<Q", 0)
        + struct.pack("<Q", 0xFFFFFFFFFFFFFFFE) * len(script_strings),
    )
    for value in script_strings:
        text(5, value)
    align(5, 7)
    for kind in [7] * len(assets) + [61]:
        write(5, struct.pack("<IIQ", kind, 0, 0xFFFFFFFFFFFFFFFD))
    layout = []
    for folder, metadata in assets:
        # Top-level -3 calls DB_InsertPointer before reading each asset.
        align(5, 7)
        reserve(5, 8)
        root = bytearray((folder / "root.bin").read_bytes())
        require(len(root) == 160, "Unexpected native XAnim root size")
        # Names and notifies are re-interned; all key payload bytes stay exact.
        for pointer in range(11):
            token = struct.unpack_from("<Q", root, pointer * 8)[0]
            require(token == 0 or token in INLINE, "Unexpected donor pointer token")
            struct.pack_into(
                "<Q", root, pointer * 8, 0xFFFFFFFFFFFFFFFE if token else 0
            )
        root_at = len(body)
        write_scratch_root(1, root)
        text(5, metadata["name"])
        align(5, 3)
        write(
            5,
            struct.pack(
                "<" + "I" * len(metadata["names"]), *(ids[v] for v in metadata["names"])
            ),
        )
        notes = bytearray((folder / "notify.bin").read_bytes())
        if notes:
            align(5, 3)
            for index, notify in enumerate(metadata["notify"]):
                struct.pack_into("<I", notes, index * 8, ids[notify["name"]])
            write(5, notes)
        for field, mask in [
            ("dataByte", 0),
            ("dataShort", 1),
            ("dataInt", 3),
            ("randomDataShort", 1),
            ("randomDataByte", 0),
            ("randomDataInt", 3),
            ("indices", 0 if metadata["numframes"] < 256 else 1),
        ]:
            data = (folder / (field + ".bin")).read_bytes()
            if data:
                align(5, mask)
                write(5, data)
        # Preload_XAnimPartsPtr and Postload_XAnimPartsPtr both push2.
        # The 160-byte resident root advances there; DB_PopStreamPos rounds
        # that resident cursor to32 instead of restoring it like scratch1.
        align(2, 7)
        reserve(2, 160)
        align(2, 31)
        layout.append(
            dict(
                type=7,
                name=metadata["name"],
                root_offset=root_at,
                physical_end=len(body),
                source_serialized_sha256=metadata["serialized_sha256"],
            )
        )
    align(5, 7)
    reserve(5, 8)
    ncs_at = len(body)
    write_scratch_root(
        1,
        struct.pack(
            "<QIIIIQ",
            0xFFFFFFFFFFFFFFFE,
            16,
            NCS_SOURCE,
            0,
            len(labels),
            0xFFFFFFFFFFFFFFFE,
        ),
    )
    text(5, "ncs_anm_common_mp_dw_inspect")
    align(5, 7)
    write(5, struct.pack("<Q", 0xFFFFFFFFFFFFFFFE) * len(labels))
    for label in labels:
        text(5, label)
    align(2, 7)
    reserve(2, 32)
    align(2, 31)
    layout.append(
        dict(
            type=61,
            name="ncs_anm_common_mp_dw_inspect",
            root_offset=ncs_at,
            string_type=16,
            source_type=NCS_SOURCE,
            entries=len(labels),
        )
    )
    require(
        streams[0] == 0 and streams[1] == 160 and streams[2] == len(assets) * 160 + 32,
        "Native root scratch/resident stream contract changed",
    )
    require(
        sum(streams) >= len(body), "Serialized zone exceeds native memory reservations"
    )
    return bytes(body), streams, layout


def render_package(packed, patch, empty_packed, empty_patch, proof):
    def array(name, data):
        return "\n".join(
            [f"inline const uint8_t {name}[] = {{"]
            + [
                "    " + ",".join(f"0x{x:02x}" for x in data[i : i + 24]) + ","
                for i in range(0, len(data), 24)
            ]
            + ["};"]
        )

    header = [
        "#pragma once",
        '#include "DW_BotStyleScriptPackage.h"',
        "// Shared native package descriptor ABI: 96 bytes on Win64.",
        "static_assert(sizeof(DWBotStyleScriptPackage) == 96);",
        "namespace DWWeaponInspectPackage {",
    ]
    for name, data in [
        ("Fastfile", packed),
        ("Patch", patch),
        ("EmptyFastfile", empty_packed),
        ("EmptyPatch", empty_patch),
    ]:
        header.append(array(name, data))
    names = [r for r in proof["installation_manifest"] if r["name"].endswith(".ff")]
    header.append("inline const char *const InstallationNames[] = {")
    header.extend("    " + json.dumps(r["name"][:-3]) + "," for r in names)
    header.append("};\ninline const char *const InstallationDirectories[] = {")
    header.extend("    " + json.dumps(r["directory"]) + "," for r in names)
    header.append("};")
    header.append(
        "inline const DWBotStyleScriptPackage Package = {"
        + json.dumps(proof["zone_name"])
        + ", Fastfile, sizeof(Fastfile), Patch, sizeof(Patch), EmptyFastfile, sizeof(EmptyFastfile), "
        + "EmptyPatch, sizeof(EmptyPatch), InstallationNames, InstallationDirectories, "
        + "sizeof(InstallationNames)/sizeof(*InstallationNames), 0};\n}"
    )
    return "\n".join(header) + "\n"


def prepare(snapshot):
    """Deferred approved-build entrypoint. Never called by research extraction."""
    snapshot = Path(snapshot).resolve(strict=True)
    require(
        snapshot.is_relative_to((ROOT / "data").resolve()),
        "Inspect output requires a private DW snapshot",
    )
    require(
        not (snapshot.parent / "client-readiness.json").exists(),
        "Cannot regenerate a sealed client snapshot",
    )
    output = snapshot / "generated/weapon-inspect-assets"
    require(not output.exists(), "Use a fresh snapshot for inspect asset preparation")
    recipe = output / "recipe"
    # Helper source belongs to the immutable snapshot receipt, just like the
    # executable translation units. Canonical input copies are never mutable
    # dependencies of a later updater verification.
    frozen_tools = []
    for source in [Path(__file__).resolve(), ROOT / "tools/bot_style_paths.py"]:
        target = snapshot / "tools" / source.name
        if target.exists():
            require(
                target.read_bytes() == source.read_bytes(),
                "Snapshot inspect helper differs: " + source.name,
            )
        else:
            target.write_bytes(source.read_bytes())
        frozen_tools.append(target)
    extraction = extract_assets(DONOR, REPLAY, recipe)
    sys.path.insert(0, str(snapshot / "tools"))
    import workstation_fastfiles as containers

    require(
        Path(containers.__file__).resolve().is_relative_to(snapshot / "tools"),
        "Fastfile container helper is outside the current snapshot",
    )
    body, streams, layout = serialize_zone(recipe)
    packed = containers.pack_replay_uncompressed(body, streams)
    require(
        containers.unpack_replay_uncompressed(packed) == body,
        "Inspect FF framing roundtrip changed its body",
    )
    template = bytearray(0x148)
    template[:8] = b"IWffd100"
    struct.pack_into("<II", template, 8, 6, 4)
    patch = containers.make_replay_header_only_patch(bytes(template), packed)
    empty_body = bytes(32)
    empty_packed = containers.pack_replay_uncompressed(empty_body, [0] * 11)
    empty_patch = containers.make_replay_header_only_patch(
        bytes(template), empty_packed
    )
    bundle_hash = sha(packed + patch + empty_packed + empty_patch)
    zone = "dw_weapon_inspect_mp_" + bundle_hash[:16]
    spec = importlib.util.spec_from_file_location(
        "dw_inspect_native_paths", snapshot / "tools/bot_style_paths.py"
    )
    paths = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(paths)
    policy = paths.derive(snapshot)
    prefixes = sorted(
        set(["techsets", "srv", *policy["regions"], *policy["supported_languages"]])
    )
    installation = []
    for name, companion in [(zone, False)] + [(p + "_" + zone, True) for p in prefixes]:
        directory = paths.directory_for_name(name, zone, policy)
        for suffix, resource in [
            (".ff", empty_packed if companion else packed),
            (".fp", empty_patch if companion else patch),
        ]:
            path = output / (name + suffix)
            path.write_bytes(resource)
            installation.append(
                dict(
                    name=path.name,
                    source=str(path),
                    sha256=sha(resource),
                    size=len(resource),
                    companion=companion,
                    directory=directory,
                    relative_path=(directory + "/" if directory else "") + path.name,
                )
            )
    # The approved build must pass the existing offline original-Replay reader
    # before these resources can become an embedded executable package.
    import roundtrip_replay_fastfile as native_reader

    require(
        Path(native_reader.__file__).resolve().is_relative_to(snapshot / "tools"),
        "Native FF verifier is outside the current snapshot",
    )
    verify_native = native_reader.verify_native
    acts = Path("D:/mw124/atian-cod-tools/build-workstation/bin/Release/acts.exe")
    image = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
    native = verify_native(
        output / (zone + ".ff"),
        body,
        output / (zone + ".ff"),
        acts,
        image,
        output / "native-reread",
        60,
        trace=True,
    )
    native_manifest = Path(native["manifest_path"])
    manifest = json.loads(native_manifest.read_bytes())
    journal_path = native_manifest.parent / manifest.get("journal", "assets.jsonl")
    journal = [
        json.loads(line)
        for line in journal_path.read_text().splitlines()
        if line.strip()
    ]
    require(
        [(r["type_id"], r["name"]) for r in journal]
        == [(r["type"], r["name"]) for r in layout],
        "Native reread asset identities differ from the inspect recipe",
    )
    empty_name = prefixes[0] + "_" + zone
    empty_native = verify_native(
        output / (empty_name + ".ff"),
        empty_body,
        output / (empty_name + ".ff"),
        acts,
        image,
        output / "native-empty-reread",
        60,
        trace=True,
    )
    require(
        empty_native["manifest"]["top_level_index"] == 0,
        "Native locale companion unexpectedly contains assets",
    )
    inputs = [
        *frozen_tools,
        DONOR,
        REPLAY,
        Path(containers.__file__).resolve(),
        Path(native_reader.__file__).resolve(),
        acts,
        image,
    ]
    source_receipts = []
    for path in inputs:
        with path.open("rb") as f:
            source_receipts.append(
                dict(
                    path=str(path),
                    bytes=path.stat().st_size,
                    sha256=hashlib.file_digest(f, "sha256").hexdigest(),
                )
            )
    proof = dict(
        schema="replay120-weapon-inspect-native-package-v1",
        zone_name=zone,
        resource_bundle_sha256=bundle_hash,
        source_inputs=source_receipts,
        extraction_manifest=str(recipe / "manifest.json"),
        extraction_manifest_sha256=sha((recipe / "manifest.json").read_bytes()),
        native_locale_codes=policy,
        native_folder_rules=policy["installation_folder_rules"],
        installation_manifest=installation,
        asset_layouts=layout,
        stream_sizes=streams,
        body_sha256=sha(body),
        fastfile_sha256=sha(packed),
        patch_sha256=sha(patch),
        packages=len(extraction["packages"]),
        animations=extraction["animations"],
        compatibility_scope="Native animation-name bindings; rendered pose remains an owner game test",
        native_reader=native,
        empty_native_reader=empty_native,
        gates=dict(
            built_fastfile=True,
            framing_roundtrip=True,
            native_reader_validated=True,
            compiled_executable=False,
            deployed=False,
            live_game_tested=False,
        ),
    )
    (output / "package-proof.json").write_text(
        json.dumps(proof, indent=2) + "\n", encoding="utf-8"
    )
    (snapshot / "src/DW_WeaponInspectPackage.h").write_text(
        render_package(packed, patch, empty_packed, empty_patch, proof),
        encoding="utf-8",
    )
    (snapshot / "src/DW_WeaponInspectAssets.h").write_bytes(
        (recipe / "weapon-inspect-assets.h").read_bytes()
    )
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donor", required=True, type=Path)
    parser.add_argument("--replay", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = extract_assets(args.donor, args.replay, args.output)
    print(
        json.dumps(
            dict(
                packages=len(result["packages"]),
                animations=result["animations"],
                excluded=len(result["excluded_packages"]),
                gates=result["gates"],
            )
        )
    )
