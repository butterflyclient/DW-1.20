"""Deferred linked-owner and modeled behavior gate for inspection blending.

The approved verify run compiles only an isolated harness. It never starts the
game, generates a fastfile, deploys, or claims rendered transition validation.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path("C:/Program Files/LLVM/bin")
OWNER = "DW_WeaponInspectBlend_StartWeaponAnim"
FALLBACK = "WIB_OriginalStartWeaponAnim"


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def verify(build):
    import pefile

    build = Path(build).resolve(strict=True)
    report = read(build / "build-report.json")
    snapshot = Path(report["source_root"]).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    image = Path(report["executable"])
    image = (image if image.is_absolute() else build / image).resolve(strict=True)
    assert image.is_relative_to(build) and sha(image) == report["sha256"]
    assert not report["unresolved_symbols"]
    proof = read(snapshot / "generated/weapon-inspect-blend-integration.json")
    assert proof["passed"] and proof["original_bodies_assembled"]
    assert proof["image_sha256"] == report["input_sha256"] == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    assert proof["generator_sha256"] == sha(snapshot / "tools/prepare-weapon-inspect-blend.py")
    assert proof["helper_tool_sha256"] == sha(snapshot / "tools/prepare-weapon-inspect-input.py")
    assert proof["clone_tool_sha256"] == sha(snapshot / "tools/replay_owned_clone.py")
    assert proof["source_sha256"] == sha(snapshot / proof["source"])
    for relative, digest in proof["dependencies"].items():
        path = (snapshot / relative).resolve(strict=True)
        assert path.is_relative_to(snapshot) and sha(path) == digest
    assert sha(snapshot / "tools/test-weapon-inspect-blend.py") == sha(Path(__file__))
    coff = module("inspect_blend_coff", snapshot / "tools/coff.py")
    linked_gate = module("inspect_blend_linked_gate", snapshot / "tools/test-weapon-inspect.py")
    objects, inputs = {}, {}
    for name in ("DW_WeaponInspectBlend.cpp", "DW_WeaponInspectBlend_Native.cpp"):
        source = snapshot / "src" / name
        rows = [row for row in report["cpp"] if Path(row["source"]).as_posix() == "src/" + name]
        assert len(rows) == 1 and rows[0]["source_sha256"] == sha(source)
        row = rows[0]
        obj = Path(row["object"])
        obj = (obj if obj.is_absolute() else build / obj).resolve(strict=True)
        assert obj.is_relative_to(build) and sha(obj) == row["object_sha256"]
        dependencies = {Path(item["path"]).resolve(strict=True): item["sha256"] for item in row["dependencies"]}
        assert len(dependencies) == len(row["dependencies"])
        for path, digest in dependencies.items():
            assert sha(path) == digest
        required = [source]
        if name == "DW_WeaponInspectBlend.cpp":
            required += [snapshot / "src" / header for header in
                         ("DW_WeaponInspectBlend.h", "DW_WeaponInspectBlendBindings.h", "DW_WeaponInspect.h")]
        for path in required:
            assert dependencies[path.resolve()] == sha(path)
        inputs[name] = dict(source_sha256=sha(source), object_sha256=sha(obj), dependencies=len(dependencies))
        objects[name] = coff.read(obj)
    pe = pefile.PE(str(image))
    symbols = report["symbols"]
    identity = proof["owners"][OWNER]["identity"]
    assert symbols[identity] == symbols[OWNER] != symbols[FALLBACK]
    linked = linked_gate.linked_object(pe, objects["DW_WeaponInspectBlend.cpp"], symbols, [OWNER],
                                      report["rva_map"]["ranges"])
    for alias, target in proof["imports"].items():
        assert symbols[alias] == symbols[target]
    # Prove the complete native fallback's linked instructions, every external
    # operand, and its unwind ranges rather than trusting a generator receipt.
    native_path = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    assert sha(native_path) == report["input_sha256"]
    native = pefile.PE(str(native_path), fast_load=True)
    owner = proof["owners"][OWNER]
    clones = [row for row in proof["clones"] if row["helper"] == FALLBACK]
    assert len(clones) == 1
    clone = clones[0]
    output = snapshot / "generated/weapon-inspect-blend"
    assert sha(output / (FALLBACK + ".cpp")) == clone["source_sha256"]
    assert sha(output / (FALLBACK + ".obj")) == clone["object_sha256"]
    expected = bytearray(b"".join(native.get_data(row["begin"], row["end"] - row["begin"])
                                  for row in owner["unwind"]))
    assert len(expected) == clone["bytes"] == owner["bytes"] == 1637
    assert hashlib.sha256(expected).hexdigest() == owner["sha256"]
    actual = bytearray(pe.get_data(symbols[FALLBACK], len(expected)))
    for fixup in clone["external_fixups"]:
        if fixup.get("section", ".text") != ".text":
            continue
        offset, kind = fixup["offset"], fixup["kind"]
        if kind == 3:
            target = struct.unpack_from("<I", actual, offset)[0]
        else:
            assert 4 <= kind <= 9
            target = symbols[FALLBACK] + offset + 4 + fixup["trailing_instruction_bytes"] + struct.unpack_from("<i", actual, offset)[0]
        assert target == symbols[fixup["stable_id"]]
        actual[offset:offset + 4] = expected[offset:offset + 4] = bytes(4)
    assert actual == expected
    unwind = sorted([row.struct for row in pe.DIRECTORY_ENTRY_EXCEPTION
                     if row.struct.BeginAddress < symbols[FALLBACK] + len(expected)
                     and row.struct.EndAddress > symbols[FALLBACK]], key=lambda row: row.BeginAddress)
    assert len(unwind) == len(owner["unwind"])
    for index, (old, new) in enumerate(zip(owner["unwind"], unwind, strict=True)):
        assert new.BeginAddress - symbols[FALLBACK] == old["begin"] - owner["rva"]
        assert new.EndAddress - new.BeginAddress == old["end"] - old["begin"]
        before = bytes.fromhex(old["bytes"])
        after = pe.get_data(new.UnwindData, len(before))
        flags = before[0] >> 3
        prefix = 4 + ((before[2] + 1) & ~1) * 2
        assert after[:prefix] == before[:prefix], "Changed native unwind opcodes"
        if flags == 4:
            chain = struct.unpack_from("<III", before, prefix)
            parent = next(i for i, row in enumerate(owner["unwind"][:index])
                          if chain == (row["begin"], row["end"], row["unwind_rva"]))
            target = unwind[parent]
            assert struct.unpack_from("<III", after, prefix) == (
                target.BeginAddress, target.EndAddress, target.UnwindData)
        elif flags == 3:
            fixup = next(row for row in clone["external_fixups"]
                         if row.get("section") == ".xdata"
                         and row["original_site_rva"] == old["unwind_rva"] + prefix)
            assert struct.unpack_from("<I", after, prefix)[0] == symbols[fixup["stable_id"]]
            assert after[prefix + 4:] == before[prefix + 4:]
        else:
            assert flags == 0 and after == before
    harness = snapshot / "tools/weapon_inspect_blend_harness.cpp"
    assert harness.is_file()
    with tempfile.TemporaryDirectory(prefix="weapon-inspect-blend-", dir=build) as temporary:
        folder = Path(temporary)
        compiler = str(LLVM / "clang++.exe")
        flags = ["--target=x86_64-pc-windows-msvc", "-std=c++20", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-UNDEBUG", "-fno-exceptions", "-fno-rtti", "-I" + str(snapshot / "src")]
        owner_obj, harness_obj = folder / "owner.obj", folder / "harness.obj"
        for source, obj in ((snapshot / proof["source"], owner_obj), (harness, harness_obj)):
            subprocess.run([compiler, *flags, "-c", str(source), "-o", str(obj)], check=True)
        executable = folder / "inspect-blend.exe"
        subprocess.run([compiler, str(owner_obj), str(harness_obj), "-o", str(executable)], check=True)
        result = subprocess.run([str(executable)], capture_output=True, text=True)
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
        cases = re.findall(r"^CASE\t([^\r\n]+)$", result.stdout, re.MULTILINE)
        assert len(cases) == len(set(cases)) == 40
        assert re.findall(r"^PASS WEAPON_INSPECT_BLEND cases=(\d+)$", result.stdout, re.MULTILINE) == ["40"]
        harness_sha = sha(executable)
    return dict(schema=1, passed=True, executable_sha256=report["sha256"], source_root=str(snapshot),
                inputs=inputs, linked_owner=linked, original_clone_bytes=1637,
                native_clone_instructions_and_fixups_verified=True, native_clone_unwind_ranges_verified=True,
                native_clone_unwind_opcodes_and_chains_verified=True,
                production_owner_compiled_separately=True, modeled_cases=40, case_names=cases,
                harness_source_sha256=sha(harness), harness_executable_sha256=harness_sha,
                checker_sha256=sha(Path(__file__)), native_boundaries_modeled=True,
                retained_clip_identity_after_exit_checked=True, unrelated_scripted_clip_checked=True,
                first_rebuilt_tree_sentinel_entry_checked=True,
                native_rendered_blend_verified=False, game_runs_performed=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.build)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS: linked native inspection blend owner, complete clone, and40 modeled cases")
