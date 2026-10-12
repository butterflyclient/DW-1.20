"""Focused native ScriptFile wrapper and preserving compiler verification."""

from pathlib import Path
import argparse, ctypes, hashlib, importlib.util, json, subprocess, tempfile, struct

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path("C:/Program Files/LLVM/bin")


def exercise_survival(module):
    """Execute the actual inserted opcodes; model only native/script callees."""
    gas, armor = module.survival_edits()
    bot = module.exported("scripts/mp/bots/bots_gametype_br.gsc.gscbin", 0x2039)
    names = {int(e["function_at"], 16): e["name"].get("string")
             for e in bot[2] if "function_at" in e}
    def execute(edit, state):
        pc, stack, locals_, calls = 0, [], [], []
        refs = {r.operand: names[r.target] for r in edit.references}
        while pc < len(edit.new):
            op = edit.new[pc]; pc += 1
            if op in (0x3C, 0x18):
                field = struct.unpack_from("<I", edit.new, pc)[0]; pc += 4
                if op == 0x3C:
                    stack.append(state.get("next") if field == 0xFFFFFFFF else state["inserting"])
                else:
                    assert field == 0xFFFFFFFF
                    state["next"] = stack.pop()
            elif op == 0xA7: stack.append(stack.pop() is not None)
            elif op in (0xA5, 0xA8, 0x59):
                value = bool(stack.pop()); stack.append(not value if op == 0xA5 else value)
            elif op in (0x72, 0x0E, 0x1C):
                delta = struct.unpack_from("<h", edit.new, pc)[0]; pc += 2
                value = bool(stack[-1])
                if op != 0x1C or not value: stack.pop()
                if (not value if op == 0x72 else value): pc += delta
            elif op == 0x1D:
                assert edit.new[pc:pc + 2] == bytes.fromhex("d700"); pc += 2
                stack.append(state["now"])
            elif op == 0x66:
                stack.append(struct.unpack_from("<H", edit.new, pc)[0]); pc += 2
            elif op in (0x02, 0x53):
                right, left = stack.pop(), stack.pop()
                stack.append(left + right if op == 0x02 else left >= right)
            elif op == 0x4F:
                name = refs[pc]; pc += 3; calls.append(name)
                stack.append(state["gas"] if name == "bot_is_in_gas" else state["point"])
            elif op == 0x5B:
                # The index byte is mandatory; omitting it corrupts stack/local
                # scope even when a cursor-only structural trace succeeds.
                assert edit.new[pc] == 27; pc += 1; locals_.append(stack.pop())
            elif op == 0x3E: stack.append(locals_[-1])
            elif op == 0x03:
                assert edit.new[pc] == 1; pc += 1; locals_.pop()
            elif op in (0x5C, 0x1A, 0x3A, 0x15):
                stack.append({0x5C: 0, 0x1A: None, 0x3A: "self", 0x15: "call"}[op])
            elif op == 0x16: stack.append(edit.new[pc]); pc += 1
            elif op == 0x7A: pc += 4; stack.append("critical")
            elif op == 0x7E:
                assert struct.unpack_from("<H", edit.new, pc)[0] == 0x8788; pc += 2
                assert stack.pop() == "self"; calls.append("dw_bot_survival"); stack.append(state["allowed"])
            elif op == 0x84:
                assert edit.new[pc:pc + 3] == bytes.fromhex("065780"); pc += 3
                assert stack.pop() == "self"
                arguments = [stack.pop() for _ in range(6)]
                assert arguments == [state["point"], 128, "critical", None, None, 0]
                calls.append("critical_goal"); stack.append(None)
            elif op == 0x60:
                pc += 3; assert stack.pop() is None and stack.pop() == "call"
                calls.append("playerusehealslot"); stack.append(None)
            elif op == 0x58: stack.pop()
            else: raise AssertionError(f"Unmodeled inserted opcode {op:#x}")
        assert not stack and not locals_, "Survival insertion leaked evaluation/local scope"
        return calls
    idle = dict(now=1000, gas=False, point=(1, 2, 3), allowed=True, inserting=False)
    assert execute(gas, idle) == ["bot_is_in_gas"]
    assert execute(armor, idle) == ["bot_is_in_gas", "dw_bot_survival", "playerusehealslot"]
    assert idle["next"] == 1500
    idle["now"] = 1499
    assert execute(gas, idle) == execute(armor, idle) == [] and idle["next"] == 1500
    idle["now"] = 1500
    assert execute(armor, idle)[-1] == "playerusehealslot" and idle["next"] == 2000
    for point in ((10, 20, 30), None):
        state = dict(now=3000, gas=True, point=point, allowed=True, inserting=False)
        calls = execute(gas, state)
        assert ("critical_goal" in calls) == (point is not None)
        assert execute(armor, state) == ["bot_is_in_gas"] and state["next"] == 3500
    for allowed, inserting in ((False, False), (True, True)):
        state = dict(now=4000, gas=False, point=None, allowed=allowed, inserting=inserting)
        assert "playerusehealslot" not in execute(armor, state) and state["next"] == 4500
    return dict(actual_inserted_opcodes_executed=True, native_and_script_callees_modeled=True,
                cooldown_boundary_checked=True, no_stack_or_local_leak=True,
                gas_goal_payload_checked=True, absent_safe_point_checked=True,
                armor_yields_to_gas_and_insertion=True, denied_armor_cadence_checked=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve()
    if args.build:
        build = json.loads((args.build / "build-report.json").read_bytes())
        assert not build["unresolved_symbols"]
        assert hashlib.sha256(Path(build["executable"]).read_bytes()).hexdigest() == build["sha256"]
        assert hashlib.sha256((snapshot / "src/DW_BotStyleScripts.cpp").read_bytes()).hexdigest() in {
            row["source_sha256"] for row in build["cpp"]
        }
    spec = importlib.util.spec_from_file_location(
        "script_prepare", ROOT / "tools/prepare-bot-style-scripts.py"
    )
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    proof = json.loads(
        (snapshot / "generated/bot-style-scripts-integration.json").read_bytes()
    )
    binding = module.method_binding(snapshot)
    assert binding == proof["method_binding"]
    module.load_tools(snapshot)
    policy_execution = exercise_survival(module)
    native = module.inspect_native(snapshot)
    assert native == proof["native"]
    package = json.loads(Path(proof["package_proof"]).read_bytes())
    assert (
        package["native_reader"]["manifest"]["complete"]
        and package["native_reader"]["manifest"]["success"]
    )
    assert package["native_reader"]["manifest"]["top_level_index"] == 3
    empty = package["empty_companion"]["native_reader"]["manifest"]
    assert empty["complete"] and empty["success"] and empty["top_level_index"] == 0
    manifest = package["installation_manifest"]
    assert package["native_locale_codes"]["supported_language_directories"] == {"eng": "english"}
    assert len(manifest) == 20
    assert all(
        Path(row["source"]).is_relative_to(snapshot / "generated/bot-style-scripts")
        for row in manifest
    )
    assert all(
        hashlib.sha256(Path(row["source"]).read_bytes()).hexdigest() == row["sha256"]
        for row in manifest
    )
    for result in package["asset_results"]:
        assert result["method_bound"] and result["inserted_method_id"] == 0x8787
        assert (
            result["strict_native_source_cursor_passed"]
            and result["exact_original_reconstruction_passed"]
        )
        assert result["export_import_source_identity_preserved"]
        fresh = result["fresh_decompile"]
        assert hashlib.sha256(Path(fresh["path"]).read_bytes()).hexdigest() == fresh["sha256"]
        if result["inserted_survival_method_id"]:
            assert result["inserted_survival_method_id"] == 0x8788
            assert len(result["function_edits"]) == 2 and len(result["source_insertions"]) == 2
            assert len(result["inserted_references"]) == 3
            assert result["survival_policy"]["cooldown_ms"] == 500
        assert (
            hashlib.sha256(Path(result["output_path"]).read_bytes()).hexdigest()
            == result["output_sha256"]
        )
    source = ROOT / "integration/replay/DW_BotStyleScripts.cpp"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == proof["source_sha256"]
    header = snapshot / "src/DW_BotStyleScriptPackage.h"
    assert (
        hashlib.sha256(header.read_bytes()).hexdigest()
        == proof["generated_header_sha256"]
    )
    with tempfile.TemporaryDirectory(
        prefix="bot-style-scripts-", dir=ROOT / "build"
    ) as temporary:
        folder = Path(temporary)
        obj = folder / "test.obj"
        dll = folder / "test.dll"
        flags = [
            "--target=x86_64-pc-windows-msvc",
            "-std=c++20",
            "-O2",
            "-ffreestanding",
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-stack-protector",
            "-mno-stack-arg-probe",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(snapshot / "src"),
        ]
        subprocess.run(
            [
                str(LLVM / "clang++.exe"),
                *flags,
                "-c",
                str(source),
                "-o",
                str(folder / "production.obj"),
            ],
            check=True,
        )
        subprocess.run(
            [
                str(LLVM / "clang++.exe"),
                *flags,
                "-c",
                str(ROOT / "tools/bot_style_scripts_harness.cpp"),
                "-o",
                str(obj),
            ],
            check=True,
        )
        subprocess.run(
            [
                str(LLVM / "lld-link.exe"),
                "/dll",
                "/noentry",
                "/nodefaultlib",
                "/opt:ref",
                "/out:" + str(dll),
                str(obj),
            ],
            check=True,
        )
        library = ctypes.CDLL(str(dll))
        try:
            result = library.Test_Run()
            assert result == 0, f"Compiled script wrapper failed at line {result}"
        finally:
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(library._handle)
    proof.update(
        passed=True,
        production_object_compiled=True,
        compiled_harness_passed=True,
        native_overlay_ff_recompiled_and_read=True,
        all_three_scriptfile_exports_exact=True,
        original_code_source_import_export_reconstruction=True,
        game_run_performed=False,
        survival_fragment_execution=policy_execution,
        both_custom_method_contracts_verified=True,
        fresh_decompile_all_assets=True,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(
        "PASS: compiled whole ScriptFile wrapper, native overlay package and preserving GSC transforms"
    )


if __name__ == "__main__":
    main()
