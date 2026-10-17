"""Focused native ScriptFile wrapper and preserving compiler verification."""

from pathlib import Path
import argparse, ctypes, hashlib, importlib.util, json, subprocess, tempfile, struct
from itertools import product

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path("C:/Program Files/LLVM/bin")


def exercise_custom_loadout_gate(module):
    """Execute the emitted gameplay gate; stock policy remains the callee."""
    # The imported stock policy explicitly invokes its mode callback on self.
    policy = module.exported("2398.gscbin", 0x1193)
    assert module.stock_instruction(policy, 0x44)[0] == b"\x3a"
    assert module.stock_instruction(policy, 0x45)[0] == bytes.fromhex("7b94110000")
    assert module.stock_instruction(policy, 0x4A)[0] == b"\x4a"
    cases = 0
    for slot, push in ((0, b"\x5c"), (1, b"\x16\x01"), (-1, b"\x51\x01")):
        code, source = module.custom_loadout_slot(push)
        assert source == bytes.fromhex("5e09000093110000")
        for uses_match_rules, match_rules, class_choice in product(
            (False, True), (None, False, True), (False, True),
        ):
            pc, stack, calls, field_reads, rules_calls = 0, [], 0, 0, 0
            while pc < len(code):
                op = code[pc]; pc += 1
                if op in (0x16, 0x51):
                    stack.append(code[pc] * (-1 if op == 0x51 else 1)); pc += 1
                elif op == 0x5C: stack.append(0)
                elif op == 0x7B:
                    assert struct.unpack_from("<I", code, pc)[0] == 0x8267; pc += 4
                    stack.append(match_rules); field_reads += 1
                elif op == 0x1D:
                    assert code[pc:pc+2] == bytes.fromhex("2101"); pc += 2
                    stack.append(uses_match_rules); rules_calls += 1
                elif op == 0xA5: stack.append(not stack.pop())
                elif op in (0xA8, 0x59): stack.append(bool(stack.pop()))
                elif op in (0x19, 0x1C):
                    delta = struct.unpack_from("<h", code, pc)[0]; pc += 2
                    if bool(stack[-1]) == (op == 0x1C): pc += delta
                    else: stack.pop()
                elif op == 0x75:
                    pc += 3; calls += 1; stack.append(class_choice)
                elif op == 0x72:
                    delta = struct.unpack_from("<h", code, pc)[0]; pc += 2
                    if not stack.pop(): pc += delta
                elif op == 0x58: stack.pop()
                elif op in (0x8B, 0x4E):
                    right, left = stack.pop(), stack.pop()
                    stack.append(left * right if op == 0x8B else left - right)
                else: raise AssertionError((hex(op), pc))
            permitted = not uses_match_rules or bool(match_rules)
            # False class-choice includes Gunfight's prescribed mode weapons;
            # true includes ordinary TDM and a later mode-authorized loadout.
            assert stack == [slot if permitted and class_choice else -2]
            assert calls == int(permitted)
            assert field_reads == int(uses_match_rules) and rules_calls == 1
            cases += 1
    return cases


def exercise_mp_class_refresh(module):
    """Run the inserted bytecode, retaining separate cache and grant roots."""
    edit = module.mp_class_refresh_edit()
    stock = module.exported("1827.gscbin", 0x5CF8)
    functions = {int(e["function_at"], 16): e["name"].get("string", e["name"].get("id"))
                 for e in stock[2] if "function_at" in e}
    references = {r.operand: functions[r.target] for r in edit.references}
    gate, gate_source = module.custom_loadout_gate()
    assert edit.source == gate_source and len(references) == 2
    cases = 0
    for receiver in ("managed", "managed_dead", "human", "generic", "br", "pre_bind"):
        for uses_match_rules, permission, class_choice, cached in product(
            (False, True), (None, False, True), (False, True), (False, True),
        ):
            original = dict(primary="stock-primary", secondary="stock-secondary", other=17)
            grant = original
            fields = {0x9C56: original if cached else None}
            stack, calls, pc, field_reads, rules_calls = [], [], 0, 0, 0
            while pc < len(edit.new):
                op = edit.new[pc]; pc += 1
                if op == 0x7B:
                    assert struct.unpack_from("<I", edit.new, pc)[0] == 0x8267; pc += 4
                    stack.append(permission); field_reads += 1
                elif op == 0x1D:
                    assert edit.new[pc:pc+2] == bytes.fromhex("2101"); pc += 2
                    stack.append(uses_match_rules); rules_calls += 1
                elif op == 0xA5: stack.append(not stack.pop())
                elif op == 0xA8: stack.append(bool(stack.pop()))
                elif op in (0x19, 0x1C):
                    delta = struct.unpack_from("<h", edit.new, pc)[0]; pc += 2
                    if bool(stack[-1]) == (op == 0x1C): pc += delta
                    else: stack.pop()
                elif op == 0x75:
                    assert edit.new[pc:pc+3] == gate[-4:-1]; pc += 3
                    calls.append("stock-class-choice")
                    stack.append(class_choice)
                elif op == 0x59: stack.append(bool(stack.pop()))
                elif op == 0x3A: stack.append("self")
                elif op == 0x7E:
                    assert struct.unpack_from("<H", edit.new, pc)[0] == 0x8789; pc += 2
                    assert stack.pop() == "self"
                    stack.append(receiver in ("managed", "managed_dead"))
                elif op == 0x72:
                    delta = struct.unpack_from("<h", edit.new, pc)[0]; pc += 2
                    if not stack.pop(): pc += delta
                elif op == 0x15: stack.append("marker")
                elif op == 0x3E: stack.append(grant)
                elif op == 0x16: stack.append(edit.new[pc]); pc += 1
                elif op == 0x1A: stack.append(None)
                elif op == 0x98:
                    target = references[pc]; pc += 3
                    assert stack.pop() is grant
                    if target == "loadout_copyclassstruct":
                        assert stack.pop() == "marker"
                        fresh = dict(grant, primary="profile-primary", secondary="profile-secondary")
                        stack.append(fresh); calls.append("clone-and-reconstruct")
                    else:
                        assert target == "0x9c55"
                        assert stack.pop() is None and stack.pop() == 1 and stack.pop() == "marker"
                        calls.append(("native-preload", grant["primary"], grant["secondary"]))
                        fields[0x9C56] = grant; stack.append(None)
                elif op == 0x24: grant = stack.pop()
                elif op == 0x58: stack.pop()
                elif op == 0x36: stack.append("self-object")
                elif op == 0x25:
                    assert stack.pop() == "self-object"
                    token = struct.unpack_from("<I", edit.new, pc)[0]; pc += 4
                    assert token == 0x9C56; fields[token] = None
                else: raise AssertionError((hex(op), pc))
            assert not stack
            assert original == dict(primary="stock-primary", secondary="stock-secondary", other=17)
            permitted = not uses_match_rules or bool(permission)
            choice_calls = ["stock-class-choice"] if permitted else []
            assert field_reads == int(uses_match_rules) and rules_calls == 1
            if permitted and class_choice and receiver in ("managed", "managed_dead"):
                assert grant is not original and grant["other"] == 17
                assert calls == choice_calls + ["clone-and-reconstruct", ("native-preload", "profile-primary", "profile-secondary")]
                assert fields[0x9C56] is None
            else:
                assert grant is original and calls == choice_calls
                assert fields[0x9C56] is (original if cached else None)
            cases += 1
    return cases


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
    custom_loadout_execution = exercise_custom_loadout_gate(module)
    mp_class_execution = exercise_mp_class_refresh(module)
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
            assert len(result["function_edits"]) == 2 and len(result["source_insertions"]) == 3
            assert len(result["inserted_references"]) == 3
            assert result["survival_policy"]["cooldown_ms"] == 500
        if result["mp_class_refresh"]:
            assert result["mp_class_refresh"]["method_id"] == 0x8789
            assert len(result["function_edits"]) == 2
            assert len(result["inserted_references"]) == 2
            text = Path(fresh["path"]).read_text()
            assert "loadout_copyclassstruct( var_6 )" in text
            assert "preloadandqueueclassstruct( var_6, undefined, 1 )" in text
        text = Path(fresh["path"]).read_text()
        gate_count = (
            5 if result["asset_name"] == "1827" else
            1 if result["inserted_survival_method_id"] else 3
        )
        assert text.count("istrue( level.matchrules_allowcustomclasses )") == gate_count
        assert text.count("!isusingmatchrulesdata() || istrue( level.matchrules_allowcustomclasses )") == gate_count
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
        all_three_custom_method_contracts_verified=True,
        mp_class_refresh_fragment_cases=mp_class_execution,
        custom_loadout_permission_fragment_cases=custom_loadout_execution,
        fresh_decompile_all_assets=True,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(
        "PASS: compiled whole ScriptFile wrapper, native overlay package and preserving GSC transforms"
    )


if __name__ == "__main__":
    main()
