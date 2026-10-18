"""Execute the actual BR roaming splice branches with modeled native methods.

This checks bytecode/source relocation and fresh decompilation, not a game run.
"""

import argparse
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load_preparer(snapshot):
    sys.path.insert(0, str(ROOT / "tools"))
    sys.path.append(str(snapshot / "tools"))
    path = ROOT / "tools/prepare-bot-style-scripts.py"
    spec = importlib.util.spec_from_file_location("br_roam_script_preparer", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.load_tools(snapshot)
    return module


def exercise(
    module, code, events, begin, stop, state, stationary, reachable=True, condition=None, ready_defined=True
):
    by_pc = {int(event["pc"], 16): event for event in events if "pc" in event}
    stack = [] if condition is None else [condition]
    locals_ = [stationary]
    fields = {}
    calls = []
    pc = begin
    for _ in range(200):
        if pc in stop:
            return dict(pc=pc, calls=calls, stack=stack, locals=locals_, fields=fields)
        event = by_pc[pc]
        next_pc = int(event["next_pc"], 16)
        op = code[pc]
        if op == 0x75:
            token = event["second"].get("id")
            if token == "0x584b":
                stack.append(4000.0)
            elif token == "0x584a":
                stack.append((100.0, 200.0, 0.0))
            elif token == "0x5aa8":
                calls.append("random-ground-nearest")
                stack.append((8000.0, 1000.0, 0.0))
            else:
                raise AssertionError(("unexpected import", event))
        elif op == 0x7B:
            token = int(event["canonical_token"]["id"], 16)
            stack.append({0x22C2: "br_circle", 0x2300: "br_level"}[token])
        elif op == 0x00:
            pass  # Native cast-field-object retains the modeled object value.
        elif op == 0x2C:
            token = int(event["canonical_token"]["id"], 16)
            owner = stack.pop()
            if token == 0x2D32:
                assert owner == "br_circle"
                stack.append(1)
            else:
                assert token == 0x22CA and owner == "br_level"
                stack.append([8000.0, 5000.0, 3000.0])
        elif op == 0x02:
            right, left = stack.pop(), stack.pop()
            stack.append(left + right)
        elif op == 0x39:
            array, index = stack.pop(), stack.pop()
            stack.append(array[index])
        elif op == 0x3A:
            stack.append("self")
        elif op in (0x7E, 0x7F, 0x80, 0x84):
            count = {0x7E: 0, 0x7F: 1, 0x80: 2}.get(op, code[pc + 1])
            operand = pc + (2 if op == 0x84 else 1)
            method = struct.unpack_from("<H", code, operand)[0]
            assert stack.pop() == "self"
            arguments = [stack.pop() for _ in range(count)]
            if method == module.ROAM_REQUEST_METHOD_ID:
                assert arguments == [(100.0, 200.0, 0.0), 3000.0]
                calls.append("request")
                stack.append(state)
            elif method == module.ROAM_GOAL_METHOD_ID:
                calls.append("cached-goal")
                stack.append((6000.0, 2000.0, 0.0) if ready_defined else None)
            elif method == module.ROAM_CANCEL_METHOD_ID:
                calls.append("cancel")
                stack.append(True)
            elif method == 0x86CD:
                calls.append("reachable")
                stack.append((7000.0, 1000.0, 0.0) if reachable else None)
            elif method == 0x8057:
                assert arguments[1:] == [1024, "hunt", None, None, not stationary]
                calls.append("set-goal")
                fields["installed-goal"] = arguments[0]
                stack.append(True)
            else:
                raise AssertionError(("unexpected method", hex(method)))
        elif op in (0x18, 0x3C):
            field = event.get("token", {}).get("string")
            if field is None:
                token = event.get("canonical_token", {}).get("id")
                assert token == "0x78df", event
                field = "lasttimereachedscriptgoal"
            if op == 0x18:
                fields[field] = stack.pop()
                if field == "lasttimereachedscriptgoal":
                    calls.append("timestamp")
            else:
                stack.append(fields.get(field))
        elif op == 0x16:
            stack.append(code[pc + 1])
        elif op == 0x10:
            right, left = stack.pop(), stack.pop()
            stack.append(left == right)
        elif op in (0x0E, 0x72):
            value = bool(stack.pop())
            if value == (op == 0x0E):
                next_pc += struct.unpack_from("<h", code, pc + 1)[0]
        elif op == 0x94:
            next_pc += struct.unpack_from("<i", code, pc + 1)[0]
        elif op == 0x5B:
            locals_.append(stack.pop())
        elif op in (0x3E, 0x3F, 0x40):
            stack.append(locals_[-1 - (op - 0x3E)])
        elif op == 0x77:
            stack.append(not stack.pop())
        elif op == 0x1A:
            stack.append(None)
        elif op == 0x7A:
            stack.append(event["string"]["string"])
        elif op == 0x66:
            stack.append(struct.unpack_from("<H", code, pc + 1)[0])
        elif op == 0x58:
            stack.pop()
        elif op == 0x1D:
            assert struct.unpack_from("<H", code, pc + 1)[0] == 0xD7
            stack.append(12345)
        elif op == 0xA7:
            stack.append(stack.pop() is not None)
        elif op == 0x03:
            del locals_[-code[pc + 1] :]
        else:
            raise AssertionError(("unmodeled executed opcode", hex(pc), hex(op)))
        pc = next_pc
    raise AssertionError("Roam fragment did not reach the original cleanup boundary")


def check(snapshot, output, build=None):
    linked_hash = None
    if build is not None:
        report = json.loads((build / "build-report.json").read_bytes())
        assert Path(report["source_root"]).resolve() == snapshot.resolve()
        assert (
            hashlib.sha256(Path(report["executable"]).read_bytes()).hexdigest()
            == report["sha256"]
        )
        assert (ROOT / "tools/prepare-bot-style-scripts.py").read_bytes() == (
            snapshot / "tools/prepare-bot-style-scripts.py"
        ).read_bytes()
        linked_hash = report["sha256"]
    module = load_preparer(snapshot)
    original = module.exported("scripts/mp/bots/bots_gametype_br.gsc.gscbin", 0x2039)
    original_start = int(original[3]["function_at"], 16)
    plan = module.plans(module.METHOD_ID)[0]
    starts = {
        event["name"].get("string", int(event["name"].get("id", "0"), 16)): int(
            event["function_at"], 16
        )
        for event in original[2]
        if "function_at" in event
    }
    edits = [
        (
            starts[
                (
                    edit.function_token
                    if edit.function_token is not None
                    else plan.function_token
                )
            ]
            + edit.offset,
            edit,
        )
        for edit in plan.edits
    ]

    def mapped(offset):
        position = original_start + offset
        return position + sum(
            len(edit.new) - len(edit.old) for at, edit in edits if at < position
        )

    with tempfile.TemporaryDirectory(
        prefix="br-roam-script-", dir=ROOT / "data"
    ) as directory:
        module.OUT = Path(directory)
        result = module.transform(plan, module.METHOD_ID, bound=True)
        path = Path(result["output_path"])
        _, code = module.parts(path.read_bytes())
        events = module.trace(path, len(code), strict=True)
        rows = []
        for state in (0, 1, 2):
            for stationary in (False, True):
                row = exercise(
                    module,
                    code,
                    events,
                    mapped(0x359),
                    {mapped(0x388)},
                    state,
                    stationary,
                )
                expected = {
                    0: [
                        "request",
                        "random-ground-nearest",
                        "reachable",
                        "set-goal",
                        "timestamp",
                    ],
                    1: ["request"],
                    2: ["request", "cached-goal", "set-goal", "timestamp"],
                }[state]
                assert row["calls"] == expected, row
                assert row["stack"] == [] and row["locals"] == [stationary], row
                rows.append(
                    dict(
                        state=state,
                        stationary=stationary,
                        calls=row["calls"],
                        original_survival_continuation=True,
                    )
                )
        denied = exercise(
            module, code, events, mapped(0x359), {mapped(0x388)}, 0, False, False
        )
        assert denied["calls"] == ["request", "random-ground-nearest", "reachable"]
        for stationary in (False, True):
            stale = exercise(
                module, code, events, mapped(0x359), {mapped(0x388)},
                2, stationary, ready_defined=False,
            )
            assert stale["calls"] == ["request", "cached-goal"], stale
            assert stale["stack"] == [] and stale["locals"] == [stationary], stale
        gate = next(edit for _, edit in edits if edit.control_rewrites)
        for allowed in (False, True):
            row = exercise(
                module,
                code,
                events,
                mapped(gate.offset),
                {mapped(0x26D), mapped(0x38A)},
                0,
                False,
                condition=allowed,
            )
            assert row["calls"] == ([] if allowed else ["cancel"])
            assert row["pc"] == mapped(0x26D if allowed else 0x38A)
            assert row["stack"] == []
        cancellation_cases = 0
        for _, edit in edits:
            if edit.purpose.startswith("Cancel") and not edit.control_rewrites:
                begin = mapped(edit.offset)
                row = exercise(
                    module, code, events, begin, {begin + len(edit.new)}, 0, False
                )
                assert row["calls"] == ["cancel"] and row["stack"] == []
                cancellation_cases += 1
        assert cancellation_cases == 8
        control = next(edit for edit in plan.edits if edit.control_rewrites)
        malformed = replace(
            control,
            control_rewrites=(replace(control.control_rewrites[0], original_target=0),),
        )
        invalid_plan = replace(
            plan,
            edits=tuple(malformed if edit is control else edit for edit in plan.edits),
        )
        try:
            module.transform(invalid_plan, module.METHOD_ID, bound=True)
        except ValueError:
            pass
        else:
            raise AssertionError("Malformed control rewrite was accepted")
        if build is not None:
            package = json.loads(
                (snapshot / "generated/bot-style-scripts-integration.json").read_bytes()
            )
            package_proof = json.loads(Path(package["package_proof"]).read_bytes())
            asset = next(
                row
                for row in package_proof["asset_results"]
                if row["asset_name"] == result["asset_name"]
            )
            assert asset["output_sha256"] == result["output_sha256"]
            assert asset["br_roam_policy"]["fresh_structured_decompile"]
        from workstation_asset_codecs import decompile_scriptfile

        config = json.loads((snapshot / "replay-project.local.json").read_bytes())
        tool = Path(config["tools"]["gsc"]["path"])
        assert (
            hashlib.sha256(tool.read_bytes()).hexdigest()
            == config["tools"]["gsc"]["sha256"]
        )
        fresh = decompile_scriptfile(
            path.read_bytes(), tool=tool, asset_name="bots_gametype_br.gsc"
        )
        main = fresh.split("bot_br_think()\n{", 1)[1].split(
            "\nbot_parachute_into_map()", 1
        )[0]
        assert "__asm" not in main
        assert main.count("self.dw_roam_state = ") == 1
        assert main.count(" botsetscriptgoal(") == 2
        assert main.count("getrandompointincurrentcircle()") == 1
        assert main.count("getclosestreachablepointonnavmesh( var_25 )") == 1
        assert "dw_survival_next_ms" in main and "gettime() + 500" in main
        fresh_path = output.with_suffix(".fresh.gsc")
        fresh_path.write_bytes(fresh.encode())
        proof = dict(
            passed=True,
            scope=__doc__,
            game_execution=False,
            preparer_sha256=hashlib.sha256(
                (ROOT / "tools/prepare-bot-style-scripts.py").read_bytes()
            ).hexdigest(),
            original_sha256=result["original_sha256"],
            transformed_sha256=result["output_sha256"],
            strict_source_cursor=result["strict_native_source_cursor_passed"],
            exact_original_reconstruction=result[
                "exact_original_reconstruction_passed"
            ],
            preserved_imports_tokens=result["export_import_source_identity_preserved"],
            branches=rows,
            fallback_undefined_preserves_no_goal=True,
            ready_undefined_preserves_no_goal=True,
            ready_undefined_cases=2,
            authored_radius_3000_dynamic_radius_4000=True,
            linked_executable_sha256=linked_hash,
            linked_bytecode_package_verified=build is not None,
            explicit_cancellation_cases=cancellation_cases,
            malformed_control_rewrite_rejected=True,
            ownership_gate_cases=2,
            cancellation_sites=result["br_roam_policy"]["cancellation_sites"],
            typed_control_rewrites=result["br_roam_policy"]["typed_control_rewrites"],
            fresh_decompile=dict(
                path=str(fresh_path),
                sha256=hashlib.sha256(fresh.encode()).hexdigest(),
                tool_sha256=config["tools"]["gsc"]["sha256"],
                no_assembly_fallback=True,
            ),
        )
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result = check(args.snapshot, args.output, args.build)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
