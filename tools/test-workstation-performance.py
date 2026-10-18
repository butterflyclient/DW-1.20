"""Verify preparation cache safety and the actual frozen-helper lifecycle.

Uses small temporary fixtures under tools/build. It never changes job sources,
compiler-base inputs, SQLite evidence, or game files.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import types

import workstation_preparation_context as context

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
BASE = ROOT / "data/dw-client/compiler-base"
HELPERS = (
    "prepare-workstation-performance.py",
    "workstation_preparation_context.py",
    "preparation_instruction_source.py",
    "verifier_performance.py",
    "native_relocation_performance.py",
)


def load_optimizer(path):
    spec = importlib.util.spec_from_file_location("tested_preparation_optimizer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expect_rejection(checks, label, operation):
    try:
        operation()
    except (TypeError, ValueError):
        checks.append(label)
    else:
        raise AssertionError("Expected rejection: " + label)


def check_cache_safety(directory, checks):
    path = directory / "input.json"
    path.write_text('{"rows":[{"id":"first"}]}')
    frozen = context.cached_input_json(path)
    expect_rejection(
        checks, "top-level JSON mutation", lambda: frozen.update(extra=True)
    )
    expect_rejection(
        checks, "nested JSON mutation", lambda: frozen["rows"][0].update(id="changed")
    )
    expect_rejection(checks, "nested list mutation", lambda: frozen["rows"].append({}))
    assert json.loads(json.dumps(frozen)) == {"rows": [{"id": "first"}]}
    path.write_text('{"rows":[{"id":"other"}]}')
    expect_rejection(
        checks, "consumed input changed at boundary", context.verify_boundary
    )
    context.reset_context()

    signature = [1]
    method_globals = {"_sqlite_file_signature": lambda path: tuple(signature)}
    exec("def entry_names(self):\n    return {}\n", method_globals)
    owner = types.SimpleNamespace(sqlite_path=directory / "evidence.sqlite")
    owner._entry_names = types.MethodType(method_globals["entry_names"], owner)
    rows = [
        {"rva": 16, "id": "one", "kind": "function"},
        {"rva": 16, "id": "data", "kind": "data"},
    ]
    owner._rows = lambda: rows
    source = object.__new__(context.SourceContext)
    source.rows_owner = None
    source.sqlite_signature = None
    source.sqlite_signature_reader = None
    source.manifest = {"sections": []}
    source.indexed_rows = None
    source.symbols = {}
    assert source.symbol_id(owner, 16) == "one"
    checks.append("function priority preserved over data alias")
    rows.extend([{"rva": 32, "id": "ambiguous-a"}, {"rva": 32, "id": "ambiguous-b"}])
    source.indexed_rows = None
    expect_rejection(
        checks, "ambiguous catalog identities", lambda: source.symbol_id(owner, 32)
    )
    signature[0] = 2
    expect_rejection(
        checks,
        "SQLite commit during symbol resolution",
        lambda: source.symbol_id(owner, 16),
    )
    context._contexts[directory] = source
    expect_rejection(
        checks, "SQLite commit before final boundary", context.verify_boundary
    )
    context.reset_context()
    assert not context._contexts and not context._guards and not context._documents
    checks.append("job lifetime reset releases cached buffers")


def check_frozen_lifecycle(directory, checks):
    snapshot = directory / "source"
    tools = snapshot / "tools"
    tools.mkdir(parents=True)
    (snapshot / "generated").mkdir()
    for name in HELPERS:
        shutil.copyfile(TOOLS / name, tools / name)
    for name in (
        "workstation_sources.py",
        "verify.py",
        "verify_material_technique.py",
        "native_linker.py",
    ):
        shutil.copyfile(BASE / "tools" / name, tools / name)

    optimizer = load_optimizer(tools / "prepare-workstation-performance.py")
    assert optimizer.HERE.resolve() == tools.resolve()
    result = optimizer.prepare(snapshot)
    assert (tools / "verify.py").read_bytes() == (BASE / "tools/verify.py").read_bytes()
    checks.append("aggregate preserves exact upstream core verifier bytes")
    assert (snapshot / "generated/preparation-performance.json").is_file()
    for item in result["transformed_files"]:
        assert optimizer.sha((snapshot / item["path"]).read_bytes()) == item["sha256"]
    for item in result["native_relocations"]["native_relocation_optimizations"]:
        assert optimizer.sha((snapshot / item["path"]).read_bytes()) == item["sha256"]
    boundary = optimizer.finish(snapshot)
    assert boundary["source_contexts"] == 0
    checks.append(
        "actual frozen helper in same directory prepares without SameFileError"
    )
    checks.append("aggregate transformed-file and native-linker receipt hashes match")
    checks.append("aggregate finish validates and releases job context")

    sealed = directory / "sealed"
    sealed.mkdir()
    (sealed / "source-receipt.json").write_text("{}")
    expect_rejection(
        checks, "sealed snapshot rejected", lambda: optimizer.prepare(sealed)
    )


def run():
    checks = []
    scratch = TOOLS / "build"
    scratch.mkdir(exist_ok=True)
    context.reset_context()
    try:
        with tempfile.TemporaryDirectory(
            prefix="preparation-test-", dir=scratch
        ) as temporary:
            directory = Path(temporary)
            check_cache_safety(directory, checks)
            check_frozen_lifecycle(directory, checks)
        optimizer = load_optimizer(TOOLS / "prepare-workstation-performance.py")
        original = (BASE / "tools/workstation_sources.py").read_text()
        optimizer.optimize_workspace(original)
        expect_rejection(
            checks,
            "unreviewed native ownership implementation",
            lambda: optimizer.optimize_workspace(
                original.replace(
                    "if index.owner(rva) not in (None, rva):",
                    "if index.owner(rva) not in (None, rva, 0):",
                )
            ),
        )
        manifest = json.loads((BASE / "generated/manifest.json").read_bytes())
        assert len(manifest["preparation_inputs"]) == 16
        assert all(
            Path(item["path"]).name != "native_linker.py"
            for item in manifest["preparation_inputs"]
        )
        checks.append(
            "native linker remains outside all sixteen pinned recovery inputs"
        )
        return {"passed": True, "checks": checks, "game_runs_performed": False}
    finally:
        context.reset_context()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=TOOLS / "build/workstation-performance-tests.json",
    )
    arguments = parser.parse_args()
    result = run()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
