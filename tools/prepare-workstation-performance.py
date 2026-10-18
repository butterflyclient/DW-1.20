"""Stage exact preparation optimizations into an unsealed private source copy.

Authored preparer call-site patches are emitted separately for review. This
helper changes only private SourceWorkspace implementation and verifier copies;
all transformations and helper bytes are recorded with before/after SHA256.
"""

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_function(text, name, replacement):
    tree = ast.parse(text)
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1:
        raise ValueError("Ambiguous source optimization anchor: " + name)
    node = matches[0]
    lines = text.splitlines(keepends=True)
    lines[node.lineno - 1 : node.end_lineno] = [replacement]
    return "".join(lines)


def cached_json_calls(text, include_manifest=False):
    edits = []
    lines = text.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    for node in ast.walk(ast.parse(text)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id == "pefile" and node.func.attr == "PE":
            start = offsets[node.func.lineno - 1] + node.func.col_offset
            end = offsets[node.func.end_lineno - 1] + node.func.end_col_offset
            edits.append((start, end, "shared_original_pe"))
        if (
            node.func.value.id != "json"
            or node.func.attr != "loads"
            or len(node.args) != 1
            or node.keywords
        ):
            continue
        read = node.args[0]
        if not isinstance(read, ast.Call) or not isinstance(read.func, ast.Attribute):
            continue
        if read.func.attr not in ("read_text", "read_bytes"):
            continue
        path = read.func.value
        names = {
            Path(value.value).name
            for value in ast.walk(path)
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        }
        if "function-catalog.json" not in names and not (
            include_manifest and "manifest.json" in names
        ):
            continue
        start = offsets[node.lineno - 1] + node.col_offset
        end = offsets[node.end_lineno - 1] + node.end_col_offset
        edits.append((start, end, "cached_input_json(" + ast.unparse(path) + ")"))
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    if edits:
        tree = ast.parse(text)
        insert = 0
        if (
            tree.body
            and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
        ):
            insert = tree.body[0].end_lineno
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                insert = max(insert, node.end_lineno)
        lines = text.splitlines(keepends=True)
        lines.insert(
            insert,
            "\nfrom workstation_preparation_context import cached_input_json, shared_original_pe, source_context\n",
        )
        text = "".join(lines)
    return text, len(edits)


WORKSPACE_METHOD_SHA256 = {
    "_catalog_symbol": "0c8b4c2b2ec628f699b04629563e4d07bf6728f020bb4080096ad7c275c63093",
    "_function_spans": "fd368d759ed3eff95fafdf8e78ba291a63c30e2eba7236a0d1585699b804ed6d",
    "_instruction_map": "1a24b47d87cc24eeadc0801e87eec44fcab699deb90787efb9484a3f333ab992",
}


def optimize_workspace(text):
    text = text.replace("\r\n", "\n")
    lines = text.splitlines(keepends=True)
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.FunctionDef) and node.name in WORKSPACE_METHOD_SHA256:
            body = "".join(lines[node.lineno - 1 : node.end_lineno]).encode()
            if sha(body) != WORKSPACE_METHOD_SHA256[node.name]:
                raise ValueError("Unreviewed SourceWorkspace method: " + node.name)
    required = (
        "self._active_spans = None",
        "instructions = self._instruction_map(manifest)",
        "if self._native_index is None:",
    )
    if not all(anchor in text for anchor in required):
        raise ValueError("Unknown SourceWorkspace ownership implementation")
    text = replace_function(
        text,
        "_catalog_symbol",
        """    def _catalog_symbol(self, rva):
        return source_context(self.root).symbol_id(self, rva)
""",
    )
    text = replace_function(
        text,
        "_instruction_map",
        """    def _instruction_map(self, manifest):
        instructions = source_context(self.root).instructions
        active = getattr(self, "_active_spans", None)
        return instructions.for_spans(active) if active else instructions
""",
    )
    start = text.index(
        "        if self._native_index is None:", text.index("    def _function_spans(")
    )
    end = text.index("        index = self._native_index", start)
    text = (
        text[:start]
        + "        source_context(self.root).attach_native_index(self, manifest)\n"
        + text[end:]
    )
    text, _ = cached_json_calls(text, include_manifest=True)
    compile(text, "optimized-workstation-sources", "exec")
    return text


def prepare(source_root, receipt_path=None):
    root = Path(source_root).resolve()
    if any(
        (parent / name).exists()
        for parent in (root, root.parent)
        for name in ("source-receipt.json", "readiness.json", "client-readiness.json")
    ):
        raise ValueError(
            "Performance preparation requires an unsealed private source copy"
        )
    from workstation_preparation_context import reset_context

    reset_context()
    changed = []
    for name in (
        "workstation_preparation_context.py",
        "preparation_instruction_source.py",
    ):
        source = HERE / name
        target = root / "tools" / name
        if source.resolve() != target.resolve():
            shutil.copyfile(source, target)
        changed.append(
            dict(
                path="tools/" + name,
                sha256=sha(target.read_bytes()),
                action="copy helper",
            )
        )
    path = root / "tools/workstation_sources.py"
    before = path.read_bytes()
    after = optimize_workspace(before.decode("utf-8")).encode("utf-8")
    path.write_bytes(after)
    changed.append(
        dict(
            path="tools/workstation_sources.py",
            before_sha256=sha(before),
            sha256=sha(after),
            action="lazy source context; same native checks",
        )
    )
    verifier = HERE / "verifier_performance.py"
    verifier_receipt = None
    if verifier.exists():
        spec = importlib.util.spec_from_file_location(
            "preparation_verifier_performance", verifier
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        verifier_receipt = module.optimize_verifiers(root)
    relocation_path = HERE / "native_relocation_performance.py"
    if not relocation_path.is_file():
        raise ValueError("Missing verified native relocation performance helper")
    spec = importlib.util.spec_from_file_location(
        "preparation_native_relocation_performance", relocation_path
    )
    relocation_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(relocation_module)
    relocation_before = sha((root / "tools/native_linker.py").read_bytes())
    relocation_receipt = relocation_module.optimize_native_relocations(root)
    relocation_receipt["before_sha256"] = relocation_before
    result = dict(
        schema=1,
        helper_sha256=sha(Path(__file__).read_bytes()),
        transformed_files=changed,
        verifiers=verifier_receipt,
        native_relocations=relocation_receipt,
        boundary_validation_required=True,
        retained_checks=[
            "original SQLite name/quarantine signature checks",
            "native FunctionIndex ownership and bounded leaf CFG",
            "original instruction-size table and complete native bodies",
            "full generated-input SHA256 checks at boundary",
        ],
    )
    target = (
        Path(receipt_path)
        if receipt_path
        else root / "generated/preparation-performance.json"
    )
    target.write_text(json.dumps(result, indent=2) + "\n")
    return result


def finish(source_root):
    from workstation_preparation_context import reset_context, verify_boundary

    try:
        return verify_boundary()
    finally:
        reset_context()
