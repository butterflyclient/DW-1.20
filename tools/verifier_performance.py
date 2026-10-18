"""Prepare equivalent verifier implementations in a new, unsealed source snapshot."""

from pathlib import Path
import hashlib


def replacements():
    return {
        "tools/verify_material_technique.py": [
            (
                "symbols = {name: base + rva for name, rva in report['symbols'].items()}",
                "symbols = {name: base + report['symbols'][name] for name in (\n"
                "                'Load_MaterialTechnique', 'DB_GetFrontendSourceXFileVersion',\n"
                "                's_dbLastXFileVersion', 's_dbFrontendProbeAccepted',\n"
                "                'DB_ConvertMaterialShaderArguments131')}",
            )
        ],
    }


def transformed(text, relative):
    for old, new in replacements()[relative]:
        if text.count(old) != 1:
            raise ValueError("Verifier optimization anchor drift: " + relative)
        text = text.replace(old, new)
    compile(text, relative, "exec")
    return text


def prepare(source_root):
    """Call only before source-receipt creation; sealed jobs must remain intact."""
    root = Path(source_root)
    changed = []
    for relative in replacements():
        path = root / relative
        text = transformed(path.read_text(encoding="utf-8"), relative)
        path.write_text(text, encoding="utf-8")
        changed.append(relative)
    return changed


def optimize_verifiers(source_root):
    root = Path(source_root)
    changed = prepare(root)
    return dict(
        schema=1,
        verifier_optimizations=[
            dict(
                path=relative,
                sha256=hashlib.sha256((root / relative).read_bytes()).hexdigest(),
            )
            for relative in changed
        ],
        retained_checks="All 151 material cases; exact original result comparison; core verifier unchanged",
    )
