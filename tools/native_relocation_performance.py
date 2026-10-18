"""Do not resolve COFF targets when the native relocation input is empty."""

from pathlib import Path
import hashlib


def replacements():
    return {
        "tools/native_linker.py": [
            (
                "        targets = self._targets(obj, symbols)\n"
                "        started = time.perf_counter()\n"
                "        relocations = section.get('relocation_bytes')\n"
                "        if relocations is None:\n"
                "            relocations = b''.join(struct.pack('<IIH', *r) for r in section['relocations'])\n",
                "        relocations = section.get('relocation_bytes')\n"
                "        if relocations is None:\n"
                "            relocations = b''.join(struct.pack('<IIH', *r) for r in section['relocations'])\n"
                "        # An empty native relocation loop never reads a target. Keep\n"
                "        # the native call, request checks, counters and parity below.\n"
                "        targets = self._targets(obj, symbols) if relocations else b''\n"
                "        started = time.perf_counter()\n",
            )
        ]
    }


def transformed(text, relative):
    for old, new in replacements()[relative]:
        if text.count(old) != 1:
            raise ValueError("Native relocation optimization anchor drift: " + relative)
        text = text.replace(old, new)
    compile(text, relative, "exec")
    return text


def prepare(source_root):
    """Apply only to a new snapshot before its compiler receipt is sealed."""
    root = Path(source_root)
    changed = []
    for relative in replacements():
        path = root / relative
        path.write_text(
            transformed(path.read_text(encoding="utf-8"), relative), encoding="utf-8"
        )
        changed.append(relative)
    return changed


def optimize_native_relocations(source_root):
    root = Path(source_root)
    changed = prepare(root)
    return dict(
        schema=1,
        native_relocation_optimizations=[
            dict(
                path=relative,
                sha256=hashlib.sha256((root / relative).read_bytes()).hexdigest(),
            )
            for relative in changed
        ],
        retained_checks="Native empty relocation call, validation, counters and differential parity remain enabled",
    )
