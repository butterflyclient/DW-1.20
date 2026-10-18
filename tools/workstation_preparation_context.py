"""Job-scoped preparation reuse; never changes native ownership/check policy.

Catalogs and parsed original PE data are read-only. Generated files actually
read by this context are SHA256 checked again at the preparation boundary.
SourceWorkspace's original SQLite signature/quarantine/name validation still
runs through its existing _rows() implementation, using one shared view.
"""

import hashlib
import json
from pathlib import Path
import threading

import pefile

from preparation_instruction_source import LazyInstructionSource

ORIGINAL = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe").resolve()
ORIGINAL_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
_documents = {}
_guards = {}
_contexts = {}
_target_pe = None
_lock = threading.RLock()


def _deny_mutation(*args, **kwargs):
    raise TypeError("Preparation input is read-only; copy it before editing")


class FrozenDict(dict):
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = (
        __ior__
    ) = _deny_mutation


class FrozenList(list):
    __setitem__ = __delitem__ = append = extend = insert = pop = remove = clear = (
        _deny_mutation
    )
    reverse = sort = __iadd__ = __imul__ = _deny_mutation


def freeze(value):
    if isinstance(value, dict):
        return FrozenDict({key: freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return FrozenList(freeze(item) for item in value)
    return value


def guarded_bytes(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    previous = _guards.setdefault(path, digest)
    if previous != digest:
        raise ValueError("Preparation input changed: " + str(path))
    return data


def cached_input_json(path):
    path = Path(path).resolve()
    with _lock:
        if path not in _documents:
            _documents[path] = freeze(json.loads(guarded_bytes(path)))
        document = _documents[path]
    # FunctionIndex adds function_entries to the top-level manifest. Nested
    # recovered source metadata stays immutable and shared.
    return dict(document) if path.name == "manifest.json" else document


class CachedOriginalPE(pefile.PE):
    def __init__(self, data):
        self._prepared_directories = {}
        super().__init__(data=data, fast_load=True)

    def parse_data_directories(
        self, directories=None, forwarded_exports_only=False, import_dllnames_only=False
    ):
        options = (forwarded_exports_only, import_dllnames_only)
        parsed = self._prepared_directories.setdefault(options, set())
        requested = (
            set(range(len(self.OPTIONAL_HEADER.DATA_DIRECTORY)))
            if directories is None
            else set(directories)
        )
        missing = sorted(requested - parsed)
        if missing:
            super().parse_data_directories(
                missing, forwarded_exports_only, import_dllnames_only
            )
            parsed.update(missing)

    set_bytes_at_offset = set_bytes_at_rva = relocate_image = _deny_mutation


def shared_original_pe(name=None, data=None, fast_load=None, **kwargs):
    global _target_pe
    # Non-target images retain pefile's normal behavior without a cache.
    target_path = name is not None and Path(name).resolve() == ORIGINAL
    if data is None and not target_path:
        return pefile.PE(name=name, data=data, fast_load=fast_load, **kwargs)
    raw = guarded_bytes(ORIGINAL) if data is None else data
    digest = hashlib.sha256(raw).hexdigest()
    if digest != ORIGINAL_SHA:
        if target_path:
            raise ValueError("Original Replay SHA256 changed")
        return pefile.PE(name=name, data=data, fast_load=fast_load, **kwargs)
    if kwargs:
        raise ValueError("Unhandled original PE construction options: " + repr(kwargs))
    _guards.setdefault(ORIGINAL, digest)
    with _lock:
        if _target_pe is None:
            _target_pe = CachedOriginalPE(raw)
        if not fast_load:
            _target_pe.parse_data_directories()
        return _target_pe


class SourceContext:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.generated = self.root / "generated"
        self.manifest = cached_input_json(self.generated / "manifest.json")
        self.catalog = cached_input_json(self.generated / "function-catalog.json")
        if self.catalog["image_sha256"] != self.manifest["input_sha256"]:
            raise ValueError("Source catalog/manifest image mismatch")
        self.instructions = LazyInstructionSource(self.generated, self.manifest)
        _guards[self.generated / "instruction-lengths.bin"] = hashlib.sha256(
            self.instructions.lengths
        ).hexdigest()
        self.native_index = None
        self.native_sources = None
        self.rows_owner = None
        self.sqlite_signature = None
        self.sqlite_signature_reader = None
        self.indexed_rows = None
        self.symbols = {}

    def attach_native_index(self, workspace, manifest):
        if self.native_index is None:
            import native_functions

            sources = [
                (section, guarded_bytes(self.generated / section["file"]))
                for section in manifest["sections"]
                if "file" in section
            ]

            def read_data(address, size):
                for section, data in sources:
                    offset = address - section["rva"]
                    if 0 <= offset and offset + size <= len(data):
                        return data[offset : offset + size]
                raise ValueError("Native metadata outside initialized source")

            owned_manifest = dict(manifest)
            owned_manifest["function_entries"] = sorted(
                {
                    row["rva"]
                    for row in (workspace._catalog or workspace._load_catalog())[
                        "functions"
                    ]
                }
            )
            self.native_index = native_functions.FunctionIndex(
                owned_manifest, read_data, self.instructions.lengths
            )
            self.native_sources = sources
        workspace._native_index = self.native_index
        workspace._native_sources = self.native_sources

    def symbol_id(self, workspace, rva):
        if self.rows_owner is None:
            self.rows_owner = workspace
            # Preserve the original text-domain test for any new SQLite rows.
            workspace._text_bounds = [
                (section["rva"], section["rva"] + section["virtual_size"])
                for section in self.manifest["sections"]
                if section.get("flags", 0) & 0x20
            ]
        if workspace.sqlite_path != self.rows_owner.sqlite_path:
            raise ValueError(
                "Cannot share source views from different SQLite databases"
            )
        reader = self.rows_owner._entry_names.__func__.__globals__[
            "_sqlite_file_signature"
        ]
        signature = reader(self.rows_owner.sqlite_path)
        if self.sqlite_signature is None:
            self.sqlite_signature = signature
            self.sqlite_signature_reader = reader
        elif signature != self.sqlite_signature:
            raise ValueError(
                "Replay SQLite changed during preparation; start a fresh preparation"
            )
        rows = self.rows_owner._rows()
        if reader(self.rows_owner.sqlite_path) != self.sqlite_signature:
            raise ValueError("Replay SQLite changed while resolving source symbols")
        if rows is not self.indexed_rows:
            grouped = {}
            for row in rows:
                grouped.setdefault(row["rva"], []).append(row)
            self.symbols = {}
            for address, candidates in grouped.items():
                functions = [
                    row
                    for row in candidates
                    if row.get("kind", "function") == "function"
                ]
                self.symbols[address] = {row["id"] for row in functions or candidates}
            self.indexed_rows = rows
        identities = self.symbols.get(rva, set())
        if len(identities) != 1:
            raise ValueError(
                f"Recovered assembly reference {rva:#x} has no unique stable catalog identity"
            )
        return next(iter(identities))


def source_context(root):
    key = Path(root).resolve()
    with _lock:
        if key not in _contexts:
            _contexts[key] = SourceContext(key)
        return _contexts[key]


def verify_boundary():
    for context in _contexts.values():
        if (
            context.rows_owner is not None
            and context.sqlite_signature_reader(context.rows_owner.sqlite_path)
            != context.sqlite_signature
        ):
            raise ValueError("Replay SQLite changed before preparation boundary")
        for index in context.instructions.loaded:
            path = (
                context.generated / "asm" / context.instructions.chunks[index]["file"]
            )
            # The parser's exact source text is immutable during this session.
            expected = context.instructions.loaded_hashes[index]
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError("Compiler assembly input changed: " + str(path))
    for path, expected in _guards.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Preparation input changed at boundary: " + str(path))
    return dict(checked_files=len(_guards), source_contexts=len(_contexts))


def reset_context():
    """Release every job-owned buffer; a later job always reloads latest inputs."""
    global _target_pe
    with _lock:
        _documents.clear()
        _guards.clear()
        _contexts.clear()
        _target_pe = None
