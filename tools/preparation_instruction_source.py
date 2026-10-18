"""Demand-load the exact recovered compiler instruction text.

No CFG, ownership, native-byte, unwind or symbol-ambiguity checks are changed.
The leaf CFG resolver receives a Mapping instead of eagerly parsing every ASM
chunk. Only chunks containing addresses it actually visits are parsed.
"""

from bisect import bisect_right
from collections.abc import Mapping
from pathlib import Path
import hashlib
import re


class LazyInstructionSource(Mapping):
    def __init__(self, generated, manifest):
        self.generated = Path(generated)
        self.manifest = manifest
        self.text = manifest["sections"][0]["rva"]
        self.lengths = (self.generated / "instruction-lengths.bin").read_bytes()
        self.chunks = sorted(manifest["chunks"], key=lambda row: row["rva"])
        self.starts = [row["rva"] for row in self.chunks]
        for first, second in zip(self.chunks, self.chunks[1:]):
            if first["rva"] + first["size"] > second["rva"]:
                raise ValueError(
                    "Overlapping compiler chunks require original eager resolution"
                )
        self.loaded = {}
        self.loaded_hashes = {}
        self.parsed_lines = 0
        self.loaded_bytes = 0

    def _chunk_index(self, address):
        index = bisect_right(self.starts, address) - 1
        if index < 0:
            return None
        chunk = self.chunks[index]
        return index if address < chunk["rva"] + chunk["size"] else None

    def _load(self, index):
        if index in self.loaded:
            return self.loaded[index]
        chunk = self.chunks[index]
        source = self.generated / "asm" / chunk["file"]
        raw = source.read_bytes()
        text = raw.decode("utf-8")
        self.loaded_hashes[index] = hashlib.sha256(raw).hexdigest()
        self.loaded_bytes += len(text.encode("utf-8"))
        result = {}
        current = None
        for line in text.splitlines():
            self.parsed_lines += 1
            match = re.fullmatch(
                r"\.org\s+0x([0-9a-fA-F]+),\s*0x[0-9a-fA-F]+", line.strip()
            )
            if match:
                current = chunk["rva"] + int(match[1], 16)
                continue
            if (
                current is not None
                and line
                and not line.startswith(".")
                and not line.endswith(":")
            ):
                result[current] = re.sub(r"^\{disp(?:8|32)\}\s*", "", line.strip())
            if current is not None and current in result:
                size = self.lengths[current - self.text]
                if size not in (0, 255):
                    current += size
        self.loaded[index] = result
        return result

    def __getitem__(self, address):
        index = self._chunk_index(address)
        if index is None:
            raise KeyError(address)
        return self._load(index)[address]

    def __contains__(self, address):
        index = self._chunk_index(address)
        return index is not None and address in self._load(index)

    def __iter__(self):
        # Preserve full Mapping semantics if an unrelated caller truly needs
        # global iteration. The bounded leaf CFG never takes this path.
        for index in range(len(self.chunks)):
            yield from self._load(index)

    def __len__(self):
        return sum(len(self._load(index)) for index in range(len(self.chunks)))

    def for_spans(self, spans):
        result = {}
        for index, chunk in enumerate(self.chunks):
            start = chunk["rva"]
            end = start + chunk["size"]
            if any(low < end and high > start for low, high in spans):
                result.update(self._load(index))
        return result
