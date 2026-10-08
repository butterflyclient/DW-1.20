"""Bounded read-only Replay mission cache and StringTable observations."""

import hashlib
import struct


def snapshot(read, symbols):
    # Original AddProgression 1410625A0 / activation callback 141064060:
    # This Replay singleton has one local-client cache, followed immediately
    # by count and activation mode. Do not read that mode as a second count.
    address = symbols["gl_144487AF0"]
    definitions = []
    initialized = bool(read(address + 15480, 1)[0])
    if initialized:
        groups = read(address + 15484, 128 * 268)
        for index in range(128):
            group = groups[index * 268 : (index + 1) * 268]
            if not group[0]:
                continue
            category, count = struct.unpack_from("<II", group, 4)
            if group[0] != 1 or category not in (0, 1, 4) or not 0 < count <= 32:
                raise RuntimeError(
                    "Native mission definition group exceeds Replay bounds"
                )
            definitions.append(
                dict(
                    mission=index + 1,
                    category=category,
                    stages=[
                        dict(id=identity, target=target)
                        for identity, target in struct.iter_unpack(
                            "<II", group[12 : 12 + count * 8]
                        )
                    ],
                )
            )
        if groups != read(address + 15484, 128 * 268):
            raise RuntimeError("Native mission definitions changed during observation")
    for _ in range(3):
        counts = read(address + 15448, 4)
        sizes = struct.unpack("<I", counts)
        if any(count > 640 for count in sizes):
            raise RuntimeError("Native quest count exceeds Replay capacity")
        blocks = [
            read(address + 88 + index * 15360, count * 24)
            for index, count in enumerate(sizes)
        ]
        if counts != read(address + 15448, 4) or any(
            block != read(address + 88 + index * 15360, len(block))
            for index, block in enumerate(blocks)
        ):
            continue
        return {
            "clients": [
                [
                    dict(
                        id=quest,
                        progress=progress,
                        category=category,
                        active=bool(active),
                    )
                    for quest, progress, category, active in struct.iter_unpack(
                        "<QIIB7x", block
                    )
                ]
                for block in blocks
            ],
            "pending_id": struct.unpack("<Q", read(address + 15456, 8))[0],
            "activation_mode": struct.unpack("<I", read(address + 15452, 4))[0],
            "definitions_initialized": initialized,
            "definitions": definitions,
            "scope": "Replay local client/controller zero; no state or memory writes",
        }
    raise RuntimeError("Native quest cache changed during every observation")


def table(read, symbols, base):
    # Replay StringTable is 48 bytes: name, columns/rows/dictionary count,
    # padding, UInt16 cell indices, hashes and dictionary pointers.
    kind = 54
    count = struct.unpack("<I", read(symbols["gl_1423FBBA0"] + kind * 4, 4))[0]
    size = struct.unpack("<I", read(symbols["gl_142458160"] + kind * 4, 4))[0]
    pool = struct.unpack("<Q", read(symbols["gl_14B8F5A80"] + kind * 8, 8))[0]
    if not pool or size != 48 or not 0 < count <= 20000:
        raise RuntimeError("Native StringTable pool bounds differ from Replay")

    def cstring(pointer, capacity):
        raw = read(pointer - base, capacity)
        end = raw.find(b"\0")
        if end < 0:
            raise RuntimeError("Native StringTable text is unterminated")
        return raw[:end].decode("utf-8")

    for offset in range(count):
        location = pool - base + offset * size
        header = read(location, size)
        name, columns, rows, dictionary_size = struct.unpack_from("<QIII", header)
        if not name or not columns or not rows:
            continue
        if cstring(name, 128) != "quest_challenges.csv":
            continue
        if not (columns == 19 and 0 < rows <= 4096 and 0 < dictionary_size <= 65536):
            raise RuntimeError("Native quest StringTable bounds differ from Replay")
        cells, hashes, strings = struct.unpack_from("<QQQ", header, 24)
        if not cells or not hashes or not strings:
            raise RuntimeError("Native quest StringTable storage is missing")
        indices_raw = read(cells - base, columns * rows * 2)
        pointers_raw = read(strings - base, dictionary_size * 8)
        indices = struct.unpack("<" + "H" * (columns * rows), indices_raw)
        if max(indices) >= dictionary_size:
            raise RuntimeError("Native quest StringTable dictionary index is invalid")
        pointers = struct.unpack("<" + "Q" * dictionary_size, pointers_raw)
        dictionary = {index: cstring(pointers[index], 512) for index in set(indices)}
        data = [
            [
                dictionary[index]
                for index in indices[row * columns : (row + 1) * columns]
            ]
            for row in range(rows)
        ]
        if (
            header != read(location, size)
            or indices_raw != read(cells - base, len(indices_raw))
            or pointers_raw != read(strings - base, len(pointers_raw))
        ):
            raise RuntimeError("Native quest StringTable changed during observation")
        return dict(
            name="quest_challenges.csv",
            columns=columns,
            row_count=rows,
            rows=data,
            rows_sha256=hashlib.sha256(repr(data).encode()).hexdigest(),
            scope="Loaded native StringTable; no asset or process writes",
        )
    raise RuntimeError(
        "Native quest_challenges.csv was not found in the loaded asset pool"
    )
