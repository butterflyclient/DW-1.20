"""Decode Replay's bounded Windows loot singleton from a read-only process reader."""

import hashlib
import struct

SYMBOL = "gl_1459E05C0"
CAPACITY = 15000
RECORDS_OFFSET = 64
COUNT_OFFSET = RECORDS_OFFSET + CAPACITY * 8


def snapshot(read, symbols):
    """Return a stable sample; never interpret a partially refreshed item array.

    Same-target IsOwned (0x141B39ED0) and native inventory readers establish
    the 64-byte singleton prefix, 8-byte records and trailing item count.
    Addresses come from the selected linked image, including ASLR in `read`.
    """
    if SYMBOL not in symbols:
        raise RuntimeError("Native loot singleton missing from linked image")
    address = symbols[SYMBOL]
    for _ in range(3):
        count = struct.unpack("<I", read(address + COUNT_OFFSET, 4))[0]
        if count > CAPACITY:
            raise RuntimeError("Native loot inventory count exceeds target capacity")
        size = count * 8
        records = read(address + RECORDS_OFFSET, size) if size else b""
        if count != struct.unpack("<I", read(address + COUNT_OFFSET, 4))[0]:
            continue
        if size and records != read(address + RECORDS_OFFSET, size):
            continue
        if count != struct.unpack("<I", read(address + COUNT_OFFSET, 4))[0]:
            continue
        return {
            "layout": "Replay Windows singleton: records +64, count +120064, capacity 15000",
            "count": count,
            "records_sha256": hashlib.sha256(records).hexdigest(),
            "items": [
                {"item_id": item, "quantity": quantity}
                for item, quantity in struct.iter_unpack("<II", records)
            ],
            "ownership_override_applied": False,
            "scope": "Actual native inventory records; independent of Lua unlock_all override",
        }
    raise RuntimeError("Native loot inventory changed during every read attempt")
