"""Exercise bounds and concurrent-refresh rejection in the read-only loot observer."""

import struct
import unittest

from native_loot_inventory import (
    CAPACITY,
    COUNT_OFFSET,
    RECORDS_OFFSET,
    SYMBOL,
    snapshot,
)


class LootSnapshotTests(unittest.TestCase):
    def reader(self, records, count=None):
        image = bytearray(COUNT_OFFSET + 4)
        image[RECORDS_OFFSET : RECORDS_OFFSET + len(records)] = records
        struct.pack_into(
            "<I", image, COUNT_OFFSET, len(records) // 8 if count is None else count
        )
        return image, lambda address, size: bytes(image[address : address + size])

    def test_relocated_global_and_unsigned_quantities(self):
        image, read = self.reader(struct.pack("<4I", 0xFFFFFFFF, 0xFFFFFFFF, 400060, 1))
        relocated = 0x24000
        result = snapshot(
            lambda address, size: read(address - relocated, size), {SYMBOL: relocated}
        )
        self.assertEqual(
            result["items"],
            [
                {"item_id": 0xFFFFFFFF, "quantity": 0xFFFFFFFF},
                {"item_id": 400060, "quantity": 1},
            ],
        )
        self.assertFalse(result["ownership_override_applied"])

    def test_empty_and_full_capacity(self):
        for count in (0, CAPACITY):
            image, read = self.reader(struct.pack("<II", 1, 1) * count)
            self.assertEqual(snapshot(read, {SYMBOL: 0})["count"], count)

    def test_invalid_count_never_reads_records(self):
        image, read = self.reader(b"", CAPACITY + 1)

        def guarded(address, size):
            self.assertEqual(address, COUNT_OFFSET)
            return read(address, size)

        with self.assertRaisesRegex(RuntimeError, "capacity"):
            snapshot(guarded, {SYMBOL: 0})

    def test_same_count_changed_payload_is_retried(self):
        image, read = self.reader(struct.pack("<II", 400060, 1))
        payload_reads = 0

        def concurrent(address, size):
            nonlocal payload_reads
            if address == RECORDS_OFFSET:
                payload_reads += 1
                if payload_reads == 2:
                    struct.pack_into("<I", image, RECORDS_OFFSET + 4, 2)
            return read(address, size)

        self.assertEqual(snapshot(concurrent, {SYMBOL: 0})["items"][0]["quantity"], 2)
        self.assertEqual(payload_reads, 4)

    def test_count_changed_after_records_is_retried(self):
        image, read = self.reader(struct.pack("<II", 400060, 1))
        count_reads = 0

        def concurrent(address, size):
            nonlocal count_reads
            if address == COUNT_OFFSET:
                count_reads += 1
                if count_reads == 3:
                    struct.pack_into("<I", image, COUNT_OFFSET, 0)
            return read(address, size)

        self.assertEqual(snapshot(concurrent, {SYMBOL: 0})["items"], [])

    def test_continuously_torn_payload_fails_bounded(self):
        image, read = self.reader(struct.pack("<II", 400060, 1))
        payload_reads = 0

        def concurrent(address, size):
            nonlocal payload_reads
            if address == RECORDS_OFFSET:
                payload_reads += 1
                struct.pack_into("<I", image, RECORDS_OFFSET + 4, payload_reads)
            return read(address, size)

        with self.assertRaisesRegex(RuntimeError, "every read attempt"):
            snapshot(concurrent, {SYMBOL: 0})
        self.assertEqual(payload_reads, 6)

    def test_missing_symbol_fails_before_access(self):
        with self.assertRaisesRegex(RuntimeError, "missing"):
            snapshot(lambda *_: self.fail("Unexpected read"), {})


if __name__ == "__main__":
    unittest.main()
