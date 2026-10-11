"""Shared assertions for the durable achievement completion marker."""

import hashlib
import json


def assert_applied(path):
    marker = json.loads(path.read_bytes())
    assert set(marker) == {"schema", "title", "phase", "writes", "checksum"}
    assert marker["schema"] == 1 and marker["title"] == 5800
    assert marker["phase"] == "applied" and marker["writes"] == []
    assert marker["checksum"] == hashlib.sha256(b"[]").hexdigest()
