"""Native Replay marketplace request shared by focused domain fixtures."""

from native_wire_client import u32


def buy(sku, transaction=""):
    text = lambda value: b"\x10" + value.encode() + b"\0"
    return (
        text("5800")
        + text(transaction)
        + u32(1)
        + u32(sku)
        + u32(1)
        + u32(1)
        + u32(1)
        + u32(0)
        + u32(0)
        + u32(0)
        + b"\x03\0\x01\0"
    )
