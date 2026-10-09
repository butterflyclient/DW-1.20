"""Read the Replay Battle Pass cache using its relocated native singleton getter."""

import struct


def snapshot(read, symbols):
    # The exact original 140F312B0 getter is LEA RAX,[RIP+disp32]; RET.
    # Resolve the rebuilt getter so shifted globals follow the linked image.
    getter = symbols["func_140F312B0"]
    code = read(getter, 8)
    if code[:3] != b"\x48\x8d\x05" or code[7] != 0xC3:
        raise RuntimeError("Native Battle Pass singleton getter changed")
    address = getter + 7 + struct.unpack_from("<i", code, 3)[0]
    # Same-Replay GetXP 140F312D0 and HandleUpdate 140F312F0 prove the
    # seven-entry XP/rank arrays at +64/+120. This Replay stores one local
    # controller, unlike the larger oracle. Index zero is not a live season.
    for _ in range(3):
        data = read(address + 64, 112)
        if data != read(address + 64, 112):
            continue
        xp = struct.unpack_from("<7Q", data)
        ranks = struct.unpack_from("<7Q", data, 56)
        if any(rank > 100 for rank in ranks):
            raise RuntimeError("Native Battle Pass tier exceeds the Replay bounds")
        return dict(
            controller=0,
            instance_rva=address,
            seasons=[
                dict(season=index, xp=xp[index], rank=ranks[index])
                for index in range(1, 7)
            ],
            scope="Read-only Replay local controller zero; no cache writes",
        )
    raise RuntimeError("Native Battle Pass cache changed during observation")
