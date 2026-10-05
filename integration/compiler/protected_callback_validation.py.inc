    # Recovered callback thunks are independently proven/assembled by the
    # linker, but remain opaque in the conservative instruction-length map.
    # Validate the whole template and both native pointer-slot destinations;
    # normalize only their verified rel32 fields for the opaque-data comparison.
    callback_count = 0
    for thunk in report.get("protected_callback_thunks", []):
        rva, size = thunk["rva"], thunk["size"]
        raw = bytearray.fromhex(thunk["raw_hex"])
        if size != 32 or len(raw) != size or hashlib.sha256(raw).hexdigest() != thunk["sha256"]:
            raise ValueError("Callback evidence size/hash is inconsistent")
        if original.get_data(rva, size) != raw:
            raise ValueError("Callback evidence differs from the original native bytes")
        if len(thunk["references"]) != 2 or {row["offset"] for row in thunk["references"]} != {10, 24}:
            raise ValueError("Callback reference coverage is incomplete")
        for reference in thunk["references"]:
            offset, destination = reference["offset"], reference["target"]
            if rva + offset + 4 + struct.unpack_from("<i", raw, offset)[0] != destination:
                raise ValueError("Callback reference disagrees with its original instruction")
            displacement = remap(destination, report) - (remap(rva, report) + offset + 4)
            struct.pack_into("<i", raw, offset, displacement)
        if rebuilt.get_data(remap(rva, report), size) != raw:
            raise ValueError("Callback template or relocated pointer-slot destination changed")
        if not old.VirtualAddress <= rva <= old.VirtualAddress + len(before) - size:
            raise ValueError("Callback evidence lies outside native text")
        before[rva - old.VirtualAddress:rva - old.VirtualAddress + size] = raw
        callback_count += 1
