                # Execute the native stack probe for C++ frames larger than one
                # page. This models only the TEB stack limit; it neither skips
                # the call nor changes the emitted unwind codes being tested.
                probe_rva = report["symbols"].get("__chkstk")
                if probe_rva is not None and any(
                        instruction[2] == "call" and instruction[3] == hex(probe_rva)
                        for instruction in prologue):
                    probe = []
                    for instruction in decoder.disasm_lite(pe.get_data(probe_rva, 128), probe_rva):
                        probe.append(instruction)
                        if instruction[2].endswith("ret"):
                            break
                    if not probe or not probe[-1][2].endswith("ret"):
                        raise ValueError("Native stack-probe extent could not be verified")
                    probe_size = sum(instruction[1] for instruction in probe)
                    first = (view + probe_rva) & -4096
                    last = (view + probe_rva + probe_size + 4095) & -4096
                    for probe_page in range(first, last, 4096):
                        if not code_page <= probe_page < code_page + code_extent:
                            machine.mem_map(probe_page, 4096)
                    machine.mem_write(view + probe_rva, pe.get_data(probe_rva, probe_size))
                    teb = 0x60000000
                    machine.mem_map(teb, 4096)
                    machine.mem_write(teb + 0x10, struct.pack("<Q", initial_rsp & -4096))
                    machine.reg_write(x86.UC_X86_REG_GS_BASE, teb)
