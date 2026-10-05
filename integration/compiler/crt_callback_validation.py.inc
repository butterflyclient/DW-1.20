def verify_dw_retired_crt_callback(site, target, report, original, rebuilt, lengths, text_start):
    owners = [row for row in report['replacements']
              if row['begin'] <= site and site + 7 <= row['end']]
    if len(owners) != 1 or owners[0]['owner'] != 'func_1403061A0':
        raise ValueError('Retired CRT registration is not owned by the DW startup constructor')
    owner = owners[0]
    if owner.get('provenance') != 'PE unwind family':
        raise ValueError('DW constructor replacement ownership is not established by PE metadata')
    old_code = original.get_data(site, 7)
    if (old_code[:3] != b'\x48\x8d\x0d' or
            site + 7 + int.from_bytes(old_code[3:], 'little', signed=True) != target or
            lengths[target - text_start] in (0, 255)):
        raise ValueError('Retired native CRT registration identity does not verify')
    entry = report['symbols'].get(owner['owner'])
    if entry is None or rebuilt.get_data(entry, 1) != b'\xc3':
        raise ValueError('DW constructor is not the compiled empty Windows compatibility initializer')
    # verify.py separately checks the complete linked C++ object and executes
    # this constructor to its caller. No registration survives its return.
    return {'site': site, 'target': target, 'owner': owner['owner'],
            'compiled_constructor_rva': entry, 'ownership': 'PE unwind family',
            'reason': 'registration instruction removed with the replaced private GDI initializer'}
