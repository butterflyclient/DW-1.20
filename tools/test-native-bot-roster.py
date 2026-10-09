"""Execute linked Replay bot roster and ClientBegin replacements at engine boundaries."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = json.loads((args.build / 'build-report.json').read_bytes())
    executable = Path(report['executable'])
    if not executable.is_absolute(): executable = args.build / executable
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == report['sha256']
    pe = pefile.PE(str(executable), fast_load=True)
    base, symbols = pe.OPTIONAL_HEADER.ImageBase, report['symbols']
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, arena, party, server_party, pool, halt = 0x10000000, 0x11000000, 0x13000000, 0x13800000, 0x14000000, 0x15000000
    for address, size in [(stack, 0x400000), (arena, 0x10000), (party, 0x80000), (server_party, 0x80000), (pool, 0x10000), (halt, 4096)]:
        vm.mem_map(address, size)
    pages = set()

    def mapped(address, size=1):
        if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage: return
        for page in range(address & ~4095, (address + size - 1 & ~4095) + 4096, 4096):
            if page not in pages:
                vm.mem_map(page, 4096)
                vm.mem_write(page, pe.get_data(page-base, 4096))
                pages.add(page)

    misses = []
    def missing(machine, access, address, size, value, context):
        if not base <= address < base + pe.OPTIONAL_HEADER.SizeOfImage:
            rip = machine.reg_read(UC_X86_REG_RIP)
            nearest = sorted((v, n) for n, v in symbols.items() if v <= rip-base)[-1]
            misses.append(f'Unmodeled native boundary at {nearest[1]}+{rip-base-nearest[0]:x}; memory={address:x} access={access}')
            return False
        mapped(address, size)
        return True

    def write(address, value, fmt='<i'):
        body = value if isinstance(value, bytes) else struct.pack(fmt, value)
        mapped(address, len(body)); vm.mem_write(address, body)

    def read(address, fmt='<i'):
        mapped(address, struct.calcsize(fmt))
        return struct.unpack(fmt, vm.mem_read(address, struct.calcsize(fmt)))[0]

    def string(address):
        out = bytearray()
        for i in range(256):
            mapped(address+i)
            value = vm.mem_read(address+i, 1)[0]
            if not value: return out.decode()
            out.append(value)
        raise AssertionError('Unbounded engine string')

    def returned(value=0):
        rsp = vm.reg_read(UC_X86_REG_RSP)
        vm.reg_write(UC_X86_REG_RAX, value & 0xffffffffffffffff)
        vm.reg_write(UC_X86_REG_RIP, read(rsp, '<Q'))
        vm.reg_write(UC_X86_REG_RSP, rsp+8)

    def member(address, index): return address+2192+488*index
    state = dict(enabled=True, lobby=True, server_bot=True, bot_count=12)
    registered, models, paths, human_calls = {}, {}, {1: 'members', 2: 'squadMembers'}, []
    for name, kind, value in [('gl_14D386988', 0, 0), ('gl_14D386990', 5, 28), ('gl_14C796328', 5, 51)]:
        ptr = arena+0x1000+len(registered)*0x100
        registered[name] = ptr
        write(base+symbols[name], ptr, '<Q'); write(ptr+29, kind, '<B'); write(ptr+40, value)
    write(base+symbols['gl_14EEF12A4'], 1, '<B')
    write(base+symbols['gl_14EEF1288'], 0)
    server_pool = base+symbols['gl_14E183D00']
    write(server_pool, b'\0'*(200*88))
    for address in (party, server_party):
        write(address+311116, 1)
        for i in range(2):
            write(member(address,i)+52, ('Human '+str(i)).encode()+b'\0')
            write(member(address,i)+392, i+1); write(member(address,i)+396, i)
            write(member(address,i)+402, 5, '<B'); write(member(address,i)+408, 42+i, '<Q')
    for i in range(14):
        for address in (pool+88*i, server_pool+88*i):
            write(address, ('Bot '+str(i)).encode()+b'\0')
            write(address+36, b'[^3Bot]\0'); write(address+77, 20+i, '<B')
            write(address+80, 7, '<H'); write(address+84, 1, '<B')
            write(address+85, int(i>=2), '<B'); write(address+86, 44+i-2, '<B')
    names = ['DW_LocalBackend_IsEnabled', 'func_141187FA0', 'func_141187EE0', 'func_14118E1F0', 'func_14118E020',
             'func_14118EE80', 'func_14118E0E0', 'func_140CA2250', 'func_140CA2270', 'func_140CA2230', 'func_140CA2210',
             'func_141359F90', 'func_141371450', 'func_14137D670', 'func_14118CF60', 'func_14118C070', 'func_14118C110',
             'func_14107EA60', 'func_1412B0570', 'func_141B23610', 'func_141B22140', 'func_141528240', 'func_140F22880',
             'func_140F23A00', 'func_14118DDB0', 'func_14118C7D0', 'func_141B0D390', 'func_141B0E150', 'func_141B0E0B0',
             'func_141B0E280', 'func_141B97080', 'func_141B97230', 'func_141B24690', 'func_141B0D520', 'func_141B0D710',
             'func_141B0D530', 'func_141192AC0', 'func_141192AA0', 'Dvar_RegisterVariant', 'Dvar_RegisterInt',
             'Dvar_GenerateChecksum', 'Com_Printf']
    boundaries = {base+symbols[name]: name for name in names}
    boundaries[base+symbols['sub_1421CCEF0']] = 'stack_probe'

    def boundary(machine, address, size, context):
        name = boundaries.get(address)
        if not name: return
        a = [machine.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
        rsp = machine.reg_read(UC_X86_REG_RSP)
        if name == 'stack_probe':
            amount=machine.reg_read(UC_X86_REG_RAX)
            assert stack <= rsp-amount < rsp < stack+0x400000
            returned(amount)
        elif name == 'DW_LocalBackend_IsEnabled': returned(state['enabled'])
        elif name == 'func_141187FA0': returned(state['lobby'])
        elif name == 'func_141187EE0': returned(party)
        elif name in ('func_14118E1F0', 'func_14118E020'): returned(a[1]<200 and read(member(a[0],a[1])+402,'<B')>=5)
        elif name == 'func_14118EE80': returned(0)
        elif name == 'func_14118E0E0': returned(a[1]==0)
        elif name == 'func_140CA2250': returned(1)
        elif name == 'func_140CA2270': returned(state['enabled'] and a[0]<state['bot_count']+2)
        elif name in ('func_140CA2230','func_140CA2210'): returned(pool+88*a[0])
        elif name == 'func_141359F90': returned(state['server_bot'])
        elif name == 'func_141371450': returned(not state['server_bot'])
        elif name == 'func_14137D670': returned(server_party)
        elif name == 'func_14118CF60': write(a[0],42+a[2],'<Q'); returned(a[0])
        elif name == 'func_14118C070': returned(a[1]-42)
        elif name == 'func_14118C110': returned(a[1]-41)
        elif name == 'func_141B23610': write(a[1],struct.pack('<200i',*range(200))); returned()
        elif name == 'func_141B22140':
            assert a[1]<2, 'Virtual bot dispatched to human identity binding'
            human_calls.append(a[1]); models[paths[a[2]]+'.gamertag']='Human '+str(a[1]); returned()
        elif name in ('func_141528240','func_140F22880','func_14118DDB0'): returned(0)
        elif name == 'func_14118C7D0': returned(152)
        elif name == 'func_141B0D390':
            path=paths.get(a[0],'global')+'.'+string(a[1]); handle=len(paths)+10
            if path in paths.values(): handle=next(i for i,p in paths.items() if p==path)
            else: paths[handle]=path
            returned(handle)
        elif name == 'func_141B0E0B0': models[paths[a[0]]]=int(bool(a[1]&255)); returned()
        elif name == 'func_141B0E150': models[paths[a[0]]]=a[1] if a[1]<0x80000000 else a[1]-0x100000000; returned()
        elif name == 'func_141B0E280': models[paths[a[0]]]=string(a[1]); returned()
        elif name == 'func_141B97080':
            assert a[0]==42 and string(a[1])=='Human 0'
            write(a[2],1,'<B'); write(a[3],struct.pack('<3i',70,80,90)); write(read(rsp+40,'<Q'),struct.pack('<3i',71,81,91)); returned(1)
        elif name == 'func_141B97230': assert a[0]==42; write(a[2],b'\0'*45248); returned(1)
        elif name == 'func_141B24690': returned()
        elif name == 'func_141B0D520': returned(3)
        elif name == 'func_141B0D710':
            key=string(a[1]); handle=4 if key.endswith('friendlySquadIndex') else 5
            paths[handle]='members.'+key.rsplit('.',1)[-1]; returned(handle)
        elif name == 'func_141B0D530': returned(models[paths[a[0]]])
        elif name in ('func_141192AC0','func_141192AA0'): returned(1)
        elif name == 'Dvar_GenerateChecksum': returned(123)
        elif name in ('Dvar_RegisterVariant','Dvar_RegisterInt'):
            key=string(a[0]); ptr=arena+0x3000+len(registered)*0x100; registered[key]=ptr
            if name=='Dvar_RegisterVariant':
                assert key=='replay_dw_reservedSquads' and a[2:4]==[9,0]
                initial=read(read(rsp+40,'<Q'),'<Q'); write(ptr+40,initial,'<Q'); write(ptr+29,9,'<B')
            else:
                assert key=='replay_dw_squadSize' and a[1:4]==[0,0,200]; write(ptr+29,5,'<B'); write(ptr+40,0)
            returned(ptr)
        else: returned()

    vm.hook_add(UC_HOOK_MEM_UNMAPPED,missing); vm.hook_add(UC_HOOK_CODE,boundary)

    def run(name,*arguments):
        rsp=stack+0x3ff000-8; write(rsp,halt,'<Q'); vm.reg_write(UC_X86_REG_RSP,rsp)
        for reg,value in zip((UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9),arguments): vm.reg_write(reg,value)
        try: vm.emu_start(base+symbols[name],halt,count=2000000)
        except Exception:
            print('Native probe fault:', misses[-3:], 'RIP', hex(vm.reg_read(UC_X86_REG_RIP)))
            raise
        assert vm.reg_read(UC_X86_REG_RIP)==halt
        result=vm.reg_read(UC_X86_REG_RAX)&0xffffffff
        return result if result<0x80000000 else result-0x100000000

    def policy(mask,size):
        write(arena+0x6000,format(mask,'050x').encode()+b'\0')
        write(registered['replay_dw_reservedSquads']+40,arena+0x6000,'<Q')
        write(registered['replay_dw_squadSize']+40,size)

    checks=[]
    run('DW_BotPolicy_Register'); policy(3,3)
    before=bytes(vm.mem_read(party,0x80000))
    run('func_141B21D50',party,1)
    assert human_calls==[0,1] and models['members.memberCount']==14 and models['members.maxCount']==152
    assert models['members.count']==14
    for row in range(2,14):
        assert models[f'members.{row}.gamertag']==f'Bot {row}' and models[f'members.{row}.isBot']==1, (row, models.get(f'members.{row}.gamertag'), models.get(f'members.{row}.isBot'))
        assert models[f'members.{row}.xuid']=='0' and models[f'members.{row}.bodyWest']==80
        assert models[f'members.{row}.clanTag']=='[^3Bot^7]'
        assert len(models[f'members.{row}.clanTag'].replace('^3','').replace('^7',''))==5
    assert bytes(vm.mem_read(party,0x80000))==before
    assert run('func_14118ADD0',party)==14
    run('func_141B22B40',party,2)
    assert models['squadMembers.count']==1
    checks.append('Native pregame count, names and operator/weapon models include all twelve bots; human bindings and party bytes are preserved; No Fill preview excludes bot teammates')
    saved_pool=bytes(vm.mem_read(pool,200*88))
    run('DW_BotPolicy_Prepare',party)
    expected=bytearray(saved_pool)
    for i in range(2,14):
        expected[88*i+77]=3+(i-2)//3
        expected[88*i+36:88*i+47]=b'[^3Bot^7]\0\0'
    assert bytes(vm.mem_read(pool,200*88))==bytes(expected)
    checks.append('Pregame preparation changes only native aiTeam and bot clan fields; all names, customization, unknown wire fields and human placeholders are preserved; the five-visible-character clan tag resets color before its closing bracket and fits its eleven-byte field')
    teams=[]
    for i in range(12):
        teams.append(run('func_141370860',44+i))
        assert run('func_1413707D0',44+i)==2+i//3
    assert teams==[3+i//3 for i in range(12)] and len(set(teams))==4
    checks.append('ClientBegin gives twelve bots four distinct BR combat teams and never uses either reserved human squad')
    policy(1,3)
    assert run('func_1413707D0',44)==1 and run('func_141370860',44)==2
    policy(0,3)
    assert run('func_1413707D0',44)==0 and run('func_141370860',44)==1
    policy(3,1)
    assert run('func_1413707D0',44)==-1 and run('func_141370860',44)==3
    checks.append('Mixed Fill On/Off allows only consenting squads; solos use independent teams without assigning a squad')
    policy(3,3)
    for i in range(2,14): write(server_pool+88*i+85,0,'<B')
    for i in range(2,14): assert run('func_14132ED80',0)==i
    assert run('func_14132ED80',0)==-1
    checks.append('BR spawn selection consumes all native bot records once, including teams beyond axis/allies, while preserving human records')
    state['server_bot']=False
    assert run('func_1413707D0',1)==1 and run('func_141370860',1)==2
    state['enabled']=False
    assert run('func_14118ADD0',party)==2
    models.clear(); human_calls.clear(); run('func_141B21D50',party,1)
    assert models['members.memberCount']==2 and human_calls==[0,1]
    checks.append('Human startup and non-DW roster behavior retain native assignment and identity consumers')
    args.output.write_text(json.dumps(dict(schema=1,passed=True,game_sha256=report['sha256'],checks=checks,native_game_verified=False),indent=2)+'\n')
    print('PASS:',len(checks),'linked native bot roster/assignment groups')


if __name__=='__main__': main()
