"""Prepare complete target-verified Replay script method registration."""

import argparse, hashlib, json, struct, shutil, importlib.util, sys
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

TARGET = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
BODIES = {
    "initializer": (
        "fn_c4246490a119c784",
        48,
        "aec83ca84c81928d3b40be630e7ddd16c42f0e5b863069ce79cf7f5929710a65",
    ),
    "dispatcher": (
        "fn_741adb5abe3f9e4d",
        575,
        "07238d07fa2749425e13d038cd76219f86718c357e190b23717075ae3d204772",
    ),
    "register": (
        "fn_3bba68547bd7a832",
        97,
        "cf082f78455ce1adcc18a671826eaf33f2e1d6b53f1c2a9074e639e9e0c60713",
    ),
    "GetEntity": (
        "fn_877b70bb50618335",
        68,
        "0e9747dfa4d5a732b6df6e295492da6c38b6511a598aa9ee4f15d3235101b372",
    ),
    "GetWeaponParam": (
        "fn_f80bb01c069e1545",
        420,
        "4646b9a1e4e4fdb567e421126e7712a24e29a4fd32d054d8ec608765d309b709",
    ),
    "AddWeaponParam": (
        "fn_8c6f91c84afccdf8",
        32,
        "b152e77e5f48fca8536ddb6303669e5dfca237cd6e7260bea439c28e27217e56",
    ),
    "GetWeaponTable": (
        "fn_81ec55875b455203",
        8,
        "3bfeff484b46ea64aaedab4f879e2f1dbe3e721b1f8a2c964de5dcc190c0925a",
    ),
    "WeaponCreate": (
        "fn_c271a959e88fbc66",
        669,
        "38a8b28cd507fdd8b8a8cc28ae04290ba2ab7467a0f0aa1f80f7aecd8b14ba0c",
    ),
    "WeaponTableInit": (
        "fn_0c8f81d1594edf1f",
        216,
        "663db540d37843742bbc0dc731b29c0670cf73a12803f8f2ba865777bfac13f5",
    ),
    "GetNumParam": (
        "fn_2d051144421c6879",
        7,
        "154fe867501c51a9409776c4896b478785d9d8bef0978f045e91a6c7d73941fa",
    ),
    "GetInt": (
        "fn_ee861ec7c72761db",
        236,
        "d2db3bdac0cf2a53134c254d3fc593c35a87a37c284a0cf429eb7494db04b10a",
    ),
    "GetString": (
        "fn_26be2baa89b9c0b9",
        20,
        "fcbb7ebdf71acc9bfd247ee2f5d71760d698268ec12ae48c30bdd24d0b205aa2",
    ),
    "VMExecute": (
        "fn_fbdd3052d3a912e0",
        17007,
        "e239b2c782f9c4f087095fa2b91958fa3b5c8b13db183d6db07fbe98fedfc86e",
    ),
    "VMGetEntityRef": (
        "fn_297df0e74a3527e1",
        41,
        "174c6a03d820715f4679b871ed15d4f0701089085fe9e79131551844dca5828e",
    ),
    "VMGetObjectType": (
        "fn_86ad6931c7fc29cd",
        19,
        "884d325ccbc3e326507784b98cf762a7db5c8016fed122d33a85db919df90bed",
    ),
    "WeaponSpawnFromString": (
        "fn_2998f538e21596dd",
        275,
        "15404bb8031fdc10e65a0961461d1113ec2e60b89a2cdc166163e8806f33bc9b",
    ),
    "GetWeaponForName": (
        "fn_61f84e2421493347",
        104,
        "a2688918331f33fd6b518ac9c8475ef6f152736106d04c54fd0e7d59acbea360",
    ),
    "ParseFullWeapon": (
        "fn_61b45f2f6d012fa4",
        2198,
        "9eb092352581147b036a3649d76b97de076e90ad05347ae165795b9b302db958",
    ),
    "FindBaseWeapon": (
        "fn_e21c4cba102fa903",
        576,
        "a2ad594e8b28ef4ead81ee0ce889b3810f2c8ef9e7e0c66410037092af93a73d",
    ),
    "IsValidWeapon": (
        "fn_a69b8da64b522288",
        381,
        "44aa9466bb411247342af812c96320ff65551ba198617ce1a17c404832b63b0c",
    ),
    "WeaponField24Consumer": (
        "fn_8e200ff93a72e7a0",
        120,
        "d1ffbf4df1e757cc46b03b6921d99c0800e223f49a74079f167e542c6ee104ab",
    ),
    "GetWeaponNameComplete": (
        "fn_22b765849c827923",
        1169,
        "03a30990461fbcc53ead81ea597e33004461f81dc6d8233b5e06e7de7c05aaed",
    ),
    "GetWeaponBaseName": (
        "fn_3dc890f09d39bc7f",
        18,
        "7abbcad99c05cd1765272bb02606c6c2e49cbe6edf43e78ff52aaff58c03cb3f",
    ),
    "WeaponBaseNameField": (
        "fn_ede1e7c4ff574745",
        40,
        "9bcc7affb165ee334d4fc95ef5003554eeb3a5c8368f46205ac7e727edce4974",
    ),
    "AddBool": (
        "fn_7c7f09b07403e547",
        25,
        "5a422e56b78f7e919f10a4e7826d1053780c16ee08b94055f9251a3329fe4408",
    ),
    "AddInt": (
        "fn_f319ee3c120327d6",
        25,
        "3782401530b85ce159d795cd8971735233212ddf7f49b3bc7f29c1df02404c89",
    ),
    "HasWeaponBoolResult": (
        "fn_a0249974a6c1d84c",
        253,
        "006bcd6e42e64f86effa89a7d152393ffe1f6d10ea48c058014a5e9a9d7526f4",
    ),
}


def derive(exe, catalog, output):
    assert hashlib.file_digest(exe.open("rb"), "sha256").hexdigest() == TARGET
    cat = json.loads(catalog.read_bytes())
    assert cat["image_sha256"] == TARGET
    byid = {r["id"]: r for r in cat["functions"]}
    byva = {cat["image_base"] + r["rva"]: r for r in cat["functions"]}
    pe = pefile.PE(str(exe), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    proof = []
    bodies = {}
    for name, (fid, size, expected) in BODIES.items():
        row = byid[fid]
        raw = pe.get_data(row["rva"], size)
        assert hashlib.sha256(raw).hexdigest() == expected
        bodies[name] = list(cs.disasm(raw, base + row["rva"]))
        proof.append(
            dict(
                symbol=name,
                function_id=fid,
                original_rva=row["rva"],
                bytes=size,
                sha256=expected,
            )
        )

    def rip(i):
        op = next(
            o for o in i.operands if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP
        )
        return i.address + i.size + op.mem.disp

    init = bodies["initializer"]
    tail = next(
        i.operands[0].imm
        for i in init
        if i.mnemonic == "jmp" and i.operands[0].type == X86_OP_IMM
    )
    tailraw = pe.get_data(tail - base, 89)
    assert (
        hashlib.sha256(tailraw).hexdigest()
        == "9e2b2480efd7da9f7ee216b4032e8261baa601952f24b32bbf4df392ca25faa4"
    )
    tailins = list(cs.disasm(tailraw, tail))
    assert tailins[-1].mnemonic == "ret"
    # The catalog reports the sum of two noncontiguous blocks (48 + 89).
    # Hash the real complete function, excluding the neighboring routine.
    initializer_bytes = pe.get_data(byid[BODIES["initializer"][0]]["rva"], 48)
    initializer_full_sha256 = hashlib.sha256(initializer_bytes + tailraw).hexdigest()
    assert (
        initializer_full_sha256
        == "ebeb12572d4a3bb9f9aaf1b38dd681a1efc26a02b09cf67227640326159238a7"
    )
    constants = {
        i.operands[0].mem.disp: i.operands[1].imm
        for i in tailins
        if i.mnemonic == "mov"
        and i.operands[0].type == X86_OP_MEM
        and i.operands[1].type == X86_OP_IMM
    }
    assert constants == {
        3188: 1,
        3192: 1049,
        3196: 1048,
        3200: 32768,
        3204: 34695,
        3208: 1927,
    }
    calls = [
        i.operands[0].imm
        for i in bodies["dispatcher"]
        if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
    ]
    tables = [
        rip(i)
        for i in bodies["dispatcher"]
        if i.mnemonic == "lea" and i.op_str.startswith("r9,")
    ]
    assert len(tables) == 19 and len(calls) == 20
    register = base + byid[BODIES["register"][0]]["rva"]
    assert calls[1:] == [register] * 19
    # Pin the parser through the verified native SpawnFromString callback.
    spawn_calls = [
        i.operands[0].imm
        for i in bodies["WeaponSpawnFromString"]
        if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
    ]
    assert spawn_calls[2] == base + byid[BODIES["GetWeaponForName"][0]]["rva"]
    parse_wrapper = bodies["GetWeaponForName"]
    parse_calls = [
        i.operands[0].imm
        for i in parse_wrapper
        if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
    ]
    assert parse_calls[0] == base + byid[BODIES["ParseFullWeapon"][0]]["rva"]
    assert (
        rip(
            next(
                i
                for i in parse_wrapper
                if i.mnemonic == "lea" and i.op_str.startswith("r8,")
            )
        )
        == base + byid[BODIES["FindBaseWeapon"][0]]["rva"]
    )
    bindings = [
        dict(
            name="SM_ContextInstances",
            kind="global",
            original_rva=rip(next(i for i in init if i.mnemonic == "lea")) - base,
        ),
        dict(
            name="SM_OriginalFunctionCallbacks",
            kind="global",
            original_rva=rip(next(i for i in tailins if i.mnemonic == "lea")) - base,
        ),
        dict(
            name="SM_ServerContext",
            kind="function",
            function_id=byva[calls[0]]["id"],
            original_rva=calls[0] - base,
        ),
        dict(
            name="SM_RegisterMethodTable",
            kind="function",
            function_id=BODIES["register"][0],
            original_rva=register - base,
        ),
    ]
    for name in [
        "GetEntity",
        "GetWeaponParam",
        "AddWeaponParam",
        "GetWeaponTable",
        "GetNumParam",
        "GetInt",
        "GetString",
        "ParseFullWeapon",
        "FindBaseWeapon",
        "IsValidWeapon",
        "GetWeaponNameComplete",
        "GetWeaponBaseName",
        "AddBool",
        "AddInt",
    ]:
        bindings.append(
            dict(
                name="SM_" + name,
                kind="function",
                function_id=BODIES[name][0],
                original_rva=byid[BODIES[name][0]]["rva"],
            )
        )
    name_field_calls = [
        i.operands[0].imm
        for i in bodies["WeaponBaseNameField"]
        if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
    ]
    assert name_field_calls[0] == base + byid[BODIES["GetWeaponBaseName"][0]]["rva"]
    definitions = rip(
        next(
            i
            for i in bodies["GetWeaponBaseName"]
            if i.mnemonic == "lea" and i.op_str.startswith("rcx,")
        )
    )
    assert any(
        i.mnemonic == "mov" and i.op_str == "rax, qword ptr [rax]"
        for i in bodies["GetWeaponBaseName"]
    )
    bindings.append(
        dict(
            name="SM_WeaponCompleteDefinitions",
            kind="global",
            original_rva=definitions - base,
        )
    )
    headers = []
    for ordinal, va in enumerate(tables):
        binding = dict(
            name=f"SM_MethodTable{ordinal:02}", kind="global", original_rva=va - base
        )
        bindings.append(binding)
        raw = pe.get_data(va - base, 16)
        tableproof = dict(
            **binding, header_bytes=len(raw), runtime_initialized=len(raw) != 16
        )
        if len(raw) == 16:
            pointer, count = struct.unpack("<QQ", raw)
            data = pe.get_data(pointer - base, count * 24)
            assert len(data) == count * 24
            tableproof.update(
                count=count,
                descriptor_rva=pointer - base,
                header_sha256=hashlib.sha256(raw).hexdigest(),
                descriptors_sha256=hashlib.sha256(data).hexdigest(),
            )
        headers.append(tableproof)
    lines = [
        "#pragma once",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "struct SM_WeaponCompleteDefView { const char *internalName; uint8_t prefix[16]; const void *field24; };",
        "static_assert(offsetof(SM_WeaponCompleteDefView, internalName) == 0);",
        "struct BuiltinMethodTable;",
        'extern "C" {',
        "extern void *SM_ContextInstances[];",
        "extern uint64_t SM_OriginalFunctionCallbacks[];",
        "void *SM_ServerContext();",
        "uint32_t SM_RegisterMethodTable(void *, const char **, uint32_t *, const BuiltinMethodTable *);",
        "void *SM_GetEntity(uint64_t);",
        "void SM_GetWeaponParam(void *, uint32_t, void *, uint8_t *);",
        "void SM_AddWeaponParam(void *, const void *, bool);",
        "const void *SM_GetWeaponTable(const void *);",
        "uint32_t SM_GetNumParam(void *);",
        "int32_t SM_GetInt(void *, uint32_t);",
        "const char *SM_GetString(void *, uint32_t);",
        "bool SM_ParseFullWeapon(const char *, void *, void *(*)(void *, const char *));",
        "void *SM_FindBaseWeapon(void *, const char *);",
        "bool SM_IsValidWeapon(const void *, bool);",
        "char *SM_GetWeaponNameComplete(const void *, bool, char *, uint32_t);",
        "const char *SM_GetWeaponBaseName(const void *, bool = false);",
        "void SM_AddBool(void *, int32_t);",
        "void SM_AddInt(void *, int32_t);",
        "extern SM_WeaponCompleteDefView *SM_WeaponCompleteDefinitions[];",
    ]
    lines += [
        f"extern const BuiltinMethodTable SM_MethodTable{i:02};" for i in range(19)
    ] + ["}"]
    for label, offset in [
        ("FunctionBegin", 3188),
        ("FunctionEnd", 3192),
        ("FunctionCount", 3196),
        ("NativeMethodBegin", 3200),
        ("NativeMethodCount", 3208),
        ("CustomMethodBegin", 3204),
    ]:
        lines.append(f"inline constexpr uint32_t SM_{label} = {constants[offset]};")
    lines += (
        ["inline const BuiltinMethodTable *const SM_NativeMethodTables[] = {"]
        + [f"    &SM_MethodTable{i:02}," for i in range(19)]
        + ["};"]
    )
    output.mkdir(parents=True, exist_ok=True)
    (output / "DW_ScriptMethodBindings.h").write_text("\n".join(lines) + "\n")
    # Replay fixed-arity method opcodes are 0x7e + argument count. Derive the
    # handler from the actual VM jump table, then validate its count decoder.
    vm_rows = bodies["VMExecute"]
    dispatch = next(
        i
        for i in vm_rows
        if i.mnemonic == "mov" and i.op_str.startswith("ecx, dword ptr [r8 + rdx*4")
    )
    table_rva = dispatch.operands[1].mem.disp
    method_opcode = 0x80
    method_handler = struct.unpack("<I", pe.get_data(table_rva + 4 * method_opcode, 4))[
        0
    ]
    handler_rows = list(
        cs.disasm(pe.get_data(method_handler, 24), base + method_handler)
    )
    assert (
        handler_rows[0].mnemonic == "lea"
        and handler_rows[0].op_str == "eax, [rdx - 0x7e]"
    )
    assert (
        handler_rows[2].mnemonic == "movzx"
        and handler_rows[2].op_str == "r14d, word ptr [rsi]"
    )
    survival_opcode = 0x7E
    survival_handler = struct.unpack(
        "<I", pe.get_data(table_rva + 4 * survival_opcode, 4)
    )[0]
    assert survival_handler == method_handler
    bool_tail = next(
        i.operands[0].imm
        for i in bodies["HasWeaponBoolResult"]
        if i.mnemonic == "call"
        and i.operands[0].type == X86_OP_IMM
        and i.operands[0].imm == base + byid[BODIES["AddBool"][0]]["rva"]
    )
    assert bool_tail == base + byid[BODIES["AddBool"][0]]["rva"]
    getter = bodies["GetWeaponTable"]
    assert (
        len(getter) == 2 and getter[0].mnemonic == "lea" and getter[1].mnemonic == "ret"
    )
    assert getter[0].op_str == "rax, [rcx + 0x1445c]"
    create = bodies["WeaponCreate"]
    assert any(
        i.mnemonic == "call"
        and i.operands[0].type == X86_OP_IMM
        and i.operands[0].imm == base + byid[BODIES["GetWeaponTable"][0]]["rva"]
        for i in create
    )
    create_offsets = {
        operand.mem.disp
        for instruction in create
        for operand in instruction.operands
        if operand.type == X86_OP_MEM
    }
    assert {60, 64000, 66000, 68000, 70594}.issubset(create_offsets)
    assert any(i.mnemonic == "imul" and i.op_str == "rdi, rsi, 0x3e" for i in create)
    table_init = bodies["WeaponTableInit"]
    init_offsets = {
        operand.mem.disp
        for instruction in table_init
        for operand in instruction.operands
        if operand.type == X86_OP_MEM
    }
    assert {62000, 64000, 66000, 68000, 70594}.issubset(init_offsets)
    receipt = dict(
        image_sha256=TARGET,
        catalog_sha256=hashlib.sha256(catalog.read_bytes()).hexdigest(),
        bodies=proof,
        tail=dict(
            derived_from=BODIES["initializer"][0],
            rva=tail - base,
            bytes=89,
            sha256=hashlib.sha256(tailraw).hexdigest(),
        ),
        initializer_complete_bytes=137,
        initializer_complete_sha256=initializer_full_sha256,
        bindings=bindings,
        weapon_table=dict(
            context_offset=83036,
            embedded=True,
            bytes=70596,
            data_offset=0,
            data_stride=62,
            capacity=1000,
            reference_offset=62000,
            next_offset=64000,
            previous_offset=66000,
            bucket_offset=68000,
            bucket_count=1297,
            free_offset=70594,
            exhausted=65535,
            getter="SM_GetWeaponTable",
            create_error=5190,
            hash_seed=0,
            hash_multiplier=16777619,
            hash_bytes=62,
            comparison_bytes=60,
            alternate_offset=60,
            pad_offset=61,
        ),
        native_method_tables=headers,
        vm_method_opcode=method_opcode,
        vm_method_handler_rva=method_handler,
        vm_survival_opcode=survival_opcode,
        vm_survival_handler_rva=survival_handler,
        add_bool_slot_helper_rva=next(
            i.operands[0].imm - base
            for i in bodies["AddBool"]
            if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM
        ),
        replacement_targets=[
            dict(
                function_id=BODIES["initializer"][0],
                symbol="DW_ScriptContextInitialize",
            ),
            dict(function_id=BODIES["dispatcher"][0], symbol="DW_GScriptMPGetMethod"),
        ],
        custom_registry=[
            dict(
                id=constants[3204],
                name="dw_botstyleweapon",
                type=0,
                argument_count=2,
                receiver="entity",
                result="managedWeaponObject",
                callback_symbol="DW_BotStyleWeaponMethod",
                opcode=method_opcode,
            ),
            dict(
                id=constants[3204] + 1,
                name="dw_bot_survival",
                type=0,
                argument_count=0,
                receiver="entity",
                result="bool",
                callback_symbol="DW_BotSurvivalAllowedMethod",
                opcode=survival_opcode,
            ),
            dict(
                id=constants[3204] + 2,
                name="dw_bot_mp_class_ready",
                type=0,
                argument_count=0,
                receiver="entity",
                result="bool",
                callback_symbol="DW_BotMPClassReadyMethod",
                opcode=survival_opcode,
            ),
        ],
        limitations=[
            "Private draft, callback provided by parent; not installed in source units",
            "Runtime Replay names are stripped; use verified baked numeric ID or extend offline compiler registry",
            "Two native method table headers are populated at runtime; preserved by alias to original headers",
        ],
    )
    (output / "script-method-integration.json").write_text(
        json.dumps(receipt, indent=2) + "\n"
    )
    return receipt


ROOT = Path(__file__).resolve().parents[1]


def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve()
    assert snapshot.is_relative_to(ROOT / "data"), "Use a private DW source snapshot"
    assert not (
        snapshot.parent / "client-readiness.json"
    ).exists(), "Never modify a completed client snapshot"
    for relative in (
        "source-units.json",
        "source-workstation/units.json",
        "src/DW_ScriptMethods.cpp",
        "src/DW_ScriptMethodBindings.h",
        "generated/bot-style-method-integration.json",
    ):
        path = snapshot / relative
        assert (
            not path.exists() or path.stat().st_nlink == 1
        ), "Detach shared source before preparation"
    catalog = snapshot / "generated/function-catalog.json"
    executable = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    receipt = derive(executable, catalog, snapshot / "generated")
    shutil.move(
        snapshot / "generated/DW_ScriptMethodBindings.h",
        snapshot / "src/DW_ScriptMethodBindings.h",
    )
    shutil.copy2(
        ROOT / "integration/replay/DW_ScriptMethods.cpp",
        snapshot / "src/DW_ScriptMethods.cpp",
    )
    cat = json.loads(catalog.read_bytes())
    symbols = cat["functions"] + cat["symbols"]
    byid = {r["id"]: r for r in symbols}
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(snapshot / "tools"))
    spec = importlib.util.spec_from_file_location(
        "script_method_source_catalog", snapshot / "tools/source_catalog.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    associations = json.loads((snapshot / "source-units.json").read_bytes())
    existing = {r["symbol"]: r["symbol_id"] for r in associations.get("imports", [])}
    for binding in receipt["bindings"]:
        if binding["kind"] == "global":
            matches = [
                r
                for r in cat["symbols"]
                if r["rva"] == binding["original_rva"]
                and r.get("kind") == "data-address"
                and not r.get("quarantined")
            ]
            assert len(matches) == 1, binding
            binding["identity"] = matches[0]["id"]
            binding["kind"] = "data"
        else:
            binding["identity"] = binding["function_id"]
        assert not byid[binding["identity"]].get("quarantined")
        if binding["name"] in existing:
            assert replace_owned and existing[binding["name"]] == binding["identity"]
        else:
            module.bind_import(binding["identity"], binding["name"])
    units_path = snapshot / "source-workstation/units.json"
    units = json.loads(units_path.read_bytes())
    source = "src/DW_ScriptMethods.cpp"
    digest = hashlib.sha256((snapshot / source).read_bytes()).hexdigest()
    for target in receipt["replacement_targets"]:
        identity, symbol = target["function_id"], target["symbol"]
        prior = [u for u in units["units"] if u["function_id"] == identity]
        assert len(prior) <= 1
        if prior:
            assert (
                replace_owned
                and prior[0]["source"] == source
                and prior[0]["symbol"] == symbol
            )
            units["units"].remove(prior[0])
        associated = [u for u in associations["units"] if u["function_id"] == identity]
        assert len(associated) <= 1
        if associated:
            assert (
                replace_owned
                and associated[0]["source"] == source
                and associated[0]["symbol"] == symbol
            )
        else:
            module.bind(identity, Path(source), symbol)
        units["units"].append(
            dict(
                function_id=identity,
                kind="cpp",
                source=source,
                symbol=symbol,
                sha256=digest,
                revision=digest,
                language="cpp",
            )
        )
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    receipt.update(
        schema=1,
        passed=True,
        method_id=receipt["custom_registry"][0]["id"],
        argument_count=2,
        survival_method_id=receipt["custom_registry"][1]["id"],
        source=source,
        source_sha256=digest,
        callback_symbol="DW_BotStyleWeaponMethod",
        registry=receipt["custom_registry"],
        bounds=dict(
            native_begin=32768,
            native_count=1927,
            extended_count=1927 + len(receipt["custom_registry"]),
            extended_end=32768 + 1927 + len(receipt["custom_registry"]),
        ),
        header="src/DW_ScriptMethodBindings.h",
        header_sha256=hashlib.sha256(
            (snapshot / "src/DW_ScriptMethodBindings.h").read_bytes()
        ).hexdigest(),
        game_run_performed=False,
    )
    receipt["limitations"] = [
        "Native registration layouts/body bindings verified; behavior tests are a separate gate",
        "Two native headers are populated at runtime and preserved through original aliases",
        "Custom callback source is supplied and frozen by the bot-style owner",
    ]
    (snapshot / "generated/bot-style-method-integration.json").write_text(
        json.dumps(receipt, indent=2) + "\n"
    )
    (snapshot / "generated/script-method-integration.json").unlink()
    return receipt


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("snapshot", type=Path)
    p.add_argument("--replace-owned", action="store_true")
    a = p.parse_args()
    print(json.dumps(prepare(a.snapshot, a.replace_owned), indent=2))
