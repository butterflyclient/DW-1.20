"""Freeze the shipping integration and add an opt-in command for its native getter."""

import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
cohort = ROOT / "data/native-counter-read-20261008"
inputs = cohort / "integration"
assert not inputs.exists(), "Keep an earlier private input snapshot intact"
inputs.mkdir(parents=True)
deployed = json.loads((ROOT / "data/deployment.json").read_bytes())
frozen = Path(deployed["compiler_source_root"]) / "src"
report = json.loads(
    (Path(deployed["build_directory"]) / "build-report.json").read_bytes()
)
assert report["sha256"] == deployed["sha256"]
verified_cpp = {
    Path(item["source"]).name: item["source_sha256"] for item in report["cpp"]
}
records = []
for original in sorted((ROOT / "integration/replay").iterdir()):
    if (
        original.suffix not in (".cpp", ".h")
        or original.name == "DW_LocalBackend_Frame.cpp"
    ):
        continue
    saved = frozen / original.name
    if not saved.exists():
        continue  # Unrelated host-migration/player-path work is not in the shipping cohort.
    raw = saved.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if saved.suffix == ".cpp":
        assert verified_cpp.get(saved.name) == digest, (
            "Unverified shipping source: " + saved.name
        )
    shutil.copyfile(saved, inputs / saved.name)
    records.append(dict(name=saved.name, source_sha256=digest))
platform = inputs / "DW_LocalPlatform.cpp"
text = platform.read_text()
marker = "    bool DW_LocalBackend_IsEnabled();"
assert text.count(marker) == 1
text = text.replace(
    marker,
    marker + """
    uint64_t func_1414F2320(int); // Original LiveCounter_GetCounterTotalValue.
    extern unsigned char gl_14E6BFB28;
    extern unsigned gl_14461B1D0;
""",
)
marker = "    void RenewFrame(bool force = false);"
assert text.count(marker) == 1
text = text.replace(marker, "    cmd_function_s s_testCounterCommand{};\n" + marker)
marker = "    void TestRenew_f()"
assert text.count(marker) == 1
text = text.replace(
    marker,
    """    void TestCounter_f()
    {
        if (s_testMode != 2 || !Sys_IsMainThread() || Cmd_Argc() != 2 ||
            !gl_14E6BFB28 || !gl_14461B1D0 || gl_14461B1D0 >= 64)
            return;
        const char *argument = Cmd_Argv(1);
        unsigned index = 0, length = 0;
        while (argument && argument[length])
        {
            if (length >= 2 || argument[length] < '0' || argument[length] > '9')
                return;
            index = index * 10 + unsigned(argument[length++] - '0');
        }
        if (!length || index >= gl_14461B1D0)
            return;
        // The original getter sets its own read-request flag; the original
        // frame/task manager owns dispatch, completion and the cached values.
        const auto value = static_cast<int64_t>(func_1414F2320(int(index)));
        Com_Printf(25, "[DW] Native global counter %u requested; cached value %lld\\n", index, value);
    }

""" + marker,
)
marker = '            Cmd_AddCommandInternal("dw_localTestRenew", TestRenew_f, &s_testRenewCommand);'
assert text.count(marker) == 1
text = text.replace(
    marker,
    marker
    + '\n            Cmd_AddCommandInternal("dw_localTestCounter", TestCounter_f, &s_testCounterCommand);',
)
platform.write_text(text, newline="\n")
receipt = dict(
    schema=1,
    shipping_game_sha256=deployed["sha256"],
    verified_shipping_sources=records,
    input_directory=str(inputs),
    private_platform_sha256=hashlib.sha256(platform.read_bytes()).hexdigest(),
    original_getter_va="0x1414F2320",
    modification="Opt-in native getter command only; no cache/task/fence writes",
    compiler_owns_function_placement_and_references=True,
)
(cohort / "input.json").write_text(json.dumps(receipt, indent=2) + "\n", newline="\n")
print(
    f"Frozen {sum(item['name'].endswith('.cpp') for item in records)} verified shipping CPP inputs; private native-counter command prepared"
)
