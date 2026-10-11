"""Import checked source revisions through the running workstation's HTTP API."""

import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]

UNLOCK_ROOTS = (
    (0x10592B0, "func_1410592B0"), (0x1059360, "func_141059360"),
    (0x1059410, "func_141059410"), (0x1059500, "func_141059500"),
    (0x1059A80, "func_141059A80"), (0xF58C60, "func_140F58C60"),
)
UNLOCK_FUNCTION_IMPORTS = (
    (0x105BC30, "func_14105BC30"), (0x20838B0, "func_1420838B0"),
    (0x20839E0, "func_1420839E0"), (0x2083A30, "func_142083A30"),
    (0x19CE9B0, "func_1419CE9B0"), (0x2084950, "func_142084950"),
    (0x2084100, "func_142084100"), (0x20833B0, "func_1420833B0"),
    (0x19CE4F0, "func_1419CE4F0"), (0x2089FB0, "func_142089FB0"),
    (0xD66C20, "func_140D66C20"),
)
UNLOCK_DATA_IMPORTS = ((0x414CC80, "gl_14414CC80"), (0x44879C8, "gl_1444879C8"))


def bind_private_unlock_projection(private_root):
    """Use copied native catalog/compiler ownership; never save through HTTP."""
    private_root = Path(private_root).resolve(strict=True)
    if not private_root.is_relative_to(ROOT.resolve()) or private_root == ROOT.resolve():
        raise ValueError("Unlock integration needs a private compiler snapshot under the DW root")
    catalog = json.loads((private_root / "generated/function-catalog.json").read_text())
    expected_image = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    if catalog["image_sha256"] != expected_image:
        raise ValueError("Unlock projection catalog belongs to another Replay build")
    target_receipt = json.loads((ROOT / "validation/20261011-unlock-progression-target.json").read_text())
    if not target_receipt["passed"] or target_receipt["image_sha256"] != expected_image:
        raise ValueError("Original unlock registration/cap proof does not verify")
    sources = ("DW_Unlocks.cpp", "dw_unlock_progression_caps.h")
    for name in sources:
        source = ROOT / "integration/replay" / name
        destination = private_root / "src" / name
        if destination.exists() and destination.read_bytes() != source.read_bytes():
            raise ValueError("Private unlock source differs; preserve it and create a fresh snapshot: " + name)
    header = ROOT / "integration/replay/dw_unlock_progression_caps.h"
    if hashlib.sha256(header.read_bytes()).hexdigest() != target_receipt["header_sha256"]:
        raise ValueError("Unlock cap header no longer matches the original CSV proof")
    source_bytes = {name: (ROOT / "integration/replay" / name).read_bytes() for name in sources}
    source_hash = hashlib.sha256(source_bytes["DW_Unlocks.cpp"]).hexdigest()
    unit_path = private_root / "source-workstation/units.json"
    units = json.loads(unit_path.read_text())
    if units["image_sha256"] != expected_image:
        raise ValueError("Workstation unit revisions belong to another Replay build")
    added_revision = False
    associations = json.loads((private_root / "source-units.json").read_text())
    root_plan, import_plan = [], []
    for rva, symbol in UNLOCK_ROOTS:
        rows = [row for row in catalog["functions"] if row["rva"] == rva and not row.get("quarantined")]
        if len(rows) != 1:
            raise ValueError("Missing or ambiguous original unlock root: " + symbol)
        row = rows[0]
        existing = [unit for unit in associations["units"] if unit["function_id"] == row["id"] or unit["symbol"] == symbol]
        expected = {"source": "src/DW_Unlocks.cpp", "symbol": symbol, "function_id": row["id"]}
        if existing:
            if existing != [expected]:
                raise ValueError("Existing native unlock ownership differs: " + symbol)
        else:
            root_plan.append((row["id"], symbol))
        revision = {"function_id": row["id"], "kind": "cpp", "source": "src/DW_Unlocks.cpp",
                    "symbol": symbol, "sha256": source_hash, "revision": source_hash, "language": "cpp"}
        existing = [unit for unit in units["units"] if unit["function_id"] == row["id"]]
        if existing:
            if existing != [revision]:
                raise ValueError("Saved native unlock revision differs: " + symbol)
        else:
            units["units"].append(revision)
            added_revision = True
    for table, imports in ((catalog["functions"], UNLOCK_FUNCTION_IMPORTS),
                           (catalog["symbols"], UNLOCK_DATA_IMPORTS)):
        for rva, symbol in imports:
            rows = [row for row in table if row["rva"] == rva and not row.get("quarantined")]
            if len(rows) != 1:
                raise ValueError("Missing or ambiguous unlock dependency: " + symbol)
            existing = [entry for entry in associations["imports"] if entry["symbol"] == symbol]
            expected = {"symbol": symbol, "symbol_id": rows[0]["id"]}
            if existing:
                if existing != [expected]:
                    raise ValueError("Existing native unlock import differs: " + symbol)
            else:
                import_plan.append((rows[0]["id"], symbol))
    # Ownership, revisions and all dependencies are reviewed before any write.
    for name in sources:
        destination = private_root / "src" / name
        if not destination.exists():
            destination.write_bytes(source_bytes[name])
    sys.path.insert(0, str(private_root / "tools"))
    spec = importlib.util.spec_from_file_location("dw_private_unlock_catalog", private_root / "tools/source_catalog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for identity, symbol in root_plan:
        module.bind(identity, Path("src/DW_Unlocks.cpp"), symbol)
    if added_revision:
        unit_path.write_text(json.dumps(units, indent=2) + "\n")
    for identity, symbol in import_plan:
        module.bind_import(identity, symbol)
    print("Verified six private Replay unlock roots and thirteen native dependencies; no HTTP workstation writes")


class Workstation:
    def __init__(self, url, credentials):
        self.url = url.rstrip("/")
        auth = json.loads(Path(credentials).read_text(encoding="utf-8-sig"))
        self.headers = {
            "Authorization": "Basic "
            + base64.b64encode(
                (auth["username"] + ":" + auth["password"]).encode()
            ).decode()
        }
        state = self.request("/api/status")
        if state["backend"].get("restart_required"):
            raise RuntimeError(
                "Workstation needs its normal restart before saving: "
                + ", ".join(state["backend"].get("changed_files", []))
            )
        if state.get("active_job"):
            raise RuntimeError(
                "A workstation compiler job is active; source edits were not changed"
            )
        self.headers["X-Replay-Token"] = state["csrf"]

    def request(self, path, body=None):
        headers = dict(self.headers)
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.url + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(error.read().decode()) from error

    def function(self, name):
        data = self.request(
            "/api/sources?" + urllib.parse.urlencode({"q": name, "limit": 100})
        )
        rows = [
            row
            for row in data["items"]
            if name == row["name"] or name in row.get("aliases", [])
        ]
        if len(rows) != 1:
            raise RuntimeError("Native function identity is missing/ambiguous: " + name)
        return self.request(
            "/api/source?" + urllib.parse.urlencode({"id": rows[0]["id"]})
        )

    def save(self, source, content):
        return self.request(
            "/api/source/save",
            {
                "id": source["id"],
                "revision": source["revision"],
                "variant": "cpp",
                "language": "cpp",
                "content": content,
            },
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8126")
    parser.add_argument(
        "--credentials",
        default=r"C:\Users\achar\AppData\Local\ReplayFrontendPreview\credentials.json",
    )
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--unlock-progression-root", type=Path,
                        help="Bind unlock projection in an existing private DW compiler snapshot without touching the HTTP workstation")
    args = parser.parse_args()
    if args.unlock_progression_root:
        if args.build:
            parser.error("Private unlock binding and HTTP build are separate operations")
        bind_private_unlock_projection(args.unlock_progression_root)
        return
    workstation = Workstation(args.url, args.credentials)
    if args.build:
        job = workstation.request("/api/build", {"profile": "engine"})
        (ROOT / "data").mkdir(exist_ok=True)
        (ROOT / "data" / "workstation-job.json").write_text(
            json.dumps(job, indent=2) + "\n"
        )
        print("Workstation compiler job:", job["id"])
        return
    backup = ROOT / "data" / "source-before-dw.json"
    receipt = ROOT / "data" / "workstation-source-receipt.json"
    (ROOT / "data").mkdir(exist_ok=True)
    names = [
        "sub_14212B100",
        "bdLoginConfig::getAuthPort",
        "bdLoginConfig::getLSGAddress",
        "bdLoginConfig::getLSGPort",
        "ScrPlace_EndFrame",
    ]
    sources = {name: workstation.function(name) for name in names}
    if not backup.exists():
        backup.write_text(json.dumps(sources, indent=2) + "\n", encoding="utf-8")
    helper = workstation.request(
        "/api/source/create",
        {
            "name": "DW_LocalBackend_Frame",
            "language": "cpp",
            "content": (
                ROOT / "integration" / "replay" / "DW_LocalBackend_Frame.cpp"
            ).read_text(),
        },
    )
    edits = [helper]
    types = [
        (
            "sub_14212B100",
            "const char*",
            "DW_LocalBackend_GetAuthAddress",
            "const void*",
        ),
        (
            "bdLoginConfig::getAuthPort",
            "uint16_t",
            "DW_LocalBackend_GetAuthPort",
            "const void*",
        ),
        (
            "bdLoginConfig::getLSGAddress",
            "const char*",
            "DW_LocalBackend_GetLSGAddress",
            "const void*",
        ),
        (
            "bdLoginConfig::getLSGPort",
            "uint16_t",
            "DW_LocalBackend_GetLSGPort",
            "const void*",
        ),
    ]
    for name, result, helper_name, argument in types:
        source = sources[name]
        content = (
            "#include <stdint.h>\n\n"
            "// Replay-local backend selection; native configuration is preserved for other builds.\n"
            f'extern "C" {result} {helper_name}({argument});\n'
            f'extern "C" {result} {source["symbol"]}({argument} config) {{\n'
            f"    return {helper_name}(config);\n}}\n"
        )
        edits.append(workstation.save(source, content))
    source = sources["ScrPlace_EndFrame"]
    content = source["content"]
    if "DW_LocalBackend_Frame" not in content:
        content = 'extern "C" void DW_LocalBackend_Frame();\n' + content
        marker = "    Com_DebugStates_Frame(0);"
        if content.count(marker) != 1:
            raise RuntimeError(
                "Frame-end source changed; review its native lifecycle before insertion"
            )
        content = content.replace(marker, "    DW_LocalBackend_Frame();\n" + marker)
    edits.append(workstation.save(source, content))
    records = [
        {
            key: source.get(key)
            for key in ("id", "name", "symbol", "revision", "language")
        }
        | {"content_sha256": hashlib.sha256(source["content"].encode()).hexdigest()}
        for source in edits
    ]
    receipt.write_text(
        json.dumps(
            {
                "schema": 1,
                "workstation": args.url,
                "method": "workstation HTTP source create/save with revision and compiler validation",
                "sources": records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    for record in records:
        print(record["name"], record["id"], record["revision"])


if __name__ == "__main__":
    main()
