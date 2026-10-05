"""Import checked source revisions through the running workstation's HTTP API."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


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
    args = parser.parse_args()
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
            "bdLoginConfig::getAuthPort",
            "uint16_t",
            "DW_LocalBackend_GetAuthPort",
            "void*",
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
