"""Source-only owned-group/catch-up checks; no compiler, fastfile builder or game."""

import argparse
import ast
import copy
import hashlib
import json
import mmap
from pathlib import Path
import subprocess
import struct
import tempfile
import types

import dw_update_assets as assets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checks = []

    def rejected(label, action):
        try:
            action()
        except (ValueError, UnicodeError, KeyError, OSError, AssertionError):
            checks.append("Rejected " + label)
        else:
            raise AssertionError("Accepted " + label)

    scratch = assets.ROOT / "data/research/weapon-inspect-20261017"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="update-groups-", dir=scratch) as temporary:
        snapshot = Path(temporary) / "source"
        (snapshot / "src").mkdir(parents=True)
        (snapshot / "tools").mkdir()
        frozen = snapshot / "tools/fixture-source.py"
        frozen.write_bytes(b"# synthetic source receipt, never executable game data\n")
        proofs = {}
        for owner, directory in (
            (1, "bot-style-scripts"),
            (2, "weapon-inspect-assets"),
        ):
            package = snapshot / "generated" / directory
            package.mkdir(parents=True)
            # These are short text tokens in .bin/.fp fixtures. No real FF is
            # produced, parsed or serialized, and all fixtures are removed.
            resources = [
                f"synthetic owner {owner} resource {index}\n".encode()
                for index in range(4)
            ]
            paths = [
                package / name
                for name in ("primary.bin", "primary.fp", "empty.bin", "empty.fp")
            ]
            for path, data in zip(paths, resources):
                path.write_bytes(data)
            identity = assets.sha(b"".join(resources))
            zone = assets.OWNERS[owner] + identity[:16]
            installation = []
            for prefix, native_directory, first in (
                ("", "", 0),
                ("eng_", "english", 2),
            ):
                for index, extension in enumerate((".ff", ".fp")):
                    name = prefix + zone + extension
                    installation.append(
                        dict(
                            name=name,
                            source=str(paths[first + index]),
                            sha256=assets.sha(resources[first + index]),
                            size=len(resources[first + index]),
                            relative_path=(
                                native_directory + "/" if native_directory else ""
                            )
                            + name,
                        )
                    )
            proof = dict(
                schema="replay120-bot-style-native-overlay-v1",
                packaged=True,
                resource_bundle_sha256=identity,
                installation_manifest=installation,
                output_fastfile=str(paths[0]),
                empty_companion=dict(output_fastfile=str(paths[2])),
                native_folder_rules=[
                    dict(name_prefix="", directory=""),
                    dict(name_prefix="eng_", directory="english"),
                ],
            )
            if owner == 2:
                extraction = package / "extraction.json"
                extraction.write_bytes(b'{"synthetic_fixture_only":true}\n')
                proof.update(
                    schema="replay120-weapon-inspect-native-package-v1",
                    gates=dict(native_reader_validated=True),
                    source_inputs=[
                        dict(
                            path=str(frozen),
                            bytes=frozen.stat().st_size,
                            sha256=assets.sha(frozen.read_bytes()),
                        )
                    ],
                    extraction_manifest=str(extraction),
                    extraction_manifest_sha256=assets.sha(extraction.read_bytes()),
                )
            proof_path = package / "package-proof.json"
            proofs[owner] = (proof_path, proof)
            if owner == 1:
                proof_path.write_text(json.dumps(proof))
        legacy_record = assets.prepare(snapshot)
        legacy = (snapshot / "generated/update-assets.bin").read_bytes()
        assert (
            legacy_record["schema"] == 1
            and assets.extract(b"fixture" + legacy) == legacy
        )
        checks.append("Bot-only source snapshots retain exact v1 format and extraction")
        path, proof = proofs[2]
        path.write_text(json.dumps(proof))
        record = assets.prepare(snapshot)
        aggregate = (snapshot / "generated/update-assets.bin").read_bytes()
        header_text = Path(record["embedded_header"]).read_text()
        import re

        embedded = bytes(
            int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", header_text)
        )
        assert embedded == legacy + aggregate
        assert (
            assets.decode(aggregate) == record["entries"]
            and assets.extract(embedded) == aggregate
        )
        assert len(record["groups"]) == 2 and len(record["payloads"]) == 8
        checks.append(
            "One referenced header retains legacy and aggregate records with separate bundle identities"
        )
        baseline = "24d3dce685607ae517d0284e74c739c84c0f9966"
        old_source = subprocess.run(
            ["git", "show", baseline + ":tools/dw_update_assets.py"],
            cwd=assets.ROOT,
            check=True,
            capture_output=True,
        ).stdout
        historical = types.ModuleType("historical_update_assets")
        historical.__file__ = str(assets.ROOT / "tools/dw_update_assets.py")
        exec(compile(old_source, historical.__file__, "exec"), historical.__dict__)
        assert historical.extract(embedded) == legacy
        assert historical.decode(legacy) == record["groups"][0]["entries"]
        assert (
            historical.encode(
                record["groups"][0]["entries"], record["groups"][0]["bundle_sha256"]
            )
            == legacy
        )
        checks.append(
            "Unmodified historical Python parser sees one valid bot record and ignores aggregate during EXE catch-up"
        )
        image = snapshot / "image.fixture"
        image.write_bytes(b"synthetic image; not an EXE\n" + embedded)
        output = snapshot / "publication-fixture"
        output.mkdir()
        published = assets.publication(image, snapshot, output)
        assert published == record and len(list((output / "assets").glob("*.bin"))) == 8
        checks.append(
            "Publication verifies both proofs and all eight frozen payloads against the exact embedded aggregate"
        )
        publisher_source = (
            assets.ROOT / "tools/publish-full-executable.py"
        ).read_text()
        tree = ast.parse(publisher_source)
        remote_script = next(
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("\nimport hashlib,json,os,pathlib,struct,mmap")
        )
        compile(remote_script, "publisher remote source (not executed)", "exec")
        validation = remote_script[
            remote_script.index(
                "if 'assets' in new:\n    assets=new['assets']"
            ) : remote_script.index("index=root/'full-image-catalog.json'")
        ]

        def remote_validation():
            exec(
                compile(validation, "local copy of publisher asset validation", "exec"),
                # Production runs on Linux; Windows rejects fsync on a read-only
                # descriptor, so only this irrelevant flush call is substituted.
                dict(
                    hashlib=hashlib,
                    struct=struct,
                    mmap=mmap,
                    os=types.SimpleNamespace(fsync=lambda _: None),
                    incoming=output,
                    image=image,
                    new=dict(
                        assets=dict(
                            manifest_sha256=record["manifest_sha256"],
                            manifest_size=len(aggregate),
                            files=len(record["entries"]),
                            payloads={
                                k: v["size"] for k, v in record["payloads"].items()
                            },
                        )
                    ),
                ),
            )

        remote_validation()
        checks.append(
            "Exact publisher-side asset validator accepts aggregate with its unique legacy catch-up record in local metadata fixture"
        )
        image.write_bytes(b"synthetic image\n" + aggregate)
        rejected(
            "publisher aggregate without legacy catch-up record", remote_validation
        )
        image.write_bytes(b"synthetic image\n" + embedded)

        def mutate_group(change):
            groups = copy.deepcopy(assets.decode_groups(aggregate))
            change(groups)
            assets.encode_groups(groups)

        rejected(
            "inspection path traversal",
            lambda: mutate_group(
                lambda g: g[1]["entries"][0].update(name="../common_base_mp.ff")
            ),
        )
        rejected(
            "stock zone ownership",
            lambda: mutate_group(
                lambda g: g[1]["entries"][0].update(name="common_base_mp.ff")
            ),
        )
        rejected(
            "inspection entry in bot group",
            lambda: mutate_group(
                lambda g: g[0]["entries"].__setitem__(
                    0, copy.deepcopy(g[1]["entries"][0])
                )
            ),
        )
        rejected(
            "bot entry in inspection group",
            lambda: mutate_group(
                lambda g: g[1]["entries"].__setitem__(
                    0, copy.deepcopy(g[0]["entries"][0])
                )
            ),
        )
        rejected("unknown owner", lambda: mutate_group(lambda g: g[1].update(owner=3)))
        rejected(
            "duplicate owner", lambda: mutate_group(lambda g: g[1].update(owner=1))
        )
        rejected("missing FF/FP", lambda: mutate_group(lambda g: g[1]["entries"].pop()))
        rejected(
            "duplicate inspection entry",
            lambda: mutate_group(lambda g: g[1]["entries"].append(g[1]["entries"][0])),
        )
        rejected(
            "oversized inspection file",
            lambda: mutate_group(
                lambda g: g[1]["entries"][0].update(size=assets.MAX_BYTES + 1)
            ),
        )
        rejected(
            "incorrect per-owner bundle",
            lambda: mutate_group(lambda g: g[1].update(bundle_sha256="0" * 64)),
        )
        rejected(
            "inconsistent shared hash size",
            lambda: mutate_group(
                lambda g: g[1]["entries"][0].update(
                    sha256=g[0]["entries"][0]["sha256"],
                    size=g[0]["entries"][0]["size"] + 1,
                )
            ),
        )
        rejected(
            "aggregate without legacy bootstrap", lambda: assets.extract(aggregate)
        )
        rejected("duplicate legacy record", lambda: assets.extract(embedded + legacy))
        rejected(
            "duplicate aggregate record", lambda: assets.extract(embedded + aggregate)
        )
        changed = copy.deepcopy(assets.decode_groups(aggregate)[0]["entries"])
        changed[0]["sha256"] = "f" * 64
        rejected(
            "different legacy group",
            lambda: assets.extract(
                assets.encode(changed, record["groups"][0]["bundle_sha256"]) + aggregate
            ),
        )
        bad = bytearray(aggregate)
        bad[-1] ^= 1
        rejected(
            "aggregate corruption without downgrade",
            lambda: assets.extract(legacy + bad),
        )
        proof["gates"]["native_reader_validated"] = False
        path.write_text(json.dumps(proof))
        rejected("unverified native inspection proof", lambda: assets.prepare(snapshot))
        proof["gates"]["native_reader_validated"] = True
        path.write_text(json.dumps(proof))
        frozen.write_bytes(b"changed source after verification\n")
        rejected("changed pinned source", lambda: assets.prepare(snapshot))
        rejected(
            "changed pinned source at publication",
            lambda: assets.publication(image, snapshot, output),
        )
        frozen.write_bytes(b"# synthetic source receipt, never executable game data\n")
        proof["native_folder_rules"][1]["directory"] = "other"
        path.write_text(json.dumps(proof))
        rejected("inspection folder mismatch", lambda: assets.prepare(snapshot))
        proof["native_folder_rules"][1]["directory"] = "english"
        proof["installation_manifest"][0]["source"] = str(frozen)
        path.write_text(json.dumps(proof))
        rejected("payload outside owned package", lambda: assets.prepare(snapshot))
        checks.append(
            "Native backup/replace/rollback implementation remains shared for both groups; no native binary was compiled or run"
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            dict(
                passed=True,
                checks=checks,
                historical_parser_commit=baseline,
                synthetic_metadata_fixtures_only=True,
                compiled_cpp=False,
                generated_fastfiles=False,
                game_modified=False,
                published_server=False,
                native_helper_execution_tested=False,
            ),
            indent=2,
        )
        + "\n"
    )
    print("PASS", len(checks), "source-only owned-group checks")


if __name__ == "__main__":
    main()
