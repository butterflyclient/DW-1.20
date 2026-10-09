"""Focused publisher recovery checks; no game build, launch or identity access."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location(
        "executable_publication", ROOT / "tools/publish-executable-update.py"
    )
    publication = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publication)
    checks = []

    # Tiny synthetic images exercise the publication lifecycle, not the Replay
    # compiler's machine-code gates. Their real MSDelta round trips stay bounded.
    with tempfile.TemporaryDirectory(prefix="update-publication-", dir=ROOT / "data") as name:
        directory = Path(name)
        archive, output = directory / "archive", directory / "publication"

        def fixture(number, content):
            folder = directory / str(number)
            folder.mkdir()
            image = folder / "image.exe"
            image.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            report = folder / "build-report.json"
            report.write_text(json.dumps(dict(sha256=digest, cpp=[{"fixture": True}])))
            (folder / "verification-report.json").write_text(
                json.dumps(dict(sha256=digest, unresolved_symbols=0))
            )
            (folder / "relocation-audit.json").write_text(
                json.dumps(dict(sha256=digest, passed=True))
            )
            return image, report

        base, base_report = fixture(1, b"MZ" + bytes(range(256)) * 100)
        target, target_report = fixture(2, base.read_bytes() + b"fresh compiler revision")
        expected, report_bytes = target.read_bytes(), target_report.read_bytes()
        target_hash = hashlib.sha256(expected).hexdigest()
        publication.retain_release(base, base_report, 1, archive)
        make_patch = publication.make_patch
        promoted = target.with_name("promoted.exe")
        promoted_report = target_report.with_name("promoted-report.json")

        def promote_after_delta(old, new):
            patch = make_patch(old, new)
            target.rename(promoted)
            target_report.rename(promoted_report)
            return patch

        publication.make_patch = promote_after_delta
        catalog = publication.publish(target, target_report, 2, archive, output)
        assert catalog["latest"] == target_hash
        assert (archive / (target_hash + ".exe")).read_bytes() == expected
        assert (archive / (target_hash + ".build-report.json")).read_bytes() == report_bytes
        checks.append("Artifact/report promotion during compression archives the verified snapshot")

        def compression_must_not_repeat(*unused):
            raise AssertionError("Verified retry needlessly repeated compression")

        publication.make_patch = compression_must_not_repeat
        assert publication.publish(promoted, promoted_report, 2, archive, output) == catalog
        checks.append("Retry revalidates cached MSDelta output without repeating compression")
        journal = (archive / "releases.json").read_bytes()
        published = (output / "catalog.json").read_bytes()
        row = next(iter(catalog["patches"].values()))
        patch_file = output / "patches" / (row["sha256"] + ".delta")
        patch = bytearray(patch_file.read_bytes())
        patch[-1] ^= 1
        patch_file.write_bytes(patch)
        try:
            publication.publish(promoted, promoted_report, 2, archive, output)
        except ValueError:
            pass
        else:
            raise AssertionError("Corrupted cached patch was accepted")
        assert (archive / "releases.json").read_bytes() == journal
        assert (output / "catalog.json").read_bytes() == published
        checks.append("Corrupted cached bytes leave the release journal and catalog unchanged")

        cache_path = output / "verified-patches.json"
        cache = json.loads(cache_path.read_bytes())
        next(iter(cache["patches"].values()))["sha256"] = "../outside"
        publication.atomic_json(cache_path, cache)
        try:
            publication.publish(promoted, promoted_report, 2, archive, output)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe cached patch identity was accepted")
        checks.append("Cached identities are constrained to content-addressed patch filenames")

    args.output.write_text(
        json.dumps(
            dict(
                passed=True,
                checks=checks,
                scope="Publication control flow and actual bounded MSDelta round trips",
                game_launched=False,
                compiler_or_gameplay_verification=False,
            ),
            indent=2,
        )
        + "\n"
    )
    print("PASS:", len(checks), "focused publication recovery checks")


if __name__ == "__main__":
    main()
