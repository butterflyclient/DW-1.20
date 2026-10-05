"""Run the DW editor with live, revision-checked DW source mirrors."""

from pathlib import Path
import hashlib
import json
import sys
import threading

ROOT = Path(__file__).resolve().parents[1] / "replay-workstation"
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]
from workstation import server
from workstation_asset_metadata import AssetMetadataIndex

# Normalize the cache directory once so junction-backed metadata shards pass
# the same physical containment checks as ordinary cache directories.
_metadata_init = AssetMetadataIndex.__init__


def _resolved_metadata_init(self, *args, **kwargs):
    _metadata_init(self, *args, **kwargs)
    self.root = self.root.resolve()
    self.path = self.root / "manifest.json"
    self.database = self.root / "search.sqlite3"


AssetMetadataIndex.__init__ = _resolved_metadata_init

metadata = json.loads((ROOT / "dw-workspace.json").read_text())
mirrors = {relative: Path(path) for relative, path in metadata["mirrors"].items()}
native_bindings = metadata["native_bindings"]
lock = threading.RLock()
active_project = [None]


def checksum(data):
    return hashlib.sha256(data).hexdigest()


class DWProject(server.Project):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mirror_revisions = {
            relative: checksum((self.root / relative).read_bytes())
            for relative in mirrors
        }
        active_project[0] = self

    def refresh_mirrors(self):
        # Parent/backend development stays authoritative. A local uncommitted
        # editor-file conflict is never silently overwritten.
        with lock:
            for relative, canonical in mirrors.items():
                local = self.root / relative
                incoming = canonical.read_bytes()
                incoming_hash = checksum(incoming)
                prior = self.mirror_revisions[relative]
                if incoming_hash == prior:
                    continue
                if checksum(local.read_bytes()) != prior:
                    raise ValueError(
                        "DW source changed in both editor and project: " + relative
                    )
                temporary = local.with_name(local.name + ".dw-sync.tmp")
                temporary.write_bytes(incoming)
                temporary.replace(local)
                self.mirror_revisions[relative] = incoming_hash

    def authored_files(self):
        self.refresh_mirrors()
        return super().authored_files()

    def read_file(self, relative):
        self.refresh_mirrors()
        return super().read_file(relative)

    def source_input_snapshot(self):
        self.refresh_mirrors()
        return super().source_input_snapshot()

    def save_file(self, relative, content, revision):
        if relative not in mirrors:
            return super().save_file(relative, content, revision)
        with lock:
            self.refresh_mirrors()
            canonical = mirrors[relative]
            prior = canonical.read_bytes()
            result = super().save_file(relative, content, revision)
            if canonical.read_bytes() != prior:
                raise ValueError(
                    "DW source changed during save; editor draft retained: " + relative
                )
            temporary = canonical.with_name(canonical.name + ".dw-editor.tmp")
            temporary.write_bytes((self.root / relative).read_bytes())
            temporary.replace(canonical)
            self.mirror_revisions[relative] = checksum(canonical.read_bytes())
            return result


class DWSources(server.SourceWorkspace):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Attach before Application starts the source-index threads.
        self.dw_project = active_project[0]

    def get_source(self, *args, **kwargs):
        self.dw_project.refresh_mirrors()
        return super().get_source(*args, **kwargs)

    def save_source(self, identity, content, revision=None, variant="cpp"):
        if variant != "cpp" or identity not in native_bindings:
            return super().save_source(identity, content, revision, variant)
        # Several native functions deliberately share one authored translation
        # unit. Save the whole file without creating conflicting per-function
        # copies or stale revisions for its neighboring definitions.
        self.dw_project.save_file(native_bindings[identity], content, revision)
        return self.get_source(identity, variant)


server.Project = DWProject
server.SourceWorkspace = DWSources
if __name__ == "__main__":
    server.main()
