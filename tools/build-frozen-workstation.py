"""Compatibility entry point for the single production DW build."""

from pathlib import Path
import runpy

# Old feature/revision switches are rejected by the production parser. They
# cannot omit the bot optimizations or create a private updater-pinned target.
runpy.run_path(str(Path(__file__).with_name("build-dw-client.py")), run_name="__main__")
