"""Compile the single production DW executable, including current optimizations."""

import argparse
import dw_client

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--prepare-only",
    action="store_true",
    help="Freeze the same production target without compiling",
)
args = parser.parse_args()
with dw_client.pipeline_lock():
    directory = dw_client.prepare()
    if not args.prepare_only:
        dw_client.build(directory)
