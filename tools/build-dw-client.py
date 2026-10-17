"""Compile the single production DW executable, including current optimizations."""

import argparse
from pathlib import Path
import dw_client

parser = argparse.ArgumentParser(description=__doc__)
mode = parser.add_mutually_exclusive_group()
mode.add_argument(
    "--prepare-only",
    action="store_true",
    help="Freeze the same production target without compiling",
)
mode.add_argument(
    "--validate-only", action="store_true",
    help="Compile and verify the production target without publishing during a live match",
)
mode.add_argument(
    "--publish-validated", type=Path, metavar="JOB",
    help="Publish an unchanged verified production job after backend activation",
)
parser.add_argument('--skip-gameplay-checks', action='store_true',
                    help='Explicit owner override: retain build/update integrity, skip gameplay regression checks')
parser.add_argument('--pending-map-record', type=Path,
                    help='Build an explicitly requested frozen map candidate; publication waits for its matching live catalog')
args = parser.parse_args()
with dw_client.pipeline_lock():
    if args.publish_validated:
        dw_client.publish_validated(args.publish_validated)
    else:
        directory = dw_client.prepare(pending_map_record=args.pending_map_record)
        if not args.prepare_only:
            dw_client.build(directory, publish_ready=not args.validate_only,
                            gameplay_checks=not args.skip_gameplay_checks)
