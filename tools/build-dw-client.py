"""Compile the single production DW executable, including current optimizations."""

import argparse
import os
from pathlib import Path
import time
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
parser.add_argument('--clean', action='store_true', help='Regenerate native preparation instead of reusing an unchanged prepared source')
parser.add_argument('--full-checks', action='store_true', help='Run every regression check instead of reusing unchanged compiled behavior')
args = parser.parse_args()
if args.full_checks:
    os.environ['REPLAY_FULL_CHECKS'] = '1'
started = time.perf_counter()
with dw_client.pipeline_lock():
    if args.publish_validated:
        dw_client.publish_validated(args.publish_validated)
    else:
        directory = dw_client.prepare(pending_map_record=args.pending_map_record, clean=args.clean)
        prepared = time.perf_counter()
        if not args.prepare_only:
            dw_client.build(directory, publish_ready=not args.validate_only,
                            gameplay_checks=not args.skip_gameplay_checks)
        timing = dict(prepare_seconds=prepared-started, build_and_checks_seconds=time.perf_counter()-prepared,
                      total_seconds=time.perf_counter()-started, directory=str(directory))
        if not (directory/'timing.json').exists():
            dw_client.save(directory/'timing.json', timing)
        dw_client.save(dw_client.settings()[1]/'latest-invocation-timing.json', timing)
        print('DW build elapsed: %.2fs' % (time.perf_counter()-started), flush=True)
