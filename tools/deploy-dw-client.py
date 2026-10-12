"""Deploy the verified production DW target, preserving owner configuration."""

import argparse
from pathlib import Path
import dw_client

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--replace-reviewed-build", type=Path,
    help="Retained DW build report matching a reviewed, manually installed candidate",
)
args = parser.parse_args()

with dw_client.pipeline_lock():
    dw_client.deploy(args.replace_reviewed_build)
