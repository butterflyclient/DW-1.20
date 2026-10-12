"""Freeze the native overlay file manifest before embedding the update helper."""
import argparse
import json
from pathlib import Path
from dw_update_assets import prepare

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot), indent=2))
