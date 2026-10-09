"""Publish the shipped premium Battle Pass activation definitions, without inventing XP rules."""
import argparse
import hashlib
import json
from pathlib import Path


def build(table):
    if table.get('name') != 'loot/battlepass_ids.csv' or table.get('columns') != 21:
        raise ValueError('Expected Replay Battle Pass table')
    rows = table['rows']
    if table.get('row_count') != len(rows): raise ValueError('Incomplete Battle Pass table')
    definitions = []
    for row in rows:
        if len(row) != 21: raise ValueError('Incomplete Battle Pass row')
        if row[2] != '0': continue
        item, identity, season = int(row[0]), int(row[6]), int(row[16])
        if not (1 <= season <= 6 and item == 430000 + 1000*(season-1) and identity == 3000001 + 1000*(season-1)):
            raise ValueError('Unexpected native premium activation')
        if not row[5]: raise ValueError('Missing native activation event')
        # Same-Replay 0x140F350D0 routes kind 20 states to 0x140F30C60.
        # Premium activation IDs enter its native activation cache. No rank/XP
        # targets or season reward rules are synthesized here.
        state = dict(id=identity, name=row[5], kind=20, status=2, progress=0, target=0)
        definitions.append({'1': row[5], '3': 20, '14': identity, 'initialState': state})
    if len(definitions) != 6 or len({r['14'] for r in definitions}) != 6:
        raise ValueError('Expected all six native premium activations')
    return definitions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('table', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    raw = args.table.read_bytes()
    rows = build(json.loads(raw))
    args.output.mkdir(parents=True, exist_ok=True)
    body = (json.dumps(rows, indent=2)+'\n').encode()
    (args.output/'definitions.json').write_bytes(body)
    (args.output/'manifest.json').write_text(json.dumps(dict(schema=1,title=5800,
        table_sha256=hashlib.sha256(raw).hexdigest(),definitions_sha256=hashlib.sha256(body).hexdigest(),
        activation_ids=[r['14'] for r in rows],native_dispatch=hex(0x140F350D0),native_consumer=hex(0x140F30C60)),indent=2)+'\n')
    print('Built six Replay premium Battle Pass activation definitions')


if __name__ == '__main__': main()
