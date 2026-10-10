"""Execute original Replay instructions for mode-qualified kill/objective packets."""

import argparse
import hashlib
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.is_relative_to(ROOT)
    original = ROOT / 'tools/research-challenge-event-parser.py'
    environment = runpy.run_path(str(original))
    proof = json.loads(output.read_bytes())
    case, kill_input = environment['case'], environment['kill_input']
    parent_path = ROOT / 'data/remaining-destruction-20261010/challenge-parser-verified.json'
    parent = json.loads(parent_path.read_bytes())
    for label, mask in parent['target_mask_cases'].items():
        row = case('kill', kill_input('iw8_pi_golf21_mp', target_type=mask))
        assert row['accepted'] and row['values'][5] >> 16 & 0xFFFF == mask
        row['fixture_label'] = label
        proof['cases'].append(row)
    kills = {
        'tdm_pistol': ('iw8_pi_golf21_mp', 6, 'MOD_PISTOL_BULLET'),
        'tdm_headshot': ('iw8_pi_golf21_mp', 6, 'MOD_HEAD_SHOT'),
        'hq_pistol': ('iw8_pi_golf21_mp', 35, 'MOD_PISTOL_BULLET'),
        'dom_pistol': ('iw8_pi_golf21_mp', 8, 'MOD_PISTOL_BULLET'),
        'dom_m19': ('iw8_pi_papa320_mp', 8, 'MOD_PISTOL_BULLET'),
        'tdm_m19': ('iw8_pi_papa320_mp', 6, 'MOD_PISTOL_BULLET'),
        'arena_smg': ('iw8_sm_mpapa5_mp', 25, 'MOD_RIFLE_BULLET'),
        'arena_pistol': ('iw8_pi_golf21_mp', 25, 'MOD_PISTOL_BULLET'),
        'gungame_smg': ('iw8_sm_mpapa5_mp', 15, 'MOD_RIFLE_BULLET'),
        'tdm_smg': ('iw8_sm_mpapa5_mp', 6, 'MOD_RIFLE_BULLET'),
        'unknown_mode_pistol': ('iw8_pi_golf21_mp', 0, 'MOD_PISTOL_BULLET'),
    }
    for label, (weapon, mode, cause) in kills.items():
        tokens = kill_input(weapon, cause=cause).split(',')
        tokens[5] = str(mode)
        row = case('kill', ','.join(tokens))
        assert row['accepted'] and row['parameter_count'] == 7
        assert row['values'][2] >> 32 == mode
        row['fixture_label'] = label
        proof['cases'].append(row)
    objective_cases = {
        'capture_dom': ('capture', 8), 'capture_hq': ('capture', 35),
        'capture_tdm': ('capture', 6), 'capture_sd': ('capture', 7),
        'defuse_sd': ('defuse', 7), 'defuse_cyber': ('defuse', 26),
        'defuse_dom': ('defuse', 8), 'plant_sd': ('plant', 7),
        'plant_cyber': ('plant', 26), 'plant_dom': ('plant', 8),
    }
    for label, (name, mode) in objective_cases.items():
        row = case(name, f'{mode},0,0,unknown_operator')
        assert row['accepted'] and row['parameter_count'] == 2
        assert row['values'][0] & 0xFFFFFFFF == mode
        row['fixture_label'] = label
        proof['cases'].append(row)
    operators = 'wyatt_western|spetsnaz_eastern'
    for name, params, count, field in (
        ('kill', '1|2,iw8_pi_golf21_mp,3,4,' + operators + ',6,no_attachments,no_perks,1,no_super,0,MOD_HEAD_SHOT,0,0', 7, 2),
        ('capture', '8,0,' + operators, 2, 0),
        ('end_match', '6,1,0,2,3,' + operators, 5, 0),
    ):
        row = case(name, params)
        assert row['accepted'] and row['parameter_count'] == count
        if name == 'kill':
            assert row['values'][field] >> 32 == 6 and row['values'][field] & 0xFFFFFFFF != 0
        elif name == 'end_match':
            assert row['values'][field] >> 32 != 0
        else:
            # This build's objective parser retains only its first two scalars;
            # operator strings in later producer slots are ignored.
            assert row['values'] == [8, 0]
        row['fixture_label'] = name + '_mode_operators'
        proof['cases'].append(row)
    for label, name, params, expected in (
        ('start_tdm', 'start_match', '6', [987654321, 6]),
        ('start_br', 'start_match', '24', [987654321, 24]),
        ('end_br', 'end_match', '24,1,0,0,0', [24, 1, 0, 0, 0]),
    ):
        row = case(name, params)
        assert row['accepted'] and row['parameter_count'] == len(expected) and row['values'] == expected
        row['fixture_label'] = label
        proof['cases'].append(row)
    proof.update(base_tool_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                 tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 parent_parser_sha256=hashlib.sha256(parent_path.read_bytes()).hexdigest())
    output.write_text(json.dumps(proof, indent=2) + '\n')
    print('Verified', len(proof['cases']), 'original parser cases with game-type/operator separation')


if __name__ == '__main__':
    main()
