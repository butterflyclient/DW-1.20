"""Generate Replay's challenge game-type IDs from shipped ScriptFile operands."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = Path(r'E:\replay-compiler\tools')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.is_relative_to(ROOT)
    folder = ROOT / 'data/remaining-match-outcomes-20261010'
    recovery = json.loads((folder / 'producer-recovery.json').read_bytes())
    row = next(r for z in recovery for r in z.get('matching_scripts', []) if r['asset_index'] == 10793)
    source_path = ROOT / row['decompiled_path']
    payload_path = ROOT / row['retained_payload']
    assert digest(source_path) == row['decompiled_sha256']
    assert digest(payload_path) == row['payload_sha256']
    source = source_path.read_text(encoding='utf-8-sig')
    initializer = source.split('initchallengeandeventglobals()\n', 1)[1].split('getchallengegamemode(', 1)[0]
    modes = dict((name, int(value)) for name, value in re.findall(r'game_type_col\["([a-z_]+)"\] = (\d+);', initializer))
    assert len(modes) == 39 and list(modes.values()) == list(range(5, 44))
    sys.path.insert(0, str(LIBRARY))
    from workstation_asset_codecs import inspect_gscbin, _script_instructions
    code = inspect_gscbin(payload_path.read_bytes()).bytecode
    instructions = list(_script_instructions(code))
    values = [(pc, code[pc + 1]) for pc, opcode, end in instructions if opcode == 0x16]
    windows = [values[i:i + 39] for i in range(len(values) - 38)
               if [v for pc, v in values[i:i + 39]] == list(modes.values())]
    assert len(windows) == 1
    positions = [pc for pc, value in windows[0]]
    assert len(set(b - a for a, b in zip(positions, positions[1:]))) == 1
    header = ROOT / 'src/replay_challenge_game_type.h'
    weapon_paths = list(Path(r'E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable\loot').glob('weapon_ids.csv.*.csv'))
    assert len(weapon_paths) == 1
    weapon_rows = list(csv.reader(weapon_paths[0].read_text(encoding='utf-8-sig').splitlines()))
    m19 = next(int(r[0]) for r in weapon_rows if r[1] == 'iw8_pi_papa320')
    gametype_table = weapon_paths[0].parent.parent / 'mp/gametypestable.csv.325.csv'
    game_rows = list(csv.reader(gametype_table.read_text(encoding='utf-8-sig').splitlines()))
    selected = {r[0]: r[1] for r in game_rows if r[0] in ('war', 'dom', 'hq', 'arena', 'sd', 'cyber')}
    assert set(selected) == {'war', 'dom', 'hq', 'arena', 'sd', 'cyber'}
    localize = ROOT / 'data/workstation-cache/fastfiles/rwt-localize-readback-0u3txpf6/mw19replay/eng_code_post_gfx/assets/localize/lua_menu_mp'
    descriptions = []
    for name, key in selected.items():
        files = list(localize.glob(key.split('/')[-1].lower() + '.*.json'))
        assert len(files) == 1
        text = json.loads(files[0].read_bytes())
        descriptions.append(dict(mode=name, key=key, value=text['value'],
                                 path=files[0].relative_to(ROOT).as_posix(), sha256=digest(files[0])))
    lines = ['#pragma once', '#include <cstdint>', '#include <string_view>', '',
             '// Generated from Replay initchallengeandeventglobals and native operands.',
             '// These are specific game types, distinct from the gamemode family field.',
             'enum class ReplayChallengeGameType : uint32_t', '{']
    lines += [f'    {name} = {value},' for name, value in modes.items()]
    lines += ['};', '', 'inline std::string_view replayChallengeGameTypeName(uint32_t value)',
              '{', '    switch (static_cast<ReplayChallengeGameType>(value))', '    {']
    lines += [f'    case ReplayChallengeGameType::{name}: return "{name}";' for name in modes]
    lines += ['    default: return {};', '    }', '}', '',
              'namespace replay_challenge_mode_data', '{',
              f'    inline constexpr uint16_t M19Weapon = {m19};', '}', '']
    header.write_text('\n'.join(lines), encoding='utf-8')
    result = dict(passed=True, tool_sha256=digest(Path(__file__)),
                  sources=[dict(path=p.relative_to(ROOT).as_posix(), sha256=digest(p))
                           for p in (source_path, payload_path, folder / 'producer-recovery.json')],
                  decoder=dict(path=str(LIBRARY / 'workstation_asset_codecs.py'),
                               sha256=digest(LIBRARY / 'workstation_asset_codecs.py')),
                  bytecode_sha256=hashlib.sha256(code).hexdigest(),
                  weapon_table=dict(path=str(weapon_paths[0]), sha256=digest(weapon_paths[0])),
                  m19_weapon_id=m19,
                  gametype_table=dict(path=str(gametype_table), sha256=digest(gametype_table)),
                  mode_descriptions=descriptions,
                  modes=[dict(name=name, value=value, original_offset=pc,
                              original_bytes_hex=code[pc:pc + 2].hex())
                         for (name, value), pc in zip(modes.items(), positions)],
                  generated=header.relative_to(ROOT).as_posix(), generated_sha256=digest(header),
                  native_game_execution_verified=False,
                  scope='Unique decoded native GetByte operand sequence agrees with the retained initializer')
    output.write_text(json.dumps(result, indent=2) + '\n')
    print('Verified and generated all 39 native challenge game types')


if __name__ == '__main__':
    main()
