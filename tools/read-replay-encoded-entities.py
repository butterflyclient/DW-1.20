"""Read Replay's complete numeric/literal-key entity grammar from a native span.

Positive keys retain their canonical numeric IDs. Key 0 carries an explicit
quoted key before its quoted value. This tool does not guess canonical names
or turn authored POI labels/model indices into runtime challenge locale IDs.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
TOKEN = re.compile(r'\s*(\{|\}|[0-9]+|"(?:\\.|[^"\\])*")')
SPACE = re.compile(r'\s*')


def parse(raw):
    text = raw.decode("utf-8")
    # The serialized char-array includes its terminal NUL; no embedded NUL
    # may silently truncate the declared native read span.
    assert text.endswith("\0") and "\0" not in text[:-1]
    text = text[:-1]
    cursor, entities = 0, []

    def token():
        nonlocal cursor
        match = TOKEN.match(text, cursor)
        if not match:
            raise ValueError(f"Invalid entity token at byte/character offset {cursor}")
        cursor = match.end()
        return match.group(1)

    def quoted(value):
        if not value.startswith('"'):
            raise ValueError("Expected a quoted entity string")
        # Preserve the engine text's escape spelling; JSON/C escape semantics
        # are not silently substituted for the native tokenizer.
        return value[1:-1]

    while True:
        cursor = SPACE.match(text, cursor).end()
        if cursor == len(text):
            break
        assert token() == "{"
        fields = []
        while (key := token()) != "}":
            if not key.isdecimal():
                raise ValueError("Replay entity keys must begin with a numeric code")
            code = int(key)
            if code:
                fields.append(dict(code=code, value=quoted(token())))
            else:
                fields.append(dict(code=0, key=quoted(token()), value=quoted(token())))
        entities.append(fields)
    assert not text[cursor:].strip()
    return entities


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert args.input.resolve().is_relative_to(ROOT)
    assert args.output.resolve().is_relative_to(ROOT)
    raw = args.input.read_bytes()
    entities = parse(raw)
    selected = [dict(index=index, fields=fields) for index, fields in enumerate(entities)
                if any(field["value"] == "locale_area_trigger" for field in fields)]
    proof = dict(passed=True, complete_grammar_consumed=True, entity_count=len(entities),
                 input_bytes=len(raw), input_sha256=hashlib.sha256(raw).hexdigest(),
                 tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 authored_locale_triggers=selected, runtime_locale_ids_verified=False,
                 scope="Full native entity-text span; numeric and explicit literal keys preserved. Runtime locale ID assignment remains a separate contract")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2)+"\n")
    print(f"PASS: {len(entities)} complete entities; {len(selected)} authored locale triggers")


if __name__ == "__main__":
    main()
