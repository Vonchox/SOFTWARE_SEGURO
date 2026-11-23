"""Escritura UTF-8 atómica para los archivos generados."""

import json
import tempfile
from pathlib import Path


def write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(text)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_json(path, value, *, compact=False):
    options = {"separators": (",", ":")} if compact else {"indent": 2}
    write_text(path, json.dumps(value, ensure_ascii=False, **options) + "\n")


def write_jsonl(path, records):
    write_text(path, "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records))
