"""JSON files of the SCA actions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class InputError(Exception):
    """The inputs are unusable, so no meaningful result can be produced."""


def read_json(path: Path) -> Any:
    """Read a JSON file; raises OSError/ValueError with a readable cause."""
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def dump_json(
    path: Path,
    data: Any,
    indent: int = 1,
    sort_keys: bool = False,
    ensure_ascii: bool = False,
) -> None:
    """Write a JSON file, UTF-8, LF line ends, a newline at the end."""
    text = json.dumps(
        data, indent=indent, sort_keys=sort_keys, ensure_ascii=ensure_ascii
    )
    path.write_text(text + "\n", encoding="utf-8", newline="\n")


def load_targets_list(path: Path) -> list[dict[str, Any]]:
    """The ``targets`` of a targets file, without a check of what they hold."""
    try:
        data = read_json(path)
    except (OSError, ValueError) as err:
        raise InputError(f"cannot read targets file {path}: {err}") from err
    targets = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(targets, list) or not all(isinstance(t, dict) for t in targets):
        raise InputError(f"targets file {path} has no 'targets' list")
    return targets
