#!/usr/bin/env python3
"""Prepare the Trivy configuration of one source (fs) scan target of the SCA scan.

Trivy reads ``trivy.yaml`` of the scanned directory by itself, and its ``skip-dirs``
and ``skip-files`` (section ``scan``) make it skip those paths silently. The
repository decides in ``.github/sca.yml`` (``trivy_skip_paths``) what the scan does
with them (see ``sca_config`` of ``sca_resolve_targets``):

* ``apply``: nothing changes, Trivy skips the paths; they are only recorded;
* ``as_non_shipped`` and ``ignore``: Trivy must scan them. An environment variable
  cannot do that (an empty value counts as unset, so it cannot clear a list that the
  file sets), so a copy of ``trivy.yaml`` without the two keys is written outside
  the workspace; the workflow passes it to Trivy as its config file. Everything else
  in ``trivy.yaml`` keeps working, as the copy is the same document.

Either way ``<id>.trivy-config.json`` is written next to the Trivy parts: the
effective lists of this very commit (they may differ between the default branch and
a release tag) and what was done with them. The merge step reads it.

Needs PyYAML (pinned with hashes in ``requirements.txt``).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

SCHEMA_VERSION = 1
MODE_APPLY = "apply"
MODES = ("as_non_shipped", MODE_APPLY, "ignore")
SECTION = "scan"
SKIP_KEYS = {"skip_dirs": "skip-dirs", "skip_files": "skip-files"}
MAX_CONFIG_BYTES = 1024 * 1024


class ConfigError(Exception):
    """The Trivy configuration of the repository cannot be understood."""


def escape_command_data(text: object) -> str:
    """Escape a text for the message of a workflow command (``::warning::``).

    The text may come from outside (scanner output, a repository, a feed), and
    ``%``, CR and LF would end or forge the command. The same function is in every
    module that prints commands (a shared package comes later).
    """
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def load_config(path: Path) -> dict[str, Any] | None:
    """The parsed trivy.yaml, None if there is no such file."""
    if not path.is_file():
        return None
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ConfigError(f"{path} is larger than {MAX_CONFIG_BYTES // 1024} KiB")
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as err:
        raise ConfigError(f"cannot read {path}: {' '.join(str(err).split())}") from err
    if document is None:
        return {}
    if not isinstance(document, dict):
        raise ConfigError(f"{path} must be a mapping")
    return document


def skip_lists(document: Mapping[str, Any], path: Path) -> dict[str, list[str]]:
    """``skip_dirs`` and ``skip_files`` of the ``scan`` section (empty if unset)."""
    section = document.get(SECTION)
    if section is None:
        section = {}
    if not isinstance(section, dict):
        raise ConfigError(f"{path}: '{SECTION}' must be a mapping")
    lists: dict[str, list[str]] = {}
    for name, key in SKIP_KEYS.items():
        value = section.get(key)
        if value is None:
            value = []
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{path}: {SECTION}.{key} must be a list of strings")
        lists[name] = list(value)
    return lists


def without_skips(document: Mapping[str, Any]) -> dict[str, Any]:
    """The document without ``scan.skip-dirs`` and ``scan.skip-files``."""
    result = dict(document)
    section = {
        key: value
        for key, value in (result.get(SECTION) or {}).items()
        if key not in SKIP_KEYS.values()
    }
    if section:
        result[SECTION] = section
    else:
        result.pop(SECTION, None)
    return result


def prepare(
    mode: str,
    config_path: Path,
    target_id: str,
    output_dir: Path,
    generated_dir: Path,
) -> Path | None:
    """Write the record of the target; return the config file Trivy has to use
    instead of ``trivy.yaml`` (None: Trivy uses its own, if any).
    """
    document = load_config(config_path)
    lists = skip_lists(document or {}, config_path)
    replacement: Path | None = None
    if document is not None and any(lists.values()) and mode != MODE_APPLY:
        generated_dir.mkdir(parents=True, exist_ok=True)
        replacement = generated_dir / f"{target_id}.trivy.yaml"
        replacement.write_text(
            yaml.safe_dump(without_skips(document), sort_keys=False), encoding="utf-8"
        )
    record = {
        "schema_version": SCHEMA_VERSION,
        "id": target_id,
        "mode": mode,
        "config_file": str(config_path) if document is not None else None,
        **lists,
        # What Trivy did with the listed paths: it scanned them unless it skipped them
        "paths_scanned": mode != MODE_APPLY,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{target_id}.trivy-config.json").write_text(
        json.dumps(record, indent=1) + "\n", encoding="utf-8", newline="\n"
    )
    return replacement


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--generated-dir", required=True, type=Path)
    parser.add_argument("--config-path", default="trivy.yaml", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        replacement = prepare(
            args.mode,
            args.config_path,
            args.target_id,
            args.output_dir,
            args.generated_dir,
        )
    except ConfigError as err:
        print(f"::error title=Invalid Trivy configuration::{escape_command_data(err)}")
        return 1
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8", newline="\n") as out:
            out.write(f"config-file={replacement or ''}\n")
    print(
        f"Trivy configuration of {args.target_id}: "
        + (f"{replacement} (without the skip paths)" if replacement else "unchanged")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
