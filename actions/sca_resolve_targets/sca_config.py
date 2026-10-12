"""Repository-level configuration of the SCA scheduled scan (``.github/sca.yml``).

The file is policy about the code of the scanned repository, so it lives with the
code and its reviewers. This module parses and validates it (or the equivalent
``config`` input of the workflow) and fills in the defaults. It is strict on purpose:
an unknown key, a wrong type or a malformed pattern is an error, since a typo must
not silently switch a policy off.

Schema (``schema_version: 1``)::

    schema_version: 1
    non_shipped_paths:      # optional, default: []
      - examples/
      - website/
    trivy_skip_paths: as_non_shipped   # optional: as_non_shipped | apply | ignore

``non_shipped_paths`` lists the lock and manifest files that are not part of what
the repository ships. The pattern syntax is a minimal gitignore-like subset, always
anchored at the repository root and case-sensitive (see ``validate_pattern``);
matching a location against a pattern is the business of the merge step.

``trivy_skip_paths`` says what to do with the ``skip-dirs`` and ``skip-files`` of
the ``trivy.yaml`` of the scanned repository (see ``TRIVY_SKIP_PATHS_MODES``); it is
carried out by the ``sca_prepare_trivy_config`` action and the merge step.

New settings are added as optional keys with defaults under the same
``schema_version`` while that is backward compatible; a breaking change bumps it.

PyYAML is the only third-party dependency of the SCA actions (pinned with hashes in
``requirements.txt``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

import yaml

SCHEMA_VERSION = 1
CONFIG_PATH = ".github/sca.yml"
SOURCE_INPUT = "input"
MAX_CONFIG_BYTES = 64 * 1024

KEY_SCHEMA_VERSION = "schema_version"
KEY_NON_SHIPPED_PATHS = "non_shipped_paths"
KEY_TRIVY_SKIP_PATHS = "trivy_skip_paths"
ALLOWED_KEYS = (KEY_SCHEMA_VERSION, KEY_NON_SHIPPED_PATHS, KEY_TRIVY_SKIP_PATHS)

# How the skip-dirs / skip-files of the repository's trivy.yaml are treated:
# - as_non_shipped: Trivy scans those paths anyway and the merge counts them like
#   non_shipped_paths (nothing is hidden from an exposure scan);
# - apply: Trivy skips them (what it does by itself); the report lists them;
# - ignore: Trivy scans them and the findings are classified normally.
SKIP_AS_NON_SHIPPED = "as_non_shipped"
SKIP_APPLY = "apply"
SKIP_IGNORE = "ignore"
TRIVY_SKIP_PATHS_MODES = (SKIP_AS_NON_SHIPPED, SKIP_APPLY, SKIP_IGNORE)

# Characters reserved for glob features this subset does not have: better refused
# than silently taken for part of a file name.
RESERVED_PATTERN_CHARS = re.compile(r"[\\?\[\]{}]|[\x00-\x1f\x7f]")
RECURSIVE_SEGMENT = "**"


class ConfigError(Exception):
    """The configuration is unusable; the message says where and what."""


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate keys and aliases.

    PyYAML keeps the last of two equal keys, so a duplicated ``non_shipped_paths``
    would silently drop the first list. Aliases are of no use in a file of two keys
    and are the way to blow a small document up, so they are refused.
    """

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            raise yaml.composer.ComposerError(
                None,
                None,
                "aliases are not supported",
                self.peek_event().start_mark,
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        if isinstance(node, yaml.MappingNode):
            self.flatten_mapping(node)
            seen: set[Any] = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=True)
                try:
                    duplicate = key in seen
                    seen.add(key)
                except TypeError:  # unhashable: the base class reports it
                    continue
                if duplicate:
                    raise yaml.constructor.ConstructorError(
                        None,
                        None,
                        f"duplicate key {key!r}",
                        key_node.start_mark,
                    )
        return super().construct_mapping(node, deep)


def default_config() -> dict[str, Any]:
    """The configuration of a repository without ``.github/sca.yml``."""
    return {
        "source": None,
        "overrides": None,
        KEY_NON_SHIPPED_PATHS: [],
        KEY_TRIVY_SKIP_PATHS: SKIP_AS_NON_SHIPPED,
    }


def validate_pattern(pattern: str) -> str:
    """Check one ``non_shipped_paths`` pattern; return it, or raise ValueError.

    A pattern is a repository-relative, ``/``-separated path, anchored at the
    repository root and case-sensitive:

    * a segment is literal text, ``*`` in it matches any characters but ``/``;
    * a segment that is exactly ``**`` matches zero or more segments;
    * a trailing ``/`` makes the pattern a directory: it matches every file below it
      (``examples/`` is ``examples/**``); without it the pattern matches the file
      with exactly that path (and ``a/**`` is a directory, too).

    There is no negation (a leading ``!`` is refused) and no ``?``, ``[...]``,
    ``{...}`` or backslash; ``.`` and ``..`` segments, empty segments (``//``) and a
    leading ``/`` are refused, and so is a pattern of ``**`` segments only, which
    would match the whole repository (turn the source scan off for that).
    """
    if not pattern or pattern != pattern.strip():
        raise ValueError("must not be empty or have leading or trailing whitespace")
    if pattern.startswith("/"):
        raise ValueError("must be relative to the repository root, not start with '/'")
    if pattern.startswith("!"):
        raise ValueError("negation ('!') is not supported")
    if RESERVED_PATTERN_CHARS.search(pattern):
        raise ValueError(
            "must not contain '\\', '?', '[', ']', '{', '}' or control characters"
        )
    segments = pattern.removesuffix("/").split("/")
    for segment in segments:
        if not segment:
            raise ValueError("must not have empty path segments ('//')")
        if segment in (".", ".."):
            raise ValueError(f"must not have a {segment!r} segment")
        if RECURSIVE_SEGMENT in segment and segment != RECURSIVE_SEGMENT:
            raise ValueError("'**' must be a whole path segment")
    if all(segment == RECURSIVE_SEGMENT for segment in segments):
        raise ValueError("matches the whole repository")
    return pattern


def _parse_document(text: str, origin: str) -> Any:
    if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{origin}: larger than {MAX_CONFIG_BYTES // 1024} KiB")
    try:
        return yaml.load(text, Loader=_StrictLoader)
    except yaml.YAMLError as err:
        # One line: the text ends up in a workflow command
        raise ConfigError(
            f"{origin}: invalid YAML: {' '.join(str(err).split())}"
        ) from err


def parse_settings(text: str, origin: str) -> dict[str, Any]:
    """Validate a configuration document; return its settings with the defaults.

    ``origin`` names where the text came from (a file or the input) in the errors.
    """
    document = _parse_document(text, origin)
    if not isinstance(document, dict):
        raise ConfigError(f"{origin}: must be a mapping with {KEY_SCHEMA_VERSION}")
    unknown = [key for key in document if key not in ALLOWED_KEYS]
    if unknown:
        names = ", ".join(repr(key) for key in unknown)
        raise ConfigError(
            f"{origin}: unknown key {names} (allowed: {', '.join(ALLOWED_KEYS)})"
        )
    version = document.get(KEY_SCHEMA_VERSION)
    if version is None:
        raise ConfigError(f"{origin}: {KEY_SCHEMA_VERSION} is required")
    if isinstance(version, bool) or version != SCHEMA_VERSION:
        raise ConfigError(
            f"{origin}: unsupported {KEY_SCHEMA_VERSION} {version!r} "
            f"(this version supports {SCHEMA_VERSION})"
        )
    return {
        KEY_NON_SHIPPED_PATHS: _parse_paths(document, origin),
        KEY_TRIVY_SKIP_PATHS: _parse_skip_mode(document, origin),
    }


def _parse_skip_mode(document: Mapping[str, Any], origin: str) -> str:
    mode = document.get(KEY_TRIVY_SKIP_PATHS, SKIP_AS_NON_SHIPPED)
    if mode not in TRIVY_SKIP_PATHS_MODES:
        raise ConfigError(
            f"{origin}: {KEY_TRIVY_SKIP_PATHS} must be one of "
            f"{', '.join(TRIVY_SKIP_PATHS_MODES)}, got {mode!r}"
        )
    return str(mode)


def _parse_paths(document: Mapping[str, Any], origin: str) -> list[str]:
    patterns = document.get(KEY_NON_SHIPPED_PATHS, [])
    if not isinstance(patterns, list):
        raise ConfigError(
            f"{origin}: {KEY_NON_SHIPPED_PATHS} must be a list of path patterns "
            "(use [] for none)"
        )
    for index, pattern in enumerate(patterns, 1):
        name = f"{origin}: {KEY_NON_SHIPPED_PATHS}[{index}]"
        if not isinstance(pattern, str):
            raise ConfigError(f"{name} must be a string, got {pattern!r}")
        try:
            validate_pattern(pattern)
        except ValueError as err:
            raise ConfigError(f"{name} {pattern!r}: {err}") from err
    return list(patterns)


def build_config(
    file_text: str | None, file_ref: str | None, override: str
) -> dict[str, Any]:
    """The configuration of a run, as recorded in ``targets.json``.

    ``file_text`` is the content of ``.github/sca.yml`` at the pinned commit (None if
    the repository has none), ``file_ref`` names it (``.github/sca.yml@<sha>``) and
    ``override`` is the ``config`` input of the workflow. A non-empty input wins over
    the file, which is then not even parsed (the caller opted out of it), and is
    named in ``overrides``. Without either, the defaults apply (``source`` is None).
    """
    config = default_config()
    if override.strip():
        config.update(parse_settings(override, "workflow input 'config'"))
        config.update(
            source=SOURCE_INPUT, overrides=file_ref if file_text is not None else None
        )
    elif file_text is not None:
        origin = file_ref or CONFIG_PATH
        config.update(parse_settings(file_text, origin), source=file_ref)
    return config
