"""The record model of the SCA merge: keys, exposure and ordering.

A record is one vulnerable package version of one repository (see ``MERGE_KEY``).
This module is the base of the others: it depends on none of them.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEV_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
UNKNOWN_SEVERITY = "UNKNOWN"
CVE_PREFIX = "CVE-"


# SCA configuration of the run (``config`` of targets.json), see sca_config.py of
# the sca_resolve_targets action
KEY_NON_SHIPPED_PATHS = "non_shipped_paths"


KEY_TRIVY_SKIP_PATHS = "trivy_skip_paths"
SKIP_AS_NON_SHIPPED = "as_non_shipped"
STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_NOT_APPLICABLE = "not_applicable"
SCANNER_TRIVY = "trivy"
SCANNER_OSV = "osv"
KIND_FS = "fs"
KIND_IMAGE = "image"
DEVELOPMENT_TAG = "development"


# Where a finding was seen: what kind of artifact a scan target is.
CLASS_RELEASE = "release"  # an image with a tag other than "development"


CLASS_DEVELOPMENT = "development"  # the "development" image
CLASS_SOURCE = "source"  # the source code of the default branch (trivy fs)


# the source code at a release tag (trivy fs); an fs target is one if it has a tag
CLASS_RELEASE_SOURCE = "release_source"


# Exposure of a finding, most urgent first.
EXPOSURE_RELEASE_AND_DEVELOPMENT = "release_and_development"


EXPOSURE_RELEASE_ONLY = "release_only"
EXPOSURE_DEVELOPMENT_ONLY = "development_only"
EXPOSURE_SOURCE_ONLY = "source_only"


EXPOSURES = (
    EXPOSURE_RELEASE_AND_DEVELOPMENT,
    EXPOSURE_RELEASE_ONLY,
    EXPOSURE_DEVELOPMENT_ONLY,
    EXPOSURE_SOURCE_ONLY,
)


EXPOSURE_ORDER = {name: index for index, name in enumerate(EXPOSURES)}
Target = dict[str, Any]
Record = dict[str, Any]
FindingKey = tuple[str | None, str | None, str | None]


# finding key -> target id -> trivy Targets (locations) it was found in
Sightings = dict[FindingKey, dict[str, list[str]]]


def blank_record(
    repo: str | None,
    vuln_id: str | None,
    pkg: str | None,
    version: str | None,
    pkg_type: str,
) -> Record:
    """A record with nothing known but its key; the scanner fills in the rest."""
    return {
        "repo": repo,
        # the id the finding is known by (a CVE, GHSA, DSA, TEMP, RUSTSEC id, ...)
        "id": vuln_id,
        # the CVE id of the finding: its id if that is one, else the first CVE of the
        # aliases, else None (set by ``finish``, once the aliases are complete)
        "cve": None,
        "aliases": [],
        "pkg": pkg,  # display name, see merge_records
        "version": version,
        # os (base image layer) vs library (a dependency): whose fix it is - a base
        # image bump or a dependency bump
        "pkg_type": pkg_type,
        # package manager / OS family (trivy Result Type: npm, gradle, jar, alpine,
        # ...); a list because one finding can surface under several types
        "ecosystem": [],
        "relationship": [],
        # True: a dev dependency (not shipped) in every sighting; False: not; None:
        # no package entry (image results)
        "dev": None,
        # the direct dependencies an indirect package comes from (at most 5) and
        # the chains from a direct dependency down to the package: the shortest
        # ones, how many there are in all (counted up to 1000) and whether that
        # count was cut
        "introduced_via": [],
        "dependency_paths": [],
        "dependency_paths_total": 0,
        "dependency_paths_truncated": False,
        "scan_targets": [],
        "locations": [],
        "pkg_paths": [],
        "exposure": None,
        "severity": UNKNOWN_SEVERITY,
        "severity_source": None,
        "cvss": None,
        # fixed | affected | will_not_fix | fix_deferred ...: tells "never getting
        # a fix" from "no fix yet"
        "status": None,
        "fixed_versions": [],
        "fix_available": False,
        "title": None,
        "cwe": None,
        "published": None,
        "primary_url": None,
        "scanners": [],
    }


def append_unique(items: list[Any], value: Any) -> None:
    if value and value not in items:
        items.append(value)


def absorb_sighting(
    record: Record,
    tid: str,
    scanner: str,
    result: Mapping[str, Any],
    relationships: Collection[str],
) -> None:
    """Add where a scanner saw the package of a record (one lockfile of one target)."""
    append_unique(record["scan_targets"], tid)
    append_unique(record["scanners"], scanner)
    append_unique(record["ecosystem"], result.get("Type"))
    append_unique(record["locations"], result.get("Target", ""))
    for relationship in relationships:
        append_unique(record["relationship"], relationship)


def record_ids(record: Mapping[str, Any]) -> set[str]:
    """Every id a record is known by: its ``id`` and its aliases."""
    return {record["id"], *record["aliases"]}


def cve_of(record: Mapping[str, Any]) -> str | None:
    """The CVE id of a record: its ``id`` if that is a CVE, else the first CVE (in
    string order) of its aliases, else None.
    """
    if record["id"].startswith(CVE_PREFIX):
        return record["id"]
    return min((a for a in record["aliases"] if a.startswith(CVE_PREFIX)), default=None)


def default_config() -> dict[str, Any]:
    """The SCA configuration of a run without one (as in sca_config.py)."""
    return {
        "source": None,
        "overrides": None,
        KEY_NON_SHIPPED_PATHS: [],
        KEY_TRIVY_SKIP_PATHS: SKIP_AS_NON_SHIPPED,
    }


def split_path_pattern(pattern: str) -> list[str]:
    """Split a glob on ``/`` outside braces."""
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(pattern):
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(depth - 1, 0)
        elif char == "/" and depth == 0:
            parts.append(pattern[start:index])
            start = index + 1
    parts.append(pattern[start:])
    return parts


def matching_brace(text: str, start: int) -> int:
    """Index of the ``}`` that closes the ``{`` at ``start``, -1 if there is none."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def split_alternatives(text: str) -> list[str]:
    """Split the inside of ``{...}`` on the commas that are not in a nested ``{}``."""
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def glob_regex(text: str) -> str:
    r"""Regex of a glob without ``**``: ``*`` and ``?`` stay within a path segment,
    ``[abc]`` / ``[!abc]`` are character classes, ``{a,b}`` alternatives and ``\``
    escapes the next character.
    """
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[" and (end := text.find("]", index + 2)) != -1:
            body = text[index + 1 : end]
            negate = body[:1] in ("!", "^")
            body = re.sub(r"([\\\[\]^])", r"\\\1", body[1:] if negate else body)
            out.append(f"[^/{body}]" if negate else f"[{body}]")
            index = end
        elif char == "{" and (end := matching_brace(text, index)) != -1:
            alternatives = split_alternatives(text[index + 1 : end])
            out.append("(?:" + "|".join(glob_regex(a) for a in alternatives) + ")")
            index = end
        elif char == "\\" and index + 1 < len(text):
            index += 1
            out.append(re.escape(text[index]))
        else:
            out.append(re.escape(char))
        index += 1
    return "".join(out)


def path_regex(pattern: str) -> re.Pattern[str]:
    """Regex of a ``/``-separated glob: a segment that is exactly ``**`` matches
    zero or more segments (a trailing ``/**`` also the directory itself).
    """
    segments: list[str] = []
    for segment in split_path_pattern(pattern):
        if not (segment == "**" and segments and segments[-1] == "**"):
            segments.append(segment)
    pieces: list[str] = []
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            pieces.append(".*" if last else "(?:[^/]+/)*")
        else:
            pieces.append(glob_regex(segment) + ("" if last else "/"))
    if segments[-1] == "**" and len(segments) > 1:
        # "a/" + ".*" is "a(?:/.*)?": the directory itself matches, too
        pieces[-2] = pieces[-2].removesuffix("/")
        pieces[-1] = "(?:/.*)?"
    return re.compile("".join(pieces))


def repository_pattern_regex(pattern: str) -> re.Pattern[str]:
    """Regex of a ``non_shipped_paths`` pattern (validated by sca_config.py of the
    sca_resolve_targets action): anchored at the repository root; a trailing ``/``
    makes it a directory, matching every file below it.
    """
    if pattern.endswith("/"):
        return re.compile(path_regex(pattern.removesuffix("/")).pattern + "/.+")
    return path_regex(pattern)


def trivy_glob_regex(pattern: str) -> re.Pattern[str] | None:
    """Regex of a ``skip-dirs`` / ``skip-files`` entry as Trivy matches it (doublestar
    against the path relative to the scan root, after ``posixpath.normpath``: a
    trailing ``/`` and a leading ``./`` do not count). None for an absolute entry,
    which never matches a relative path.
    """
    normalized = posixpath.normpath(pattern) if pattern else "."
    if normalized.startswith("/"):
        return None
    return path_regex(normalized)


def trivy_skips_path(
    path: str, dirs: Sequence[re.Pattern[str]], files: Sequence[re.Pattern[str]]
) -> bool:
    """Whether Trivy would have skipped a file: a directory above it (or the scan
    root, ``.``) matches a ``skip-dirs`` entry, or the file a ``skip-files`` one.
    """
    parts = path.split("/")
    ancestors = [".", *("/".join(parts[:n]) for n in range(1, len(parts)))]
    return any(rx.fullmatch(a) for rx in dirs for a in ancestors) or any(
        rx.fullmatch(path) for rx in files
    )


class NotShipped:
    """Which locations of which targets are not part of what the repository ships:
    the ``non_shipped_paths`` of the configuration (all fs targets) and, per target,
    the skip paths of its trivy.yaml that were scanned anyway (``as_non_shipped``).
    """

    def __init__(
        self,
        patterns: Iterable[str] = (),
        trivy_configs: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self.patterns = list(patterns)
        self._patterns = [repository_pattern_regex(p) for p in self.patterns]
        self._skips: dict[str, tuple[list[re.Pattern[str]], list[re.Pattern[str]]]] = {}
        for tid, config in (trivy_configs or {}).items():
            if config["mode"] != SKIP_AS_NON_SHIPPED:
                continue
            dirs = [rx for d in config["skip_dirs"] if (rx := trivy_glob_regex(d))]
            files = [rx for f in config["skip_files"] if (rx := trivy_glob_regex(f))]
            if dirs or files:
                self._skips[tid] = (dirs, files)

    def __bool__(self) -> bool:
        return bool(self._patterns or self._skips)

    def matches(self, tid: str, location: str) -> bool:
        """Whether a location (a trivy ``Target``) of a target is not shipped."""
        path = location.removeprefix("./")
        if any(rx.fullmatch(path) for rx in self._patterns):
            return True
        skips = self._skips.get(tid)
        return skips is not None and trivy_skips_path(path, *skips)


def target_class(target: Mapping[str, Any]) -> str | None:
    """What a scan target is: an image (release or development) or source code
    (of the default branch or of a release tag).
    """
    if target.get("kind") == KIND_FS:
        return CLASS_RELEASE_SOURCE if target.get("tag") else CLASS_SOURCE
    if target.get("kind") == KIND_IMAGE:
        return (
            CLASS_DEVELOPMENT if target.get("tag") == DEVELOPMENT_TAG else CLASS_RELEASE
        )
    return None


def release_class(has_images: bool) -> str:
    """Kind of target that stands for a release: its image, else its source."""
    return CLASS_RELEASE if has_images else CLASS_RELEASE_SOURCE


def classify_exposure(classes: Collection[str], has_images: bool) -> str:
    """Exposure of a finding by the kinds of targets it was found in.

    With images, the images decide: a finding seen in any image is classified by
    the release and development images (the source of the default branch counts as
    development), and one seen only in sources is ``source_only``. The source of a
    release tag is never counted as release or development there, since a lockfile
    also lists build and test dependencies that are not shipped.

    Without images (e.g. a Python package) the sources are the subject: a finding
    in the source of a release tag is a release one, in the source of the default
    branch a development one. A finding with no class at all, because every sighting
    of it is in a not shipped location (see ``assign_exposure``), is ``source_only``
    in either case.
    """
    if not classes:
        return EXPOSURE_SOURCE_ONLY
    if has_images:
        if not classes & {CLASS_RELEASE, CLASS_DEVELOPMENT}:
            return EXPOSURE_SOURCE_ONLY
        in_release = CLASS_RELEASE in classes
        in_development = CLASS_DEVELOPMENT in classes or CLASS_SOURCE in classes
    else:
        in_release = CLASS_RELEASE_SOURCE in classes
        in_development = CLASS_SOURCE in classes
    if in_release and in_development:
        return EXPOSURE_RELEASE_AND_DEVELOPMENT
    if in_release:
        return EXPOSURE_RELEASE_ONLY
    return EXPOSURE_DEVELOPMENT_ONLY


def assign_exposure(
    records: Iterable[Record],
    targets: Sequence[Target],
    sightings: Sightings | None = None,
    not_shipped: NotShipped | None = None,
) -> None:
    """Set the exposure of the records. A target whose every sighting of a record is
    in a not shipped location (``not_shipped``; sources only, never an image) says
    nothing about what the record is exposed to, so it adds no class.
    """
    by_id = {t["id"]: t for t in targets}
    has_images = any(t.get("kind") == KIND_IMAGE for t in targets)
    for record in records:
        seen = (sightings or {}).get(record_identity(record), {})
        classes = set()
        for tid in record["scan_targets"]:
            target = by_id[tid]
            if (
                not_shipped
                and target.get("kind") == KIND_FS
                and seen.get(tid)
                and all(not_shipped.matches(tid, loc) for loc in seen[tid])
            ):
                continue
            classes.add(target_class(target))
        classes.discard(None)
        record["exposure"] = classify_exposure(classes, has_images)  # type: ignore[arg-type]


def record_sort_key(record: Record) -> tuple[Any, ...]:
    """Urgency, severity, CVSS score (highest first, none last), then identity."""
    score = (record.get("cvss") or {}).get("score")
    return (
        EXPOSURE_ORDER.get(record["exposure"], len(EXPOSURES)),
        SEV_ORDER.get(record["severity"], len(SEV_ORDER)),
        score is None,
        -(score or 0),
        record["pkg"] or "",
        record["version"] or "",
        record["id"] or "",
    )


def finalize_records(
    records: Iterable[Record],
    targets: Sequence[Target],
    sightings: Sightings | None = None,
    not_shipped: NotShipped | None = None,
) -> list[Record]:
    """Enrich the merged records (exposure) and put them in report order."""
    records = list(records)
    assign_exposure(records, targets, sightings, not_shipped)
    return sorted(records, key=record_sort_key)


def target_name(target: Mapping[str, Any]) -> str:
    """The id of a target, qualified by the scanner unless it is Trivy."""
    if target["scanner"] == SCANNER_TRIVY:
        return target["id"]
    return f"{target['id']} ({target['scanner']})"


def record_identity(record: Mapping[str, Any]) -> tuple[Any, Any, Any]:
    return (record["id"], record["pkg"], record["version"])
