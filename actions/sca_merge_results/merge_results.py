#!/usr/bin/env python3
"""Merge the per-target scan results of an SCA scheduled scan into one report.

Inputs:
  * targets.json written by sca_resolve_targets (the list of targets);
  * a parts directory with one subdirectory per scanner (``trivy/``, ``osv/``)
    holding, per scanned target id, ``<id>.json`` (native JSON),
    ``<id>.status.json``, an optional ``<id>.txt`` (table) and, for a Trivy Gradle
    build, ``<id>.gradle-graph/`` (the resolved dependency graph, one JSON file per
    Gradle project, written by the generate_gradle_lockfiles action).

Outputs (in the output directory):
  * ``_report/vulnerabilities.json`` - the findings only: canonical deduplicated
    set, one record per (repo, CVE x package x installed version), with the
    ``exposure`` of the finding (which shipped artifacts carry it), the
    ``scan_targets`` it was found in, its ``locations`` within them and the
    ``scanners`` that reported it;
  * ``_report/scan_report.json`` - the run manifest and the metrics: one entry
    per target with its status, the scanner that scanned it and its finding
    counts, plus the ``totals`` of the run;
  * ``summary.md`` - the human-readable, decision-first layer;
  * ``_native/<scanner>/<id>.json|txt`` - the unmodified per-target results
    (audit).

A target is identified by its scanner and its id (the id names the scanned
subject, which several scanners share). OSV, queried for the language packages of
every Trivy target, is reported per target (status, package and finding counts,
native result) and its findings are merged into the records: a vulnerability that
Trivy reports too joins its record (``scanners`` becomes ``["osv", "trivy"]``), one
that only OSV knows becomes a record of its own (``scanners: ["osv"]``), with the
package context of the Trivy package of the same purl.

A Gradle lockfile has no dependency graph, so the packages of a trivy ``gradle``
Result carry neither ``Relationship`` nor ``DependsOn``. They are filled in from
the Gradle graph of the project (in memory only, ``_native/`` stays as trivy
wrote it), before the dependency chains are built.

A target is an image, the source of the default branch or - an fs target with a
``tag`` - the source of a release tag. A release source gives the findings of a
release image their dependency chains (the same package version in the lockfile of
the tag; an image has no graph) and, in a run without images, stands for the
release in the exposure and in the headline. With images it never raises a
finding above ``source_only``: see ``classify_exposure``.

Paths that are not shipped (``non_shipped_paths`` of the SCA configuration in
targets.json, and the ``skip-dirs`` / ``skip-files`` of a source target's trivy.yaml
when the configuration says ``trivy_skip_paths: as_non_shipped``) do not count
towards the release or development exposure: a finding seen only in lockfiles under
them is ``source_only`` in every repository, and its locations are marked as not
shipped. The record stays in ``vulnerabilities.json``.

A scan that broke is reported as ``failed`` and never looks like a clean
target. The script still exits 0 once the outputs are written: the workflow
decides about failing the run after the artifact has been uploaded.

The module is organised in layers, each made of small pure functions:
reading inputs, trivy result analysis (CVSS selection, version comparison),
record merging and enrichment (exposure, upgrade_to), report building and
markdown rendering, orchestration/CLI.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import posixpath
import re
import shutil
import sys
import urllib.parse
from collections.abc import (
    Callable,
    Collection,
    Iterable,
    Iterator,
    Mapping,
    Sequence,
)
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cmp_to_key
from pathlib import Path
from typing import Any, NamedTuple

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEV_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
UNKNOWN_SEVERITY = "UNKNOWN"
SCHEMA_VERSION = 1
SHORT_SHA_LENGTH = 7
TRIVY_DB_KEYS = ("vulnerability_db_updated_at", "java_db_updated_at")
MERGE_KEY = (
    "(repo, CVE x package x installed-version), merged across scan_targets and "
    "scanners; a vulnerability only OSV knows is keyed by its OSV id when it has no CVE"
)
TARGET_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# SCA configuration of the run (``config`` of targets.json), see sca_config.py of
# the sca_resolve_targets action
KEY_NON_SHIPPED_PATHS = "non_shipped_paths"
KEY_TRIVY_SKIP_PATHS = "trivy_skip_paths"
SKIP_AS_NON_SHIPPED = "as_non_shipped"
SKIP_APPLY = "apply"
SKIP_IGNORE = "ignore"
SKIP_MODES = (SKIP_AS_NON_SHIPPED, SKIP_APPLY, SKIP_IGNORE)
TRIVY_CONFIG_SUFFIX = ".trivy-config.json"  # <id>.trivy-config.json of an fs target
TRIVY_CONFIG_SCHEMA_VERSION = 1
NOT_SHIPPED_MARK = "(not shipped)"
MAX_LISTED_SKIPS = 5

GRADLE_RESULT_TYPE = "gradle"
GRADLE_GRAPH_SUFFIX = ".gradle-graph"  # <id>.gradle-graph/ next to <id>.json
GRADLE_GRAPH_SCHEMA_VERSION = 1
ROOT_PROJECT_DIR = "."

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_NOT_APPLICABLE = "not_applicable"

SCANNER_TRIVY = "trivy"
SCANNER_OSV = "osv"
SCANNERS = (SCANNER_TRIVY, SCANNER_OSV)

CLASS_LANGUAGE_PACKAGES = "lang-pkgs"
CLASS_OS_PACKAGES = "os-pkgs"

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
MAX_INTRODUCED_VIA = 5
MAX_DEPENDENCY_PATHS = 5
# Counting stops here (the count is then "at least this many") and so does the
# enumeration of candidate paths of one length; the walk has a step budget too.
PATH_COUNT_LIMIT = 1000
PATH_WALK_BUDGET = 50_000
PATH_SEPARATOR = " › "
RELEASE_LINE_RE = re.compile(r"^v?(\d+)\.(\d+)")

# Trivy result types by ecosystem family. The family decides how a package name
# is compared (Python names are case-insensitive, PEP 503) and what the summary
# shows; a type that is not listed is shown as is and compared exactly. OS package
# types (alpine, debian, ...) are case-sensitive and canonical in trivy.
PYTHON_FAMILY = "python"
ECOSYSTEM_FAMILIES = {
    "python-pkg": PYTHON_FAMILY,
    "pip": PYTHON_FAMILY,
    "pipenv": PYTHON_FAMILY,
    "poetry": PYTHON_FAMILY,
    "uv": PYTHON_FAMILY,
    "conda-pkg": PYTHON_FAMILY,
    "conda-environment": PYTHON_FAMILY,
    "node-pkg": "npm",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "bun": "npm",
    "jar": "java",
    "pom": "java",
    "gradle": "java",
    "sbt": "java",
    "gobinary": "go",
    "gomod": "go",
    "dotnet-core": "dotnet",
    "nuget": "dotnet",
    "packages-props": "dotnet",
    "gemspec": "ruby",
    "bundler": "ruby",
    "cargo": "rust",
    "rustbinary": "rust",
    "composer": "php",
    "composer-vendor": "php",
}
_PEP503_SEPARATORS_RE = re.compile(r"[-_.]+")

TITLE_MAX_LENGTH = 80
MAX_LISTED_LOCATIONS = 3

Target = dict[str, Any]
Record = dict[str, Any]
FindingKey = tuple[str | None, str | None, str | None]
# finding key -> target id -> trivy Targets (locations) it was found in
Sightings = dict[FindingKey, dict[str, list[str]]]


class InputError(Exception):
    """The inputs are unusable, so no meaningful report can be produced."""


# --------------------------------------------------------------------------
# Reading inputs
# --------------------------------------------------------------------------


def read_json(path: Path) -> Any:
    """Read a JSON file; raises OSError/ValueError with a readable cause."""
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_targets_file(path: Path) -> dict[str, Any]:
    """Load and validate targets.json."""
    try:
        data = read_json(path)
    except (OSError, ValueError) as e:
        raise InputError(f"cannot read targets file {path}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("targets"), list):
        raise InputError(f"targets file {path} has no 'targets' list")
    seen: set[tuple[str, str]] = set()
    for target in data["targets"]:
        tid = target.get("id") if isinstance(target, dict) else None
        if not isinstance(tid, str) or not TARGET_ID_RE.fullmatch(tid):
            raise InputError(f"targets file {path} has an invalid target id: {tid!r}")
        scanner = target.get("scanner")
        if scanner not in SCANNERS:
            raise InputError(
                f"targets file {path} has an invalid scanner of {tid}: {scanner!r}"
            )
        if (scanner, tid) in seen:
            raise InputError(
                f"targets file {path} has a duplicate {scanner} target id: {tid}"
            )
        seen.add((scanner, tid))
    data["config"] = validate_config(data.get("config"), path)
    return data


def validate_config(raw: Any, path: Path) -> dict[str, Any]:
    """The SCA configuration of targets.json (the defaults if it has none)."""
    config = default_config()
    if raw is None:
        return config
    where = f"targets file {path}: invalid config"
    if not isinstance(raw, dict):
        raise InputError(f"{where}: not an object")
    patterns = raw.get(KEY_NON_SHIPPED_PATHS, [])
    if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
        raise InputError(f"{where}: {KEY_NON_SHIPPED_PATHS} must be a list of strings")
    mode = raw.get(KEY_TRIVY_SKIP_PATHS, SKIP_AS_NON_SHIPPED)
    if mode not in SKIP_MODES:
        raise InputError(
            f"{where}: {KEY_TRIVY_SKIP_PATHS} {mode!r} is not one of the modes"
        )
    for key in ("source", "overrides"):
        if not isinstance(raw.get(key), str | None):
            raise InputError(f"{where}: {key} must be a string or null")
        config[key] = raw.get(key)
    config.update({KEY_NON_SHIPPED_PATHS: list(patterns), KEY_TRIVY_SKIP_PATHS: mode})
    return config


def load_trivy_config_record(path: Path) -> dict[str, Any]:
    """The ``<id>.trivy-config.json`` of a source target (written by the
    sca_prepare_trivy_config action); raises OSError or ValueError if unusable.
    """
    record = read_json(path)
    if not isinstance(record, dict):
        raise ValueError("not a JSON object")
    if record.get("schema_version") != TRIVY_CONFIG_SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version {record.get('schema_version')!r}")
    if record.get("mode") not in SKIP_MODES:
        raise ValueError(f"invalid mode {record.get('mode')!r}")
    for key in ("skip_dirs", "skip_files"):
        value = record.get(key)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError(f"{key} must be a list of strings")
    if not isinstance(record.get("paths_scanned"), bool):
        raise ValueError("paths_scanned must be a boolean")
    return {
        key: record.get(key)
        for key in ("mode", "paths_scanned", "config_file", "skip_dirs", "skip_files")
    }


def load_target_result(
    target: Mapping[str, Any], scanner_parts_dir: Path
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Determine the final status of one target.

    Returns ``(state, native)``: state carries ``status`` and ``reason``; native
    is the parsed native result of the target's scanner for ``ok`` targets, else
    None. Anything short of a complete, valid result is ``failed`` - a broken scan
    must not look like a clean target.
    """
    tid = target["id"]
    scanner = target["scanner"]
    state: dict[str, Any] = {
        "status": target.get("status"),
        "reason": target.get("reason"),
    }
    if state["status"] in (STATUS_FAILED, STATUS_NOT_APPLICABLE):
        return state, None

    def failed(reason: str) -> tuple[dict[str, Any], None]:
        state.update(status=STATUS_FAILED, reason=reason)
        return state, None

    status_path = scanner_parts_dir / f"{tid}.status.json"
    if not status_path.is_file():
        return failed("scan job produced no result")
    try:
        status = read_json(status_path)
    except (OSError, ValueError) as e:
        return failed(f"unreadable status file: {e}")
    if not isinstance(status, dict):
        return failed("unreadable status file: not a JSON object")

    if status.get("status") == STATUS_FAILED:
        return failed(status.get("reason") or "scan job reported failure")
    if status.get("status") == STATUS_NOT_APPLICABLE:
        # The job found nothing to scan (an OSV target whose Trivy target failed)
        state.update(
            status=STATUS_NOT_APPLICABLE,
            reason=status.get("reason") or "nothing to scan",
        )
        return state, None
    if status.get("status") != STATUS_OK:
        return failed(f"unexpected scan status: {status.get('status')!r}")

    native_path = scanner_parts_dir / f"{tid}.json"
    if not native_path.is_file():
        return failed(f"{scanner} result file is missing")
    try:
        native = read_json(native_path)
    except (OSError, ValueError) as e:
        return failed(f"{scanner} result is not valid JSON: {e}")
    if not isinstance(native, dict):
        return failed(f"{scanner} result is not a JSON object")
    if scanner == SCANNER_OSV and (problem := osv_result_problem(native)):
        return failed(problem)

    state.update(status=STATUS_OK, reason=None)
    return state, native


# --------------------------------------------------------------------------
# Gradle dependency graph
# --------------------------------------------------------------------------


@dataclass
class ProjectGraph:
    """The resolved dependencies of one Gradle project, over all its configurations.

    ``direct`` are the modules the project depends on (see lockfiles.init.gradle:
    other projects of the build are transparent) and ``edges`` maps every module
    to the modules it depends on; modules are ``group:artifact:version`` as in
    ``gradle.lockfile``, which is also the trivy package ID.
    """

    direct: set[str] = field(default_factory=set)
    edges: dict[str, set[str]] = field(default_factory=dict)

    def knows(self, module: str) -> bool:
        return module in self.direct or module in self.edges


def normalize_project_dir(directory: str) -> str:
    """A project directory as a relative POSIX path, ``.`` for the build root."""
    return posixpath.normpath(directory) if directory else ROOT_PROJECT_DIR


def lockfile_project_dir(target: str | None) -> str:
    """The project directory of a trivy Result Target (``server/gradle.lockfile``)."""
    return normalize_project_dir(posixpath.dirname(target or ""))


def _string_list(value: Any, what: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{what} is not a list of strings")
    return value


def parse_project_graph(data: Any) -> tuple[str, ProjectGraph]:
    """Validate one graph file; returns ``(project directory, graph)``.

    Raises ValueError if the file is not a graph of a supported schema version.
    """
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    if data.get("schema_version") != GRADLE_GRAPH_SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version {data.get('schema_version')!r}")
    project_dir = data.get("project_dir")
    configurations = data.get("configurations")
    if not isinstance(project_dir, str) or not isinstance(configurations, dict):
        raise ValueError("no project_dir or configurations")
    graph = ProjectGraph()
    for name, configuration in configurations.items():
        what = f"configuration {name!r}"
        if not isinstance(configuration, dict) or not isinstance(
            configuration.get("modules"), dict
        ):
            raise ValueError(f"{what} has no modules")
        graph.direct.update(_string_list(configuration.get("direct"), f"{what} direct"))
        for module, dependencies in configuration["modules"].items():
            graph.edges.setdefault(module, set()).update(
                _string_list(dependencies, f"{what} dependencies of {module}")
            )
    return normalize_project_dir(project_dir), graph


def load_gradle_graphs(
    graph_dir: Path,
) -> tuple[dict[str, ProjectGraph], list[str]]:
    """Read the graph files of a target: ``(project directory -> graph, problems)``.

    A missing directory is no graph at all. A file that cannot be used is
    reported in the problems and skipped; files of one project directory are
    united.
    """
    graphs: dict[str, ProjectGraph] = {}
    problems: list[str] = []
    if not graph_dir.is_dir():
        return graphs, problems
    for path in sorted(graph_dir.glob("*.json")):
        try:
            project_dir, graph = parse_project_graph(read_json(path))
        except (OSError, ValueError) as e:
            problems.append(f"{path.name}: {e}")
            continue
        merged = graphs.setdefault(project_dir, ProjectGraph())
        merged.direct.update(graph.direct)
        for module, dependencies in graph.edges.items():
            merged.edges.setdefault(module, set()).update(dependencies)
    return graphs, problems


def enrich_gradle_results(
    native: Mapping[str, Any], graphs: Mapping[str, ProjectGraph]
) -> list[str]:
    """Fill ``Relationship`` and ``DependsOn`` of the packages of every gradle
    Result from the graph of its project, in place.

    ``DependsOn`` holds the IDs of the packages of the same Result: edges to
    modules that are not in the lockfile are dropped. A package the graph does
    not know is left as it is. Returns the Targets of the Results whose project
    has no graph.
    """
    without_graph: list[str] = []
    for result in native.get("Results") or []:
        if result.get("Type") != GRADLE_RESULT_TYPE:
            continue
        graph = graphs.get(lockfile_project_dir(result.get("Target")))
        if graph is None:
            without_graph.append(result.get("Target") or "")
            continue
        packages = result.get("Packages") or []
        ids = {p["ID"] for p in packages if p.get("ID")}
        for package in packages:
            module = package.get("ID")
            if not module or not graph.knows(module):
                continue
            package["Relationship"] = "direct" if module in graph.direct else "indirect"
            package["DependsOn"] = sorted(
                (graph.edges.get(module, set()) & ids) - {module}
            )
    return without_graph


def apply_gradle_graph(
    target_id: str, native: Mapping[str, Any], graph_dir: Path
) -> None:
    """Enrich the gradle Results of an fs scan with the graph of ``graph_dir``;
    without a graph (an older part, a project the build did not resolve) the
    Results stay as trivy reported them, which is a warning.
    """
    if not any(
        r.get("Type") == GRADLE_RESULT_TYPE for r in native.get("Results") or []
    ):
        return
    graphs, problems = load_gradle_graphs(graph_dir)
    for problem in problems:
        print(
            f"::warning title=Gradle dependency graph ignored::{target_id}: {problem}"
        )
    for lockfile in enrich_gradle_results(native, graphs):
        print(
            f"::warning title=No Gradle dependency graph::{target_id}: {lockfile} "
            "has no dependency graph, so its findings have no dependency paths"
        )


# --------------------------------------------------------------------------
# Analysing trivy results
# --------------------------------------------------------------------------


@dataclass
class PackageIndex:
    """The Packages inventory of one trivy Result: finds the package of a finding
    and walks the dependency graph (``DependsOn`` holds package IDs).
    """

    packages: Sequence[Mapping[str, Any]]
    result_type: str | None = None
    by_uid: dict[str, Mapping[str, Any]] = field(default_factory=dict, init=False)
    by_id: dict[str, Mapping[str, Any]] = field(default_factory=dict, init=False)
    by_name: dict[tuple[Any, Any], list[Mapping[str, Any]]] = field(
        default_factory=dict, init=False
    )
    # (file, canonical name) -> versions the package has in that file
    by_file: dict[tuple[str, Any], list[Any]] = field(default_factory=dict, init=False)
    parents: dict[str, list[str]] = field(default_factory=dict, init=False)
    _info: dict[str, DependencyInfo] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        for package in self.packages:
            uid = (package.get("Identifier") or {}).get("UID")
            if uid:
                self.by_uid.setdefault(uid, package)
            if package.get("ID"):
                self.by_id.setdefault(package["ID"], package)
            name = canonical_package_name(package.get("Name"), self.result_type)
            self.by_name.setdefault((name, package.get("Version")), []).append(package)
            if package.get("FilePath"):
                self.by_file.setdefault((package["FilePath"], name), []).append(
                    package.get("Version")
                )
            for child in package.get("DependsOn") or []:
                if package.get("ID"):
                    self.parents.setdefault(child, []).append(package["ID"])

    def match(self, vuln: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        """The package of a finding: by UID, else by package ID, else by name and
        version (the name compared as ``canonical_package_name`` does).
        """
        uid = (vuln.get("PkgIdentifier") or {}).get("UID")
        if uid in self.by_uid:
            return [self.by_uid[uid]]
        if vuln.get("PkgID") in self.by_id:
            return [self.by_id[vuln["PkgID"]]]
        name = canonical_package_name(vuln.get("PkgName"), self.result_type)
        return self.by_name.get((name, vuln.get("InstalledVersion")), [])

    def other_versions_in_file(self, package: Mapping[str, Any]) -> list[str]:
        """The other versions this inventory lists for the package in its own file.

        Only a package with a ``FilePath`` (a jar, a Python distribution) has any: a
        lockfile lists one version per package.
        """
        name = canonical_package_name(package.get("Name"), self.result_type)
        versions = self.by_file.get((package.get("FilePath") or "", name), [])
        return [
            v for v in versions if isinstance(v, str) and v != package.get("Version")
        ]

    def _is_direct(self, package_id: str) -> bool:
        return self.by_id[package_id].get("Relationship") == "direct"

    def _ancestors(self, target_id: str) -> dict[str, int]:
        """Packages the target is reachable from, with their distance to it.

        A reverse breadth-first walk over ``DependsOn`` that stops at direct
        packages (the nearest direct dependency is the one that matters); the
        visited set makes it safe against cycles.
        """
        depth = {target_id: 0}
        queue = [target_id]
        for node in queue:
            if node != target_id and self._is_direct(node):
                continue
            for parent in sorted(self.parents.get(node, ())):
                if parent in self.by_id and parent not in depth:
                    depth[parent] = depth[node] + 1
                    queue.append(parent)
        return depth

    def _count_paths(self, target_id: str, scope: Mapping[str, int]) -> int:
        """Number of paths from a direct package down to the target, at most
        ``PATH_COUNT_LIMIT``: a memoized count over the graph (never an
        enumeration), where the edges that close a cycle are ignored.
        """
        memo: dict[str, int] = {}
        total = {target_id: 0}
        on_path = {target_id}
        stack = [(target_id, iter(sorted(self.parents.get(target_id, ()))))]
        while stack:
            node, parents = stack[-1]
            for parent in parents:
                if parent not in scope or parent in on_path:
                    continue
                if parent in memo:
                    total[node] += memo[parent]
                elif self._is_direct(parent):
                    memo[parent] = 1
                    total[node] += 1
                else:
                    on_path.add(parent)
                    total[parent] = 0
                    stack.append((parent, iter(sorted(self.parents.get(parent, ())))))
                    break
            else:
                stack.pop()
                on_path.discard(node)
                memo[node] = min(total.pop(node), PATH_COUNT_LIMIT)
                if stack:
                    total[stack[-1][0]] += memo[node]
        return memo[target_id]

    def _shortest_paths(
        self, target_id: str, depth: Mapping[str, int]
    ) -> list[tuple[str, ...]]:
        """Up to ``MAX_DEPENDENCY_PATHS`` shortest paths (as names), shortest
        first, equal lengths in alphabetical order.

        Paths are enumerated by increasing length, walking down from every direct
        package and pruning with the distance to the target; the step budget keeps
        a dense graph from blowing up.
        """
        roots = sorted(n for n in depth if n != target_id and self._is_direct(n))
        names = {n: self.by_id[n].get("Name") or n for n in depth}
        found: set[tuple[str, ...]] = set()
        budget = PATH_WALK_BUDGET

        def walk(path: list[str], remaining: int) -> None:
            nonlocal budget
            budget -= 1
            node = path[-1]
            if budget < 0 or len(found) >= PATH_COUNT_LIMIT:
                return
            if remaining == 0:
                if node == target_id:
                    found.add(tuple(names[n] for n in path))
                return
            children = self.by_id[node].get("DependsOn") or []
            for child in sorted(children, key=lambda c: (names.get(c, ""), c)):
                if child in depth and child not in path and depth[child] < remaining:
                    if child == target_id or not self._is_direct(child):
                        path.append(child)
                        walk(path, remaining - 1)
                        path.pop()

        for length in range(min(depth[r] for r in roots), len(depth)):
            for root in roots:
                if depth[root] <= length:
                    walk([root], length)
            if len(found) >= MAX_DEPENDENCY_PATHS or budget < 0:
                break
        return sorted(found, key=lambda path: (len(path), path))[:MAX_DEPENDENCY_PATHS]

    def dependency_info(self, package: Mapping[str, Any]) -> DependencyInfo:
        """How a package got into the project: the chains of dependencies from a
        direct package to it. A direct package is its own chain; without graph
        information (no ``DependsOn``, unknown relationship) there is none.
        """
        package_id = package.get("ID")
        if package_id in self._info:
            return self._info[package_id]
        name = package.get("Name")
        info = DependencyInfo()
        if package.get("Relationship") == "direct":
            info = DependencyInfo([(name,)], 1, False, frozenset())
        elif package.get("Relationship") == "indirect" and package_id in self.by_id:
            depth = self._ancestors(package_id)
            roots = {self.by_id[n].get("Name") for n in depth if self._is_direct(n)}
            roots.discard(None)
            if roots - {name}:
                scope = depth
                count = self._count_paths(package_id, scope)
                info = DependencyInfo(
                    self._shortest_paths(package_id, depth),
                    count,
                    count >= PATH_COUNT_LIMIT,
                    frozenset(roots),
                )
        self._info[package_id] = info
        return info


@dataclass(frozen=True)
class DependencyInfo:
    """Dependency chains of one package: the shortest ones (as package names), the
    number of all of them, whether that number was cut at ``PATH_COUNT_LIMIT`` and
    the direct packages they start from.
    """

    paths: Sequence[tuple[str, ...]] = ()
    total: int = 0
    truncated: bool = False
    roots: frozenset[str] = frozenset()


def combine_dependency_info(
    infos: Iterable[DependencyInfo],
) -> tuple[list[list[str]], int, bool, list[str]]:
    """Merge the chains of all sightings of a finding: ``(paths, total,
    truncated, introduced_via)`` with the shortest distinct paths first.
    """
    infos = list(infos)
    paths: set[tuple[str, ...]] = set()
    roots: set[str] = set()
    total = 0
    for info in infos:
        paths.update(info.paths)
        roots.update(info.roots)
        total += info.total
    truncated = total >= PATH_COUNT_LIMIT or any(i.truncated for i in infos)
    ordered = sorted(paths, key=lambda path: (len(path), path))
    return (
        [list(path) for path in ordered[:MAX_DEPENDENCY_PATHS]],
        min(total, PATH_COUNT_LIMIT),
        truncated,
        sorted(roots)[:MAX_INTRODUCED_VIA],
    )


class Finding(NamedTuple):
    """One vulnerability of a trivy Result with its package from the inventory."""

    result: Mapping[str, Any]
    vuln: Mapping[str, Any]
    packages: list[Mapping[str, Any]]
    index: PackageIndex


def package_relationships(packages: Iterable[Mapping[str, Any]]) -> set[str]:
    """``direct`` / ``indirect`` / ...; ``unknown`` carries no information."""
    return {
        p["Relationship"]
        for p in packages
        if p.get("Relationship") and p["Relationship"] != "unknown"
    }


def package_dev_flag(packages: Iterable[Mapping[str, Any]]) -> bool | None:
    """True if all given packages are dev-only, False if one is not, None if empty."""
    flags = [p.get("Dev") is True for p in packages]
    return all(flags) if flags else None


def iter_findings(native: Mapping[str, Any]) -> Iterator[Finding]:
    for result in native.get("Results") or []:
        vulns = result.get("Vulnerabilities") or []
        if not vulns:
            continue
        index = PackageIndex(result.get("Packages") or [], result.get("Type"))
        for vuln in vulns:
            yield Finding(result, vuln, index.match(vuln), index)


def canonical_package_name(name: str | None, result_type: str | None) -> str | None:
    """The name a package is merged by: PEP 503 for Python, as is for the rest.

    ``Mako`` in an image (python-pkg) and ``mako`` in poetry.lock are one package.
    """
    if name and ECOSYSTEM_FAMILIES.get(result_type or "") == PYTHON_FAMILY:
        return _PEP503_SEPARATORS_RE.sub("-", name).lower()
    return name


def finding_key(result: Mapping[str, Any], vuln: Mapping[str, Any]) -> FindingKey:
    return (
        vuln.get("VulnerabilityID"),
        canonical_package_name(vuln.get("PkgName"), result.get("Type")),
        vuln.get("InstalledVersion"),
    )


def normalize_severity(value: Any) -> str:
    return value if value in SEV_ORDER else UNKNOWN_SEVERITY


def split_fixed_versions(raw: Any) -> list[str]:
    """Trivy ``FixedVersion`` ("15.5.27, 16.3.8") as a list; [] if there is none."""
    if not isinstance(raw, str):
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def count_packages(native: Mapping[str, Any]) -> dict[str, int]:
    """Inventory size of one target, so that 0 findings differ from 0 packages seen.

    Needs the full package list in the native result (``TRIVY_LIST_ALL_PKGS``).
    ``locations_scanned`` is the number of trivy Results (lockfiles, OS package
    databases, ...); ``packages_scanned`` the distinct name x version pairs.
    """
    results = native.get("Results") or []
    packages: set[tuple[str | None, str | None]] = set()
    for result in results:
        for package in result.get("Packages") or []:
            packages.add((package.get("Name"), package.get("Version")))
    return {"packages_scanned": len(packages), "locations_scanned": len(results)}


def image_digest(native: Mapping[str, Any]) -> str | None:
    digests = (native.get("Metadata") or {}).get("RepoDigests") or []
    return digests[0] if digests else None


def image_os(native: Mapping[str, Any]) -> str | None:
    """``ubuntu 24.04``: the OS of an image, as Trivy detected it."""
    detected = (native.get("Metadata") or {}).get("OS") or {}
    parts = (detected.get("Family"), detected.get("Name"))
    return " ".join(p for p in parts if p) or None


def package_type(result: Mapping[str, Any]) -> str:
    """'os' for OS packages (base image layer), 'library' for dependencies."""
    return "os" if result.get("Class") == CLASS_OS_PACKAGES else "library"


# ---- CVSS selection


def cvss_vector_version(vector: Any) -> str | None:
    """``CVSS:3.1/AV:N/...`` -> ``3.1``."""
    match = re.match(r"CVSS:(\d+\.\d+)/", vector) if isinstance(vector, str) else None
    return match.group(1) if match else None


def cvss_entry(source: str, data: Any) -> Record | None:
    """The CVSS of one source: v4.0 if the source has it, else v3.x, else None."""
    if not isinstance(data, Mapping):
        return None
    for score_key, vector_key, default_version in (
        ("V40Score", "V40Vector", "4.0"),
        ("V3Score", "V3Vector", None),
    ):
        score = data.get(score_key)
        if isinstance(score, int | float) and not isinstance(score, bool):
            vector = data.get(vector_key) or None
            return {
                "score": score,
                "vector": vector,
                "version": cvss_vector_version(vector) or default_version,
                "source": source,
            }
    return None


def select_cvss(vuln: Mapping[str, Any]) -> Record | None:
    """Pick one CVSS score: the severity source if it has one, else nvd, ghsa, then
    the first source alphabetically. Sources without a v3/v4 score do not count.
    """
    cvss = vuln.get("CVSS")
    if not isinstance(cvss, Mapping):
        return None
    entries = {
        source: entry
        for source, data in cvss.items()
        if (entry := cvss_entry(source, data)) is not None
    }
    if not entries:
        return None
    preferred = [vuln.get("SeveritySource"), "nvd", "ghsa", *sorted(entries)]
    source = next(name for name in preferred if name in entries)
    return entries[source]


# ---- Version comparison

PRERELEASE_TOKENS = frozenset(
    {"a", "alpha", "b", "beta", "c", "rc", "pre", "preview", "dev", "snapshot", "m"}
)
_VERSION_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


def version_tokens(version: str) -> list[int | str]:
    """Split a version into numeric (int) and alphabetic (lowercase str) tokens."""
    return [
        int(token) if token.isdigit() else token.lower()
        for token in _VERSION_TOKEN_RE.findall(version)
    ]


def _tail_order(tail: Sequence[int | str]) -> int:
    """Order of a version that has ``tail`` more tokens than the one it is compared to.

    Trailing zeros change nothing (1.0 == 1.0.0), a pre-release word makes the
    longer version older (1.0rc1 < 1.0), anything else makes it newer (1.0.1, 1.0-r1).
    """
    if all(token == 0 for token in tail):
        return 0
    return -1 if tail[0] in PRERELEASE_TOKENS else 1


def compare_versions(a: str, b: str) -> int | None:
    """Tolerant version comparison: -1, 0 or 1; None if the versions are not comparable.

    Works for semver-like, Alpine (``1.3.2-r1``) and similar schemes by comparing
    numeric tokens as integers and alphabetic ones as text. Versions without any
    number, or whose first difference is a number against a word, are not comparable.
    """
    tokens_a, tokens_b = version_tokens(a), version_tokens(b)
    if not any(isinstance(t, int) for t in tokens_a) or not any(
        isinstance(t, int) for t in tokens_b
    ):
        return None
    for x, y in zip(tokens_a, tokens_b, strict=False):
        if x == y:
            continue
        if isinstance(x, int) != isinstance(y, int):
            return None
        return -1 if x < y else 1  # type: ignore[operator]
    common = min(len(tokens_a), len(tokens_b))
    if len(tokens_a) > common:
        return _tail_order(tokens_a[common:])
    if len(tokens_b) > common:
        return -_tail_order(tokens_b[common:])
    return 0


def minimal_fix(installed: str, fixed_versions: Iterable[str]) -> str | None:
    """The lowest of ``fixed_versions`` that is above ``installed``.

    None if there is none or if a comparison is not possible.
    """
    best: str | None = None
    for candidate in fixed_versions:
        against_installed = compare_versions(candidate, installed)
        if against_installed is None:
            return None
        if against_installed <= 0:
            continue
        if best is None:
            best = candidate
            continue
        against_best = compare_versions(candidate, best)
        if against_best is None:
            return None
        if against_best < 0:
            best = candidate
    return best


def upgrade_target(
    installed: str, fixed_per_cve: Iterable[Sequence[str]]
) -> str | None:
    """The version that fixes all CVEs of a package: max of the per-CVE minimal fixes.

    None if any CVE has no fix above the installed version, or versions are not
    comparable (a partial upgrade would leave the package vulnerable).
    """
    target: str | None = None
    for fixed_versions in fixed_per_cve:
        minimal = minimal_fix(installed, fixed_versions)
        if minimal is None:
            return None
        if target is None:
            target = minimal
            continue
        against_target = compare_versions(minimal, target)
        if against_target is None:
            return None
        if against_target > 0:
            target = minimal
    return target


def fixed_in_place(
    packages: Sequence[Mapping[str, Any]],
    fixed_versions: Sequence[str],
    index: PackageIndex,
) -> bool:
    """Whether the file of each of the packages already holds a fixed version of it.

    Trivy can list one artifact under two version strings, e.g. a jar whose manifest
    says ``12.10.2`` and whose POM says ``12.10.2.jre11`` (Maven orders the second
    above the first). The advisory then matches the first, but the file ships the
    second, which is the fix: there is nothing to upgrade to. The comparison is the
    one of ``minimal_fix``, so it is as tolerant as the rest of the module.
    """
    if not packages:
        return False
    for package in packages:
        installed = package.get("Version")
        minimal = (
            minimal_fix(installed, fixed_versions)
            if isinstance(installed, str)
            else None
        )
        if minimal is None or not any(
            compare_versions(other, minimal) in (0, 1)
            for other in index.other_versions_in_file(package)
        ):
            return False
    return True


# --------------------------------------------------------------------------
# Records: merging and enrichment
# --------------------------------------------------------------------------


def blank_record(
    repo: str | None,
    cve: str | None,
    pkg: str | None,
    version: str | None,
    pkg_type: str,
) -> Record:
    """A record with nothing known but its key; the scanner fills in the rest."""
    return {
        "repo": repo,
        "cve": cve,
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
        "upgrade_to": None,
        "title": None,
        "cwe": None,
        "published": None,
        "primary_url": None,
        "scanners": [],
    }


def new_record(
    repo: str | None,
    key: FindingKey,
    result: Mapping[str, Any],
    vuln: Mapping[str, Any],
) -> Record:
    """A record from the first copy of a finding; ``absorb_finding`` adds the rest."""
    cve, _, version = key
    record = blank_record(repo, cve, vuln.get("PkgName"), version, package_type(result))
    record.update(
        severity=normalize_severity(vuln.get("Severity")),
        severity_source=vuln.get("SeveritySource") or None,
        cvss=select_cvss(vuln),
        status=vuln.get("Status"),
        title=(vuln.get("Title") or "").strip() or None,
        cwe=vuln.get("CweIDs") or None,
        published=vuln.get("PublishedDate") or None,
        primary_url=vuln.get("PrimaryURL") or None,
    )
    return record


def _append_unique(items: list[Any], value: Any) -> None:
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
    _append_unique(record["scan_targets"], tid)
    _append_unique(record["scanners"], scanner)
    _append_unique(record["ecosystem"], result.get("Type"))
    _append_unique(record["locations"], result.get("Target", ""))
    for relationship in relationships:
        _append_unique(record["relationship"], relationship)


def absorb_finding(
    record: Record,
    tid: str,
    scanner: str,
    result: Mapping[str, Any],
    vuln: Mapping[str, Any],
    relationships: Collection[str],
) -> None:
    """Add one copy of a Trivy finding (one lockfile of one target) to its record.

    The first copy wins for the descriptive fields; later copies only add to the
    lists and backfill what the first one lacked (a fix, a CVSS score).
    """
    absorb_sighting(record, tid, scanner, result, relationships)
    _append_unique(record["pkg_paths"], vuln.get("PkgPath"))
    for alias in vuln.get("VendorIDs") or []:
        if alias != record["cve"]:
            _append_unique(record["aliases"], alias)
    fixed_versions = split_fixed_versions(vuln.get("FixedVersion"))
    if fixed_versions and not record["fix_available"]:
        record["fix_available"] = True
        record["status"] = vuln.get("Status") or record["status"]
    for fixed in fixed_versions:
        _append_unique(record["fixed_versions"], fixed)
    if record["cvss"] is None:
        record["cvss"] = select_cvss(vuln)
        record["severity_source"] = (
            record["severity_source"] or vuln.get("SeveritySource") or None
        )


def record_ids(record: Mapping[str, Any]) -> set[str]:
    """Every id a record is known by: its ``cve`` and its aliases."""
    return {record["cve"], *record["aliases"]}


class MergeResult(NamedTuple):
    """What the merge knows: the records, where each was seen and which are fixed in
    place (see ``fixed_in_place``); the last two are keyed by ``(cve, pkg, version)``.
    """

    records: list[Record]
    sightings: Sightings
    fixed_in_place: frozenset[tuple[Any, Any, Any]]


class RecordSet:
    """The records of one repository while the scans are merged into them.

    Trivy findings are added first, as they create the records; OSV findings then
    join them (``add_osv``) or, where Trivy does not know the vulnerability, create
    records of their own. ``finish`` completes and returns the records.
    """

    def __init__(self, repo: str | None, image_ids: Collection[str] = ()) -> None:
        self.repo = repo
        self.image_ids = image_ids
        self.by_key: dict[FindingKey, Record] = {}
        self.sightings: dict[FindingKey, dict[str, list[str]]] = {}
        # (canonical package name, version) -> keys of the records of the package
        self.by_package: dict[tuple[str | None, str | None], list[FindingKey]] = {}
        self._target_order: dict[str, int] = {}
        self._named_by_image: set[FindingKey] = set()
        self._dev_packages: dict[FindingKey, list[Mapping[str, Any]]] = {}
        self._chains: dict[FindingKey, dict[tuple[Any, Any], DependencyInfo]] = {}
        # key -> whether every sighting found the fix in the package's own file
        self._in_place: dict[FindingKey, bool] = {}

    def _add_record(self, key: FindingKey, record: Record) -> None:
        self.by_key[key] = record
        self.by_package.setdefault((key[1], key[2]), []).append(key)

    def _note_packages(
        self,
        key: FindingKey,
        tid: str,
        pkg_name: str | None,
        result: Mapping[str, Any],
        packages: Sequence[Mapping[str, Any]],
        index: PackageIndex,
    ) -> None:
        """Remember the packages of a sighting: display name, dev flag, chains and
        where the record was seen.
        """
        if tid in self.image_ids and key not in self._named_by_image:
            self._named_by_image.add(key)
            self.by_key[key]["pkg"] = pkg_name
        self._in_place[key] = self._in_place.get(key, True) and fixed_in_place(
            packages, self.by_key[key]["fixed_versions"], index
        )
        self._dev_packages.setdefault(key, []).extend(packages)
        for package in packages:
            # one chain set per package of a lockfile, however many targets saw it
            sighting = (result.get("Target"), package.get("ID") or package.get("Name"))
            self._chains.setdefault(key, {})[sighting] = index.dependency_info(package)
        _append_unique(
            self.sightings.setdefault(key, {}).setdefault(tid, []),
            result.get("Target", ""),
        )

    def _position(self, tid: str) -> int:
        """The place of a target in the targets file (the order it was added in)."""
        return self._target_order.setdefault(tid, len(self._target_order))

    def add_trivy(self, tid: str, scanner: str, native: Mapping[str, Any]) -> None:
        self._position(tid)
        for result, vuln, packages, index in iter_findings(native):
            key = finding_key(result, vuln)
            record = self.by_key.get(key)
            if record is None:
                record = new_record(self.repo, key, result, vuln)
                self._add_record(key, record)
            absorb_finding(
                record, tid, scanner, result, vuln, package_relationships(packages)
            )
            self._note_packages(key, tid, vuln.get("PkgName"), result, packages, index)

    def add_osv(self, scan: OsvScan) -> None:
        """Merge the findings of one OSV target into the records.

        Per package, the OSV ids that alias each other are one vulnerability
        (``osv_vulnerabilities``). It joins every record of the same package
        version that it shares an id with (the record's ``cve`` or an alias): the
        record gains the ``osv`` scanner, the ids and where OSV saw it, and keeps
        everything Trivy said. A vulnerability no record has becomes a record of
        its own, whose package context comes from the Trivy package of the purl.
        """
        self._position(scan.tid)
        records = scan.native["vulnerabilities"]
        for purl, vuln_ids in sorted(scan.native["packages"].items()):
            if not vuln_ids:
                continue
            for vulnerability in osv_vulnerabilities(records, vuln_ids):
                for found in scan.packages[purl]:
                    self._add_osv_finding(scan.tid, purl, vulnerability, found)

    def _add_osv_finding(
        self,
        tid: str,
        purl: str,
        vulnerability: OsvVulnerability,
        found: PackageSighting,
    ) -> None:
        result, package, index = found
        name = canonical_package_name(package.get("Name"), result.get("Type"))
        version = package.get("Version")
        matched = [
            key
            for key in self.by_package.get((name, version), [])
            if vulnerability.names & record_ids(self.by_key[key])
        ]
        if not matched:
            key = (osv_primary_id(vulnerability), name, version)
            self._add_record(
                key, new_osv_record(self.repo, key, purl, vulnerability, found)
            )
            matched = [key]
        # Ids of the vulnerability that are the CVE of one of the matched records
        # stay out of the aliases of the others
        cves = {self.by_key[key]["cve"] for key in matched}
        packages = [package]
        for key in matched:
            record = self.by_key[key]
            for alias in sorted(vulnerability.names - cves):
                _append_unique(record["aliases"], alias)
            absorb_sighting(
                record, tid, SCANNER_OSV, result, package_relationships(packages)
            )
            self._note_packages(key, tid, package.get("Name"), result, packages, index)

    def finish(self) -> MergeResult:
        """The records, completed, and what is known of them (see ``merge_records``)."""
        for key, record in self.by_key.items():
            for name in (
                "locations",
                "scanners",
                "ecosystem",
                "relationship",
                "aliases",
            ):
                record[name].sort()
            record["pkg_paths"].sort()
            # OSV may have added targets after the Trivy ones: back to targets order
            record["scan_targets"].sort(key=self._target_order.__getitem__)
            record["dev"] = package_dev_flag(self._dev_packages.get(key, []))
            (
                record["dependency_paths"],
                record["dependency_paths_total"],
                record["dependency_paths_truncated"],
                record["introduced_via"],
            ) = combine_dependency_info(self._chains.get(key, {}).values())
        by_record = {
            (r["cve"], r["pkg"], r["version"]): self.sightings[key]
            for key, r in self.by_key.items()
        }
        in_place = frozenset(
            (r["cve"], r["pkg"], r["version"])
            for key, r in self.by_key.items()
            if self._in_place.get(key)
        )
        return MergeResult(list(self.by_key.values()), by_record, in_place)


def merge_records(
    repo: str | None,
    scans: Iterable[tuple[str, str, Mapping[str, Any]]],
    image_ids: Collection[str] = (),
    osv_scans: Iterable[OsvScan] = (),
) -> MergeResult:
    """Deduplicate findings across lockfiles and merge them across targets.

    ``scans`` is ``(target id, scanner, native JSON)`` of the Trivy targets in
    targets-file order, which is also the order of each record's ``scan_targets``;
    ``osv_scans`` are the OSV targets, merged into the Trivy records. Returns the
    records (unordered, not enriched yet), where each finding was seen and which
    findings are fixed in place, keyed by ``(cve, pkg, version)`` of the record. A
    package seen under several spellings (see ``canonical_package_name``) is shown
    under the spelling of its first image record, else of its first record.
    """
    record_set = RecordSet(repo, image_ids)
    for tid, scanner, native in scans:
        record_set.add_trivy(tid, scanner, native)
    for osv_scan in osv_scans:
        record_set.add_osv(osv_scan)
    return record_set.finish()


# ---- OSV: reported per target and merged into the records

OSV_NATIVE_SCHEMA_VERSION = 1
OSV_FOOTER = "OSV: language packages only"
OSV_VULNERABILITY_URL = "https://osv.dev/vulnerability/"
# CVSS 3.x qualitative rating: lower bound of the base score -> severity
CVSS3_RATINGS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"))
CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges required depend on the scope: (unchanged, changed)
CVSS3_PRIVILEGES = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.5)}
# purl type -> (OSV ecosystem, separator of namespace and name in the OSV name)
PURL_ECOSYSTEMS = {
    "npm": ("npm", "/"),
    "pypi": ("PyPI", "/"),
    "maven": ("Maven", ":"),
    "golang": ("Go", "/"),
    "cargo": ("crates.io", "/"),
    "nuget": ("NuGet", "/"),
    "gem": ("RubyGems", "/"),
    "composer": ("Packagist", "/"),
}
# Ecosystems whose package names are case-insensitive (PEP 503 normalization)
CASE_INSENSITIVE_ECOSYSTEMS = ("PyPI", "NuGet")
# Version ranges whose "fixed" events are versions (GIT ranges name commits)
OSV_VERSION_RANGE_TYPES = ("ECOSYSTEM", "SEMVER")


def osv_result_problem(native: Mapping[str, Any]) -> str | None:
    """Why an OSV result cannot be counted (it is incomplete), else None."""
    if native.get("schema_version") != OSV_NATIVE_SCHEMA_VERSION:
        version = native.get("schema_version")
        return f"osv result has an unsupported schema_version: {version!r}"
    packages = native.get("packages")
    records = native.get("vulnerabilities")
    if not isinstance(packages, dict) or not isinstance(records, dict):
        return "osv result has no packages or vulnerabilities"
    for vuln_ids in packages.values():
        if not isinstance(vuln_ids, list):
            return "osv result has a malformed package entry"
        for vuln_id in vuln_ids:
            if not isinstance(records.get(vuln_id), dict):
                return f"osv result has no record of {vuln_id}"
    return None


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """``(type, namespace, name)`` of a purl, percent-decoded; None if malformed."""
    if not purl.startswith("pkg:"):
        return None
    body = purl[len("pkg:") :].split("#", 1)[0].split("?", 1)[0].split("@", 1)[0]
    parts = body.split("/")
    if len(parts) < 2 or not all(parts):
        return None
    namespace = "/".join(urllib.parse.unquote(part) for part in parts[1:-1])
    return parts[0].lower(), namespace, urllib.parse.unquote(parts[-1])


def purl_version(purl: str) -> str | None:
    """The version inside a purl (percent-decoded); None if it has none."""
    path = purl.split("#", 1)[0].split("?", 1)[0]
    _, at, version = path.rpartition("@")
    return urllib.parse.unquote(version) if at and "/" not in version else None


def osv_identity(ecosystem: str, name: str) -> tuple[str, str]:
    """``(ecosystem, name)`` in the form OSV package references are compared in."""
    if ecosystem in CASE_INSENSITIVE_ECOSYSTEMS:
        name = _PEP503_SEPARATORS_RE.sub("-", name).lower()
    return ecosystem, name


def purl_identity(purl: str) -> tuple[str, str] | None:
    """The OSV package of a purl; None for a malformed purl or an unknown purl type."""
    parsed = parse_purl(purl)
    known = PURL_ECOSYSTEMS.get(parsed[0]) if parsed else None
    if parsed is None or known is None:
        return None
    ecosystem, separator = known
    _, namespace, name = parsed
    return osv_identity(ecosystem, separator.join(p for p in (namespace, name) if p))


def affected_identity(affected: Mapping[str, Any]) -> tuple[str, str] | None:
    """The package of an OSV ``affected`` entry, by its purl or ecosystem and name."""
    package = affected.get("package") or {}
    purl = package.get("purl")
    if isinstance(purl, str) and (identity := purl_identity(purl)):
        return identity
    ecosystem, name = package.get("ecosystem"), package.get("name")
    if not isinstance(ecosystem, str) or not isinstance(name, str):
        return None
    # An ecosystem may carry a suffix ("Alpine:v3.15")
    return osv_identity(ecosystem.split(":", 1)[0], name)


def osv_fixed_versions(
    record: Mapping[str, Any], purl: str, installed: str | None = None
) -> list[str]:
    """The versions the advisory names as the fix of the package of ``purl``.

    Only entries of this very package count (an advisory often covers several
    packages) and only version ranges (``GIT`` ranges name commits). A range
    that has ``last_affected`` but no ``fixed`` event has no fix. A version that
    is not above the ``installed`` one cannot be the fix of it (it belongs to
    another branch of the package), so it is left out; an incomparable one is
    kept. This is the one definition of a fix, for records and target counts.
    """
    identity = purl_identity(purl)
    if identity is None:
        return []
    fixed: list[str] = []
    for affected in record.get("affected") or []:
        if affected_identity(affected) != identity:
            continue
        for version_range in affected.get("ranges") or []:
            if version_range.get("type") not in OSV_VERSION_RANGE_TYPES:
                continue
            for event in version_range.get("events") or []:
                version = event.get("fixed")
                if not isinstance(version, str) or not version:
                    continue
                if installed is None or compare_versions(version, installed) not in (
                    -1,
                    0,
                ):
                    _append_unique(fixed, version)
    return fixed


def osv_has_fix(
    record: Mapping[str, Any], purl: str, installed: str | None = None
) -> bool:
    """Whether the advisory names a fixed version of the package of ``purl``."""
    return bool(osv_fixed_versions(record, purl, installed))


def cvss3_roundup(value: float) -> float:
    """Round up to one decimal as CVSS 3.1 specifies (immune to float noise)."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (scaled // 10_000 + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """The base score of a CVSS 3.x vector string; None if it is not a valid one."""
    version, *parts = vector.split("/")
    if version not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics = dict(part.split(":", 1) for part in parts if ":" in part)
    try:
        changed = {"U": False, "C": True}[metrics["S"]]
        privileges = CVSS3_PRIVILEGES[metrics["PR"]][changed]
        exploitability_weights = [
            CVSS3_WEIGHTS[k][metrics[k]] for k in ("AV", "AC", "UI")
        ]
        impact_weights = [CVSS3_WEIGHTS[k][metrics[k]] for k in ("C", "I", "A")]
    except KeyError:
        return None
    iss = 1 - math.prod(1 - weight for weight in impact_weights)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * math.prod(exploitability_weights) * privileges
    return cvss3_roundup(min((1.08 if changed else 1) * (impact + exploitability), 10))


def cvss3_rating(score: float) -> str:
    return next(
        (rating for bound, rating in CVSS3_RATINGS if score >= bound), UNKNOWN_SEVERITY
    )


def worst_severity(severities: Iterable[str]) -> str:
    """The most severe of the given levels; UNKNOWN when there are none."""
    return min(severities, key=SEV_ORDER.__getitem__, default=UNKNOWN_SEVERITY)


def osv_database_rating(record: Mapping[str, Any]) -> str | None:
    """The rating the database itself gives (``database_specific.severity`` of GHSA
    records, where ``MODERATE`` is ``MEDIUM``) as one of the Trivy levels, if any.
    """
    own = (record.get("database_specific") or {}).get("severity")
    if not isinstance(own, str):
        return None
    own = {"MODERATE": "MEDIUM"}.get(own.upper(), own.upper())
    return own if own in SEV_ORDER and own != UNKNOWN_SEVERITY else None


def osv_cvss3_vectors(record: Mapping[str, Any]) -> list[tuple[float, str]]:
    """``(base score, vector)`` of the valid CVSS 3.x vectors of ``severity[]``."""
    vectors = []
    for entry in record.get("severity") or []:
        vector = entry.get("score")
        score = cvss3_base_score(vector) if isinstance(vector, str) else None
        if score is not None:
            vectors.append((score, vector))
    return vectors


def osv_severity(record: Mapping[str, Any]) -> str:
    """The severity of an OSV record as one of the Trivy levels.

    The database's own rating wins; otherwise the highest rating of the CVSS 3.x
    vectors in ``severity[]``. CVSS 2 and 4 vectors are not rated, so a record that
    has nothing else is UNKNOWN.
    """
    return osv_database_rating(record) or worst_severity(
        cvss3_rating(score) for score, _ in osv_cvss3_vectors(record)
    )


def osv_findings(native: Mapping[str, Any]) -> dict[tuple[str, str], tuple[str, bool]]:
    """Unique findings of one OSV target: (purl, OSV id) -> (severity, fixable)."""
    records = native["vulnerabilities"]
    return {
        (purl, vuln_id): (
            osv_severity(records[vuln_id]),
            osv_has_fix(records[vuln_id], purl, purl_version(purl)),
        )
        for purl, vuln_ids in native["packages"].items()
        for vuln_id in set(vuln_ids)
    }


# ---- OSV: findings as records


class PackageSighting(NamedTuple):
    """A Trivy package of a lockfile (or image layer) with its inventory."""

    result: Mapping[str, Any]
    package: Mapping[str, Any]
    index: PackageIndex


class OsvScan(NamedTuple):
    """The native result of an OSV target with the Trivy packages of its purls."""

    tid: str
    native: Mapping[str, Any]
    packages: Mapping[str, list[PackageSighting]]


class OsvResolutionError(Exception):
    """An OSV result that does not fit the Trivy result of its twin target."""


def resolve_osv_scan(
    tid: str, native: Mapping[str, Any], trivy_native: Mapping[str, Any] | None
) -> OsvScan:
    """Find the Trivy package of every purl of the OSV result that has findings.

    OSV was asked about the purls of the language packages of the twin Trivy
    target (the same id), so every purl with a finding must be a package there
    (``Identifier.PURL``, in any of its lockfiles): that package gives the
    findings their name, version, relationship, dev flag and dependency chains.
    A result that does not fit means the two parts are not of the same scan, so
    the OSV target is failed rather than guessed at.
    """
    needed = {purl for purl, vuln_ids in native["packages"].items() if vuln_ids}
    if not needed:
        return OsvScan(tid, native, {})
    if trivy_native is None:
        raise OsvResolutionError("there is no trivy result of this target to join with")
    found: dict[str, list[PackageSighting]] = {}
    for result in trivy_native.get("Results") or []:
        if result.get("Class") != CLASS_LANGUAGE_PACKAGES:
            continue
        packages = result.get("Packages") or []
        index = PackageIndex(packages, result.get("Type"))
        for package in packages:
            purl = (package.get("Identifier") or {}).get("PURL")
            if purl in needed:
                found.setdefault(purl, []).append(
                    PackageSighting(result, package, index)
                )
    if missing := sorted(needed - found.keys()):
        raise OsvResolutionError(
            f"{len(missing)} package(s) with findings are not in the trivy result "
            f"of this target, first: {missing[0]}"
        )
    return OsvScan(tid, native, found)


@dataclass(frozen=True)
class OsvVulnerability:
    """The OSV ids reported for one package that are one vulnerability.

    ``ids`` are the ids OSV reported, ``names`` those and all their aliases;
    ``records`` are the OSV records of the ids, GHSA first, then by id.
    """

    ids: tuple[str, ...]
    names: frozenset[str]
    records: tuple[Mapping[str, Any], ...]


def osv_aliases(record: Mapping[str, Any]) -> list[str]:
    return [a for a in record.get("aliases") or [] if isinstance(a, str)]


def osv_record_order(record: Mapping[str, Any]) -> tuple[bool, str]:
    """GHSA records first (they carry the summary, severity and CWE), then by id."""
    return not record["id"].startswith("GHSA-"), record["id"]


def osv_vulnerabilities(
    records: Mapping[str, Mapping[str, Any]], vuln_ids: Iterable[str]
) -> list[OsvVulnerability]:
    """Group the ids reported for a package into vulnerabilities by their aliases.

    Two ids are one vulnerability if they are linked through ``aliases`` (``PYSEC-x``
    and ``GHSA-y`` that both alias ``CVE-z``, or one that lists the other). The
    ``related`` field is not used: it links advisories that are similar, not the
    same. Groups come in the order of their smallest id.
    """
    parent: dict[str, str] = {}

    def find(name: str) -> str:
        parent.setdefault(name, name)
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    ids = sorted(set(vuln_ids))
    for vuln_id in ids:
        for alias in osv_aliases(records[vuln_id]):
            parent[find(alias)] = find(vuln_id)
    groups: dict[str, list[str]] = {}
    for vuln_id in ids:
        groups.setdefault(find(vuln_id), []).append(vuln_id)
    vulnerabilities = []
    for members in groups.values():
        names = {
            name
            for member in members
            for name in (member, *osv_aliases(records[member]))
        }
        ordered = sorted((records[m] for m in members), key=osv_record_order)
        vulnerabilities.append(
            OsvVulnerability(tuple(members), frozenset(names), tuple(ordered))
        )
    return vulnerabilities


def osv_primary_id(vulnerability: OsvVulnerability) -> str:
    """The id an OSV-only record is known by (its ``cve``).

    The first CVE among the ids and aliases (in string order, the only one in
    nearly every case), else the first GHSA id, else the first id OSV reported.
    """
    for prefix in ("CVE-", "GHSA-"):
        if candidates := sorted(n for n in vulnerability.names if n.startswith(prefix)):
            return candidates[0]
    return vulnerability.ids[0]


def osv_group_severity(records: Iterable[Mapping[str, Any]]) -> str:
    """The severity of a vulnerability: the database rating of its records (the
    most severe if several), else the highest rating of their CVSS 3.x vectors,
    else UNKNOWN.
    """
    records = list(records)
    if own := [r for r in map(osv_database_rating, records) if r]:
        return worst_severity(own)
    return worst_severity(
        cvss3_rating(score) for r in records for score, _ in osv_cvss3_vectors(r)
    )


def osv_group_cvss(records: Iterable[Mapping[str, Any]]) -> Record | None:
    """The best CVSS vector of a vulnerability, in the shape of the Trivy ``cvss``.

    The highest-scoring CVSS 3.x vector (its score is computed from the vector).
    Without one, the first CVSS 4.0 vector, kept with ``score: null`` because a
    4.0 score is not computed here. CVSS 2 vectors are ignored.
    """
    records = list(records)
    vectors = [v for r in records for v in osv_cvss3_vectors(r)]
    if vectors:
        score, vector = max(vectors, key=lambda v: v[0])
    else:
        score = None
        vector = next(
            (
                entry["score"]
                for r in records
                for entry in r.get("severity") or []
                if isinstance(entry.get("score"), str)
                and cvss_vector_version(entry["score"]) == "4.0"
            ),
            None,
        )
        if vector is None:
            return None
    return {
        "score": score,
        "vector": vector,
        "version": cvss_vector_version(vector),
        "source": SCANNER_OSV,
    }


def osv_group_fixes(
    records: Iterable[Mapping[str, Any]], purl: str, installed: str | None
) -> list[str]:
    """The fixed versions of the package in a vulnerability, in the order of the
    records and their events (see ``osv_fixed_versions``).
    """
    fixed: list[str] = []
    for record in records:
        for version in osv_fixed_versions(record, purl, installed):
            _append_unique(fixed, version)
    return fixed


def osv_title(record: Mapping[str, Any]) -> str:
    """The ``summary`` of a record, else the first non-empty line of its ``details``
    (PYSEC records have no summary); empty if there is neither.
    """
    summary = record.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()
    details = record.get("details")
    if isinstance(details, str):
        return next((line.strip() for line in details.splitlines() if line.strip()), "")
    return ""


def osv_cwe_ids(record: Mapping[str, Any]) -> list[str]:
    """database_specific.cwe_ids (GHSA records), as given."""
    ids = (record.get("database_specific") or {}).get("cwe_ids")
    return [i for i in ids if isinstance(i, str)] if isinstance(ids, list) else []


def osv_primary_url(records: Sequence[Mapping[str, Any]]) -> str:
    """The first ADVISORY reference of the records, else the OSV page of the first."""
    for record in records:
        for reference in record.get("references") or []:
            url = reference.get("url")
            if reference.get("type") == "ADVISORY" and isinstance(url, str) and url:
                return url
    return f"{OSV_VULNERABILITY_URL}{records[0]['id']}"


def new_osv_record(
    repo: str | None,
    key: FindingKey,
    purl: str,
    vulnerability: OsvVulnerability,
    found: PackageSighting,
) -> Record:
    """A record for a vulnerability only OSV reports, from the OSV records of its
    ids and the Trivy package of the purl.
    """
    cve, _, version = key
    records = vulnerability.records
    record = blank_record(
        repo, cve, found.package.get("Name"), version, package_type(found.result)
    )
    severity = osv_group_severity(records)
    fixed = osv_group_fixes(records, purl, version)
    titles = [osv_title(r) for r in records]
    published = [r["published"] for r in records if isinstance(r.get("published"), str)]
    cwe = {cwe_id for r in records for cwe_id in osv_cwe_ids(r)}
    record.update(
        severity=severity,
        severity_source=None if severity == UNKNOWN_SEVERITY else SCANNER_OSV,
        cvss=osv_group_cvss(records),
        status="fixed" if fixed else "affected",
        fixed_versions=fixed,
        fix_available=bool(fixed),
        title=next((text for text in titles if text), None),
        cwe=sorted(cwe) or None,
        published=min(published, default=None),
        primary_url=osv_primary_url(records),
    )
    return record


# ---- Not shipped paths


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


# ---- Exposure


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


def assign_upgrades(
    records: Sequence[Record],
    in_place: Collection[tuple[Any, Any, Any]] = frozenset(),
) -> None:
    """Set ``upgrade_to`` on the fixable records of each package version.

    It is the version that resolves all of the package's fixable CVEs; records
    without a fix keep ``None``, and so do the ``in_place`` ones (see
    ``fixed_in_place``): no upgrade is needed, so none is named, and they do not
    count for the upgrade of the other records of the package.
    """

    def needs_upgrade(record: Record) -> bool:
        identity = (record["cve"], record["pkg"], record["version"])
        return record["fix_available"] and identity not in in_place

    fixed_by_package: dict[tuple[Any, Any], list[list[str]]] = {}
    for record in records:
        if needs_upgrade(record):
            key = (record["pkg"], record["version"])
            fixed_by_package.setdefault(key, []).append(record["fixed_versions"])
    for record in records:
        installed = record["version"]
        fixed = fixed_by_package.get((record["pkg"], installed))
        record["upgrade_to"] = (
            upgrade_target(installed, fixed)
            if fixed and needs_upgrade(record) and isinstance(installed, str)
            else None
        )


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
        record["cve"] or "",
    )


def finalize_records(
    records: Iterable[Record],
    targets: Sequence[Target],
    in_place: Collection[tuple[Any, Any, Any]] = frozenset(),
    sightings: Sightings | None = None,
    not_shipped: NotShipped | None = None,
) -> list[Record]:
    """Enrich the merged records (exposure, upgrade_to) and put them in report order."""
    records = list(records)
    assign_exposure(records, targets, sightings, not_shipped)
    assign_upgrades(records, in_place)
    return sorted(records, key=record_sort_key)


# --------------------------------------------------------------------------
# Building the reports
# --------------------------------------------------------------------------


def empty_severity_counts() -> dict[str, int]:
    return dict.fromkeys(SEVERITIES, 0)


def count_by_severity(severities: Iterable[str]) -> dict[str, int]:
    counts = empty_severity_counts()
    for severity in severities:
        counts[normalize_severity(severity)] += 1
    return counts


def finding_stats(items: Iterable[tuple[str, bool]]) -> dict[str, Any]:
    """``{total, fixable, by_severity}`` of ``(severity, fixable)`` items."""
    items = list(items)
    return {
        "total": len(items),
        "fixable": sum(fixable for _, fixable in items),
        "by_severity": count_by_severity(severity for severity, _ in items),
    }


def target_findings(native: Mapping[str, Any]) -> dict[FindingKey, tuple[str, bool]]:
    """Unique findings of one target: key -> (severity, has a fix in any copy)."""
    found: dict[FindingKey, tuple[str, bool]] = {}
    for result, vuln, _, _ in iter_findings(native):
        key = finding_key(result, vuln)
        severity, fixable = found.get(
            key, (normalize_severity(vuln.get("Severity")), False)
        )
        found[key] = (
            severity,
            fixable or bool(split_fixed_versions(vuln.get("FixedVersion"))),
        )
    return found


def build_target_entry(
    target: Mapping[str, Any],
    state: Mapping[str, Any],
    native: Mapping[str, Any] | None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": target["id"],
        "scanner": target["scanner"],
        "kind": target.get("kind"),
        "image": target.get("image"),
        "tag": target.get("tag"),
        "ref": target.get("ref"),
        "git_ref": target.get("git_ref"),
        "commit_sha": target.get("commit_sha"),
        "image_digest": None,
        "status": state["status"],
        "reason": state["reason"],
        "packages_scanned": None,
        "locations_scanned": None,
        "findings": None,
        "queried_at": None,
    }
    if native is None:
        return entry
    if target["scanner"] == SCANNER_OSV:
        entry["packages_scanned"] = len(native["packages"])
        entry["findings"] = finding_stats(osv_findings(native).values())
        entry["queried_at"] = native.get("queried_at")
    else:
        entry.update(count_packages(native))
        entry["findings"] = finding_stats(target_findings(native).values())
        if target.get("kind") == KIND_IMAGE:
            entry["image_digest"] = image_digest(native)
    return entry


def build_totals(
    targets: Sequence[Mapping[str, Any]], records: Sequence[Record]
) -> dict[str, Any]:
    """Run-level numbers: targets by status, findings by severity and exposure."""
    statuses = [t["status"] for t in targets]
    by_exposure = dict.fromkeys(EXPOSURES, 0)
    for record in records:
        by_exposure[record["exposure"]] += 1
    findings = finding_stats((r["severity"], r["fix_available"]) for r in records)
    findings["by_exposure"] = by_exposure
    return {
        "targets": {
            "total": len(targets),
            "ok": statuses.count(STATUS_OK),
            "failed": statuses.count(STATUS_FAILED),
            "not_applicable": statuses.count(STATUS_NOT_APPLICABLE),
        },
        "findings": findings,
    }


def build_scan_report(
    targets_doc: Mapping[str, Any],
    results: Sequence[tuple[Target, dict[str, Any], Mapping[str, Any] | None]],
    records: Sequence[Record],
    generated_utc: str,
    trivy_db: Mapping[str, str | None] | None = None,
    trivy_configs: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    trivy_version = None
    osv_api_url = None
    targets: list[dict[str, Any]] = []
    for target, state, native in results:
        entry = build_target_entry(target, state, native)
        if target["scanner"] == SCANNER_TRIVY and target["id"] in (trivy_configs or {}):
            # What trivy.yaml of the scanned commit says to skip, and what was done
            entry["trivy_skip_paths"] = dict((trivy_configs or {})[target["id"]])
        if native is not None:
            if entry["packages_scanned"] == 0:
                print(
                    "::warning title=No packages in scan result::"
                    f"{target_name(target)}: "
                    "0 packages were seen (an empty scan is suspicious: no lockfiles, "
                    "an unsupported ecosystem or a missing package list)"
                )
            if target["scanner"] == SCANNER_OSV:
                osv_api_url = osv_api_url or native.get("api_url")
            else:
                trivy_version = trivy_version or (native.get("Trivy") or {}).get(
                    "Version"
                )
        targets.append(entry)
    has_osv = any(t["scanner"] == SCANNER_OSV for t in targets)
    return {
        "schema_version": SCHEMA_VERSION,
        "repo": targets_doc.get("repo"),
        "commit_sha": targets_doc.get("commit_sha"),
        "default_branch": targets_doc.get("default_branch"),
        "run_id": targets_doc.get("run_id"),
        "run_url": targets_doc.get("run_url"),
        "run_started_at": targets_doc.get("run_started_at"),
        "generated_utc": generated_utc,
        "trivy_version": trivy_version,
        "trivy_db": {key: (trivy_db or {}).get(key) for key in TRIVY_DB_KEYS},
        "osv": {"api_url": osv_api_url} if has_osv else None,
        "config": targets_doc.get("config") or default_config(),
        "totals": build_totals(targets, records),
        "targets": targets,
    }


def build_vulnerabilities(
    repo: str | None, generated_utc: str, records: Sequence[Record]
) -> dict[str, Any]:
    """Findings only; metrics live in scan_report.json."""
    return {
        "schema_version": SCHEMA_VERSION,
        "repo": repo,
        "generated_utc": generated_utc,
        "merge_key": MERGE_KEY,
        "records": list(records),
    }


def parse_trivy_db_info(raw: str) -> dict[str, str | None]:
    """Parse the ``--trivy-db-info`` JSON; empty or malformed means unknown.

    The metadata only decorates the report, so a problem with it must not break the
    merge (the trivy-db job may have failed; then there is nothing to pass).
    """
    info: dict[str, str | None] = dict.fromkeys(TRIVY_DB_KEYS)
    if not raw.strip():
        return info
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"::warning title=Trivy DB info ignored::not valid JSON: {e}")
        return info
    if not isinstance(parsed, dict):
        print("::warning title=Trivy DB info ignored::not a JSON object")
        return info
    for key in TRIVY_DB_KEYS:
        value = parsed.get(key)
        info[key] = value if isinstance(value, str) and value else None
    return info


# --------------------------------------------------------------------------
# summary.md: rendering primitives
# --------------------------------------------------------------------------


def md_cell(value: Any) -> str:
    """Render a value as one safe Markdown table cell."""
    if value is None or value == "":
        return "-"
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("\r", " ").replace("\n", " ")


def md_table(
    header: Sequence[str],
    rows: Iterable[Sequence[Any]],
    right: Sequence[int] = (),
) -> list[str]:
    align = ["---:" if i in right else "---" for i in range(len(header))]
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(align) + "|"]
    lines.extend("| " + " | ".join(md_cell(c) for c in row) + " |" for row in rows)
    return lines


def md_details(summary: str, body: Sequence[str], is_open: bool = False) -> list[str]:
    """A collapsible block; the blank lines make GitHub render the Markdown inside."""
    tag = "<details open>" if is_open else "<details>"
    return [tag, f"<summary>{summary}</summary>", "", *body, "", "</details>"]


def strip_package_prefix(title: str | None, pkg: str | None) -> str | None:
    """Drop the leading ``<package>: `` repeats of advisory titles, as in
    ``urllib3: urllib3: Denial of Service``.
    """
    if not title or not pkg:
        return title
    prefix = re.compile(rf"{re.escape(pkg)}:\s+", re.IGNORECASE)
    while (match := prefix.match(title)) and len(title) > match.end():
        title = title[match.end() :]
    return title


def short_title(record: Mapping[str, Any]) -> str | None:
    return truncate(strip_package_prefix(record["title"], record["pkg"]))


def truncate(text: str | None, limit: int = TITLE_MAX_LENGTH) -> str | None:
    if text is None or len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


_TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})")


def format_timestamp(value: str | None, with_date: bool = True) -> str | None:
    """``2026-10-12T01:14:57Z`` -> ``2026-10-12 01:14Z`` (``01:14Z`` if no date)."""
    match = _TIMESTAMP_RE.match(value or "")
    if not match:
        return None
    date, time = match.groups()
    return f"{date} {time}Z" if with_date else f"{time}Z"


def format_severity_counts(counts: Mapping[str, int], separator: str = " · ") -> str:
    """``2 HIGH · 4 MEDIUM``; empty string when there is nothing."""
    return separator.join(f"{counts[s]} {s}" for s in SEVERITIES if counts.get(s))


def image_short_name(target: Mapping[str, Any]) -> str:
    return (target.get("image") or "image").rsplit("/", 1)[-1]


def has_several_images(targets: Iterable[Mapping[str, Any]]) -> bool:
    return len({t.get("image") for t in targets if t.get("kind") == KIND_IMAGE}) > 1


def target_name(target: Mapping[str, Any]) -> str:
    """The id of a target, qualified by the scanner unless it is Trivy."""
    if target["scanner"] == SCANNER_TRIVY:
        return target["id"]
    return f"{target['id']} ({target['scanner']})"


def trivy_targets(targets: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The targets whose findings are in the records."""
    return [t for t in targets if t["scanner"] == SCANNER_TRIVY]


def target_label(target: Mapping[str, Any], several_images: bool) -> str:
    """Short name: ``source @ development 3d0c8a3``, ``source @ 1.0 3d0c8a3``,
    ``image :1.0``, ``app :1.0``.
    """
    if target.get("kind") == KIND_FS:
        parts = ["source @", target.get("git_ref") or "?"]
        if target.get("commit_sha"):
            parts.append(target["commit_sha"][:SHORT_SHA_LENGTH])
        return " ".join(parts)
    name = image_short_name(target) if several_images else "image"
    return f"{name} :{target.get('tag')}"


# --------------------------------------------------------------------------
# summary.md: headline
# --------------------------------------------------------------------------


def records_in(records: Iterable[Record], target_ids: Collection[str]) -> list[Record]:
    return [r for r in records if not target_ids.isdisjoint(r["scan_targets"])]


def release_subjects(targets: Iterable[Mapping[str, Any]]) -> dict[str, set[str]]:
    """The scanned targets that stand for a release, by tag in targets order: the
    images of the tag or, in a run without images, its source (``source-<tag>``).
    """
    targets = list(targets)
    kind = release_class(any(t.get("kind") == KIND_IMAGE for t in targets))
    subjects: dict[str, set[str]] = {}
    for target in trivy_targets(targets):
        if target["status"] == STATUS_OK and target_class(target) == kind:
            subjects.setdefault(target["tag"], set()).add(target["id"])
    return subjects


def development_scanned(targets: Iterable[Mapping[str, Any]]) -> bool:
    """Whether the development images or the default branch source were scanned."""
    return any(
        t["status"] == STATUS_OK
        and target_class(t) in (CLASS_DEVELOPMENT, CLASS_SOURCE)
        for t in trivy_targets(targets)
    )


def join_names(names: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    if len(names) < 2:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


def severity_phrase(records: Sequence[Record]) -> str:
    """``46 CRITICAL/HIGH``: the findings that matter, else the rest, by count."""
    counts = count_by_severity(r["severity"] for r in records)
    tier = SEVERITIES[:2] if counts["CRITICAL"] + counts["HIGH"] else SEVERITIES[2:]
    present = [s for s in tier if counts[s]]
    return f"{sum(counts[s] for s in present)} {'/'.join(present)}"


def record_identity(record: Mapping[str, Any]) -> tuple[Any, Any, Any]:
    return (record["cve"], record["pkg"], record["version"])


def report_not_shipped(report: Mapping[str, Any]) -> NotShipped:
    """The not shipped locations of a run, from its scan_report.json."""
    config = report.get("config") or default_config()
    configs = {
        t["id"]: t["trivy_skip_paths"]
        for t in report["targets"]
        if t.get("trivy_skip_paths")
    }
    return NotShipped(config[KEY_NON_SHIPPED_PATHS], configs)


def source_only_what(report: Mapping[str, Any]) -> str:
    """What a ``source_only`` finding is in: build / test dependencies, and, if the
    run knows not shipped paths, those paths.
    """
    base = "build / test dependencies"
    return f"{base} or not shipped paths" if report_not_shipped(report) else base


def verdict_text(
    report: Mapping[str, Any],
    records: Sequence[Record],
    in_place: Collection[tuple[Any, Any, Any]] = frozenset(),
) -> str:
    """What to do, derived from the exposure of the (unique) records: one clause per
    action, in at most two sentences, the most severe first (then the larger, then
    the more urgent exposure). Records fixed in place need no action, so they do
    not make a clause.
    """
    targets = report["targets"]
    by_exposure: dict[str, list[Record]] = {}
    for record in records:
        by_exposure.setdefault(record["exposure"], []).append(record)
    # Only what an upgrade resolves is an action; what has no fix is watched
    actionable = {
        exposure: [
            r
            for r in group
            if r["fix_available"] and record_identity(r) not in in_place
        ]
        for exposure, group in by_exposure.items()
    }
    unfixed = [
        r
        for exposure, group in by_exposure.items()
        if exposure != EXPOSURE_SOURCE_ONLY
        for r in group
        if not r["fix_available"]
    ]

    def lines_of(group: Sequence[Record]) -> str:
        return ", ".join(release_lines(release_tags_of(group, trivy_targets(targets))))

    patch_suffix = (
        " already fixed in development" if development_scanned(targets) else ""
    )
    texts = {
        EXPOSURE_RELEASE_AND_DEVELOPMENT: lambda g: (
            f"Fix {severity_phrase(g)} in development and backport to {lines_of(g)}"
        ),
        EXPOSURE_RELEASE_ONLY: lambda g: (
            f"Release a patch from {lines_of(g)} — {severity_phrase(g)}{patch_suffix}"
        ),
        EXPOSURE_DEVELOPMENT_ONLY: lambda g: (
            f"Fix {severity_phrase(g)} in development before the next release"
        ),
    }
    ranked = sorted(
        (
            (
                min(SEV_ORDER.get(r["severity"], len(SEV_ORDER)) for r in group),
                -len(group),
                EXPOSURE_ORDER[exposure],
                texts[exposure](group),
            )
            for exposure, group in actionable.items()
            if group and exposure in texts
        )
    )
    clauses = [text for *_, text in ranked]
    top_unfixed = [r for r in unfixed if r["severity"] in SEVERITIES[:2]]
    in_base_image = sum(is_base_image(r) for r in top_unfixed)
    where = f" ({in_base_image} in the base image)" if in_base_image else ""
    watch = f"{len(top_unfixed)} CRITICAL/HIGH without a fix{where} — see watch"
    if not clauses and unfixed:
        # nothing to upgrade is not "no vulnerabilities"
        text = f"Nothing to upgrade — {severity_phrase(unfixed)} without a fix"
        text += f"{where} — see watch" if top_unfixed else ", see watch"
        if only_sources := len(by_exposure.get(EXPOSURE_SOURCE_ONLY, ())):
            text += f" · {only_sources} only in {source_only_what(report)}"
        return text
    if not clauses:
        names = [*release_subjects(targets)]
        if development_scanned(targets):
            names.append(DEVELOPMENT_TAG)
        text = (
            f"No known vulnerabilities in {join_names(names) or 'the scanned targets'}"
        )
        if only_sources := len(by_exposure.get(EXPOSURE_SOURCE_ONLY, ())):
            text += f" — {only_sources} only in {source_only_what(report)}"
        return text
    # The first action is a sentence, the others follow in a second: "…; fix …"
    rest = "; ".join(c[0].lower() + c[1:] for c in clauses[2:])
    sentences = clauses[:2]
    if rest:
        sentences[-1] += f"; {rest}"
    text = ". ".join(sentences)
    return f"{text} · {watch}" if top_unfixed else text


def scope_row(
    label: str,
    records: Sequence[Record],
    severities: Sequence[str],
    base_column: bool = True,
) -> list[Any]:
    """Unique records by severity, those with a fix, and those of the base image."""
    counts = count_by_severity(r["severity"] for r in records)
    return [
        label,
        *(counts[s] for s in severities),
        sum(r["fix_available"] for r in records),
        sum(is_base_image(r) for r in records) if base_column else "—",
    ]


def scope_table(report: Mapping[str, Any], records: Sequence[Record]) -> list[str]:
    """The findings by scope: each release, development and what is only in sources.

    A record is counted once per row: in a release if it is in the release's images
    (its source in a run without images), in development if it is in development
    (see ``classify_exposure``), and in the last row only if it is in no shipped
    artifact. Rows without records are left out.
    """
    targets = report["targets"]
    scopes: list[tuple[str, list[Record], bool]] = []
    in_release = (EXPOSURE_RELEASE_AND_DEVELOPMENT, EXPOSURE_RELEASE_ONLY)
    for tag, ids in release_subjects(targets).items():
        found = [r for r in records_in(records, ids) if r["exposure"] in in_release]
        scopes.append((f"{tag} (released)", found, True))
    if development_scanned(targets):
        in_development = (EXPOSURE_RELEASE_AND_DEVELOPMENT, EXPOSURE_DEVELOPMENT_ONLY)
        found = [r for r in records if r["exposure"] in in_development]
        scopes.append((DEVELOPMENT_TAG, found, True))
    found = [r for r in records if r["exposure"] == EXPOSURE_SOURCE_ONLY]
    label = (
        "build / test / not shipped" if report_not_shipped(report) else "build / test"
    )
    scopes.append((f"Source only ({label})", found, False))
    scopes = [scope for scope in scopes if scope[1]]
    if not scopes:
        return []
    # UNKNOWN has a column only if some record has no usable severity
    has_unknown = any(
        r["severity"] == UNKNOWN_SEVERITY for _, group, _ in scopes for r in group
    )
    severities = SEVERITIES if has_unknown else SEVERITIES[:-1]
    header = ["Scope", *severities, "Fixable", "Base image"]
    rows = [scope_row(label, group, severities, base) for label, group, base in scopes]
    return md_table(header, rows, right=range(1, len(header)))


def totals_line(
    report: Mapping[str, Any], osv_only: int = 0, packages: int | None = None
) -> str:
    """Coverage of the run: ``8/8 targets scanned · 10 found only by OSV``."""
    counts = report["totals"]["targets"]
    applicable = counts["total"] - counts["not_applicable"]
    line = f"{counts['ok']}/{applicable} targets scanned"
    if packages is not None:
        line += f" · {packages} packages"
    if osv_only:
        line += f" · {osv_only} found only by OSV"
    if counts["not_applicable"]:
        line += f" · {counts['not_applicable']} not applicable"
    return line


def headline_blocks(
    report: Mapping[str, Any],
    records: Sequence[Record],
    in_place: Collection[tuple[Any, Any, Any]] = frozenset(),
) -> list[list[str]]:
    """The paragraphs of the headline: failures, the verdict, the scope table and
    the coverage of the run.
    """
    targets = report["targets"]
    blocks: list[list[str]] = []
    failed = [target_name(t) for t in targets if t["status"] == STATUS_FAILED]
    if failed:
        blocks.append(
            [
                f"**Incomplete: {len(failed)} target(s) failed** — {', '.join(failed)} "
                "(their findings are missing)"
            ]
        )
    ok = [t for t in trivy_targets(targets) if t["status"] == STATUS_OK]
    if not ok:
        scanned = any(t["status"] == STATUS_OK for t in targets)
        text = "No Trivy target was scanned" if scanned else "No target was scanned"
        return [*blocks, [text]]

    osv_only = sum(is_osv_only(r) for r in records)
    blocks.append([f"**{verdict_text(report, records, in_place)}**"])
    if records:
        if table := scope_table(report, records):
            blocks.append(table)
        blocks.append([totals_line(report, osv_only)])
    else:
        packages = sum(t["packages_scanned"] or 0 for t in ok)
        blocks.append([totals_line(report, osv_only, packages)])
    return blocks


def render_headline(blocks: Sequence[Sequence[str]]) -> list[str]:
    """A blockquote with one paragraph per block (a plain newline would merge them)."""
    quoted: list[str] = []
    for block in blocks:
        if quoted:
            quoted.append(">")
        quoted.extend(f"> {line}" for line in block)
    return quoted


# --------------------------------------------------------------------------
# summary.md: "What to fix"
# --------------------------------------------------------------------------


def max_cvss_score(records: Iterable[Record]) -> float | None:
    scores = [r["cvss"]["score"] for r in records if r["cvss"]]
    scores = [score for score in scores if score is not None]
    return max(scores) if scores else None


def is_base_image(record: Mapping[str, Any]) -> bool:
    """Whether the package is an OS package, so the fix is a new base image."""
    return record["pkg_type"] == "os"


def urgency_key(group: Sequence[Record], name: str, version: str) -> tuple[Any, ...]:
    """Order of a group of records of one exposure: urgency, worst severity, highest
    CVSS score (none last), then its name.
    """
    score = max_cvss_score(group)
    return (
        EXPOSURE_ORDER.get(group[0]["exposure"], len(EXPOSURES)),
        min(SEV_ORDER.get(r["severity"], len(SEV_ORDER)) for r in group),
        score is None,
        -(score or 0),
        name,
        version,
    )


def group_fixes(records: Iterable[Record]) -> list[list[Record]]:
    """One group per (exposure, package, installed version), most urgent first."""
    groups: dict[tuple[Any, Any, Any], list[Record]] = {}
    for record in records:
        key = (record["exposure"], record["pkg"], record["version"])
        groups.setdefault(key, []).append(record)
    return sorted(
        groups.values(),
        key=lambda group: urgency_key(
            group, group[0]["pkg"] or "", group[0]["version"] or ""
        ),
    )


def base_image_label(group: Iterable[Record], base_os: Mapping[str, str]) -> str:
    """The base image line of OS records: ``ubuntu 24.04`` (the OS of the images they
    were found in), ``alpine`` (the package manager) if no image reports its OS.
    """
    group = list(group)
    labels = {
        base_os[tid] for r in group for tid in r["scan_targets"] if tid in base_os
    }
    labels = labels or {e for r in group for e in r["ecosystem"]}
    return " / ".join(sorted(labels)) or "unknown"


def base_image_groups(
    records: Iterable[Record], base_os: Mapping[str, str]
) -> list[tuple[str, list[Record]]]:
    """One group per (exposure, base image line), most urgent first."""
    groups: dict[tuple[str, str], list[Record]] = {}
    for record in records:
        label = base_image_label([record], base_os)
        groups.setdefault((record["exposure"], label), []).append(record)
    ordered = sorted(
        ((label, group) for (_, label), group in groups.items()),
        key=lambda item: urgency_key(item[1], item[0], ""),
    )
    return ordered


def package_cell(group: Sequence[Record]) -> str:
    first = group[0]
    text = str(first["pkg"])
    families = package_families(group)
    if families:
        text += f" · {families}"
    if group_relationship(group) == "indirect":
        text += ", indirect"
    if first["pkg_type"] == "os":
        text += " (base image)"
    return text


def package_families(group: Iterable[Record]) -> str:
    return "/".join(
        sorted({ECOSYSTEM_FAMILIES.get(e, e) for r in group for e in r["ecosystem"]})
    )


def group_relationship(group: Iterable[Record]) -> str | None:
    """``direct`` if any record says so, ``indirect`` if all that know are indirect."""
    relationships = {rel for r in group for rel in r["relationship"]}
    if "direct" in relationships:
        return "direct"
    return "indirect" if "indirect" in relationships else None


def group_dev(group: Iterable[Record]) -> bool | None:
    flags = [r["dev"] for r in group if r["dev"] is not None]
    return all(flags) if flags else None


def group_paths(group: Iterable[Record]) -> tuple[list[list[str]], int, bool]:
    """Chains of a package version (the same on all its records) as stored."""
    paths: list[list[str]] = []
    total, truncated = 0, False
    for r in group:
        for path in r["dependency_paths"]:
            if path not in paths:
                paths.append(path)
        total = max(total, r["dependency_paths_total"])
        truncated = truncated or r["dependency_paths_truncated"]
    paths.sort(key=lambda path: (len(path), path))
    return paths, total, truncated


def shortest_path_text(group: Iterable[Record]) -> str:
    """``jest › micromatch › braces (+3 more paths)``; empty without a chain."""
    paths, total, truncated = group_paths(group)
    if not paths:
        return ""
    text = PATH_SEPARATOR.join(paths[0])
    more = total - 1
    if more > 0:
        plus = f"{more}+" if truncated else str(more)
        text += f" (+{plus} more {'path' if more == 1 and not truncated else 'paths'})"
    return text


def fixed_versions_text(
    versions: Iterable[str], installed: str | None = None, limit: int = 3
) -> str:
    """``1.2, 1.3, 2.0 +4 more``: the fixed versions above the installed one (all of
    them if it is unknown or they cannot be compared), lowest first.
    """

    def order(a: str, b: str) -> int:
        return compare_versions(a, b) or 0

    # versions that cannot be compared keep their alphabetical order
    candidates = sorted(sorted(set(versions)), key=cmp_to_key(order))
    if installed:
        above = [v for v in candidates if compare_versions(v, installed) != -1]
        candidates = above or candidates
    text = ", ".join(candidates[:limit])
    return (
        f"{text} +{len(candidates) - limit} more" if len(candidates) > limit else text
    )


def upgrade_cell(fixable: Sequence[Record]) -> str:
    version = fixable[0]["version"]
    upgrade = fixable[0]["upgrade_to"]
    if upgrade:
        return f"{version} → {upgrade}"
    fixed = fixed_versions_text(
        (f for r in fixable for f in r["fixed_versions"]), version
    )
    return f"{version} → no upgrade computed (fixed in {fixed})"


def resolves_cell(group: Sequence[Record]) -> str:
    """Severities an upgrade resolves, and how many CVEs of the package it does not."""
    fixable = [r for r in group if r["fix_available"]]
    counts = count_by_severity(r["severity"] for r in fixable)
    text = format_severity_counts(counts, ", ")
    unfixed = len(group) - len(fixable)
    return f"{text} · {unfixed} without fix (see watch)" if unfixed else text


def release_tags_of(
    group: Iterable[Record], targets: Sequence[Mapping[str, Any]]
) -> list[str]:
    """Release tags (in targets order) of the images a group was found in, or of
    the release sources if the run has no images.
    """
    found = {tid for r in group for tid in r["scan_targets"]}
    kind = release_class(any(t.get("kind") == KIND_IMAGE for t in targets))
    tags: list[str] = []
    for target in targets:
        if target["id"] in found and target_class(target) == kind:
            _append_unique(tags, target["tag"])
    return tags


def release_line(tag: str) -> str:
    """Release branch of a tag: ``1.1.14`` -> ``release-1.1``."""
    match = RELEASE_LINE_RE.match(tag)
    return f"release-{match.group(1)}.{match.group(2)}" if match else f"release-{tag}"


def release_lines(tags: Iterable[str]) -> list[str]:
    lines: list[str] = []
    for tag in tags:
        _append_unique(lines, release_line(tag))
    return lines


def exposure_label(
    exposure: str, dev: bool | None, tags: Sequence[str], has_images: bool
) -> str:
    """Where the finding lives (a state, not an action)."""
    released = ", ".join(tags)
    if exposure == EXPOSURE_RELEASE_AND_DEVELOPMENT:
        return f"Released {released} + development"
    if exposure == EXPOSURE_RELEASE_ONLY:
        return f"Released {released} only"
    if exposure == EXPOSURE_SOURCE_ONLY:
        if dev:
            return "Source only · dev dependency"
        return (
            "Source only · not in images" if has_images else "Source only · not shipped"
        )
    return "development only" if has_images else "development (source)"


def found_in_default_source(
    group: Iterable[Record], targets: Sequence[Mapping[str, Any]]
) -> bool:
    """Whether a group was found in the source of the default branch."""
    found = {tid for r in group for tid in r["scan_targets"]}
    return any(t["id"] in found and target_class(t) == CLASS_SOURCE for t in targets)


def action_text(
    exposure: str,
    dev: bool | None,
    tags: Sequence[str],
    via: str = "",
    open_in_development: bool = True,
    base_image: bool = False,
    has_images: bool = True,
) -> str:
    """What to do, verb first; ``via`` is the dependency chain to upgrade through.

    ``open_in_development`` is False for a finding that sits only in the source of
    a release tag: the default branch is clear of it, so there is nothing to upgrade.
    A ``base_image`` finding is fixed by rebuilding on an updated base image.
    """
    lines = ", ".join(release_lines(tags))
    via_text = f" via {via}" if via else ""
    if base_image:
        if exposure == EXPOSURE_RELEASE_AND_DEVELOPMENT:
            return (
                f"Rebuild on an updated base image in development, backport to {lines}"
            )
        if exposure == EXPOSURE_RELEASE_ONLY:
            return (
                f"Release a patch from {lines} rebuilt on an updated base image "
                "(already fixed in development)"
            )
        return "Rebuild on an updated base image in development before the next release"
    if exposure == EXPOSURE_RELEASE_AND_DEVELOPMENT:
        return f"Upgrade in development{via_text}, backport to {lines}"
    if exposure == EXPOSURE_RELEASE_ONLY:
        return f"Release a patch from {lines} (already fixed in development){via_text}"
    if exposure == EXPOSURE_SOURCE_ONLY:
        note = (
            "dev dependency, not shipped"
            if dev
            else ("not in published images" if has_images else "not shipped")
        )
        if not open_in_development:
            return f"Already fixed in development — {note}"
        return f"Upgrade in development{via_text} — {note}"
    return f"Upgrade in development{via_text} before the next release"


def where_cell(
    group: Sequence[Record],
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
    not_shipped: NotShipped | None = None,
) -> str:
    """Where a group was found: tags per image, then the lockfiles of the source
    of the default branch and of each release tag; a lockfile in a not shipped
    location is marked ``(not shipped)``.

    ``statgpt-chat :development, :0.17.7 · statgpt-admin :development · source
    poetry.lock · source @ 0.17.7 poetry.lock``; a run with one image calls it
    ``image``.
    """
    several = has_several_images(targets)
    tags: dict[str, list[str]] = {}
    sources: dict[str, list[str]] = {}  # "source" / "source @ <tag>" -> lockfiles
    for target in targets:
        for record in group:
            seen = sightings.get((record["cve"], record["pkg"], record["version"]), {})
            if target["id"] not in seen:
                continue
            if target.get("kind") == KIND_FS:
                name = f"source @ {target['tag']}" if target.get("tag") else "source"
                sources.setdefault(name, []).extend(
                    f"{loc} {NOT_SHIPPED_MARK}"
                    if not_shipped and not_shipped.matches(target["id"], loc)
                    else loc
                    for loc in seen[target["id"]]
                )
            else:
                name = image_short_name(target) if several else "image"
                _append_unique(tags.setdefault(name, []), f":{target.get('tag')}")
    parts = [f"{name} {', '.join(names)}" for name, names in tags.items()]
    for name, locations in sources.items():
        shown = sorted(set(locations))
        text = f"{name} " + ", ".join(shown[:MAX_LISTED_LOCATIONS])
        if len(shown) > MAX_LISTED_LOCATIONS:
            text += f" +{len(shown) - MAX_LISTED_LOCATIONS} more"
        parts.append(text)
    return " · ".join(parts)


def group_exposure_label(
    group: Sequence[Record], targets: Sequence[Mapping[str, Any]]
) -> str:
    has_images = any(t.get("kind") == KIND_IMAGE for t in targets)
    return exposure_label(
        group[0]["exposure"],
        group_dev(group),
        release_tags_of(group, targets),
        has_images,
    )


WHAT_TO_FIX_HEADER = [
    "#",
    "Package",
    "Upgrade",
    "Resolves",
    "Exposure",
    "Action",
    "Where",
]
BASE_IMAGE_UPGRADE = "rebuild on an updated base image"


def verify_action(fixable: Sequence[Record]) -> str:
    """The action for a package whose file already holds the fix (see
    ``fixed_in_place``): look at it, there is nothing to upgrade.
    """
    first = fixable[0]
    where = (first["pkg_paths"] or first["locations"] or ["the file"])[0]
    fixed = minimal_fix(first["version"], first["fixed_versions"]) or "a fixed version"
    return (
        f"Verify — {where} is already at {fixed}; "
        "the scanner reports it under two versions"
    )


def package_fix_row(
    group: Sequence[Record],
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
    in_place: Collection[tuple[Any, Any, Any]] = frozenset(),
    not_shipped: NotShipped | None = None,
) -> list[Any]:
    """A package version with a fixable CVE: what resolves it, and what to do."""
    fixable = [r for r in group if r["fix_available"]]
    base_image = is_base_image(group[0])
    if all(record_identity(r) in in_place for r in fixable):
        action = verify_action(fixable)
    else:
        action = action_text(
            group[0]["exposure"],
            group_dev(group),
            release_tags_of(group, targets),
            shortest_path_text(group)
            if group_relationship(group) == "indirect"
            else "",
            found_in_default_source(group, targets),
            base_image,
            any(t.get("kind") == KIND_IMAGE for t in targets),
        )
    return [
        package_cell(group),
        upgrade_cell(fixable),
        resolves_cell(group),
        group_exposure_label(group, targets),
        action,
        where_cell(fixable, sightings, targets, not_shipped),
    ]


def base_image_row(
    label: str,
    group: Sequence[Record],
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
    not_shipped: NotShipped | None = None,
) -> list[Any]:
    """The OS packages of one exposure and base image line that a rebuild fixes."""
    packages = len({(r["pkg"], r["version"]) for r in group})
    noun = "package" if packages == 1 else "packages"
    counts = count_by_severity(r["severity"] for r in group)
    return [
        f"Base image · {label} ({packages} {noun})",
        BASE_IMAGE_UPGRADE,
        format_severity_counts(counts, ", "),
        group_exposure_label(group, targets),
        action_text(
            group[0]["exposure"],
            None,
            release_tags_of(group, targets),
            base_image=True,
        ),
        where_cell(group, sightings, targets, not_shipped),
    ]


def render_what_to_fix(
    records: Sequence[Record],
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
    base_os: Mapping[str, str] | None = None,
    in_place: Collection[tuple[Any, Any, Any]] = frozenset(),
    not_shipped: NotShipped | None = None,
) -> list[str]:
    """Packages with at least one CVE an upgrade resolves; empty if there are none.

    The OS packages of a base image are one row per base image line (they are all
    fixed by the same rebuild), with the packages themselves in a collapsed block
    below the table.
    """
    base_os = base_os or {}
    dependencies = [r for r in records if not is_base_image(r)]
    os_records = [r for r in records if is_base_image(r) and r["fix_available"]]
    rows: list[tuple[tuple[Any, ...], list[Any]]] = []
    for group in group_fixes(dependencies):
        if any(r["fix_available"] for r in group):
            key = urgency_key(group, group[0]["pkg"] or "", group[0]["version"] or "")
            rows.append(
                (
                    key,
                    package_fix_row(group, sightings, targets, in_place, not_shipped),
                )
            )
    for label, group in base_image_groups(os_records, base_os):
        key = urgency_key(group, label, "")
        rows.append(
            (key, base_image_row(label, group, sightings, targets, not_shipped))
        )
    if not rows:
        return []
    rows.sort(key=lambda row: row[0])
    table = md_table(
        WHAT_TO_FIX_HEADER,
        ([i, *row] for i, (_, row) in enumerate(rows, 1)),
        right=(0,),
    )
    lines = ["## What to fix", "", *table]
    packages = [
        package_fix_row(group, sightings, targets, in_place, not_shipped)
        for group in group_fixes(r for r in records if is_base_image(r))
        if any(r["fix_available"] for r in group)
    ]
    if packages:
        body = md_table(
            WHAT_TO_FIX_HEADER,
            ([i, *row] for i, row in enumerate(packages, 1)),
            right=(0,),
        )
        summary = f"Base image packages ({len(packages)})"
        lines += ["", *md_details(summary, body)]
    return lines


def render_dependency_paths(records: Sequence[Record]) -> list[str]:
    """One collapsible block with the stored chains of every package that has them."""
    items: list[str] = []
    seen: set[tuple[Any, Any]] = set()
    for group in group_fixes(records):
        key = (group[0]["pkg"], group[0]["version"])
        paths, total, truncated = group_paths(group)
        if key in seen or not paths or group_relationship(group) != "indirect":
            continue
        seen.add(key)
        count = f"{total}+" if truncated else str(total)
        shown = f", showing {len(paths)}" if len(paths) < total else ""
        noun = "path" if total == 1 and not truncated else "paths"
        label = f"{group[0]['pkg']} {group[0]['version']}"
        items.append(f"- **{label}** ({count} {noun}{shown})")
        items += [f"  - {PATH_SEPARATOR.join(path)}" for path in paths]
    if not items:
        return []
    return ["", *md_details(f"Dependency paths ({len(seen)})", items)]


def scope_cell(group: Sequence[Record]) -> str:
    dev = group_dev(group)
    scope = "-" if dev is None else ("dev" if dev else "runtime")
    relationship = group_relationship(group)
    return f"{scope}, {relationship}" if relationship else scope


def render_watch(
    records: Sequence[Record], targets: Sequence[Mapping[str, Any]]
) -> list[str]:
    """Findings without a fix: nothing to upgrade to, so watch, mitigate or replace.

    The dependencies are open if anything HIGH or CRITICAL is in them, else
    collapsed; the OS packages of the base image are always collapsed.
    """
    unfixed = [r for r in records if not r["fix_available"]]
    dependencies = [r for r in unfixed if not is_base_image(r)]
    os_records = [r for r in unfixed if is_base_image(r)]
    lines: list[str] = []
    if dependencies:
        lines += render_watch_dependencies(dependencies, targets)
    if os_records:
        lines += ["", *render_watch_base_image(os_records, targets)]
    return lines


def render_watch_dependencies(
    unfixed: Sequence[Record], targets: Sequence[Mapping[str, Any]]
) -> list[str]:
    rows = []
    for group in group_fixes(unfixed):
        counts = count_by_severity(r["severity"] for r in group)
        family = package_families(group)
        suggested = (
            "Accept as dev-only risk or replace the parent; re-check on next scan"
            if group_dev(group)
            else "Mitigate or replace the package; re-check on next scan"
        )
        rows.append(
            [
                f"{group[0]['pkg']} {group[0]['version']}"
                + (f" · {family}" if family else ""),
                format_severity_counts(counts, ", "),
                scope_cell(group),
                shortest_path_text(group),
                group_exposure_label(group, targets),
                suggested,
            ]
        )
    header = [
        "Package",
        "Severity",
        "Scope",
        "Introduced via",
        "Exposure",
        "Suggested",
    ]
    table = md_table(["#", *header], ([i, *row] for i, row in enumerate(rows, 1)))
    title = "No fix available — watch"
    if any(r["severity"] in ("CRITICAL", "HIGH") for r in unfixed):
        return ["", f"## {title}", "", *table]
    return ["", *md_details(f"{title} ({len(unfixed)})", table)]


def render_watch_base_image(
    unfixed: Sequence[Record], targets: Sequence[Mapping[str, Any]]
) -> list[str]:
    """OS packages without a fix: a new base image may bring one, and so may a wait."""
    rows = []
    for group in group_fixes(unfixed):
        counts = count_by_severity(r["severity"] for r in group)
        rows.append(
            [
                f"{group[0]['pkg']} {group[0]['version']}",
                format_severity_counts(counts, ", "),
                group_exposure_label(group, targets),
                "Wait for a distribution fix or change the base image; "
                "re-check on next scan",
            ]
        )
    header = ["#", "Package", "Severity", "Exposure", "Suggested"]
    table = md_table(header, ([i, *row] for i, row in enumerate(rows, 1)))
    title = f"No fix available — base image (OS packages) ({len(unfixed)})"
    return md_details(title, table)


# --------------------------------------------------------------------------
# summary.md: details
# --------------------------------------------------------------------------


def is_osv_only(record: Mapping[str, Any]) -> bool:
    """Whether only OSV, not Trivy, reports the vulnerability."""
    return record["scanners"] == [SCANNER_OSV]


def cve_cell(record: Record) -> str:
    cve = record["cve"]
    text = f"[{cve}]({record['primary_url']})" if record["primary_url"] else cve
    return f"{text} · OSV only" if is_osv_only(record) else text


def cvss_cell(record: Record) -> str | None:
    cvss = record["cvss"]
    if not cvss:
        return None
    # A CVSS 4.0 vector from OSV has no computed score
    score = cvss["score"] if cvss["score"] is not None else f"v{cvss['version']}"
    return f"{score} ({cvss['source']})"


def installed_to_fixed_cell(record: Record) -> str:
    fixed = (
        record["upgrade_to"]
        or fixed_versions_text(record["fixed_versions"], record["version"])
        or "no fix"
    )
    return f"{record['version']} → {fixed}"


def render_severity_section(
    severity: str,
    records: Sequence[Record],
    targets: Sequence[Mapping[str, Any]],
) -> list[str]:
    rows = (
        [
            cve_cell(r),
            r["pkg"],
            installed_to_fixed_cell(r),
            cvss_cell(r),
            (r["published"] or "")[:10],
            group_exposure_label([r], targets),
            short_title(r),
        ]
        for r in records
    )
    header = [
        "CVE",
        "Package",
        "Installed → Fixed",
        "CVSS",
        "Published",
        "Exposure",
        "Title",
    ]
    body = md_table(header, rows)
    summary = f"{severity} ({len(records)})"
    return md_details(summary, body, is_open=severity in ("CRITICAL", "HIGH"))


def render_severity_sections(
    records: Sequence[Record], targets: Sequence[Mapping[str, Any]]
) -> list[str]:
    """The findings by severity: the dependencies, then the OS packages of the base
    image in one collapsed block (a base image is hundreds of lines of noise).
    """

    def sections(group: Sequence[Record]) -> list[list[str]]:
        return [
            render_severity_section(severity, selected, targets)
            for severity in SEVERITIES
            if (selected := [r for r in group if r["severity"] == severity])
        ]

    lines: list[str] = []
    for section in sections([r for r in records if not is_base_image(r)]):
        lines += ["", *section]
    os_records = [r for r in records if is_base_image(r)]
    if os_records:
        body: list[str] = []
        for section in sections(os_records):
            body += ["", *section] if body else section
        summary = f"Base image (OS packages) ({len(os_records)})"
        lines += ["", *md_details(summary, body)]
    return lines


def scan_cell(
    target: Mapping[str, Any] | None, describe: Callable[[Mapping[str, Any]], str]
) -> str:
    """``ok · 556 pkgs · <findings>`` of a scanned target, else its status and
    reason, ``—`` without a target.
    """
    if target is None:
        return "—"
    if target["status"] != STATUS_OK:
        reason = f" · {target['reason']}" if target["reason"] else ""
        return f"{target['status']}{reason}"
    return f"ok · {target['packages_scanned']} pkgs · {describe(target['findings'])}"


def trivy_findings_text(findings: Mapping[str, Any]) -> str:
    """``5/31/190/55``: CRITICAL/HIGH/MEDIUM/LOW, plus the unknown ones if any."""
    by_severity = findings["by_severity"]
    text = "/".join(str(by_severity[s]) for s in SEVERITIES[:4])
    unknown = by_severity[UNKNOWN_SEVERITY]
    return f"{text} · {unknown} UNKNOWN" if unknown else text


def skip_paths_note(target: Mapping[str, Any] | None) -> str | None:
    """What was done with the skip-dirs / skip-files of the trivy.yaml of a source
    target, None if it lists none.
    """
    skip = (target or {}).get("trivy_skip_paths")
    paths = [*skip["skip_dirs"], *skip["skip_files"]] if skip else []
    if not paths:
        return None
    shown = ", ".join(paths[:MAX_LISTED_SKIPS])
    if len(paths) > MAX_LISTED_SKIPS:
        shown += f" +{len(paths) - MAX_LISTED_SKIPS} more"
    return {
        SKIP_APPLY: f"trivy.yaml skip paths skipped by Trivy: {shown}",
        SKIP_AS_NON_SHIPPED: f"trivy.yaml skip paths scanned, not shipped: {shown}",
        SKIP_IGNORE: f"trivy.yaml skip paths scanned: {shown}",
    }[skip["mode"]]


def render_coverage(targets: Sequence[Mapping[str, Any]]) -> list[str]:
    """One row per scanned subject (the id Trivy and OSV share), a cell per scanner."""
    several = has_several_images(targets)
    subjects: dict[str, dict[str, Mapping[str, Any]]] = {}
    for target in targets:
        subjects.setdefault(target["id"], {})[target["scanner"]] = target
    # Only a run with OSV targets needs the column: Trivy-only reports stay as is
    with_osv = any(t["scanner"] == SCANNER_OSV for t in targets)
    rows = []
    for scanners in subjects.values():
        trivy = scanners.get(SCANNER_TRIVY)
        osv = scanners.get(SCANNER_OSV)
        scanned = [t for t in (trivy, osv) if t and t["status"] == STATUS_OK]
        empty = any(t["packages_scanned"] == 0 for t in scanned)
        rows.append(
            [
                target_label(trivy or osv, several),  # type: ignore[arg-type]
                scan_cell(trivy, trivy_findings_text),
                *([scan_cell(osv, lambda f: str(f["total"]))] if with_osv else []),
                "; ".join(
                    note
                    for note in (
                        "no packages seen" if empty else None,
                        skip_paths_note(trivy),
                    )
                    if note
                )
                or None,
            ]
        )
    header = ["Target", "Trivy", *(["OSV"] if with_osv else []), "Note"]
    legend = "Trivy: status · packages · CRITICAL/HIGH/MEDIUM/LOW findings"
    if with_osv:
        legend += (
            "; OSV: status · language packages only (not the OS packages of an image)"
            " · findings"
        )
    body = [f"<sub>{legend}</sub>", "", *md_table(header, rows)]
    return ["", *md_details("Scan coverage", body)]


def config_text(config: Mapping[str, Any] | None) -> str | None:
    """Where the SCA configuration of the run came from and what it sets; None if
    the run has none.
    """
    if not config or not config.get("source"):
        return None

    def short(ref: str) -> str:
        path, _, sha = ref.partition("@")
        return f"{path}@{sha[:SHORT_SHA_LENGTH]}" if sha else ref

    if config["source"] == "input":
        text = "Configuration: workflow input"
        if config.get("overrides"):
            text += f" (replaces {short(config['overrides'])})"
    else:
        text = f"Configuration: {short(config['source'])}"
    if config[KEY_NON_SHIPPED_PATHS]:
        text += f" · not shipped: {', '.join(config[KEY_NON_SHIPPED_PATHS])}"
    if config[KEY_TRIVY_SKIP_PATHS] != SKIP_AS_NON_SHIPPED:
        text += f" · trivy_skip_paths: {config[KEY_TRIVY_SKIP_PATHS]}"
    return text


def render_footer(report: Mapping[str, Any]) -> list[str]:
    parts = []
    if report["commit_sha"]:
        parts.append(f"commit {report['commit_sha'][:SHORT_SHA_LENGTH]}")
    if report["run_url"]:
        run_label = f"run {report['run_id']}" if report["run_id"] else "run"
        parts.append(f"[{run_label}]({report['run_url']})")
    if report["trivy_version"]:
        parts.append(f"Trivy {report['trivy_version']}")
    db = report["trivy_db"]
    vuln_db = format_timestamp(db["vulnerability_db_updated_at"])
    if vuln_db:
        text = f"DB vuln {vuln_db}"
        java_raw = db["java_db_updated_at"]
        same_day = (java_raw or "")[:10] == (db["vulnerability_db_updated_at"] or "")[
            :10
        ]
        java_db = format_timestamp(java_raw, with_date=not same_day)
        parts.append(f"{text} (java {java_db})" if java_db else text)
    generated = format_timestamp(report["generated_utc"])
    if generated:
        parts.append(f"generated {generated}")
    lines = ["", f"<sub>{' · '.join(parts)}</sub>"]
    if text := config_text(report.get("config")):
        lines += ["", f"<sub>{text}</sub>"]
    if report.get("osv"):
        queried = [t["queried_at"] for t in report["targets"] if t["queried_at"]]
        queried_at = format_timestamp(max(queried)) if queried else None
        text = f"{OSV_FOOTER} · queried {queried_at}" if queried_at else OSV_FOOTER
        lines += ["", f"<sub>{text}</sub>"]
    return lines


def build_summary_md(
    report: Mapping[str, Any],
    vulns: Mapping[str, Any],
    sightings: Sightings,
    base_os: Mapping[str, str] | None = None,
    in_place: Collection[tuple[Any, Any, Any]] = frozenset(),
) -> str:
    """``base_os`` is the OS of each scanned image (target id -> ``ubuntu 24.04``),
    ``in_place`` the findings that are fixed in place (see ``fixed_in_place``).
    """
    records = vulns["records"]
    targets = report["targets"]
    # The findings sections are about the records, so about the Trivy targets only
    record_targets = trivy_targets(targets)
    not_shipped = report_not_shipped(report)
    lines = [f"# SCA · {md_cell(report['repo'])}", ""]
    lines += render_headline(headline_blocks(report, records, in_place))
    if records:
        fixes = render_what_to_fix(
            records, sightings, record_targets, base_os, in_place, not_shipped
        )
        lines += ["", *fixes] if fixes else []
        lines += render_watch(records, record_targets)
        lines += render_severity_sections(records, record_targets)
        lines += render_dependency_paths(records)
    lines += render_coverage(targets)
    lines += render_footer(report)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Orchestration and CLI
# --------------------------------------------------------------------------


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def dump_json(path: Path, data: Any) -> None:
    write_text(path, json.dumps(data, indent=1, ensure_ascii=False) + "\n")


def copy_native(scanner_parts_dir: Path, target_id: str, native_dir: Path) -> None:
    """Keep the unmodified per-target results of one scanner for audit."""
    for suffix in (".json", ".txt"):
        src = scanner_parts_dir / f"{target_id}{suffix}"
        if src.is_file():
            shutil.copyfile(src, native_dir / src.name)


def resolve_osv_targets(
    results: list[tuple[Target, dict[str, Any], dict[str, Any] | None]],
    trivy_natives: Mapping[str, Mapping[str, Any]],
) -> list[OsvScan]:
    """Join the ``ok`` OSV targets with their Trivy twins (same id).

    An OSV result that does not fit its twin cannot be merged, so its target is
    set to ``failed`` in ``results``: a broken result never looks like a clean one.
    """
    scans = []
    for position, (target, state, native) in enumerate(results):
        if native is None or target["scanner"] != SCANNER_OSV:
            continue
        try:
            scans.append(
                resolve_osv_scan(target["id"], native, trivy_natives.get(target["id"]))
            )
        except OsvResolutionError as e:
            state.update(
                status=STATUS_FAILED, reason=f"osv result does not fit trivy's: {e}"
            )
            results[position] = (target, state, None)
    return scans


def run_merge(
    targets_file: Path,
    parts_dir: Path,
    output_dir: Path,
    generated_utc: str,
    trivy_db: Mapping[str, str | None] | None = None,
) -> int:
    """Write all outputs; return the number of failed targets."""
    targets_doc = load_targets_file(targets_file)
    report_dir = output_dir / "_report"
    report_dir.mkdir(parents=True, exist_ok=True)
    # The Trivy native directory always exists; other scanners' only if they are used
    (output_dir / "_native" / SCANNER_TRIVY).mkdir(parents=True, exist_ok=True)

    results = []
    trivy_configs: dict[str, dict[str, Any]] = {}
    for target in targets_doc["targets"]:
        scanner = target["scanner"]
        # Parts are namespaced by scanner: <parts-dir>/<scanner>/<id>.*
        native_dir = output_dir / "_native" / scanner
        native_dir.mkdir(parents=True, exist_ok=True)
        scanner_parts_dir = parts_dir / scanner
        state, native = load_target_result(target, scanner_parts_dir)
        if (
            native is not None
            and scanner == SCANNER_TRIVY
            and target.get("kind") == KIND_FS
        ):
            record_path = scanner_parts_dir / f"{target['id']}{TRIVY_CONFIG_SUFFIX}"
            if record_path.is_file():
                try:
                    trivy_configs[target["id"]] = load_trivy_config_record(record_path)
                except (OSError, ValueError) as e:
                    state.update(
                        status=STATUS_FAILED,
                        reason=f"unreadable trivy config record: {e}",
                    )
                    native = None
        if (
            native is not None
            and scanner == SCANNER_TRIVY
            and target.get("kind") == KIND_FS
        ):
            apply_gradle_graph(
                target["id"],
                native,
                scanner_parts_dir / f"{target['id']}{GRADLE_GRAPH_SUFFIX}",
            )
        results.append((target, state, native))
        copy_native(scanner_parts_dir, target["id"], native_dir)

    # Trivy findings create the records, OSV findings join them or add their own
    trivy_only = trivy_targets(targets_doc["targets"])
    ok_scans = [
        (t["id"], SCANNER_TRIVY, native)
        for t, _, native in results
        if native is not None and t["scanner"] == SCANNER_TRIVY
    ]
    osv_scans = resolve_osv_targets(results, {tid: n for tid, _, n in ok_scans})
    repo = targets_doc.get("repo")
    image_ids = {t["id"] for t in trivy_only if t.get("kind") == KIND_IMAGE}
    merged, sightings, in_place = merge_records(repo, ok_scans, image_ids, osv_scans)
    not_shipped = NotShipped(
        targets_doc["config"][KEY_NON_SHIPPED_PATHS], trivy_configs
    )
    records = finalize_records(merged, trivy_only, in_place, sightings, not_shipped)
    scan_report = build_scan_report(
        targets_doc, results, records, generated_utc, trivy_db, trivy_configs
    )
    vulns = build_vulnerabilities(repo, generated_utc, records)

    dump_json(report_dir / "vulnerabilities.json", vulns)
    dump_json(report_dir / "scan_report.json", scan_report)
    base_os = {
        t["id"]: label
        for t, _, native in results
        if native is not None
        and t["scanner"] == SCANNER_TRIVY
        and t.get("kind") == KIND_IMAGE
        and (label := image_os(native))
    }
    write_text(
        output_dir / "summary.md",
        build_summary_md(scan_report, vulns, sightings, base_os, in_place),
    )

    failed = [t for t in scan_report["targets"] if t["status"] == STATUS_FAILED]
    for t in failed:
        name = f"{t['id']} ({t['scanner']})"
        print(f"::error title=Scan target failed::{name}: {t['reason']}")
    totals = scan_report["totals"]["findings"]
    print(
        f"canonical set: {totals['total']} records ({totals['fixable']} fixable); "
        f"{len(failed)} failed target(s)"
    )
    return len(failed)


def append_text(path: str, text: str) -> None:
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(text)


def parse_bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in ("true", "1", "yes"):
        return True
    if lowered in ("false", "0", "no", ""):
        return False
    raise argparse.ArgumentTypeError(f"expected true or false, got {value!r}")


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge per-target scan results of an SCA scheduled scan."
    )
    parser.add_argument(
        "--targets-file",
        required=True,
        type=Path,
        help="targets.json of the targets step",
    )
    parser.add_argument(
        "--parts-dir",
        required=True,
        type=Path,
        help="directory with the scan parts: <scanner>/<id>.json and <id>.status.json",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="directory to write the report to",
    )
    parser.add_argument(
        "--step-summary",
        type=parse_bool,
        default=True,
        help="append summary.md to $GITHUB_STEP_SUMMARY (true/false, default true)",
    )
    parser.add_argument(
        "--trivy-db-info",
        default="",
        help=(
            "JSON object with vulnerability_db_updated_at and java_db_updated_at "
            "of the Trivy DB snapshot used by the run (default: unknown)"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    generated_utc = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        failed_count = run_merge(
            args.targets_file,
            args.parts_dir,
            args.output_dir,
            generated_utc,
            parse_trivy_db_info(args.trivy_db_info),
        )
    except InputError as e:
        print(f"::error title=Invalid merge input::{e}", file=sys.stderr)
        return 1

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.step_summary and step_summary:
        summary = (args.output_dir / "summary.md").read_text(encoding="utf-8")
        append_text(step_summary, summary)
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        append_text(
            github_output,
            f"failed-count={failed_count}\nreport-dir={args.output_dir}\n",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
