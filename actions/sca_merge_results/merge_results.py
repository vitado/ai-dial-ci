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
subject, which several scanners share). Trivy is the only scanner whose findings
are merged into the records. OSV, queried for the language packages of every Trivy
target, is reported per target - status, package and finding counts, native
result - but contributes no records yet.

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
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NamedTuple

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEV_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
UNKNOWN_SEVERITY = "UNKNOWN"
SCHEMA_VERSION = 1
SHORT_SHA_LENGTH = 7
TRIVY_DB_KEYS = ("vulnerability_db_updated_at", "java_db_updated_at")
MERGE_KEY = (
    "(repo, CVE x package x installed-version), merged across scan_targets and scanners"
)
TARGET_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")

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
    return data


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


def package_type(result: Mapping[str, Any]) -> str:
    """'os' for OS packages (base image layer), 'library' for dependencies."""
    return "os" if result.get("Class") == "os-pkgs" else "library"


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


# --------------------------------------------------------------------------
# Records: merging and enrichment
# --------------------------------------------------------------------------


def new_record(
    repo: str | None,
    key: FindingKey,
    result: Mapping[str, Any],
    vuln: Mapping[str, Any],
) -> Record:
    """A record from the first copy of a finding; ``absorb_finding`` adds the rest."""
    cve, _, version = key
    return {
        "repo": repo,
        "cve": cve,
        "aliases": [],
        "pkg": vuln.get("PkgName"),  # display name, see merge_records
        "version": version,
        # os (base image layer) vs library (a dependency): whose fix it is - a base
        # image bump or a dependency bump
        "pkg_type": package_type(result),
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
        "severity": normalize_severity(vuln.get("Severity")),
        "severity_source": vuln.get("SeveritySource") or None,
        "cvss": select_cvss(vuln),
        # fixed | affected | will_not_fix | fix_deferred ...: tells "never getting
        # a fix" from "no fix yet"
        "status": vuln.get("Status"),
        "fixed_versions": [],
        "fix_available": False,
        "upgrade_to": None,
        "title": (vuln.get("Title") or "").strip() or None,
        "cwe": vuln.get("CweIDs") or None,
        "published": vuln.get("PublishedDate") or None,
        "primary_url": vuln.get("PrimaryURL") or None,
        "scanners": [],
    }


def _append_unique(items: list[Any], value: Any) -> None:
    if value and value not in items:
        items.append(value)


def absorb_finding(
    record: Record,
    tid: str,
    scanner: str,
    result: Mapping[str, Any],
    vuln: Mapping[str, Any],
    relationships: Collection[str],
) -> None:
    """Add one copy of a finding (one lockfile of one target) to its record.

    The first copy wins for the descriptive fields; later copies only add to the
    lists and backfill what the first one lacked (a fix, a CVSS score).
    """
    _append_unique(record["scan_targets"], tid)
    _append_unique(record["scanners"], scanner)
    _append_unique(record["ecosystem"], result.get("Type"))
    _append_unique(record["locations"], result.get("Target", ""))
    _append_unique(record["pkg_paths"], vuln.get("PkgPath"))
    for alias in vuln.get("VendorIDs") or []:
        if alias != record["cve"]:
            _append_unique(record["aliases"], alias)
    for relationship in relationships:
        _append_unique(record["relationship"], relationship)
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


def merge_records(
    repo: str | None,
    scans: Iterable[tuple[str, str, Mapping[str, Any]]],
    image_ids: Collection[str] = (),
) -> tuple[list[Record], Sightings]:
    """Deduplicate findings across lockfiles and merge them across targets.

    ``scans`` is ``(target id, scanner, native JSON)`` in targets-file order,
    which is also the order of each record's ``scan_targets``. Returns the
    records (unordered, not enriched yet) and where each finding was seen, keyed
    by ``(cve, pkg, version)`` of the record. A package seen under several
    spellings (see ``canonical_package_name``) is shown under the spelling of its
    first image record, else of its first record.
    """
    by_key: dict[FindingKey, Record] = {}
    sightings: dict[FindingKey, dict[str, list[str]]] = {}
    named_by_image: set[FindingKey] = set()
    dev_packages: dict[FindingKey, list[Mapping[str, Any]]] = {}
    chains: dict[FindingKey, dict[tuple[Any, Any], DependencyInfo]] = {}
    for tid, scanner, native in scans:
        for result, vuln, packages, index in iter_findings(native):
            relationships = package_relationships(packages)
            key = finding_key(result, vuln)
            record = by_key.get(key)
            if record is None:
                record = by_key[key] = new_record(repo, key, result, vuln)
            if tid in image_ids and key not in named_by_image:
                named_by_image.add(key)
                record["pkg"] = vuln.get("PkgName")
            absorb_finding(record, tid, scanner, result, vuln, relationships)
            dev_packages.setdefault(key, []).extend(packages)
            for package in packages:
                # one chain set per package of a lockfile, however many targets saw it
                sighting = (
                    result.get("Target"),
                    package.get("ID") or package.get("Name"),
                )
                chains.setdefault(key, {})[sighting] = index.dependency_info(package)
            _append_unique(
                sightings.setdefault(key, {}).setdefault(tid, []),
                result.get("Target", ""),
            )
    for key, record in by_key.items():
        for name in ("locations", "scanners", "ecosystem", "relationship", "aliases"):
            record[name].sort()
        record["pkg_paths"].sort()
        record["dev"] = package_dev_flag(dev_packages.get(key, []))
        (
            record["dependency_paths"],
            record["dependency_paths_total"],
            record["dependency_paths_truncated"],
            record["introduced_via"],
        ) = combine_dependency_info(chains.get(key, {}).values())
    by_record = {
        (r["cve"], r["pkg"], r["version"]): sightings[key] for key, r in by_key.items()
    }
    return list(by_key.values()), by_record


# ---- OSV: reported per target, not merged into the records yet

OSV_NATIVE_SCHEMA_VERSION = 1
OSV_FOOTER = (
    "OSV: language packages only; findings counted, not yet merged into the "
    "findings above"
)
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


def osv_has_fix(record: Mapping[str, Any], purl: str) -> bool:
    """Whether the advisory names a fixed version of the package of ``purl``.

    Only entries of this very package count (an advisory often covers several
    packages) and only version ranges (``GIT`` ranges name commits).
    """
    identity = purl_identity(purl)
    return identity is not None and any(
        "fixed" in event
        for affected in record.get("affected") or []
        if affected_identity(affected) == identity
        for version_range in affected.get("ranges") or []
        if version_range.get("type") in OSV_VERSION_RANGE_TYPES
        for event in version_range.get("events") or []
    )


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


def osv_severity(record: Mapping[str, Any]) -> str:
    """The severity of an OSV record as one of the Trivy levels.

    The database's own rating wins (``database_specific.severity`` of GHSA records,
    where ``MODERATE`` is ``MEDIUM``); otherwise the highest rating of the CVSS 3.x
    vectors in ``severity[]``. CVSS 2 and 4 vectors are not rated, so a record that
    has nothing else is UNKNOWN.
    """
    own = (record.get("database_specific") or {}).get("severity")
    if isinstance(own, str):
        own = {"MODERATE": "MEDIUM"}.get(own.upper(), own.upper())
        if own in SEV_ORDER:
            return own
    ratings = [
        cvss3_rating(score)
        for entry in record.get("severity") or []
        if isinstance(entry.get("score"), str)
        and (score := cvss3_base_score(entry["score"])) is not None
    ]
    return min(ratings, key=SEV_ORDER.__getitem__, default=UNKNOWN_SEVERITY)


def osv_findings(native: Mapping[str, Any]) -> dict[tuple[str, str], tuple[str, bool]]:
    """Unique findings of one OSV target: (purl, OSV id) -> (severity, fixable)."""
    records = native["vulnerabilities"]
    return {
        (purl, vuln_id): (
            osv_severity(records[vuln_id]),
            osv_has_fix(records[vuln_id], purl),
        )
        for purl, vuln_ids in native["packages"].items()
        for vuln_id in set(vuln_ids)
    }


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
    branch a development one.
    """
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


def assign_exposure(records: Iterable[Record], targets: Sequence[Target]) -> None:
    by_id = {t["id"]: t for t in targets}
    has_images = any(t.get("kind") == KIND_IMAGE for t in targets)
    for record in records:
        classes = {target_class(by_id[tid]) for tid in record["scan_targets"]}
        classes.discard(None)
        record["exposure"] = classify_exposure(classes, has_images)  # type: ignore[arg-type]


def assign_upgrades(records: Sequence[Record]) -> None:
    """Set ``upgrade_to`` on the fixable records of each package version.

    It is the version that resolves all of the package's fixable CVEs (the same
    on all of them); records without a fix keep ``None``.
    """
    fixed_by_package: dict[tuple[Any, Any], list[list[str]]] = {}
    for record in records:
        if record["fix_available"]:
            key = (record["pkg"], record["version"])
            fixed_by_package.setdefault(key, []).append(record["fixed_versions"])
    for record in records:
        installed = record["version"]
        fixed = fixed_by_package.get((record["pkg"], installed))
        record["upgrade_to"] = (
            upgrade_target(installed, fixed)
            if fixed and record["fix_available"] and isinstance(installed, str)
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
    records: Iterable[Record], targets: Sequence[Target]
) -> list[Record]:
    """Enrich the merged records (exposure, upgrade_to) and put them in report order."""
    records = list(records)
    assign_exposure(records, targets)
    assign_upgrades(records)
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
) -> dict[str, Any]:
    trivy_version = None
    osv_api_url = None
    targets: list[dict[str, Any]] = []
    for target, state, native in results:
        entry = build_target_entry(target, state, native)
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


def release_headline(
    tag: str, group_records: Sequence[Record], development_scanned: bool
) -> str:
    if not group_records:
        return f"**Released {tag} — no known vulnerabilities**"
    counts = count_by_severity(r["severity"] for r in group_records)
    line = f"**Released {tag} — exposed: {format_severity_counts(counts)}**"
    if not development_scanned:
        return line
    also_open = sum(
        r["exposure"] == EXPOSURE_RELEASE_AND_DEVELOPMENT for r in group_records
    )
    suffix = (
        f"{also_open} also open in development"
        if also_open
        else "all fixed in development"
    )
    return f"{line}, {suffix}"


def source_only_note(source_records: Sequence[Record]) -> str:
    """What the source-only findings are: ``(dev dependencies)``, ``(not in images)``
    or counts when mixed or when other source findings are also in an image.
    """
    outside = [r for r in source_records if r["exposure"] == EXPOSURE_SOURCE_ONLY]
    if not outside:
        return ""
    dev = sum(r["dev"] is True for r in outside)
    other = len(outside) - dev
    if len(outside) == len(source_records) and not (dev and other):
        return " (dev dependencies)" if dev else " (not in images)"
    parts = []
    if dev:
        parts.append(f"{dev} dev {'dependency' if dev == 1 else 'dependencies'}")
    if other:
        parts.append(f"{other} not in images")
    return f" ({', '.join(parts)})"


def development_headline(
    image_records: Sequence[Record] | None,
    source_records: Sequence[Record] | None,
) -> str | None:
    """``development — image: clean; source: 1 LOW (dev dependencies)``.

    ``None`` for a part means it was not scanned, so it is left out.
    """
    parts = []
    if image_records is not None:
        counts = count_by_severity(r["severity"] for r in image_records)
        parts.append(f"image: {format_severity_counts(counts) or 'clean'}")
    if source_records is not None:
        counts = count_by_severity(r["severity"] for r in source_records)
        text = f"source: {format_severity_counts(counts) or 'clean'}"
        parts.append(text + source_only_note(source_records))
    return f"**development — {'; '.join(parts)}**" if parts else None


def totals_line(report: Mapping[str, Any]) -> str:
    totals = report["totals"]
    findings, counts = totals["findings"], totals["targets"]
    applicable = counts["total"] - counts["not_applicable"]
    line = (
        f"{findings['total']} findings ({findings['fixable']} fixable) · "
        f"{counts['ok']}/{applicable} targets scanned"
    )
    if counts["not_applicable"]:
        line += f" · {counts['not_applicable']} not applicable"
    return line


def no_findings_line(report: Mapping[str, Any]) -> str:
    ok_targets = [
        t for t in trivy_targets(report["targets"]) if t["status"] == STATUS_OK
    ]
    packages = sum(t["packages_scanned"] or 0 for t in ok_targets)
    return (
        f"No known vulnerabilities · {packages} packages in {len(ok_targets)} targets"
    )


def headline_lines(report: Mapping[str, Any], records: Sequence[Record]) -> list[str]:
    """One line per group: failures, each released tag, development, totals."""
    targets = report["targets"]
    lines: list[str] = []
    failed = [target_name(t) for t in targets if t["status"] == STATUS_FAILED]
    if failed:
        lines.append(
            f"**Incomplete: {len(failed)} target(s) failed** — {', '.join(failed)} "
            "(their findings are missing)"
        )
    ok = [t for t in trivy_targets(targets) if t["status"] == STATUS_OK]
    if not ok:
        scanned = any(t["status"] == STATUS_OK for t in targets)
        return [
            *lines,
            "No Trivy target was scanned" if scanned else "No target was scanned",
        ]
    if not records:
        return [*lines, no_findings_line(report)]

    by_class: dict[str, list[Mapping[str, Any]]] = {}
    for target in ok:
        by_class.setdefault(target_class(target) or "", []).append(target)
    development_images = by_class.get(CLASS_DEVELOPMENT)
    sources = by_class.get(CLASS_SOURCE)
    development_scanned = bool(development_images or sources)

    # the verdict of a release is the one of its images; without images, of its source
    has_images = any(t.get("kind") == KIND_IMAGE for t in targets)
    release_tags: dict[str, set[str]] = {}
    for target in by_class.get(release_class(has_images), []):
        release_tags.setdefault(target["tag"], set()).add(target["id"])
    for tag, tids in release_tags.items():
        lines.append(
            release_headline(tag, records_in(records, tids), development_scanned)
        )

    def part(group: list[Mapping[str, Any]] | None) -> list[Record] | None:
        return None if not group else records_in(records, {t["id"] for t in group})

    development = development_headline(part(development_images), part(sources))
    if development:
        lines.append(development)
    lines.append(totals_line(report))
    return lines


def render_headline(lines: Sequence[str]) -> list[str]:
    """A blockquote with one paragraph per line (a plain newline would merge them)."""
    quoted: list[str] = []
    for line in lines:
        if quoted:
            quoted.append(">")
        quoted.append(f"> {line}")
    return quoted


# --------------------------------------------------------------------------
# summary.md: "What to fix"
# --------------------------------------------------------------------------


def max_cvss_score(records: Iterable[Record]) -> float | None:
    scores = [r["cvss"]["score"] for r in records if r["cvss"]]
    return max(scores) if scores else None


def group_fixes(records: Iterable[Record]) -> list[list[Record]]:
    """One group per (exposure, package, installed version), most urgent first."""
    groups: dict[tuple[Any, Any, Any], list[Record]] = {}
    for record in records:
        key = (record["exposure"], record["pkg"], record["version"])
        groups.setdefault(key, []).append(record)

    def sort_key(group: list[Record]) -> tuple[Any, ...]:
        first = group[0]
        score = max_cvss_score(group)
        return (
            EXPOSURE_ORDER.get(first["exposure"], len(EXPOSURES)),
            min(SEV_ORDER.get(r["severity"], len(SEV_ORDER)) for r in group),
            score is None,
            -(score or 0),
            first["pkg"] or "",
            first["version"] or "",
        )

    return sorted(groups.values(), key=sort_key)


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


def upgrade_cell(fixable: Sequence[Record]) -> str:
    version = fixable[0]["version"]
    upgrade = fixable[0]["upgrade_to"]
    if upgrade:
        return f"{version} → {upgrade}"
    fixed = sorted({f for r in fixable for f in r["fixed_versions"]})
    return f"{version} → {', '.join(fixed)}"


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
        return "Source only · dev dependency" if dev else "Source only · not in images"
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
) -> str:
    """What to do, verb first; ``via`` is the dependency chain to upgrade through.

    ``open_in_development`` is False for a finding that sits only in the source of
    a release tag: the default branch is clear of it, so there is nothing to upgrade.
    """
    lines = ", ".join(release_lines(tags))
    via_text = f" via {via}" if via else ""
    if exposure == EXPOSURE_RELEASE_AND_DEVELOPMENT:
        return f"Upgrade in development{via_text}, backport to {lines}"
    if exposure == EXPOSURE_RELEASE_ONLY:
        return f"Release a patch from {lines} (already fixed in development){via_text}"
    if exposure == EXPOSURE_SOURCE_ONLY:
        note = "dev dependency, not shipped" if dev else "not in published images"
        if not open_in_development:
            return f"Already fixed in development — {note}"
        return f"Upgrade in development{via_text} — {note}"
    return f"Upgrade in development{via_text} before the next release"


def where_cell(
    group: Sequence[Record],
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
) -> str:
    """Where a group was found: tags per image, then the lockfiles of the source
    of the default branch and of each release tag.

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
                sources.setdefault(name, []).extend(seen[target["id"]])
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


def render_what_to_fix(
    records: Sequence[Record],
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Packages with at least one CVE an upgrade resolves; empty if there are none."""
    rows = []
    for group in group_fixes(records):
        fixable = [r for r in group if r["fix_available"]]
        if not fixable:
            continue
        rows.append(
            [
                len(rows) + 1,
                package_cell(group),
                upgrade_cell(fixable),
                resolves_cell(group),
                group_exposure_label(group, targets),
                action_text(
                    group[0]["exposure"],
                    group_dev(group),
                    release_tags_of(group, targets),
                    shortest_path_text(group)
                    if group_relationship(group) == "indirect"
                    else "",
                    found_in_default_source(group, targets),
                ),
                where_cell(fixable, sightings, targets),
            ]
        )
    if not rows:
        return []
    header = ["#", "Package", "Upgrade", "Resolves", "Exposure", "Action", "Where"]
    return ["## What to fix", "", *md_table(header, rows, right=(0,))]


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

    Open if anything HIGH or CRITICAL is in it, else collapsed.
    """
    unfixed = [r for r in records if not r["fix_available"]]
    if not unfixed:
        return []
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


# --------------------------------------------------------------------------
# summary.md: details
# --------------------------------------------------------------------------


def cve_cell(record: Record) -> str:
    cve = record["cve"]
    return f"[{cve}]({record['primary_url']})" if record["primary_url"] else cve


def cvss_cell(record: Record) -> str | None:
    cvss = record["cvss"]
    return f"{cvss['score']} ({cvss['source']})" if cvss else None


def installed_to_fixed_cell(record: Record) -> str:
    fixed = record["upgrade_to"] or ", ".join(record["fixed_versions"]) or "no fix"
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
    lines: list[str] = []
    for severity in SEVERITIES:
        selected = [r for r in records if r["severity"] == severity]
        if selected:
            lines += ["", *render_severity_section(severity, selected, targets)]
    return lines


def severity_cells(findings: Mapping[str, Any] | None) -> list[Any]:
    by_severity = (findings or {}).get("by_severity")
    return [by_severity[s] if by_severity else None for s in SEVERITIES[:4]]


def render_coverage(targets: Sequence[Mapping[str, Any]]) -> list[str]:
    several = has_several_images(targets)
    # Only a run with another scanner needs the column: Trivy-only reports stay as is
    with_scanner = any(t["scanner"] != SCANNER_TRIVY for t in targets)
    rows = (
        [
            target_label(t, several),
            *([t["scanner"]] if with_scanner else []),
            t["status"],
            t["packages_scanned"],
            *severity_cells(t["findings"]),
            t["reason"],
        ]
        for t in targets
    )
    header = [
        "Target",
        *(["Scanner"] if with_scanner else []),
        "Status",
        "Packages",
        "C",
        "H",
        "M",
        "L",
        "Note",
    ]
    first_number = 3 if with_scanner else 2
    body = md_table(header, rows, right=range(first_number, first_number + 5))
    return ["", *md_details("Scan coverage", body)]


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
    if report.get("osv"):
        lines += ["", f"<sub>{OSV_FOOTER}</sub>"]
    return lines


def build_summary_md(
    report: Mapping[str, Any], vulns: Mapping[str, Any], sightings: Sightings
) -> str:
    records = vulns["records"]
    targets = report["targets"]
    # The findings sections are about the records, so about the Trivy targets only
    record_targets = trivy_targets(targets)
    lines = [f"# SCA · {md_cell(report['repo'])}", ""]
    lines += render_headline(headline_lines(report, records))
    if records:
        fixes = render_what_to_fix(records, sightings, record_targets)
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
            apply_gradle_graph(
                target["id"],
                native,
                scanner_parts_dir / f"{target['id']}{GRADLE_GRAPH_SUFFIX}",
            )
        results.append((target, state, native))
        copy_native(scanner_parts_dir, target["id"], native_dir)

    # Only Trivy findings are records; OSV targets are reported per target
    trivy_only = trivy_targets(targets_doc["targets"])
    ok_scans = [
        (t["id"], SCANNER_TRIVY, native)
        for t, _, native in results
        if native is not None and t["scanner"] == SCANNER_TRIVY
    ]
    repo = targets_doc.get("repo")
    image_ids = {t["id"] for t in trivy_only if t.get("kind") == KIND_IMAGE}
    merged, sightings = merge_records(repo, ok_scans, image_ids)
    records = finalize_records(merged, trivy_only)
    scan_report = build_scan_report(
        targets_doc, results, records, generated_utc, trivy_db
    )
    vulns = build_vulnerabilities(repo, generated_utc, records)

    dump_json(report_dir / "vulnerabilities.json", vulns)
    dump_json(report_dir / "scan_report.json", scan_report)
    write_text(
        output_dir / "summary.md", build_summary_md(scan_report, vulns, sightings)
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
