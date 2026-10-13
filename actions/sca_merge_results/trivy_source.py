"""Trivy results of the SCA merge: findings, CVSS, Gradle graph, dependency chains."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

from _sca_lib.gha import escape_command_data
from _sca_lib.jsonio import read_json
from _sca_lib.versions import compare_tokens
from records import (
    SEV_ORDER,
    UNKNOWN_SEVERITY,
    FindingKey,
    Record,
    absorb_sighting,
    append_unique,
    blank_record,
    minimal_fix,
)

GRADLE_RESULT_TYPE = "gradle"
GRADLE_GRAPH_SCHEMA_VERSION = 1
ROOT_PROJECT_DIR = "."
CLASS_OS_PACKAGES = "os-pkgs"
MAX_INTRODUCED_VIA = 5
MAX_DEPENDENCY_PATHS = 5


# Counting stops here (the count is then "at least this many") and so does the
# enumeration of candidate paths of one length; the walk has a step budget too.
PATH_COUNT_LIMIT = 1000


PATH_WALK_BUDGET = 50_000


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
            "::warning title=Gradle dependency graph ignored::"
            + escape_command_data(f"{target_id}: {problem}")
        )
    for lockfile in enrich_gradle_results(native, graphs):
        print(
            "::warning title=No Gradle dependency graph::"
            + escape_command_data(
                f"{target_id}: {lockfile} has no dependency graph, "
                "so its findings have no dependency paths"
            )
        )


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


def package_type(result: Mapping[str, Any]) -> str:
    """'os' for OS packages (base image layer), 'library' for dependencies."""
    return "os" if result.get("Class") == CLASS_OS_PACKAGES else "library"


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
            compare_tokens(other, minimal) in (0, 1)
            for other in index.other_versions_in_file(package)
        ):
            return False
    return True


def new_record(
    repo: str | None,
    key: FindingKey,
    result: Mapping[str, Any],
    vuln: Mapping[str, Any],
) -> Record:
    """A record from the first copy of a finding; ``absorb_finding`` adds the rest."""
    vuln_id, _, version = key
    record = blank_record(
        repo, vuln_id, vuln.get("PkgName"), version, package_type(result)
    )
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
    append_unique(record["pkg_paths"], vuln.get("PkgPath"))
    for alias in vuln.get("VendorIDs") or []:
        if alias != record["id"]:
            append_unique(record["aliases"], alias)
    fixed_versions = split_fixed_versions(vuln.get("FixedVersion"))
    if fixed_versions and not record["fix_available"]:
        record["fix_available"] = True
        record["status"] = vuln.get("Status") or record["status"]
    for fixed in fixed_versions:
        append_unique(record["fixed_versions"], fixed)
    if record["cvss"] is None:
        record["cvss"] = select_cvss(vuln)
        record["severity_source"] = (
            record["severity_source"] or vuln.get("SeveritySource") or None
        )
