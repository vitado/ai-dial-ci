"""Normalizers of the SCA merge: Trivy and osv-scanner results into findings.

A finding is one row per (target, scanner, class, id, package, version); the copies
of a finding in several lockfiles of one target are one row with several
``locations``. The ``id`` is the CVE if the id or an alias is one, so that the rows
of both scanners about one vulnerability share it. Severity and fixed version are the
scanner's own. The package of an OSV finding is looked up in the Trivy inventory of
the same target, which gives the finding its chain, dev flag and locations.
"""

from __future__ import annotations

import posixpath
import re
from collections import deque
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from _sca_lib.gha import escape_command_data
from _sca_lib.jsonio import read_json

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
CLASS_OS_PACKAGES = "os-pkgs"
GRADLE_RESULT_TYPE = "gradle"
OSV_URL = "https://osv.dev/vulnerability/"

Finding = dict[str, Any]
# (target id, scanner, class, id, normalized package name, version) -> finding
Findings = dict[tuple[str, str, str, str, str, str], Finding]
# (normalized package name, version) -> {chain, relationship, dev, locations}
Inventory = dict[tuple[str, str], dict[str, Any]]


def norm(name: str) -> str:
    """The name a package is matched by (PEP 503 for every ecosystem)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def pick_id(ids: list[str]) -> str:
    """The first CVE (in string order) among the ids, else the first id."""
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    return cves[0] if cves else ids[0]


def add_finding(findings: Findings, row: Finding) -> None:
    """Add a finding; a copy of a known one only adds its locations."""
    key = (
        row["target"],
        row["scanner"],
        row["class"],
        row["id"],
        norm(row["pkg"]),
        row["version"],
    )
    known = findings.setdefault(key, row)
    if known is not row:
        known["locations"] += [
            l for l in row["locations"] if l not in known["locations"]
        ]


def finding_row(**fields: Any) -> Finding:
    """A finding with its fields in the order of the report."""
    order = ["target", "scanner", "id", "aliases", "pkg", "version", "ecosystem", "class", "locations", "severity", "fixed_version", "dev", "relationship", "chain", "title", "url"]
    return {name: fields[name] for name in order}


# ---------------------------------------------------------------- Gradle graph


def load_gradle_graphs(graph_dir: Path, tid: str) -> dict[str, tuple[set, dict]]:
    """The graph files written by lockfiles.init.gradle: project dir -> (direct
    modules, module -> modules it depends on), united over all configurations.
    A file that cannot be read is skipped with a warning.
    """
    graphs: dict[str, tuple[set[str], dict[str, set[str]]]] = {}
    for path in sorted(graph_dir.glob("*.json")) if graph_dir.is_dir() else []:
        try:
            data = read_json(path)
            direct: set[str] = set()
            edges: dict[str, set[str]] = {}
            for config in data["configurations"].values():
                direct.update(config["direct"])
                for module, deps in config["modules"].items():
                    edges.setdefault(module, set()).update(deps)
            project_dir = posixpath.normpath(data["project_dir"])
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            print(
                "::warning title=Gradle dependency graph ignored::"
                + escape_command_data(f"{tid}: {path.name}: {e!r}")
            )
            continue
        known_direct, known_edges = graphs.setdefault(project_dir, (set(), {}))
        known_direct.update(direct)
        for module, deps in edges.items():
            known_edges.setdefault(module, set()).update(deps)
    return graphs


def apply_gradle_graph(tid: str, native: Mapping[str, Any], graph_dir: Path) -> None:
    """Fill ``Relationship`` and ``DependsOn`` of the packages of the gradle Results
    of an fs scan (a lockfile has no graph), in memory: ``_native/`` stays as is.
    """
    results = [r for r in native.get("Results") or [] if r.get("Type") == "gradle"]
    graphs = load_gradle_graphs(graph_dir, tid) if results else {}
    for result in results:
        graph = graphs.get(posixpath.normpath(posixpath.dirname(result["Target"])))
        if graph is None:
            print(
                "::warning title=No Gradle dependency graph::"
                + escape_command_data(
                    f"{tid}: {result['Target']} has no dependency graph, "
                    "so its findings have no chains"
                )
            )
            continue
        direct, edges = graph
        packages = result.get("Packages") or []
        ids = {p["ID"] for p in packages if p.get("ID")}
        for package in packages:
            module = package.get("ID")
            if module in direct or module in edges:
                package["Relationship"] = "direct" if module in direct else "indirect"
                package["DependsOn"] = sorted(
                    (edges.get(module, set()) & ids) - {module}
                )


# ---------------------------------------------------------------- Trivy


def pkg_id(package: Mapping[str, Any]) -> str:
    return package.get("ID") or f"{package['Name']}@{package.get('Version')}"


def shortest_chain(
    start: str, packages: Mapping[str, Any], parents: Mapping[str, list[str]]
) -> list[str]:
    """Names from the nearest direct dependency down to ``start``: a reverse
    breadth-first walk over ``DependsOn``; the visited set makes it cycle-safe.
    Empty if no direct dependency leads to it.
    """
    seen = {start}
    queue = deque([[start]])
    while queue:
        path = queue.popleft()
        if packages[path[-1]].get("Relationship") == "direct":
            return [packages[i]["Name"] for i in reversed(path)]
        for parent in parents.get(path[-1], []):
            if parent not in seen:
                seen.add(parent)
                queue.append([*path, parent])
    return []


def normalize_trivy(
    tid: str, native: Mapping[str, Any], findings: Findings, inventory: Inventory
) -> None:
    """The vulnerabilities of a Trivy result as findings; every language package
    (vulnerable or not) goes into ``inventory`` for the OSV findings and the images.
    """
    for result in native.get("Results") or []:
        lang = result.get("Class") != CLASS_OS_PACKAGES
        packages = {pkg_id(p): p for p in result.get("Packages") or []}
        parents: dict[str, list[str]] = {}
        for pid, package in packages.items():
            for dep in package.get("DependsOn") or []:
                parents.setdefault(dep, []).append(pid)

        def info(pid: str, packages=packages, parents=parents) -> dict[str, Any]:
            package = packages.get(pid, {})
            rel = package.get("Relationship")
            chain = (
                shortest_chain(pid, packages, parents)
                if rel in ("direct", "indirect")
                else []
            )
            return {
                "chain": chain,
                "relationship": rel,
                "dev": bool(package.get("Dev")),
            }

        if lang:
            for pid, package in packages.items():
                entry = inventory.setdefault(
                    (norm(package["Name"]), package.get("Version")),
                    {**info(pid), "locations": []},
                )
                location = package.get("FilePath") or result["Target"]
                if location not in entry["locations"]:
                    entry["locations"].append(location)
        for vuln in result.get("Vulnerabilities") or []:
            ids = [vuln["VulnerabilityID"], *(vuln.get("VendorIDs") or [])]
            vid = pick_id(ids)
            name, version = vuln["PkgName"], vuln["InstalledVersion"]
            package_info = (
                info(vuln.get("PkgID") or f"{name}@{version}")
                if lang
                else {"chain": [], "relationship": None, "dev": False}
            )
            add_finding(
                findings,
                finding_row(
                    target=tid,
                    scanner="trivy",
                    id=vid,
                    aliases=[i for i in ids if i != vid],
                    pkg=name,
                    version=version,
                    ecosystem=result["Type"],
                    **{"class": "lang" if lang else "os"},
                    locations=[vuln.get("PkgPath") or result["Target"]] if lang else [],
                    severity=vuln.get("Severity", "UNKNOWN"),
                    fixed_version=vuln.get("FixedVersion", ""),
                    title=vuln.get("Title", ""),
                    url=vuln.get("PrimaryURL", ""),
                    **package_info,
                ),
            )


# ---------------------------------------------------------------- OSV


def osv_packages(native: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [p for r in native["results"] for p in r["packages"]]


def severity_of_score(score: Any) -> str:
    """The rating of a CVSS base score (osv-scanner's ``max_severity``)."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    for bound, name in ((9, "CRITICAL"), (7, "HIGH"), (4, "MEDIUM"), (0.1, "LOW")):
        if value >= bound:
            return name
    return "UNKNOWN"


def normalize_osv(
    tid: str, native: Mapping[str, Any], findings: Findings, inventory: Inventory
) -> None:
    """One finding per osv-scanner group of a package. Severity is the rating the
    database gives (GHSA), else the bucket of the group's CVSS score.
    """
    for entry in osv_packages(native):
        vulns = {v["id"]: v for v in entry.get("vulnerabilities", [])}
        name, version = entry["package"]["name"], entry["package"]["version"]
        own = inventory.get(
            (norm(name), version),
            {"chain": [], "relationship": None, "dev": False, "locations": []},
        )
        for group in entry.get("groups", []):
            members = [vulns[i] for i in group["ids"] if i in vulns]
            ids = list(dict.fromkeys(group["ids"] + group.get("aliases", [])))
            vid = pick_id(ids)
            rating = next(
                (
                    v["database_specific"]["severity"]
                    for v in members
                    if (v.get("database_specific") or {}).get("severity")
                ),
                None,
            )
            rating = {"MODERATE": "MEDIUM"}.get(rating, rating)
            fixed = next(
                (
                    event["fixed"]
                    for v in members
                    for affected in v.get("affected", [])
                    if affected.get("package", {}).get("name") == name
                    for rng in affected.get("ranges", [])
                    for event in rng.get("events", [])
                    if "fixed" in event
                ),
                "",
            )
            first = members[0] if members else {}
            add_finding(
                findings,
                finding_row(
                    target=tid,
                    scanner="osv",
                    id=vid,
                    aliases=[i for i in ids if i != vid],
                    pkg=name,
                    version=version,
                    ecosystem=entry["package"]["ecosystem"],
                    **{"class": "lang"},
                    locations=list(own["locations"]),
                    severity=rating
                    if rating in SEVERITIES
                    else severity_of_score(group.get("max_severity")),
                    fixed_version=fixed,
                    dev=own["dev"],
                    relationship=own["relationship"],
                    chain=own["chain"],
                    title=first.get("summary")
                    or next(iter((first.get("details") or "").splitlines()), ""),
                    url=OSV_URL + group["ids"][0],
                ),
            )


def borrow_source_chains(
    findings: Findings, inventories: Mapping[str, Inventory], source_ids: list[str]
) -> None:
    """A language package of an image without a chain (an image has no graph) takes
    the chain of the same package and version from a source target of the repo.
    The dev flag is not borrowed: what is in an image is shipped.
    """
    for row in findings.values():
        if row["class"] != "lang" or row["chain"] or row["target"] in source_ids:
            continue
        for sid in source_ids:
            known = inventories.get(sid, {}).get((norm(row["pkg"]), row["version"]))
            if known and known["chain"]:
                row["chain"], row["relationship"] = (
                    known["chain"],
                    known["relationship"],
                )
                break
