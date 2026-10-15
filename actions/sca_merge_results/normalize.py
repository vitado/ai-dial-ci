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

from _sca_lib import escape_command_data, read_json

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
OSV_URL = "https://osv.dev/vulnerability/"

Finding = dict[str, Any]
# (target id, scanner, class, id, normalized package name, version) -> finding
Findings = dict[tuple[str, str, str, str, str, str], Finding]
# (normalized package name, version) -> {chain, relationship, dev, locations}
Inventory = dict[tuple[str, str], dict[str, Any]]


def no_graph() -> dict[str, Any]:
    """What a package without a dependency graph (an OS package) has."""
    return {"chain": [], "relationship": None, "dev": False}


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
            loc for loc in row["locations"] if loc not in known["locations"]
        ]


# ---------------------------------------------------------------- Gradle graph


def load_gradle_graphs(graph_dir: Path, tid: str) -> dict[str, tuple[set, dict]]:
    """The graph files written by lockfiles.init.gradle: project dir -> (direct
    modules, module -> modules it depends on), united over all configurations. A file
    that cannot be read is skipped with a warning.
    """
    graphs: dict[str, tuple[set[str], dict[str, set[str]]]] = {}
    for path in sorted(graph_dir.glob("*.json")):
        try:
            data = read_json(path)
            direct: set[str] = set()
            edges: dict[str, set[str]] = {}
            for config in data["configurations"].values():
                direct.update(config["direct"])
                for module, deps in config["modules"].items():
                    edges.setdefault(module, set()).update(deps)
            graphs[posixpath.normpath(data["project_dir"])] = (direct, edges)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            print(
                "::warning title=Gradle dependency graph ignored::"
                + escape_command_data(f"{tid}: {path.name}: {e!r}")
            )
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


def package_graph_info(
    pid: str, packages: Mapping[str, Any], parents: Mapping[str, list[str]]
) -> dict[str, Any]:
    package = packages.get(pid, {})
    relationship = package.get("Relationship")
    known = relationship in ("direct", "indirect")
    return {
        "chain": shortest_chain(pid, packages, parents) if known else [],
        "relationship": relationship,
        "dev": bool(package.get("Dev")),
    }


def normalize_trivy(
    tid: str, native: Mapping[str, Any], findings: Findings, inventory: Inventory
) -> None:
    """The vulnerabilities of a Trivy result as findings; every language package
    (vulnerable or not) goes into ``inventory`` for the OSV findings and the images.
    """
    for result in native.get("Results") or []:
        lang = result.get("Class") != "os-pkgs"
        packages = {
            p.get("ID") or f"{p['Name']}@{p.get('Version')}": p
            for p in result.get("Packages") or []
        }
        parents: dict[str, list[str]] = {}
        for pid, package in packages.items():
            for dep in package.get("DependsOn") or []:
                parents.setdefault(dep, []).append(pid)

        if lang:
            for pid, package in packages.items():
                entry = inventory.setdefault(
                    (norm(package["Name"]), package.get("Version")),
                    {**package_graph_info(pid, packages, parents), "locations": []},
                )
                location = package.get("FilePath") or result["Target"]
                if location not in entry["locations"]:
                    entry["locations"].append(location)
        for vuln in result.get("Vulnerabilities") or []:
            ids = [vuln["VulnerabilityID"], *(vuln.get("VendorIDs") or [])]
            vid = pick_id(ids)
            name, version = vuln["PkgName"], vuln["InstalledVersion"]
            graph = no_graph()
            if lang:
                pid = vuln.get("PkgID") or f"{name}@{version}"
                graph = package_graph_info(pid, packages, parents)
            add_finding(
                findings,
                {
                    "target": tid,
                    "scanner": "trivy",
                    "id": vid,
                    "aliases": [i for i in ids if i != vid],
                    "pkg": name,
                    "version": version,
                    "ecosystem": result["Type"],
                    "class": "lang" if lang else "os",
                    "locations": [vuln.get("PkgPath") or result["Target"]]
                    if lang
                    else [],
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "dev": graph["dev"],
                    "relationship": graph["relationship"],
                    "chain": graph["chain"],
                    "title": vuln.get("Title", ""),
                    "url": vuln.get("PrimaryURL", ""),
                },
            )


# ---------------------------------------------------------------- OSV


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
    for entry in (p for r in native["results"] for p in r["packages"]):
        vulns = {v["id"]: v for v in entry.get("vulnerabilities", [])}
        name, version = entry["package"]["name"], entry["package"]["version"]
        own = inventory.get((norm(name), version), {**no_graph(), "locations": []})
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
            # fixes of every branch (ECOSYSTEM/SEMVER ranges; GIT ranges hold commits)
            fixed = ", ".join(
                dict.fromkeys(
                    event["fixed"]
                    for v in members
                    for affected in v.get("affected", [])
                    if affected.get("package", {}).get("name") == name
                    for rng in affected.get("ranges", [])
                    if rng.get("type") in ("ECOSYSTEM", "SEMVER")
                    for event in rng.get("events", [])
                    if "fixed" in event
                )
            )
            first = members[0] if members else {}
            add_finding(
                findings,
                {
                    "target": tid,
                    "scanner": "osv",
                    "id": vid,
                    "aliases": [i for i in ids if i != vid],
                    "pkg": name,
                    "version": version,
                    "ecosystem": entry["package"]["ecosystem"],
                    "class": "lang",
                    "locations": list(own["locations"]),
                    "severity": rating
                    if rating in SEVERITIES
                    else severity_of_score(group.get("max_severity")),
                    "fixed_version": fixed,
                    "dev": own["dev"],
                    "relationship": own["relationship"],
                    "chain": own["chain"],
                    "title": first.get("summary")
                    or next(iter((first.get("details") or "").splitlines()), ""),
                    "url": OSV_URL + group["ids"][0],
                },
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
                row["chain"] = known["chain"]
                row["relationship"] = known["relationship"]
                break
