"""osv-scanner output of the SCA merge: vulnerabilities per package and OSV records."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, NamedTuple

from _sca_lib.purl import parse_purl
from _sca_lib.versions import compare_tokens
from records import (
    SCANNER_OSV,
    SEV_ORDER,
    UNKNOWN_SEVERITY,
    FindingKey,
    Record,
    append_unique,
    blank_record,
)
from trivy_source import (
    _PEP503_SEPARATORS_RE,
    PackageIndex,
    cvss_vector_version,
    package_type,
)

CLASS_LANGUAGE_PACKAGES = "lang-pkgs"
OSV_FOOTER = "OSV: language packages only"
OSV_VULNERABILITY_URL = "https://osv.dev/vulnerability/"


# Qualitative rating of a CVSS base score (v3 and v4 alike): lower bound -> severity
SCORE_RATINGS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"))


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


class OsvResultError(Exception):
    """The osv-scanner output does not have the shape this merge reads."""


def osv_result_problem(native: Mapping[str, Any]) -> str | None:
    """Why an OSV result cannot be counted (it is incomplete), else None."""
    try:
        osv_packages(native)
    except OsvResultError as e:
        return f"osv result {e}"
    return None


def osv_identity(ecosystem: str, name: str) -> tuple[str, str]:
    """``(ecosystem, name)`` in the form OSV package references are compared in."""
    if ecosystem in CASE_INSENSITIVE_ECOSYSTEMS:
        name = _PEP503_SEPARATORS_RE.sub("-", name).lower()
    return ecosystem, name


def purl_identity(purl: str) -> tuple[str, str] | None:
    """The OSV package of a purl; None for a malformed purl or an unknown purl type."""
    parsed = parse_purl(purl)
    known = PURL_ECOSYSTEMS.get(parsed.type) if parsed else None
    if parsed is None or known is None:
        return None
    ecosystem, separator = known
    return osv_identity(
        ecosystem, separator.join(p for p in (parsed.namespace, parsed.name) if p)
    )


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
    record: Mapping[str, Any],
    identity: tuple[str, str],
    installed: str | None = None,
) -> list[str]:
    """The versions the advisory names as the fix of the package ``identity``.

    Only entries of this very package count (an advisory often covers several
    packages) and only version ranges (``GIT`` ranges name commits). A range
    that has ``last_affected`` but no ``fixed`` event has no fix. A version that
    is not above the ``installed`` one cannot be the fix of it (it belongs to
    another branch of the package), so it is left out; an incomparable one is
    kept. This is the one definition of a fix, for records and target counts.
    """
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
                if installed is None or compare_tokens(version, installed) not in (
                    -1,
                    0,
                ):
                    append_unique(fixed, version)
    return fixed


def score_rating(score: float | None) -> str:
    """The qualitative rating of a CVSS base score; UNKNOWN without a positive one."""
    if score is None:
        return UNKNOWN_SEVERITY
    return next(
        (rating for bound, rating in SCORE_RATINGS if score >= bound), UNKNOWN_SEVERITY
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


@dataclass(frozen=True)
class OsvVulnerability:
    """One vulnerability of a package: an osv-scanner group of aliasing ids.

    ``ids`` are the ids of the group, ``names`` those and all their aliases;
    ``records`` are the OSV records of the ids, GHSA first, then by id;
    ``max_severity`` is the highest CVSS base score osv-scanner found in them.
    """

    ids: tuple[str, ...]
    names: frozenset[str]
    records: tuple[Mapping[str, Any], ...]
    max_severity: float | None


# (OSV package identity, version)
OsvKey = tuple[tuple[str, str], str]


class OsvPackage(NamedTuple):
    """A package osv-scanner looked at, with the vulnerabilities it found."""

    identity: tuple[str, str]
    version: str
    vulnerabilities: tuple[OsvVulnerability, ...]

    @property
    def key(self) -> OsvKey:
        return self.identity, self.version


def osv_record_order(record: Mapping[str, Any]) -> tuple[bool, str]:
    """GHSA records first (they carry the summary, severity and CWE), then by id."""
    return not record["id"].startswith("GHSA-"), record["id"]


def osv_score(value: Any) -> float | None:
    """The ``max_severity`` of a group (a number as a string, empty without one)."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if math.isfinite(score) and score > 0 else None


def osv_vulnerability(
    group: Any, records: Mapping[str, Mapping[str, Any]]
) -> OsvVulnerability:
    ids = group.get("ids") if isinstance(group, dict) else None
    if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
        raise OsvResultError("has a malformed group")
    for vuln_id in ids:
        if vuln_id not in records:
            raise OsvResultError(f"has no record of {vuln_id}")
    aliases = [a for a in group.get("aliases") or [] if isinstance(a, str)]
    return OsvVulnerability(
        tuple(sorted(ids)),
        frozenset(ids) | frozenset(aliases),
        tuple(sorted((records[i] for i in ids), key=osv_record_order)),
        osv_score(group.get("max_severity")),
    )


def osv_package(entry: Any) -> OsvPackage:
    info = entry.get("package") if isinstance(entry, dict) else None
    fields = [info.get(k) for k in ("ecosystem", "name", "version")] if info else []
    if len(fields) != 3 or not all(isinstance(f, str) and f for f in fields):
        raise OsvResultError("has a malformed package entry")
    ecosystem, name, version = fields
    found = entry.get("vulnerabilities") or []
    groups = entry.get("groups") or []
    if not isinstance(found, list) or not isinstance(groups, list):
        raise OsvResultError("has a malformed package entry")
    if not all(isinstance(v, dict) and isinstance(v.get("id"), str) for v in found):
        raise OsvResultError("has a malformed vulnerability record")
    records = {v["id"]: v for v in found}
    vulnerabilities = tuple(osv_vulnerability(group, records) for group in groups)
    covered = {i for v in vulnerabilities for i in v.ids}
    if missing := sorted(records.keys() - covered):
        raise OsvResultError(f"has no group of {missing[0]}")
    return OsvPackage(osv_identity(ecosystem, name), version, vulnerabilities)


def osv_packages(native: Mapping[str, Any]) -> dict[OsvKey, OsvPackage]:
    """The packages of an osv-scanner result (``--format json --all-packages``),
    distinct by ecosystem, name and version, in the order of the result.
    """
    results = native.get("results")
    if not isinstance(results, list):
        raise OsvResultError("has no results list")
    packages: dict[OsvKey, OsvPackage] = {}
    for result in results:
        entries = result.get("packages") if isinstance(result, dict) else None
        if not isinstance(entries, list):
            raise OsvResultError("has a malformed result entry")
        for package in map(osv_package, entries):
            known = packages.get(package.key)
            if known is not None:
                seen = {v.ids for v in known.vulnerabilities}
                package = known._replace(
                    vulnerabilities=known.vulnerabilities
                    + tuple(v for v in package.vulnerabilities if v.ids not in seen)
                )
            packages[package.key] = package
    return packages


def osv_group_severity(vulnerability: OsvVulnerability) -> str:
    """The severity of a vulnerability: the database rating of its records (the
    most severe if several), else the rating of the ``max_severity`` of the group,
    else UNKNOWN.
    """
    if own := [r for r in map(osv_database_rating, vulnerability.records) if r]:
        return worst_severity(own)
    return score_rating(vulnerability.max_severity)


def osv_findings(
    native: Mapping[str, Any],
) -> dict[tuple[OsvKey, tuple[str, ...]], tuple[str, bool]]:
    """Unique findings of one OSV target: (package, ids of the group) ->
    (severity, fixable).
    """
    return {
        (package.key, vulnerability.ids): (
            osv_group_severity(vulnerability),
            bool(
                osv_group_fixes(
                    vulnerability.records, package.identity, package.version
                )
            ),
        )
        for package in osv_packages(native).values()
        for vulnerability in package.vulnerabilities
    }


class PackageSighting(NamedTuple):
    """A Trivy package of a lockfile (or image layer) with its inventory."""

    result: Mapping[str, Any]
    package: Mapping[str, Any]
    index: PackageIndex


class OsvScan(NamedTuple):
    """The packages of an OSV target that have findings, with their Trivy packages."""

    tid: str
    packages: tuple[OsvPackage, ...]
    sightings: Mapping[OsvKey, list[PackageSighting]]


class OsvResolutionError(Exception):
    """An OSV result that does not fit the Trivy result of its twin target."""


def resolve_osv_scan(
    tid: str, native: Mapping[str, Any], trivy_native: Mapping[str, Any] | None
) -> OsvScan:
    """Find the Trivy package of every package of the OSV result that has findings.

    osv-scanner read the language packages of the twin Trivy target (the same id)
    as a BOM, so every package with a finding must be a package there: the one
    whose ``Identifier.PURL`` is the OSV package (ecosystem and name) and whose
    version is the OSV one, in any of its lockfiles. That package gives the
    findings their name, version, relationship, dev flag and dependency chains. A
    result that does not fit means the two parts are not of the same scan, so the
    OSV target is failed rather than guessed at.
    """
    packages = tuple(p for p in osv_packages(native).values() if p.vulnerabilities)
    if not packages:
        return OsvScan(tid, (), {})
    if trivy_native is None:
        raise OsvResolutionError("there is no trivy result of this target to join with")
    needed = {package.key for package in packages}
    found: dict[OsvKey, list[PackageSighting]] = {}
    for result in trivy_native.get("Results") or []:
        if result.get("Class") != CLASS_LANGUAGE_PACKAGES:
            continue
        trivy_packages = result.get("Packages") or []
        index = PackageIndex(trivy_packages, result.get("Type"))
        for package in trivy_packages:
            purl = (package.get("Identifier") or {}).get("PURL")
            identity = purl_identity(purl) if isinstance(purl, str) else None
            if identity and (identity, package.get("Version")) in needed:
                found.setdefault((identity, package["Version"]), []).append(
                    PackageSighting(result, package, index)
                )
    if missing := sorted(needed - found.keys()):
        (ecosystem, name), version = missing[0]
        raise OsvResolutionError(
            f"{len(missing)} package(s) with findings are not in the trivy result "
            f"of this target, first: {ecosystem} {name}@{version}"
        )
    return OsvScan(tid, packages, found)


def osv_primary_id(vulnerability: OsvVulnerability) -> str:
    """The id an OSV-only record is known by (its ``id``).

    The first CVE among the ids and aliases (in string order, the only one in
    nearly every case), else the first GHSA id, else the first id OSV reported.
    """
    for prefix in ("CVE-", "GHSA-"):
        if candidates := sorted(n for n in vulnerability.names if n.startswith(prefix)):
            return candidates[0]
    return vulnerability.ids[0]


def osv_group_cvss(vulnerability: OsvVulnerability) -> Record | None:
    """The CVSS of a vulnerability, in the shape of the Trivy ``cvss``.

    The vector is the first one of the latest CVSS version in the ``severity[]``
    of its records (4.0 over 3.x, as for Trivy; CVSS 2 vectors are ignored), the
    score is the ``max_severity`` of the group: osv-scanner computed it, so
    nothing is calculated here. It is the highest score over all the vectors of
    the group, so with both a 3.x and a 4.0 vector it may belong to the other one.
    Without a vector there is no ``cvss``.
    """
    vectors = [
        entry["score"]
        for record in vulnerability.records
        for entry in record.get("severity") or []
        if isinstance(entry.get("score"), str) and cvss_vector_version(entry["score"])
    ]
    if not vectors:
        return None
    vector = max(vectors, key=lambda v: float(cvss_vector_version(v) or 0))
    return {
        "score": vulnerability.max_severity,
        "vector": vector,
        "version": cvss_vector_version(vector),
        "source": SCANNER_OSV,
    }


def osv_group_fixes(
    records: Iterable[Mapping[str, Any]],
    identity: tuple[str, str],
    installed: str | None,
) -> list[str]:
    """The fixed versions of the package in a vulnerability, in the order of the
    records and their events (see ``osv_fixed_versions``).
    """
    fixed: list[str] = []
    for record in records:
        for version in osv_fixed_versions(record, identity, installed):
            append_unique(fixed, version)
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
    identity: tuple[str, str],
    vulnerability: OsvVulnerability,
    found: PackageSighting,
) -> Record:
    """A record for a vulnerability only OSV reports, from the OSV records of its
    ids and the Trivy package it was found in.
    """
    vuln_id, _, version = key
    records = vulnerability.records
    record = blank_record(
        repo, vuln_id, found.package.get("Name"), version, package_type(found.result)
    )
    severity = osv_group_severity(vulnerability)
    fixed = osv_group_fixes(records, identity, version)
    titles = [osv_title(r) for r in records]
    published = [r["published"] for r in records if isinstance(r.get("published"), str)]
    cwe = {cwe_id for r in records for cwe_id in osv_cwe_ids(r)}
    record.update(
        severity=severity,
        severity_source=None if severity == UNKNOWN_SEVERITY else SCANNER_OSV,
        cvss=osv_group_cvss(vulnerability),
        status="fixed" if fixed else "affected",
        fixed_versions=fixed,
        fix_available=bool(fixed),
        title=next((text for text in titles if text), None),
        cwe=sorted(cwe) or None,
        published=min(published, default=None),
        primary_url=osv_primary_url(records),
    )
    return record
