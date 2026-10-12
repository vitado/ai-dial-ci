#!/usr/bin/env python3
"""Merge the per-target scan results of an SCA scheduled scan into one report.

Inputs:
  * targets.json written by sca_resolve_targets (the list of targets);
  * a parts directory with one subdirectory per scanner (``trivy/``) holding,
    per scanned target id, ``<id>.json`` (native JSON), ``<id>.status.json``
    and an optional ``<id>.txt`` (table).

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

Trivy is the only scanner today; the report schema names the scanner wherever
another one could contribute (``scanners``, ``scanner``, ``_native/<scanner>/``).

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
import os
import re
import shutil
import sys
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_NOT_APPLICABLE = "not_applicable"

SCANNER_TRIVY = "trivy"

KIND_FS = "fs"
KIND_IMAGE = "image"
DEVELOPMENT_TAG = "development"

# Where a finding was seen: what kind of artifact a scan target is.
CLASS_RELEASE = "release"  # an image with a tag other than "development"
CLASS_DEVELOPMENT = "development"  # the "development" image
CLASS_SOURCE = "source"  # the source code (trivy fs)

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
EXPOSURE_ACTIONS = {
    EXPOSURE_RELEASE_AND_DEVELOPMENT: "Fix in development and backport",
    EXPOSURE_RELEASE_ONLY: "Release a patch (fixed in development)",
    EXPOSURE_DEVELOPMENT_ONLY: "Fix before next release",
    EXPOSURE_SOURCE_ONLY: "Not in any image (lower priority)",
}
EXPOSURE_SHORT = {
    EXPOSURE_RELEASE_AND_DEVELOPMENT: "release + development",
    EXPOSURE_RELEASE_ONLY: "release only",
    EXPOSURE_DEVELOPMENT_ONLY: "development only",
    EXPOSURE_SOURCE_ONLY: "source only",
}

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
    seen: set[str] = set()
    for target in data["targets"]:
        tid = target.get("id") if isinstance(target, dict) else None
        if not isinstance(tid, str) or not TARGET_ID_RE.fullmatch(tid):
            raise InputError(f"targets file {path} has an invalid target id: {tid!r}")
        if tid in seen:
            raise InputError(f"targets file {path} has a duplicate target id: {tid}")
        seen.add(tid)
    return data


def load_target_result(
    target: Mapping[str, Any], scanner_parts_dir: Path
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Determine the final status of one target.

    Returns ``(state, native)``: state carries ``status`` and ``reason``; native
    is the parsed trivy result for ``ok`` targets, else None. Anything short of
    a complete, valid result is ``failed`` - a broken scan must not look like a
    clean target.
    """
    tid = target["id"]
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
    if status.get("status") != STATUS_OK:
        return failed(f"unexpected scan status: {status.get('status')!r}")

    native_path = scanner_parts_dir / f"{tid}.json"
    if not native_path.is_file():
        return failed("trivy result file is missing")
    try:
        native = read_json(native_path)
    except (OSError, ValueError) as e:
        return failed(f"trivy result is not valid JSON: {e}")
    if not isinstance(native, dict):
        return failed("trivy result is not a JSON object")

    state.update(status=STATUS_OK, reason=None)
    return state, native


# --------------------------------------------------------------------------
# Analysing trivy results
# --------------------------------------------------------------------------


def relationship_index(result: Mapping[str, Any]) -> dict[tuple[Any, Any], set[str]]:
    """``(name, version) -> relationships`` from the Packages of one trivy Result.

    ``unknown`` carries no information and is left out.
    """
    index: dict[tuple[Any, Any], set[str]] = {}
    for package in result.get("Packages") or []:
        relationship = package.get("Relationship")
        if relationship and relationship != "unknown":
            key = (package.get("Name"), package.get("Version"))
            index.setdefault(key, set()).add(relationship)
    return index


def iter_findings(
    native: Mapping[str, Any],
) -> Iterator[tuple[Mapping[str, Any], Mapping[str, Any], set[str]]]:
    """Yield (trivy Result, vulnerability, relationships of its package)."""
    for result in native.get("Results") or []:
        vulns = result.get("Vulnerabilities") or []
        index = relationship_index(result) if vulns else {}
        for vuln in vulns:
            pkg_key = (vuln.get("PkgName"), vuln.get("InstalledVersion"))
            yield result, vuln, index.get(pkg_key, set())


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
    for tid, scanner, native in scans:
        for result, vuln, relationships in iter_findings(native):
            key = finding_key(result, vuln)
            record = by_key.get(key)
            if record is None:
                record = by_key[key] = new_record(repo, key, result, vuln)
            if tid in image_ids and key not in named_by_image:
                named_by_image.add(key)
                record["pkg"] = vuln.get("PkgName")
            absorb_finding(record, tid, scanner, result, vuln, relationships)
            _append_unique(
                sightings.setdefault(key, {}).setdefault(tid, []),
                result.get("Target", ""),
            )
    for record in by_key.values():
        for field in ("locations", "scanners", "ecosystem", "relationship", "aliases"):
            record[field].sort()
        record["pkg_paths"].sort()
    by_record = {
        (r["cve"], r["pkg"], r["version"]): sightings[key] for key, r in by_key.items()
    }
    return list(by_key.values()), by_record


# ---- Exposure


def target_class(target: Mapping[str, Any]) -> str | None:
    """What a scan target is: release image, development image or source code."""
    if target.get("kind") == KIND_FS:
        return CLASS_SOURCE
    if target.get("kind") == KIND_IMAGE:
        return (
            CLASS_DEVELOPMENT if target.get("tag") == DEVELOPMENT_TAG else CLASS_RELEASE
        )
    return None


def classify_exposure(classes: Collection[str], has_images: bool) -> str:
    """Exposure of a finding by the kinds of targets it was found in.

    A run without image targets (e.g. a Python package) ships its source, so a
    finding there counts as a development one.
    """
    in_release = CLASS_RELEASE in classes
    in_development = CLASS_DEVELOPMENT in classes or CLASS_SOURCE in classes
    if in_release and in_development:
        return EXPOSURE_RELEASE_AND_DEVELOPMENT
    if in_release:
        return EXPOSURE_RELEASE_ONLY
    if CLASS_DEVELOPMENT in classes:
        return EXPOSURE_DEVELOPMENT_ONLY
    if has_images:
        return EXPOSURE_SOURCE_ONLY
    return EXPOSURE_DEVELOPMENT_ONLY


def assign_exposure(records: Iterable[Record], targets: Sequence[Target]) -> None:
    by_id = {t["id"]: t for t in targets}
    has_images = any(t.get("kind") == KIND_IMAGE for t in targets)
    for record in records:
        classes = {target_class(by_id[tid]) for tid in record["scan_targets"]}
        classes.discard(None)
        record["exposure"] = classify_exposure(classes, has_images)  # type: ignore[arg-type]


def assign_upgrades(records: Sequence[Record]) -> None:
    """Set ``upgrade_to`` (same value on every record of one package version)."""
    fixed_by_package: dict[tuple[Any, Any], list[list[str]]] = {}
    for record in records:
        key = (record["pkg"], record["version"])
        fixed_by_package.setdefault(key, []).append(record["fixed_versions"])
    for record in records:
        installed = record["version"]
        fixed = fixed_by_package[(record["pkg"], installed)]
        record["upgrade_to"] = (
            upgrade_target(installed, fixed) if isinstance(installed, str) else None
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
    for result, vuln, _ in iter_findings(native):
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
        "scanner": SCANNER_TRIVY,
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
    }
    if native is not None:
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
    targets: list[dict[str, Any]] = []
    for target, state, native in results:
        entry = build_target_entry(target, state, native)
        if native is not None:
            if entry["packages_scanned"] == 0:
                print(
                    f"::warning title=No packages in scan result::{target['id']}: "
                    "0 packages were seen (an empty scan is suspicious: no lockfiles, "
                    "an unsupported ecosystem or a missing package list)"
                )
            trivy_version = trivy_version or (native.get("Trivy") or {}).get("Version")
        targets.append(entry)
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


def target_label(target: Mapping[str, Any], several_images: bool) -> str:
    """Short name: ``source @ development 3d0c8a3``, ``image :1.0``, ``app :1.0``."""
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


def development_headline(
    image_records: Sequence[Record] | None,
    source_records: Sequence[Record] | None,
) -> str | None:
    """``development — image: clean; source: 1 LOW (not in any image)``.

    ``None`` for a part means it was not scanned, so it is left out.
    """
    parts = []
    if image_records is not None:
        counts = count_by_severity(r["severity"] for r in image_records)
        parts.append(f"image: {format_severity_counts(counts) or 'clean'}")
    if source_records is not None:
        counts = count_by_severity(r["severity"] for r in source_records)
        text = f"source: {format_severity_counts(counts) or 'clean'}"
        outside = sum(r["exposure"] == EXPOSURE_SOURCE_ONLY for r in source_records)
        if outside == len(source_records) and outside:
            text += " (not in any image)"
        elif outside:
            text += f" ({outside} not in any image)"
        parts.append(text)
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
    ok_targets = [t for t in report["targets"] if t["status"] == STATUS_OK]
    packages = sum(t["packages_scanned"] or 0 for t in ok_targets)
    return (
        f"No known vulnerabilities · {packages} packages in {len(ok_targets)} targets"
    )


def headline_lines(report: Mapping[str, Any], records: Sequence[Record]) -> list[str]:
    """One line per group: failures, each released tag, development, totals."""
    targets = report["targets"]
    lines: list[str] = []
    failed = [t["id"] for t in targets if t["status"] == STATUS_FAILED]
    if failed:
        lines.append(
            f"**Incomplete: {len(failed)} target(s) failed** — {', '.join(failed)} "
            "(their findings are missing)"
        )
    ok = [t for t in targets if t["status"] == STATUS_OK]
    if not ok:
        return [*lines, "No target was scanned"]
    if not records:
        return [*lines, no_findings_line(report)]

    by_class: dict[str, list[Mapping[str, Any]]] = {}
    for target in ok:
        by_class.setdefault(target_class(target) or "", []).append(target)
    development_images = by_class.get(CLASS_DEVELOPMENT)
    sources = by_class.get(CLASS_SOURCE)
    development_scanned = bool(development_images or sources)

    release_tags: dict[str, set[str]] = {}
    for target in by_class.get(CLASS_RELEASE, []):
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
    families = sorted(
        {ECOSYSTEM_FAMILIES.get(e, e) for r in group for e in r["ecosystem"]}
    )
    if families:
        text += f" · {'/'.join(families)}"
    relationships = {rel for r in group for rel in r["relationship"]}
    if "indirect" in relationships and "direct" not in relationships:
        text += ", indirect"
    if first["pkg_type"] == "os":
        text += " (base image)"
    return text


def upgrade_cell(group: Sequence[Record]) -> str:
    version = group[0]["version"]
    upgrade = group[0]["upgrade_to"]
    if upgrade:
        return f"{version} → {upgrade}"
    if all(r["fix_available"] for r in group):
        fixed = sorted({f for r in group for f in r["fixed_versions"]})
        return f"{version} → {', '.join(fixed)}"
    return f"{version} → no fix"


def where_cell(
    group: Sequence[Record],
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
) -> str:
    """Where a group was found: tags per image, then the source lockfiles.

    ``statgpt-chat :development, :0.17.7 · statgpt-admin :development · source
    poetry.lock``; a run with one image calls it ``image``.
    """
    several = has_several_images(targets)
    tags: dict[str, list[str]] = {}
    locations: list[str] = []
    for target in targets:
        for record in group:
            seen = sightings.get((record["cve"], record["pkg"], record["version"]), {})
            if target["id"] not in seen:
                continue
            if target.get("kind") == KIND_FS:
                locations.extend(seen[target["id"]])
            else:
                name = image_short_name(target) if several else "image"
                _append_unique(tags.setdefault(name, []), f":{target.get('tag')}")
    parts = [f"{name} {', '.join(names)}" for name, names in tags.items()]
    if locations:
        shown = sorted(set(locations))
        text = "source " + ", ".join(shown[:MAX_LISTED_LOCATIONS])
        if len(shown) > MAX_LISTED_LOCATIONS:
            text += f" +{len(shown) - MAX_LISTED_LOCATIONS} more"
        parts.append(text)
    return " · ".join(parts)


def render_what_to_fix(
    records: Sequence[Record],
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
) -> list[str]:
    rows = []
    for number, group in enumerate(group_fixes(records), start=1):
        counts = count_by_severity(r["severity"] for r in group)
        rows.append(
            [
                number,
                EXPOSURE_ACTIONS[group[0]["exposure"]],
                package_cell(group),
                upgrade_cell(group),
                format_severity_counts(counts, ", "),
                where_cell(group, sightings, targets),
            ]
        )
    header = ["#", "Action", "Package", "Upgrade", "Resolves", "Where"]
    return ["## What to fix", "", *md_table(header, rows, right=(0,))]


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


def render_severity_section(severity: str, records: Sequence[Record]) -> list[str]:
    rows = (
        [
            cve_cell(r),
            r["pkg"],
            installed_to_fixed_cell(r),
            cvss_cell(r),
            (r["published"] or "")[:10],
            EXPOSURE_SHORT[r["exposure"]],
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


def render_severity_sections(records: Sequence[Record]) -> list[str]:
    lines: list[str] = []
    for severity in SEVERITIES:
        selected = [r for r in records if r["severity"] == severity]
        if selected:
            lines += ["", *render_severity_section(severity, selected)]
    return lines


def render_no_fix(records: Sequence[Record]) -> list[str]:
    unfixed = [r for r in records if not r["fix_available"]]
    if not unfixed:
        return []
    rows = (
        [
            r["cve"],
            r["pkg"],
            r["version"],
            r["severity"],
            r["status"],
            short_title(r),
        ]
        for r in unfixed
    )
    body = md_table(
        ["CVE", "Package", "Installed", "Severity", "Status", "Title"], rows
    )
    return ["", *md_details(f"No fix available ({len(unfixed)})", body)]


def severity_cells(findings: Mapping[str, Any] | None) -> list[Any]:
    by_severity = (findings or {}).get("by_severity")
    return [by_severity[s] if by_severity else None for s in SEVERITIES[:4]]


def render_coverage(targets: Sequence[Mapping[str, Any]]) -> list[str]:
    several = has_several_images(targets)
    rows = (
        [
            target_label(t, several),
            t["status"],
            t["packages_scanned"],
            *severity_cells(t["findings"]),
            t["reason"],
        ]
        for t in targets
    )
    header = ["Target", "Status", "Packages", "C", "H", "M", "L", "Note"]
    body = md_table(header, rows, right=(2, 3, 4, 5, 6))
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
    return ["", f"<sub>{' · '.join(parts)}</sub>"]


def build_summary_md(
    report: Mapping[str, Any], vulns: Mapping[str, Any], sightings: Sightings
) -> str:
    records = vulns["records"]
    targets = report["targets"]
    lines = [f"# SCA · {md_cell(report['repo'])}", ""]
    lines += render_headline(headline_lines(report, records))
    if records:
        lines += ["", *render_what_to_fix(records, sightings, targets)]
        lines += render_severity_sections(records)
        lines += render_no_fix(records)
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
    native_dir = output_dir / "_native" / SCANNER_TRIVY
    # Parts are namespaced by scanner: <parts-dir>/<scanner>/<id>.*
    scanner_parts_dir = parts_dir / SCANNER_TRIVY
    report_dir.mkdir(parents=True, exist_ok=True)
    native_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for target in targets_doc["targets"]:
        state, native = load_target_result(target, scanner_parts_dir)
        results.append((target, state, native))
        copy_native(scanner_parts_dir, target["id"], native_dir)

    ok_scans = [
        (t["id"], SCANNER_TRIVY, native)
        for t, _, native in results
        if native is not None
    ]
    repo = targets_doc.get("repo")
    image_ids = {t["id"] for t in targets_doc["targets"] if t.get("kind") == KIND_IMAGE}
    merged, sightings = merge_records(repo, ok_scans, image_ids)
    records = finalize_records(merged, targets_doc["targets"])
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
        print(f"::error title=Scan target failed::{t['id']}: {t['reason']}")
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
