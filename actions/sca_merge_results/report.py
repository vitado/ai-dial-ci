"""The machine-readable reports of the SCA merge: ``vulnerabilities.json`` and
``scan_report.json`` (their contract).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any

from _sca_lib.gha import escape_command_data
from early_warning_merge import EarlyWarning
from osv_source import osv_findings, osv_packages
from records import (
    EXPOSURES,
    KIND_IMAGE,
    SCANNER_OSV,
    SCANNER_TRIVY,
    SEVERITIES,
    STATUS_FAILED,
    STATUS_NOT_APPLICABLE,
    STATUS_OK,
    FindingKey,
    Record,
    Target,
    default_config,
    target_name,
)
from trivy_source import (
    count_packages,
    finding_key,
    image_digest,
    iter_findings,
    normalize_severity,
    split_fixed_versions,
)

SCHEMA_VERSION = 1
TRIVY_DB_KEYS = ("vulnerability_db_updated_at", "java_db_updated_at")


# The vulnerability DB is built daily; a snapshot older than this is reported
TRIVY_DB_STALE_DAYS = 2


MERGE_KEY = (
    "(repo, id x package x installed-version), merged across scan_targets and "
    "scanners; id is the one Trivy reports, for a vulnerability only OSV knows its "
    "first CVE, else its first GHSA id, else its first id"
)


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
        "packages_unread": None,
    }
    if native is None:
        return entry
    if target["scanner"] == SCANNER_OSV:
        entry["packages_scanned"] = len(osv_packages(native))
        entry["findings"] = finding_stats(osv_findings(native).values())
        entry["queried_at"] = state.get("queried_at")
        entry["packages_unread"] = state.get("packages_unread")
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
    early_warning: EarlyWarning | None = None,
) -> dict[str, Any]:
    trivy_version = None
    osv_scanner_version = None
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
                    + escape_command_data(
                        f"{target_name(target)}: "
                        "0 packages were seen (an empty scan is suspicious: no "
                        "lockfiles, an unsupported ecosystem or a missing package list)"
                    )
                )
            if target["scanner"] == SCANNER_OSV:
                osv_scanner_version = osv_scanner_version or state.get(
                    "scanner_version"
                )
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
        "osv": {"scanner_version": osv_scanner_version} if has_osv else None,
        "early_warning": early_warning.report if early_warning else None,
        "run_kind": targets_doc["run_kind"],
        "run_kind_reasons": targets_doc["run_kind_reasons"],
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


def trivy_db_age_days(
    trivy_db: Mapping[str, str | None] | None, generated_utc: str
) -> int | None:
    """Whole days between the update of the vulnerability DB snapshot and the report;
    None if either is unknown. Only the vulnerability DB is judged: it is the one
    that is built daily.
    """
    # Trivy writes nanoseconds and the zone as Z: the first 19 characters are enough
    try:
        updated = datetime.strptime(
            ((trivy_db or {}).get("vulnerability_db_updated_at") or "")[:19],
            "%Y-%m-%dT%H:%M:%S",
        )
        generated = datetime.strptime((generated_utc or "")[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    return (generated - updated).days


def trivy_db_stale_days(
    trivy_db: Mapping[str, str | None] | None, generated_utc: str
) -> int | None:
    """The age in days of a Trivy DB snapshot that is too old, else None."""
    age = trivy_db_age_days(trivy_db, generated_utc)
    return age if age is not None and age >= TRIVY_DB_STALE_DAYS else None


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
        print(
            "::warning title=Trivy DB info ignored::not valid JSON: "
            + escape_command_data(e)
        )
        return info
    if not isinstance(parsed, dict):
        print("::warning title=Trivy DB info ignored::not a JSON object")
        return info
    for key in TRIVY_DB_KEYS:
        value = parsed.get(key)
        info[key] = value if isinstance(value, str) and value else None
    return info
