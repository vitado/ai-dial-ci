"""The early warning of the SCA merge: the radar matched with the findings."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from _sca_lib.jsonio import read_json
from records import (
    SEV_ORDER,
    STATUS_FAILED,
    STATUS_OK,
    NotShipped,
    Record,
    Sightings,
    Target,
    append_unique,
    assign_exposure,
    record_identity,
    record_ids,
)
from trivy_source import normalize_severity

STATUS_SKIPPED = "skipped"
EARLY_WARNING_DIR = "early-warning"
EARLY_WARNING_SCHEMA_VERSION = 1
CVE_RECORD_URL = "https://www.cve.org/CVERecord?id="
EARLY_WARNING_COLLAPSE_ABOVE = 5
EARLY_WARNING_GAPS_LISTED = 5
ADP_SOURCE_PREFIX = "adp:"


# How the part matched a candidate, strongest first (see sca_early_warning)
EARLY_WARNING_MATCHES = ("package_name", "source_repo", "product_name", "repo_module")


HEADLINE_SEVERITIES = ("CRITICAL", "HIGH")


# The fields of an entry of _report/early_warning.json
EARLY_WARNING_ENTRY_KEYS = (
    "cve",
    "aliases",
    "cna",
    "published",
    "updated",
    "title",
    "package",
    "affected_range",
    "match",
    "severity",
    "severity_source",
    "cvss",
    "cvss_v4",
    "exploitation",
    "scan_targets",
    "locations",
    "exposure",
)


class EarlyWarningPartError(Exception):
    """The early warning part does not hold a usable result."""


@dataclass
class EarlyWarning:
    """The early warning of a run.

    ``report`` is ``scan_report.json: early_warning``, ``document`` is
    ``_report/early_warning.json``. ``entries`` are the reported early warnings, one
    per CVE and package version, shaped like records (``pkg``, ``version``,
    ``scan_targets``, ``exposure``) so that the summary can reuse the exposure and
    location texts; ``sightings`` says where each was seen, as for records. ``gaps``
    are the hours of the window for which the CVE feed had no delta, as texts.
    """

    report: dict[str, Any]
    document: dict[str, Any]
    entries: list[Record] = field(default_factory=list)
    sightings: Sightings = field(default_factory=dict)
    gaps: list[str] = field(default_factory=list)


def early_warning_report(
    status: str,
    reason: str | None,
    window_days: int | None = None,
    records_scanned: int | None = None,
    candidates: int | None = None,
    reported: int | None = None,
    packages: int | None = None,
    index: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "reason": reason,
        "window_days": window_days,
        "records_scanned": records_scanned,
        "candidates": candidates,
        "reported": reported,
        "packages": packages,
        "index": index,
    }


def early_warning_index(status: Mapping[str, Any]) -> dict[str, Any] | None:
    """The CVE index the part was made from (``ref``, ``digest``, ``built_at``,
    ``gaps``: ranges of hours without a feed delta, ``stale``: the index was built
    long before the run); None if the part has none.
    """
    index = status.get("index")
    if index is None:
        return None
    try:
        return {
            "ref": str(index["ref"]),
            "digest": index.get("digest"),
            "built_at": str(index["built_at"]),
            "gaps": [
                {"from": str(g["from"]), "to": str(g["to"])} for g in index["gaps"]
            ],
            "stale": bool(index.get("stale")),
        }
    except (KeyError, TypeError, AttributeError) as e:
        raise EarlyWarningPartError(
            f"the early warning index is not valid ({e!r})"
        ) from e


def early_warning_without_entries(
    repo: str | None,
    generated_utc: str,
    report: dict[str, Any],
    generated_from: Any = None,
) -> EarlyWarning:
    document = {
        "schema_version": EARLY_WARNING_SCHEMA_VERSION,
        "repo": repo,
        "generated_utc": generated_utc,
        "generated_from": generated_from,
        "status": report["status"],
        "reason": report["reason"],
        "entries": [],
    }
    return EarlyWarning(report, document)


def load_early_warning_part(part_dir: Path) -> tuple[dict[str, Any], Any, list[Any]]:
    """``(status document, generated_from, candidates)`` of the part; the last two
    only for an ``ok`` part. Raises EarlyWarningPartError for a part that is missing
    or does not hold what the action writes.
    """
    try:
        status = read_json(part_dir / "status.json")
    except (OSError, ValueError) as e:
        raise EarlyWarningPartError(
            f"the early warning part is missing or unreadable ({e})"
        ) from e
    if not isinstance(status, dict) or status.get("status") not in (
        STATUS_OK,
        STATUS_FAILED,
        STATUS_SKIPPED,
    ):
        raise EarlyWarningPartError("the early warning part has no valid status")
    if status["status"] != STATUS_OK:
        return status, None, []
    try:
        document = read_json(part_dir / "candidates.json")
    except (OSError, ValueError) as e:
        raise EarlyWarningPartError(
            f"the early warning candidates are missing or unreadable ({e})"
        ) from e
    candidates = document.get("candidates") if isinstance(document, dict) else None
    if (
        document.get("schema_version") != EARLY_WARNING_SCHEMA_VERSION
        or not isinstance(candidates, list)
        or not all(isinstance(c, dict) for c in candidates)
    ):
        raise EarlyWarningPartError("the early warning candidates are not valid")
    return status, document.get("generated_from"), candidates


def early_warning_match(match: Any) -> str:
    """How a candidate was matched, as the part wrote it. TypeError if it is not one
    of ``EARLY_WARNING_MATCHES``.
    """
    if match not in EARLY_WARNING_MATCHES:
        raise TypeError(f"unknown match {match!r}")
    return match


def early_warning_entry(
    candidate: Mapping[str, Any], target_order: Mapping[str, int]
) -> tuple[Record, dict[str, list[str]]]:
    """An entry (record-shaped) and its sightings from a candidate of the part."""
    try:
        package = candidate["package"]
        sightings = {
            str(tid): [str(loc) for loc in locations]
            for tid, locations in candidate["sightings"].items()
        }
        entry: Record = {
            "cve": candidate["cve"],
            "aliases": list(candidate.get("aliases") or []),
            "cna": candidate.get("cna"),
            "published": candidate.get("published"),
            "updated": candidate.get("updated"),
            "title": candidate.get("title"),
            "package": {
                "ecosystem": package["ecosystem"],
                "name": package["name"],
                "version": package["version"],
            },
            "affected_range": candidate.get("affected_range"),
            "match": early_warning_match(candidate["match"]),
            "severity": normalize_severity(candidate.get("severity")),
            "severity_source": candidate.get("severity_source"),
            "cvss": candidate.get("cvss"),
            "cvss_v4": candidate.get("cvss_v4"),
            "exploitation": candidate.get("exploitation"),
        }
    except (KeyError, TypeError, AttributeError) as e:
        raise EarlyWarningPartError(f"a candidate is not valid ({e!r})") from e
    unknown = [tid for tid in sightings if tid not in target_order]
    if not sightings or unknown:
        raise EarlyWarningPartError(
            "the early warning part does not fit the targets of the run"
        )
    scan_targets = sorted(sightings, key=target_order.__getitem__)
    locations: list[str] = []
    for tid in scan_targets:
        for location in sightings[tid]:
            append_unique(locations, location)
    entry.update(
        scan_targets=scan_targets,
        locations=locations,
        exposure=None,
        # What the shared texts of the summary read from a record
        id=entry["cve"],
        pkg=entry["package"]["name"],
        version=entry["package"]["version"],
        dev=None,
    )
    return entry, sightings


def early_warning_sort_key(entry: Record) -> tuple[Any, ...]:
    """Severity, then CVSS score (highest first, none last)."""
    score = (entry["cvss"] or {}).get("score")
    return (
        SEV_ORDER.get(entry["severity"], len(SEV_ORDER)),
        score is None,
        -(score or 0),
    )


def order_early_warning(entries: list[Record]) -> None:
    """Severity, CVSS score, newest publication, package, CVE (stable sorts, the
    least significant key first).
    """
    entries.sort(key=lambda e: (e["pkg"], e["version"], e["cve"]))
    entries.sort(key=lambda e: e["published"] or "", reverse=True)
    entries.sort(key=early_warning_sort_key)


def early_warning_groups(entries: Iterable[Record]) -> list[list[Record]]:
    """The entries per package version, in the order of the first of each."""
    groups: dict[tuple[Any, Any], list[Record]] = {}
    for entry in entries:
        groups.setdefault((entry["pkg"], entry["version"]), []).append(entry)
    return list(groups.values())


def build_early_warning(
    part_dir: Path,
    repo: str | None,
    generated_utc: str,
    records: Sequence[Record],
    targets: Sequence[Target],
    scanned: bool,
    not_shipped: NotShipped | None = None,
) -> EarlyWarning:
    """The early warning of a run whose records are final.

    A candidate whose CVE id or alias is the ``id`` or an alias of any record is
    dropped: a scanner reports that vulnerability. The rest are classified by
    exposure like records. ``scanned`` says whether any Trivy target was scanned; if
    not there is nothing to check and the early warning is ``skipped``. A part that
    is missing or broken makes it ``failed``, never an empty result.
    """
    if not scanned:
        report = early_warning_report(STATUS_SKIPPED, "no Trivy target was scanned")
        return early_warning_without_entries(repo, generated_utc, report)
    try:
        status, generated_from, candidates = load_early_warning_part(part_dir)
        index_info = early_warning_index(status)
        if status["status"] != STATUS_OK:
            report = early_warning_report(
                status["status"],
                status.get("reason"),
                status.get("window_days"),
                index=index_info,
            )
            return early_warning_without_entries(repo, generated_utc, report)
        if index_info is None:
            raise EarlyWarningPartError("the early warning part has no index")
        known = {i.upper() for r in records for i in record_ids(r) if i}
        target_order = {t["id"]: index for index, t in enumerate(targets)}
        entries: list[Record] = []
        sightings: Sightings = {}
        for candidate in candidates:
            entry, seen = early_warning_entry(candidate, target_order)
            if known & {i.upper() for i in (entry["cve"], *entry["aliases"]) if i}:
                continue
            entries.append(entry)
            sightings[record_identity(entry)] = seen
    except EarlyWarningPartError as e:
        report = early_warning_report(STATUS_FAILED, str(e))
        return early_warning_without_entries(repo, generated_utc, report)
    assign_exposure(entries, targets, sightings, not_shipped)
    order_early_warning(entries)
    report = early_warning_report(
        STATUS_OK,
        None,
        status.get("window_days"),
        status.get("records_scanned"),
        len(candidates),
        len(entries),
        len(early_warning_groups(entries)),
        index_info,
    )
    result = early_warning_without_entries(repo, generated_utc, report, generated_from)
    result.document["entries"] = [
        {key: entry[key] for key in EARLY_WARNING_ENTRY_KEYS} for entry in entries
    ]
    result.entries = entries
    result.sightings = sightings
    result.gaps = [f"{g['from']} to {g['to']}" for g in index_info["gaps"]]
    return result
