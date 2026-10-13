"""CRITICAL / HIGH early warnings in shipped artifacts and the verdict of summary.md
(synthetic fixtures only)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from test_early_warning_merge import candidate, write_part
from test_merge_results import (
    DEV,
    PACKAGES_NATIVE_CLEAN,
    REL,
    SOURCE,
    Workspace,
    make_targets_doc,
    mr,
)

IN_DEVELOPMENT_IMAGE = {"app-development": ["Java"]}
IN_SOURCE = {"source-development": ["gradle.lockfile"]}


@pytest.fixture
def clean(tmp_path: Path) -> Workspace:
    """Source, development image and release image, all clean."""
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, DEV, REL))
    for tid in ("source-development", "app-development", "app-1.0.0"):
        ws.add_part(tid, None)
        (ws.trivy_parts / f"{tid}.json").write_text(
            json.dumps(PACKAGES_NATIVE_CLEAN), encoding="utf-8"
        )
    return ws


def verdict(ws: Workspace, candidates: list[dict[str, Any]]) -> str:
    write_part(ws, candidates)
    assert ws.run(early_warning_enabled=True) == 0
    text = (ws.out / "summary.md").read_text(encoding="utf-8")
    (line,) = [x for x in text.splitlines() if x.startswith("> **")]
    return line.removeprefix("> **").removesuffix("**")


def test_a_clean_verdict_says_it_is_about_the_databases_when_a_high_early_warning_ships(
    clean: Workspace,
) -> None:
    assert verdict(clean, [candidate(sightings=IN_DEVELOPMENT_IMAGE)]) == (
        "No known vulnerabilities in vulnerability databases for 1.0.0 and development"
        " — 1 HIGH early warning to verify"
    )


def test_the_clean_verdict_is_unchanged_without_early_warnings(
    clean: Workspace,
) -> None:
    assert verdict(clean, []) == "No known vulnerabilities in 1.0.0 and development"


def test_a_medium_early_warning_does_not_change_a_clean_verdict(
    clean: Workspace,
) -> None:
    candidates = [
        candidate(severity="MEDIUM", score=5.0, sightings=IN_DEVELOPMENT_IMAGE),
        candidate("CVE-2030-0002", severity="LOW", score=2.0),
    ]
    assert verdict(clean, candidates) == (
        "No known vulnerabilities in 1.0.0 and development"
    )


def test_an_early_warning_without_a_severity_does_not_change_a_clean_verdict(
    clean: Workspace,
) -> None:
    candidates = [
        candidate(severity="UNKNOWN", score=None, sightings=IN_DEVELOPMENT_IMAGE)
    ]
    assert verdict(clean, candidates) == (
        "No known vulnerabilities in 1.0.0 and development"
    )


def test_an_early_warning_in_the_source_only_does_not_change_a_clean_verdict(
    clean: Workspace,
) -> None:
    candidates = [candidate("CVE-2030-0001", severity="CRITICAL", sightings=IN_SOURCE)]
    assert verdict(clean, candidates) == (
        "No known vulnerabilities in 1.0.0 and development"
    )


def test_the_early_warnings_are_counted_per_package_by_their_worst_severity(
    clean: Workspace,
) -> None:
    guava = {
        "ecosystem": "maven",
        "name": "com.google.guava:guava",
        "version": "33.4.8-jre",
    }
    other = {"ecosystem": "npm", "name": "left-pad", "version": "1.0.0"}
    candidates = [
        candidate("CVE-2030-0001", package=guava, sightings=IN_DEVELOPMENT_IMAGE),
        candidate(
            "CVE-2030-0002",
            package=guava,
            severity="CRITICAL",
            score=9.8,
            sightings=IN_DEVELOPMENT_IMAGE,
        ),
        candidate("CVE-2030-0003", package=other, sightings={"app-1.0.0": ["Java"]}),
    ]
    assert verdict(clean, candidates).endswith(
        " — 1 CRITICAL, 1 HIGH early warnings to verify"
    )


def test_the_early_warning_never_makes_a_fix_clause_or_counts_in_the_scope(
    clean: Workspace,
) -> None:
    write_part(clean, [candidate(sightings=IN_DEVELOPMENT_IMAGE)])
    assert clean.run(early_warning_enabled=True) == 0
    text = (clean.out / "summary.md").read_text(encoding="utf-8")
    assert "Fix " not in text.split("## ")[0]
    assert "| Scope |" not in text
    assert clean.json("_report/scan_report.json")["totals"]["findings"]["total"] == 0


def test_a_verdict_with_a_high_clause_gets_nothing_added(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, DEV, REL))
    ws.add_part("source-development", "source", lockfiles=3)
    ws.add_part("app-development", "app-development")
    ws.add_part("app-1.0.0", "app-1.0.0")
    text = verdict(ws, [candidate(sightings=IN_DEVELOPMENT_IMAGE)])
    assert text == (
        "Fix 1 HIGH in development before the next release. "
        "Fix 1 MEDIUM in development and backport to release-1.0"
    )
    # only the headline carries the early warning
    assert "1 early warning (1 HIGH)" in (ws.out / "summary.md").read_text(
        encoding="utf-8"
    )


def make_record(**fields: Any) -> dict[str, Any]:
    record = mr.blank_record("example/app", "CVE-2000-1", "pkg", "1", "library")
    record.update(
        scan_targets=["app-development"],
        exposure="development_only",
        severity="MEDIUM",
        fix_available=True,
    )
    record.update(fields)
    return record


def early_warning_of(*severities: str, exposure: str = "development_only") -> Any:
    entries = []
    for index, severity in enumerate(severities):
        entries.append(
            {
                "cve": f"CVE-2030-{index}",
                "id": f"CVE-2030-{index}",
                "severity": severity,
                "exposure": exposure,
                "pkg": f"p{index}",
                "version": "1",
            }
        )
    report = mr.early_warning_report(mr.STATUS_OK, None)
    return mr.EarlyWarning(report, {}, entries)


@pytest.fixture
def report() -> dict[str, Any]:
    return {
        "targets": [
            {**SOURCE, "scanner": "trivy", "status": "ok"},
            {**DEV, "scanner": "trivy", "status": "ok"},
        ]
    }


def test_a_verdict_with_only_medium_clauses_carries_the_caveat(
    report: dict[str, Any],
) -> None:
    text = mr.verdict_text(
        report, [make_record()], early_warning=early_warning_of("HIGH")
    )
    assert text == (
        "Fix 1 MEDIUM in development before the next release"
        " · 1 HIGH early warning to verify"
    )


def test_a_nothing_to_upgrade_verdict_with_only_medium_findings_carries_the_caveat(
    report: dict[str, Any],
) -> None:
    record = make_record(fix_available=False)
    text = mr.verdict_text(report, [record], early_warning=early_warning_of("CRITICAL"))
    assert text == (
        "Nothing to upgrade — 1 MEDIUM without a fix, see watch"
        " · 1 CRITICAL early warning to verify"
    )


def test_a_verdict_with_a_critical_or_high_action_or_watch_gets_nothing_added(
    report: dict[str, Any],
) -> None:
    warning = early_warning_of("HIGH")
    actionable = make_record(severity="HIGH")
    assert "early warning" not in mr.verdict_text(
        report, [actionable], early_warning=warning
    )
    unfixed = make_record(severity="CRITICAL", fix_available=False)
    assert "early warning" not in mr.verdict_text(
        report, [unfixed], early_warning=warning
    )


def test_early_warnings_in_the_source_only_or_unavailable_add_nothing(
    report: dict[str, Any],
) -> None:
    source_only = early_warning_of("CRITICAL", exposure="source_only")
    assert mr.shipped_early_warning_text(source_only) is None
    failed = early_warning_of("CRITICAL")
    failed.report = mr.early_warning_report(mr.STATUS_FAILED, "feed down")
    assert mr.shipped_early_warning_text(failed) is None
    assert mr.shipped_early_warning_text(None) is None
    assert mr.verdict_text(report, [], early_warning=failed) == (
        "No known vulnerabilities in development"
    )
