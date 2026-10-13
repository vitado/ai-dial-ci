"""Tests of actions/sca_merge_results/records.py (synthetic fixtures only)."""

from __future__ import annotations

import pytest
from records import (
    assign_upgrades,
    classify_exposure,
    cve_of,
    minimal_fix,
    record_sort_key,
    release_class,
    target_class,
    upgrade_target,
)
from test_merge_results import DEV, REL, RELEASE_SOURCE, SOURCE, Record


def test_record_sort_key_orders_exposure_severity_cvss_then_identity() -> None:
    def record(
        vuln_id: str, exposure: str, severity: str, score: float | None
    ) -> Record:
        return {
            "exposure": exposure,
            "severity": severity,
            "cvss": None if score is None else {"score": score},
            "pkg": "p",
            "version": "1",
            "id": vuln_id,
        }

    records = [
        record("E", "source_only", "CRITICAL", 9.8),
        record("D", "release_only", "HIGH", None),
        record("C", "release_only", "HIGH", 7.0),
        record("B", "release_only", "HIGH", 8.0),
        record("A", "release_and_development", "LOW", 1.0),
        record("F", "release_only", "HIGH", 8.0),
    ]
    ordered = sorted(records, key=record_sort_key)
    assert [r["id"] for r in ordered] == ["A", "B", "F", "C", "D", "E"]


@pytest.mark.parametrize(
    ("classes", "has_images", "expected"),
    [
        ({"release", "development"}, True, "release_and_development"),
        ({"release", "source"}, True, "release_and_development"),
        ({"release", "development", "source"}, True, "release_and_development"),
        ({"release"}, True, "release_only"),
        ({"development"}, True, "development_only"),
        ({"development", "source"}, True, "development_only"),
        ({"source"}, True, "source_only"),
        ({"source"}, False, "development_only"),
    ],
)
def test_classify_exposure(classes: set[str], has_images: bool, expected: str) -> None:
    assert classify_exposure(classes, has_images) == expected


def test_target_class() -> None:
    assert target_class(SOURCE) == "source"
    assert target_class(DEV) == "development"
    assert target_class(REL) == "release"
    assert target_class({"kind": "other"}) is None


@pytest.mark.parametrize(
    ("installed", "fixed", "expected"),
    [
        ("15.5.24", ["15.5.27", "16.3.8"], "15.5.27"),
        ("15.5.24", ["16.3.8", "15.5.27"], "15.5.27"),
        ("1.3.2-r0", ["1.3.2-r1"], "1.3.2-r1"),
        ("2.0", ["1.9", "2.0"], None),
        ("2.0", [], None),
        ("1.0", ["weird"], None),
    ],
)
def test_minimal_fix(installed: str, fixed: list[str], expected: str | None) -> None:
    assert minimal_fix(installed, fixed) == expected


@pytest.mark.parametrize(
    ("installed", "fixed_per_cve", "expected"),
    [
        ("15.5.24", [["15.5.27", "16.3.8"]], "15.5.27"),
        ("1.3.2-r0", [["1.3.2-r1"]], "1.3.2-r1"),
        ("2.7.0", [["2.8.0"], ["2.9.1"]], "2.9.1"),
        ("2.7.0", [["2.9.1"], ["2.8.0"]], "2.9.1"),
        ("2.7.0", [["2.8.0"], []], None),
        ("2.7.0", [], None),
        ("2.7.0", [["x"]], None),
    ],
)
def test_upgrade_target(
    installed: str, fixed_per_cve: list[list[str]], expected: str | None
) -> None:
    assert upgrade_target(installed, fixed_per_cve) == expected


def test_target_class_of_release_source() -> None:
    assert target_class(RELEASE_SOURCE) == "release_source"
    assert target_class(SOURCE) == "source"
    assert release_class(True) == "release"
    assert release_class(False) == "release_source"


@pytest.mark.parametrize(
    ("classes", "expected"),
    [
        # a finding seen in an image keeps the classification of the images, the
        # source of a release tag changes nothing
        ({"release", "release_source"}, "release_only"),
        ({"release", "release_source", "source"}, "release_and_development"),
        ({"release", "development", "release_source"}, "release_and_development"),
        ({"development", "release_source"}, "development_only"),
        ({"development", "source", "release_source"}, "development_only"),
        ({"release", "source"}, "release_and_development"),
        # seen only in sources: never above source_only
        ({"release_source"}, "source_only"),
        ({"release_source", "source"}, "source_only"),
        ({"source"}, "source_only"),
    ],
)
def test_classify_exposure_with_images_and_release_sources(
    classes: set[str], expected: str
) -> None:
    assert classify_exposure(classes, True) == expected


@pytest.mark.parametrize(
    ("classes", "expected"),
    [
        ({"release_source", "source"}, "release_and_development"),
        ({"release_source"}, "release_only"),
        ({"source"}, "development_only"),
    ],
)
def test_classify_exposure_without_images_is_decided_by_the_sources(
    classes: set[str], expected: str
) -> None:
    assert classify_exposure(classes, False) == expected


@pytest.mark.parametrize(
    ("vuln_id", "aliases", "expected"),
    [
        ("CVE-2030-1", ["GHSA-aaaa-aaaa-aaaa", "CVE-2030-0"], "CVE-2030-1"),
        ("GHSA-aaaa-aaaa-aaaa", ["CVE-2030-2", "CVE-2030-1"], "CVE-2030-1"),
        ("DSA-5000-1", ["CVE-2030-9"], "CVE-2030-9"),
        ("TEMP-0000-ABC", [], None),
        ("RUSTSEC-2030-0001", ["GHSA-aaaa-aaaa-aaaa"], None),
    ],
)
def test_the_cve_of_a_record_is_its_id_or_the_first_cve_of_its_aliases(
    vuln_id: str, aliases: list[str], expected: str | None
) -> None:
    assert cve_of({"id": vuln_id, "aliases": aliases}) == expected


def test_a_cve_fixed_in_place_does_not_hold_back_the_upgrade_of_the_others() -> None:
    def record(vuln_id: str, fixed: list[str]) -> Record:
        return {
            "id": vuln_id,
            "pkg": "lib",
            "version": "1.0",
            "fix_available": True,
            "fixed_versions": fixed,
        }

    records = [record("CVE-1", ["1.1"]), record("CVE-2", ["2.0"])]
    assign_upgrades(records, {("CVE-1", "lib", "1.0")})
    assert [r["upgrade_to"] for r in records] == [None, "2.0"]
    assign_upgrades(records)
    assert [r["upgrade_to"] for r in records] == ["2.0", "2.0"]
