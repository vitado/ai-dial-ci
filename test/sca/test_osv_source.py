"""Tests of actions/sca_merge_results/osv_source.py (synthetic fixtures only)."""

from __future__ import annotations

from typing import Any

import pytest
from osv_source import (
    osv_database_rating,
    osv_findings,
    osv_fixed_versions,
    osv_group_fixes,
    osv_group_severity,
    osv_packages,
    osv_primary_id,
    osv_score,
    osv_title,
    purl_identity,
    score_rating,
)
from test_merge_results import (
    affected_range,
    osv_native,
    osv_part,
    osv_record,
    vulnerabilities,
    vulnerability,
)


def test_osv_database_rating_maps_moderate_to_medium() -> None:
    def rating(value: Any) -> str | None:
        return osv_database_rating({"database_specific": {"severity": value}})

    assert [
        rating(v) for v in ("MODERATE", "moderate", "MEDIUM", "HIGH", "CRITICAL", "LOW")
    ] == ["MEDIUM", "MEDIUM", "MEDIUM", "HIGH", "CRITICAL", "LOW"]
    assert [rating(v) for v in ("BOGUS", 7, None, "UNKNOWN")] == [None] * 4
    assert osv_database_rating({"database_specific": None}) is None
    assert osv_database_rating({}) is None


@pytest.mark.parametrize(
    ("score", "rating"),
    [
        (10.0, "CRITICAL"),
        (9.0, "CRITICAL"),
        (8.9, "HIGH"),
        (7.0, "HIGH"),
        (6.9, "MEDIUM"),
        (4.0, "MEDIUM"),
        (3.9, "LOW"),
        (0.1, "LOW"),
        (0.0, "UNKNOWN"),
        (None, "UNKNOWN"),
    ],
)
def test_score_rating(score: float | None, rating: str) -> None:
    assert score_rating(score) == rating


def test_osv_group_severity_takes_the_database_rating_before_the_score() -> None:
    ghsa = osv_record("GHSA-a", database_specific={"severity": "LOW"})
    pysec = osv_record("PYSEC-1")
    # the database rating wins over the score of the group
    assert osv_group_severity(vulnerability(ghsa, max_severity=9.8)) == "LOW"
    assert osv_group_severity(vulnerability(ghsa, pysec, max_severity=9.8)) == "LOW"
    other = osv_record("GHSA-b", database_specific={"severity": "HIGH"})
    assert osv_group_severity(vulnerability(ghsa, other)) == "HIGH"
    # no rating of the database: the rating of the score (v3 and v4 alike)
    assert osv_group_severity(vulnerability(pysec, max_severity=9.8)) == "CRITICAL"
    assert osv_group_severity(vulnerability(pysec, max_severity=5.3)) == "MEDIUM"
    assert osv_group_severity(vulnerability(pysec)) == "UNKNOWN"


@pytest.mark.parametrize(
    ("value", "score"),
    [("8.7", 8.7), (7, 7.0), ("", None), (None, None), ("x", None), ("0", None)],
)
def test_osv_score_reads_max_severity(value: Any, score: float | None) -> None:
    assert osv_score(value) == score


@pytest.mark.parametrize(
    ("purl", "identity"),
    [
        ("pkg:npm/%40babel/traverse@7.20.0", ("npm", "@babel/traverse")),
        ("pkg:pypi/Foo_Bar.baz@1", ("PyPI", "foo-bar-baz")),
        ("pkg:maven/org.example/lib@1", ("Maven", "org.example:lib")),
        ("pkg:golang/github.com/a/b@v1", ("Go", "github.com/a/b")),
        ("pkg:apk/alpine/zlib@1.3.2-r0", None),
        ("not a purl", None),
    ],
)
def test_purl_identity_is_the_osv_package(
    purl: str, identity: tuple[str, str] | None
) -> None:
    assert purl_identity(purl) == identity


def test_osv_fixed_versions_need_a_fixed_event_of_this_package() -> None:
    record = {
        "affected": [
            affected_range("PyPI", "requests", {"fixed": "2.31.0"}),
            affected_range("PyPI", "other", {"last_affected": "1.0"}),
        ]
    }
    assert osv_fixed_versions(record, ("PyPI", "requests")) == ["2.31.0"]
    assert osv_fixed_versions(record, ("PyPI", "other")) == []
    assert osv_fixed_versions(record, ("PyPI", "unlisted")) == []


def test_osv_fixed_versions_ignore_git_ranges() -> None:
    record = {"affected": [affected_range("npm", "a", {"fixed": "abc123"}, kind="GIT")]}
    assert osv_fixed_versions(record, ("npm", "a")) == []
    record = {
        "affected": [affected_range("npm", "a", {"fixed": "1.2.3"}, kind="SEMVER")]
    }
    assert osv_fixed_versions(record, ("npm", "a")) == ["1.2.3"]
    assert osv_fixed_versions({}, ("npm", "a")) == []


def test_osv_fixed_versions_match_by_purl_or_by_ecosystem_with_a_suffix() -> None:
    identity = ("Maven", "org.example:lib")
    by_purl = {
        "affected": [
            {
                "package": {"purl": "pkg:maven/org.example/lib"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.0"}]}],
            }
        ]
    }
    assert osv_fixed_versions(by_purl, identity) == ["2.0"]
    suffixed = {
        "affected": [
            affected_range("Maven:https://repo", "org.example:lib", {"fixed": "2"})
        ]
    }
    assert osv_fixed_versions(suffixed, identity) == ["2"]
    broken = {"affected": [{"package": {"ecosystem": "npm"}}, {"ranges": []}]}
    assert osv_fixed_versions(broken, ("npm", "a")) == []


def test_osv_packages_are_distinct_by_ecosystem_name_and_version() -> None:
    native = osv_native()
    entry = native["results"][0]["packages"][0]
    native["results"].append({"packages": [entry]})
    packages = osv_packages(native)
    assert [(p.identity, p.version) for p in packages.values()] == [
        (("npm", "lodash"), "4.17.0"),
        (("npm", "@scope/pkg"), "1.0.0"),
        (("PyPI", "requests"), "2.0.0"),
        (("Maven", "org.example:lib"), "1.0"),
        (("npm", "clean"), "1.0.0"),
    ]
    assert [len(p.vulnerabilities) for p in packages.values()] == [2, 1, 1, 1, 0]


def test_osv_packages_read_the_groups_of_osv_scanner() -> None:
    native = osv_part(
        {"pkg:npm/lib@1.0": ["PYSEC-1", "GHSA-b", "GHSA-c", "RUSTSEC-d"]},
        osv_record("PYSEC-1", aliases=["CVE-1"]),
        osv_record("GHSA-b", aliases=["CVE-1", "OTHER-9"]),
        osv_record("GHSA-c"),
        osv_record("RUSTSEC-d", aliases=["GHSA-c"]),
        scores={"GHSA-b": "8.7"},
    )
    groups = osv_packages(native)[(("npm", "lib"), "1.0")].vulnerabilities
    assert [(v.ids, sorted(v.names), v.max_severity) for v in groups] == [
        (("GHSA-b", "PYSEC-1"), ["CVE-1", "GHSA-b", "OTHER-9", "PYSEC-1"], 8.7),
        (("GHSA-c", "RUSTSEC-d"), ["GHSA-c", "RUSTSEC-d"], None),
    ]
    # GHSA records come first, then by id
    assert [r["id"] for r in groups[0].records] == ["GHSA-b", "PYSEC-1"]
    assert [r["id"] for r in groups[1].records] == ["GHSA-c", "RUSTSEC-d"]


def test_osv_findings_are_distinct_by_package_and_group() -> None:
    found = osv_findings(osv_native())
    lodash = (("npm", "lodash"), "4.17.0")
    assert sorted(found) == [
        ((("Maven", "org.example:lib"), "1.0"), ("GHSA-dddd-dddd-0001",)),
        ((("PyPI", "requests"), "2.0.0"), ("PYSEC-2030-1",)),
        ((("npm", "@scope/pkg"), "1.0.0"), ("GHSA-bbbb-bbbb-0001",)),
        (lodash, ("GHSA-aaaa-aaaa-0001",)),
        (lodash, ("GHSA-aaaa-aaaa-0002",)),
    ]
    assert found[(lodash, ("GHSA-aaaa-aaaa-0001",))] == ("CRITICAL", True)
    assert found[(lodash, ("GHSA-aaaa-aaaa-0002",))] == ("LOW", False)
    # no database rating: the max_severity of the group (7.5)
    scoped = (("npm", "@scope/pkg"), "1.0.0")
    assert found[(scoped, ("GHSA-bbbb-bbbb-0001",))] == ("HIGH", True)
    requests = (("PyPI", "requests"), "2.0.0")
    assert found[(requests, ("PYSEC-2030-1",))] == ("UNKNOWN", True)
    library = (("Maven", "org.example:lib"), "1.0")
    assert found[(library, ("GHSA-dddd-dddd-0001",))] == ("MEDIUM", False)


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        # the only CVE
        ([osv_record("PYSEC-1", aliases=["CVE-2030-5"])], "CVE-2030-5"),
        # several CVEs: the first in string order
        (
            [osv_record("GHSA-a", aliases=["CVE-2030-9", "CVE-2030-12", "CVE-2029-3"])],
            "CVE-2029-3",
        ),
        # no CVE: the first GHSA, even if it is only an alias
        ([osv_record("PYSEC-1", aliases=["GHSA-z", "GHSA-b"])], "GHSA-b"),
        ([osv_record("GHSA-m"), osv_record("GHSA-k", aliases=["GHSA-m"])], "GHSA-k"),
        # neither: the first id OSV reported
        ([osv_record("RUSTSEC-2", aliases=["PYSEC-1"])], "RUSTSEC-2"),
        ([osv_record("PYSEC-2"), osv_record("OSV-1", aliases=["PYSEC-2"])], "OSV-1"),
    ],
)
def test_osv_primary_id(records: list[dict[str, Any]], expected: str) -> None:
    (group,) = vulnerabilities(*records)
    assert osv_primary_id(group) == expected


def test_osv_group_fixes_keeps_incomparable_versions() -> None:
    record = osv_record(
        "GHSA-a", affected=[affected_range("npm", "lib", {"fixed": "next"})]
    )
    assert osv_group_fixes([record], ("npm", "lib"), "1.0") == ["next"]
    assert osv_group_fixes([record], ("npm", "lib"), None) == ["next"]


@pytest.mark.parametrize(
    "fields",
    [{}, {"summary": "  "}, {"details": " \n "}, {"details": 5}, {"summary": 3}],
)
def test_osv_title_is_empty_without_a_summary_or_details(
    fields: dict[str, Any],
) -> None:
    assert osv_title(osv_record("GHSA-a", **fields)) == ""


def test_osv_title_prefers_the_summary_to_the_details() -> None:
    record = osv_record("GHSA-a", summary=" Short ", details="Long\ntext")
    assert osv_title(record) == "Short"
