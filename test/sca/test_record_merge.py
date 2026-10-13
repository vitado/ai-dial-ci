"""Tests of actions/sca_merge_results/record_merge.py (synthetic fixtures only)."""

from __future__ import annotations

from record_merge import merge_records
from test_merge_results import lang_package, lang_result, python_native, trivy_vuln


def test_merge_records_unions_scanners_sorted() -> None:
    native = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2000-0001",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.0",
                        "Severity": "HIGH",
                    }
                ],
            }
        ]
    }
    records, sightings = merge_records(
        "example/app",
        [
            ("source-development", "trivy", native),
            ("deps", "other-scanner", native),
            ("image", "trivy", native),
        ],
    )
    assert len(records) == 1
    assert records[0]["scanners"] == ["other-scanner", "trivy"]
    assert records[0]["scan_targets"] == ["source-development", "deps", "image"]
    assert records[0]["locations"] == ["package-lock.json"]
    assert sightings[("CVE-2000-0001", "lodash", "4.17.0")] == {
        "source-development": ["package-lock.json"],
        "deps": ["package-lock.json"],
        "image": ["package-lock.json"],
    }


def test_display_name_falls_back_to_first_seen_without_an_image() -> None:
    records, sightings = merge_records(
        "r",
        [
            ("a", "trivy", python_native("poetry.lock", "poetry", "Mako")),
            ("b", "trivy", python_native("uv.lock", "uv", "mako")),
        ],
    )
    assert [r["pkg"] for r in records] == ["Mako"]
    assert sightings[("CVE-1", "Mako", "1.3.12")] == {
        "a": ["poetry.lock"],
        "b": ["uv.lock"],
    }


def test_case_sensitive_ecosystems_are_not_merged() -> None:
    records, _ = merge_records(
        "r",
        [
            ("a", "trivy", python_native("package-lock.json", "npm", "Lodash")),
            ("a", "trivy", python_native("package-lock.json", "npm", "lodash")),
        ],
    )
    assert len(records) == 2


def test_merge_records_without_osv_scans_is_the_trivy_merge() -> None:
    native = {
        "Results": [
            lang_result(
                "npm",
                "package-lock.json",
                [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
                [trivy_vuln("CVE-2030-1", "lib", "1.0")],
            )
        ]
    }
    scans = [("source-development", "trivy", native)]
    assert merge_records("example/app", scans) == merge_records(
        "example/app", scans, (), ()
    )
