"""Tests of actions/sca_merge_results/report.py (synthetic fixtures only)."""

from __future__ import annotations

import pytest
from report import parse_trivy_db_info, trivy_db_stale_days


@pytest.mark.parametrize(
    "raw",
    ["", "  ", "not json", "[1]", '"x"', '{"vulnerability_db_updated_at": 5}'],
)
def test_parse_trivy_db_info_unknown_for_bad_input(raw: str) -> None:
    assert parse_trivy_db_info(raw) == {
        "vulnerability_db_updated_at": None,
        "java_db_updated_at": None,
    }


def test_parse_trivy_db_info_partial() -> None:
    info = parse_trivy_db_info('{"java_db_updated_at": "2030-01-01T00:00:00Z"}')
    assert info == {
        "vulnerability_db_updated_at": None,
        "java_db_updated_at": "2030-01-01T00:00:00Z",
    }


@pytest.mark.parametrize(
    ("updated", "stale"),
    [
        ("2030-01-03T00:00:00.123456789Z", None),
        ("2030-01-02T00:00:00Z", 2),
        ("2029-12-25T00:00:00Z", 10),
        (None, None),
        ("soon", None),
    ],
)
def test_a_trivy_db_snapshot_of_two_days_or_more_is_stale(
    updated: str | None, stale: int | None
) -> None:
    db = {"vulnerability_db_updated_at": updated, "java_db_updated_at": None}
    assert trivy_db_stale_days(db, "2030-01-04T00:00:00Z") == stale
