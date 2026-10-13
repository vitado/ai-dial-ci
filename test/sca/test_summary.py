"""Tests of actions/sca_merge_results/summary.py (synthetic fixtures only)."""

from __future__ import annotations

from typing import Any

import pytest
from summary import (
    STEP_SUMMARY_LIMIT_BYTES,
    exposure_label,
    fixed_versions_text,
    format_timestamp,
    join_names,
    md_cell,
    md_join,
    md_link,
    package_families,
    release_line,
    release_tags_of,
    render_footer,
    scope_table,
    severity_phrase,
    shortest_path_text,
    strip_package_prefix,
    totals_line,
    truncate,
    truncate_summary,
)
from test_merge_results import (
    DEV,
    OLDER_RELEASE_SOURCE,
    REL,
    RELEASE_SOURCE,
    SOURCE,
    Record,
    plain,
    plain_lines,
    rec,
)


def test_footer_shows_java_db_time_only_on_the_same_day() -> None:
    report = {
        "commit_sha": None,
        "run_url": None,
        "run_id": None,
        "trivy_version": None,
        "generated_utc": None,
        "trivy_db": {
            "vulnerability_db_updated_at": "2030-01-01T06:00:00.123456789Z",
            "java_db_updated_at": "2030-01-01T01:02:03Z",
        },
    }
    assert render_footer(report)[-1] == (
        "<sub>DB vuln 2030-01-01 06:00Z (java 01:02Z)</sub>"
    )


def test_markdown_cells_are_escaped() -> None:
    assert md_cell("a|b") == "a\\|b"
    assert md_cell("line1\nline2") == "line1 line2"
    assert md_cell("back\\slash|x") == "back\\\\slash\\|x"
    assert md_cell(None) == "-"
    assert md_cell(0) == "0"


@pytest.mark.parametrize(
    ("severities", "expected"),
    [
        (["CRITICAL", "HIGH", "HIGH", "LOW"], "3 CRITICAL/HIGH"),
        (["HIGH", "MEDIUM"], "1 HIGH"),
        (["CRITICAL"], "1 CRITICAL"),
        (["MEDIUM", "LOW", "LOW"], "3 MEDIUM/LOW"),
        (["LOW"], "1 LOW"),
        (["UNKNOWN"], "1 UNKNOWN"),
    ],
)
def test_severity_phrase_counts_the_findings_that_matter(
    severities: list[str], expected: str
) -> None:
    assert severity_phrase([rec("release_only", s) for s in severities]) == expected


@pytest.mark.parametrize(
    ("names", "expected"),
    [([], ""), (["a"], "a"), (["a", "b"], "a and b"), (["a", "b", "c"], "a, b and c")],
)
def test_join_names(names: list[str], expected: str) -> None:
    assert join_names(names) == expected


def test_scope_table_has_a_row_per_release_and_an_unknown_column_if_needed() -> None:
    older = {**REL, "id": "app-0.9.0", "tag": "0.9.0"}
    targets = [
        {**t, "scanner": "trivy", "status": "ok"} for t in (SOURCE, DEV, REL, older)
    ]
    records = [
        rec("release_only", "UNKNOWN", scan_targets=["app-1.0.0", "app-0.9.0"]),
        rec("release_only", "HIGH", scan_targets=["app-0.9.0"]),
    ]
    assert plain_lines(scope_table({"targets": targets}, records)) == [
        "| Scope | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Fixable | Base image |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        "| 1.0.0 (released) | 0 | 0 | 0 | 0 | 1 | 0 | 0 |",
        "| 0.9.0 (released) | 0 | 1 | 0 | 0 | 1 | 0 | 0 |",
    ]


def test_totals_line_is_the_coverage_of_the_run() -> None:
    def report(**counts: int) -> dict[str, Any]:
        base = {"total": 8, "ok": 8, "failed": 0, "not_applicable": 0}
        return {"totals": {"targets": {**base, **counts}}}

    assert totals_line(report()) == "8/8 targets scanned"
    assert totals_line(report(), osv_only=3) == (
        "8/8 targets scanned · 3 found only by OSV"
    )
    assert totals_line(report(ok=5, failed=1, not_applicable=2)) == (
        "5/6 targets scanned · 2 not applicable"
    )
    assert totals_line(report(), packages=12) == "8/8 targets scanned · 12 packages"


def test_format_timestamp() -> None:
    assert format_timestamp("2026-10-12T01:14:57.362085088Z") == "2026-10-12 01:14Z"
    assert format_timestamp("2026-10-12T01:14:57Z", with_date=False) == "01:14Z"
    assert format_timestamp("garbage") is None
    assert format_timestamp(None) is None


def test_truncate() -> None:
    assert truncate("short", 10) == "short"
    assert truncate("x" * 20, 10) == "x" * 9 + "…"
    assert truncate(None) is None


def test_markdown_cells_escape_html() -> None:
    assert md_cell("<b>x</b>") == "&lt;b&gt;x&lt;/b&gt;"


def test_package_families_group_the_ecosystems_of_a_package() -> None:
    def families(*ecosystems: str) -> str:
        return package_families([{"ecosystem": list(ecosystems)}])

    assert families("python-pkg", "poetry") == "python"
    assert families("node-pkg", "npm") == "npm"
    assert families("gradle", "jar") == "java"
    assert families("alpine") == "alpine"
    assert families("conan") == "conan"


@pytest.mark.parametrize(
    ("title", "pkg", "expected"),
    [
        ("urllib3: urllib3: Denial of Service", "urllib3", "Denial of Service"),
        ("pyjwt: PyJWT: Token bypass", "PyJWT", "Token bypass"),
        ("Mako: Path traversal", "Mako", "Path traversal"),
        ("urllib3 is vulnerable", "urllib3", "urllib3 is vulnerable"),
        ("urllib3: ", "urllib3", "urllib3: "),
        (None, "urllib3", None),
    ],
)
def test_strip_package_prefix(
    title: str | None, pkg: str, expected: str | None
) -> None:
    assert strip_package_prefix(title, pkg) == expected


def test_shortest_path_text_and_more_paths() -> None:
    def record(paths: list[list[str]], total: int, truncated: bool = False) -> Record:
        return {
            "dependency_paths": paths,
            "dependency_paths_total": total,
            "dependency_paths_truncated": truncated,
        }

    one = record([["jest", "core", "braces"]], 1)
    assert shortest_path_text([one]) == "jest › core › braces"
    two = record([["b", "t"], ["a", "x", "t"]], 2)
    assert shortest_path_text([two]) == "b › t (+1 more path)"
    many = record([["a", "t"]], 7)
    assert shortest_path_text([many]) == "a › t (+6 more paths)"
    cut = record([["a", "t"]], 1000, True)
    assert shortest_path_text([cut]) == "a › t (+999+ more paths)"
    assert shortest_path_text([record([], 0)]) == ""


@pytest.mark.parametrize(
    ("tag", "expected"),
    [("1.1.14", "release-1.1"), ("v2.10.0", "release-2.10"), ("rc", "release-rc")],
)
def test_release_line(tag: str, expected: str) -> None:
    assert release_line(tag) == expected


def test_exposure_labels() -> None:
    label = exposure_label
    assert label("release_and_development", [], ["1.1.14", "1.0.3"], True) == (
        "Released 1.1.14, 1.0.3 + development"
    )
    assert label("release_only", [], ["0.12.0"], True) == "Released 0.12.0 only"
    assert label("development_only", [], [], True) == "development only"
    assert label("development_only", [], [], False) == "development (source)"
    assert label("source_only", [], [], True) == "Source only · not in images"
    # source only without a reason is not marked as not in production
    assert label("source_only", [], [], False) == "Source only"
    assert label("source_only", ["dev dependency"], [], True) == (
        "not in production · dev dependency"
    )
    assert label("source_only", ["not shipped path"], [], False) == (
        "not in production · not shipped path"
    )
    assert label("source_only", ["dev dependency", "not shipped path"], [], True) == (
        "not in production · dev dependency · not shipped path"
    )
    assert label("development_only", ["dev dependency"], [], False) == (
        "development (source) · not in production · dev dependency"
    )


def test_exposure_label_lists_the_release_tags_of_the_images_it_was_found_in() -> None:
    other = {**REL, "id": "app-0.9.0", "tag": "0.9.0"}
    targets = [SOURCE, DEV, REL, other]
    record = {"scan_targets": ["source-development", "app-0.9.0", "app-1.0.0"]}
    assert release_tags_of([record], targets) == ["1.0.0", "0.9.0"]


def test_release_tags_of_uses_release_sources_only_without_images() -> None:
    record = {"scan_targets": ["source-1.0.0", "source-0.9.0", "app-1.0.0"]}
    sources = [SOURCE, RELEASE_SOURCE, OLDER_RELEASE_SOURCE]
    assert release_tags_of([record], sources) == ["1.0.0", "0.9.0"]
    with_images = [*sources, DEV, REL]
    assert release_tags_of([record], with_images) == ["1.0.0"]


def test_fixed_versions_text_names_the_fixes_above_the_installed_version() -> None:
    fixes = ["2.0.1", "1.9", "1.0", "3.1", "2.5"]
    assert fixed_versions_text(fixes) == "1.0, 1.9, 2.0.1 +2 more"
    assert fixed_versions_text(fixes, "2.0") == "2.0.1, 2.5, 3.1"
    # nothing above it, or nothing comparable: all of them
    assert fixed_versions_text(["1.0", "1.1"], "2.0") == "1.0, 1.1"
    assert fixed_versions_text(["abc", "def"], "1.0") == "abc, def"
    assert fixed_versions_text([]) == ""


def test_md_cell_leaves_no_link_image_or_code_span_to_an_outside_text() -> None:
    cell = md_cell("[x](https://e.invalid) ![i](u) `c` a|b <b>")
    assert plain(cell) == "[x](https://e.invalid) ![i](u) `c` a|b &lt;b&gt;"
    for char in "[]()!`|":
        assert all(
            cell[i - 1] == "\\" for i, c in enumerate(cell) if c == char and i > 0
        )
    assert md_cell("a\r\nb") == "a  b"
    assert md_cell(None) == "-"


def test_md_link_is_a_link_that_md_cell_keeps() -> None:
    link = md_link("CVE-1 [x]", "https://e.invalid/a(b) c")
    assert link == "[CVE-1 \\[x\\]](https://e.invalid/a%28b%29%20c)"
    assert md_cell(link) == link
    joined = md_join(", ", [link, "[plain](u)"])
    assert md_cell(joined).endswith(", \\[plain\\]\\(u\\)")


def test_a_summary_that_fits_is_written_as_it_is() -> None:
    assert truncate_summary("# SCA\n", None) == "# SCA\n"


def test_a_summary_over_the_limit_is_cut_with_a_note_and_open_blocks_are_closed() -> (
    None
):
    row = "| " + "x" * 100 + " |\n"
    text = "# SCA\n\n<details>\n<summary>big</summary>\n\n" + row * 20000
    assert len(text.encode()) > STEP_SUMMARY_LIMIT_BYTES
    cut = truncate_summary(text, "https://github.com/o/r/actions/runs/1#artifacts")
    assert len(cut.encode()) <= STEP_SUMMARY_LIMIT_BYTES
    assert cut.count("<details>") == cut.count("</details>")
    assert "The summary is cut" in cut
    assert "[this run](https://github.com/o/r/actions/runs/1#artifacts)" in cut
    assert cut.startswith("# SCA")
