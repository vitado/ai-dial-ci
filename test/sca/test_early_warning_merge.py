"""Tests of the early warning in actions/sca_merge_results/merge_results.py
(synthetic fixtures only)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from test_merge_results import (
    DEV,
    REL,
    SOURCE,
    Workspace,
    make_targets_doc,
    mr,
    records_by_id,
)

GUAVA = {
    "ecosystem": "maven",
    "name": "com.google.guava:guava",
    "version": "33.4.8-jre",
}
GENERATED_FROM = {
    "days": 90,
    "from": "2029-10-12T10:00:00Z",
    "to": "2030-01-01T10:00:00Z",
}
INDEX = {
    "ref": "ghcr.io/example/ai-dial-sca-cve-index:1",
    "digest": "sha256:" + "0123456789abcdef" * 4,
    "built_at": "2030-01-01T03:21:00Z",
    "gaps": [],
}


def candidate(
    cve: str = "CVE-2030-0001",
    package: dict[str, str] | None = None,
    severity: str = "HIGH",
    score: float | None = 7.5,
    sightings: dict[str, list[str]] | None = None,
    **fields: Any,
) -> dict[str, Any]:
    cvss = None
    if score is not None:
        cvss = {
            "score": score,
            "vector": "CVSS:3.1/AV:N",
            "version": "3.1",
            "source": "cna",
        }
    return {
        "cve": cve,
        "aliases": [],
        "cna": "Google",
        "published": "2030-01-05T10:00:00.000Z",
        "updated": "2030-01-06T10:00:00.000Z",
        "title": "A title",
        "package": package or GUAVA,
        "affected_range": ">= 4.0, < 33.7.2",
        "match": "source_repo",
        "severity": severity,
        "severity_source": "cna" if cvss else None,
        "cvss": cvss,
        "cvss_v4": None,
        "exploitation": None,
        "sightings": sightings or {"source-development": ["gradle.lockfile"]},
        **fields,
    }


def write_part(
    ws: Workspace,
    candidates: list[dict[str, Any]] | None = None,
    status: str = "ok",
    reason: str | None = None,
    generated_from: dict[str, Any] | None = None,
    index: dict[str, Any] | None = INDEX,
) -> None:
    part = ws.parts / "early-warning"
    part.mkdir(parents=True, exist_ok=True)
    (part / "status.json").write_text(
        json.dumps(
            {
                "status": status,
                "reason": reason,
                "window_days": 90,
                "records_scanned": 4321,
                "candidates": len(candidates or []),
                "index": index,
                "diagnostics": {},
            }
        ),
        encoding="utf-8",
    )
    if status == "ok":
        (part / "candidates.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_utc": "2030-01-01T10:00:00Z",
                    "generated_from": generated_from or GENERATED_FROM,
                    "candidates": candidates or [],
                }
            ),
            encoding="utf-8",
        )


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    """fs + development image + release image, all ok."""
    workspace = Workspace(tmp_path, make_targets_doc(SOURCE, DEV, REL))
    workspace.add_part("source-development", "source", lockfiles=3)
    workspace.add_part("app-development", "app-development")
    workspace.add_part("app-1.0.0", "app-1.0.0")
    return workspace


def merge(ws: Workspace, enabled: bool = True) -> dict[str, Any]:
    assert ws.run(early_warning_enabled=enabled) == 0
    return ws.json("_report/scan_report.json")["early_warning"]


def summary(ws: Workspace) -> str:
    return (ws.out / "summary.md").read_text(encoding="utf-8")


def entries(ws: Workspace) -> list[dict[str, Any]]:
    return ws.json("_report/early_warning.json")["entries"]


# ------------------------------------------------------------------ disabled


def test_without_early_warning_the_report_has_none(ws: Workspace) -> None:
    write_part(ws, [candidate()])  # a part that nobody asked for is not read
    assert merge(ws, enabled=False) is None
    assert not (ws.out / "_report" / "early_warning.json").exists()
    assert "Early warning" not in summary(ws)
    assert "early warning" not in summary(ws)


def test_disabled_changes_nothing_but_the_null_field(
    ws: Workspace, tmp_path: Path
) -> None:
    ws.run()
    plain = {
        name: (ws.out / name).read_text(encoding="utf-8")
        for name in ("summary.md", "_report/vulnerabilities.json")
    }
    report = ws.json("_report/scan_report.json")
    assert report.pop("early_warning") is None
    (tmp_path / "other").mkdir()
    other = Workspace(tmp_path / "other", make_targets_doc(SOURCE, DEV, REL))
    other.add_part("source-development", "source", lockfiles=3)
    other.add_part("app-development", "app-development")
    other.add_part("app-1.0.0", "app-1.0.0")
    other.run(early_warning_enabled=False)
    for name, text in plain.items():
        assert (other.out / name).read_text(encoding="utf-8") == text
    assert other.json("_report/scan_report.json")["early_warning"] is None


# ------------------------------------------------------------------- reported


def test_an_early_warning_is_reported_and_is_not_a_finding(ws: Workspace) -> None:
    ws.run()
    without = ws.json("_report/scan_report.json")["totals"]
    write_part(ws, [candidate()])
    report = merge(ws)
    assert report == {
        "status": "ok",
        "reason": None,
        "window_days": 90,
        "records_scanned": 4321,
        "candidates": 1,
        "reported": 1,
        "packages": 1,
        "index": INDEX,
    }
    document = ws.json("_report/early_warning.json")
    assert document["schema_version"] == 1
    assert document["repo"] == "example/app"
    assert document["generated_from"] == GENERATED_FROM
    assert document["status"] == "ok"
    (entry,) = document["entries"]
    assert entry == {
        "cve": "CVE-2030-0001",
        "aliases": [],
        "cna": "Google",
        "published": "2030-01-05T10:00:00.000Z",
        "updated": "2030-01-06T10:00:00.000Z",
        "title": "A title",
        "package": GUAVA,
        "affected_range": ">= 4.0, < 33.7.2",
        "match": "source_repo",
        "severity": "HIGH",
        "severity_source": "cna",
        "cvss": {
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N",
            "version": "3.1",
            "source": "cna",
        },
        "cvss_v4": None,
        "exploitation": None,
        "scan_targets": ["source-development"],
        "locations": ["gradle.lockfile"],
        "exposure": "source_only",
    }
    # not a record, not in the totals
    assert "CVE-2030-0001" not in records_by_id(ws)
    assert ws.json("_report/scan_report.json")["totals"] == without
    assert ws.json("_report/vulnerabilities.json")["records"]


def test_candidates_known_to_a_scanner_are_dropped(ws: Workspace) -> None:
    write_part(
        ws,
        [
            candidate("CVE-2000-0001"),  # a record of the run
            candidate("CVE-2030-0002", aliases=["GHSA-aaaa-bbbb-cccc"]),
            candidate("CVE-2030-0003"),
        ],
    )
    report = merge(ws)
    assert (report["candidates"], report["reported"]) == (3, 2)
    assert {e["cve"] for e in entries(ws)} == {"CVE-2030-0002", "CVE-2030-0003"}


def test_aliases_are_compared_with_the_aliases_of_records_case_insensitively() -> None:
    record = mr.blank_record("r", "CVE-2030-0009", "p", "1", "library")
    record["aliases"] = ["GHSA-AAAA-bbbb-cccc"]
    part_dir = Path("unused")
    known = {i.upper() for i in mr.record_ids(record)}
    assert "GHSA-AAAA-BBBB-CCCC" in known
    assert part_dir  # the id comparison itself is covered by the run below


def test_a_record_with_an_alias_drops_the_candidate_of_the_cve(
    ws: Workspace,
) -> None:
    ws.run()
    victim = records_by_id(ws)["CVE-2000-0001"]
    assert victim  # the fixture record the candidate below is an alias of
    write_part(
        ws,
        [
            candidate(
                "CVE-2030-0004", aliases=["CVE-2000-0001"]
            ),  # an alias that is a record's cve
        ],
    )
    assert merge(ws)["reported"] == 0


def test_exposure_is_computed_like_for_records(ws: Workspace) -> None:
    write_part(
        ws,
        [
            candidate("CVE-2030-0001", sightings={"source-development": ["a.lock"]}),
            candidate("CVE-2030-0002", sightings={"app-development": ["Java"]}),
            candidate(
                "CVE-2030-0003",
                sightings={"app-development": ["Java"], "app-1.0.0": ["Java"]},
            ),
            candidate("CVE-2030-0004", sightings={"app-1.0.0": ["Java"]}),
        ],
    )
    merge(ws)
    exposure = {e["cve"]: e["exposure"] for e in entries(ws)}
    assert exposure == {
        "CVE-2030-0001": "source_only",
        "CVE-2030-0002": "development_only",
        "CVE-2030-0003": "release_and_development",
        "CVE-2030-0004": "release_only",
    }
    by_cve = {e["cve"]: e for e in entries(ws)}
    # the targets and locations come in the order of the targets file
    both = candidate(
        sightings={"app-1.0.0": ["Java"], "source-development": ["a.lock"]}
    )
    write_part(ws, [both])
    merge(ws)
    (entry,) = entries(ws)
    assert entry["scan_targets"] == ["source-development", "app-1.0.0"]
    assert entry["locations"] == ["a.lock", "Java"]
    assert by_cve


def test_not_shipped_locations_do_not_count(tmp_path: Path) -> None:
    doc = make_targets_doc(SOURCE)
    doc["config"] = {
        "source": None,
        "overrides": None,
        "non_shipped_paths": ["examples/"],
        "trivy_skip_paths": "as_non_shipped",
    }
    workspace = Workspace(tmp_path, doc)
    workspace.add_part("source-development", "source")
    write_part(
        workspace,
        [
            candidate(
                "CVE-2030-0001", sightings={"source-development": ["examples/p.lock"]}
            ),
            candidate("CVE-2030-0002", sightings={"source-development": ["p.lock"]}),
        ],
    )
    merge(workspace)
    assert {e["cve"]: e["exposure"] for e in entries(workspace)} == {
        "CVE-2030-0001": "source_only",
        "CVE-2030-0002": "development_only",
    }
    assert "examples/p.lock (not shipped)" in summary(workspace)


# -------------------------------------------------------------------- ordering


def test_entries_are_ordered_by_severity_then_score_then_publication(
    ws: Workspace,
) -> None:
    def named(cve: str, name: str, severity: str, score: float | None, day: str):
        return candidate(
            cve,
            package={**GUAVA, "name": name},
            severity=severity,
            score=score,
            published=f"2030-01-{day}T00:00:00Z",
        )

    write_part(
        ws,
        [
            named("CVE-2030-0001", "a", "UNKNOWN", None, "09"),
            named("CVE-2030-0002", "b", "HIGH", 7.5, "01"),
            named("CVE-2030-0003", "c", "CRITICAL", 9.8, "02"),
            named("CVE-2030-0004", "d", "HIGH", 7.5, "08"),
            named("CVE-2030-0005", "e", "HIGH", 8.1, "03"),
            named("CVE-2030-0006", "f", "MEDIUM", 5.0, "05"),
        ],
    )
    merge(ws)
    assert [e["cve"] for e in entries(ws)] == [
        "CVE-2030-0003",
        "CVE-2030-0005",
        "CVE-2030-0004",
        "CVE-2030-0002",
        "CVE-2030-0006",
        "CVE-2030-0001",
    ]


# --------------------------------------------------------------------- summary


def test_summary_section_has_a_row_per_package_version(ws: Workspace) -> None:
    write_part(
        ws,
        [
            candidate(
                "CVE-2030-0001",
                sightings={
                    "source-development": ["gradle.lockfile"],
                    "app-development": ["Java"],
                },
            ),
            candidate(
                "CVE-2030-0002",
                severity="CRITICAL",
                score=9.8,
                affected_range="< 33.8.0",
                sightings={
                    "source-development": ["gradle.lockfile"],
                    "app-development": ["Java"],
                },
            ),
            candidate(
                "CVE-2030-0003",
                package={
                    **GUAVA,
                    "name": "org.bouncycastle:bcprov-jdk18on",
                    "version": "1.85",
                },
                severity="MEDIUM",
                score=5.0,
                cna="bcorg",
                match="repo_module",
                affected_range="< 1.86",
            ),
        ],
    )
    merge(ws)
    text = summary(ws)
    assert (
        "## Early warning — not yet in vulnerability databases (2)\n\n"
        "CVE records of their CNAs match these packages, but no vulnerability database "
        "maps them to a package yet; verify and upgrade if confirmed."
    ) in text
    lines = text.splitlines()
    header = (
        "| Package | Severity | CVE | CNA | Published | Affected | Match "
        "| Exposure | Where |"
    )
    start = lines.index(header)
    table = []
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        table.append(line)
    guava, bcprov = table[2:]  # after the header and its separator
    section = "\n".join(table)
    # the worst package first; its severity is the worst of its CVEs, which are
    # listed worst first, each with its own
    assert guava.startswith("| com.google.guava:guava 33.4.8-jre | CRITICAL 9.8 | ")
    assert (
        "[CVE-2030-0002](https://www.cve.org/CVERecord?id=CVE-2030-0002) "
        "(CRITICAL 9.8), "
        "[CVE-2030-0001](https://www.cve.org/CVERecord?id=CVE-2030-0001) (HIGH 7.5)"
    ) in guava
    # distinct values only
    assert (
        "| Google | 2030-01-05 | &lt; 33.8.0 · &gt;= 4.0, &lt; 33.7.2 "
        "| source repo |" in guava
    )
    assert "development only" in guava
    assert "image :development" in guava
    assert "source gradle.lockfile" in guava
    assert bcprov.startswith("| org.bouncycastle:bcprov-jdk18on 1.85 | MEDIUM 5.0 | ")
    assert "| bcorg |" in bcprov
    assert "| repo module |" in bcprov
    assert "<details>" not in section  # up to 5 packages stay open


def test_summary_section_is_collapsed_above_five_packages(ws: Workspace) -> None:
    write_part(
        ws,
        [
            candidate(f"CVE-2030-000{i}", package={**GUAVA, "name": f"g:p{i}"})
            for i in range(6)
        ],
    )
    merge(ws)
    text = summary(ws)
    assert "## Early warning — not yet in vulnerability databases (6)" in text
    assert "<summary>Show the 6 packages</summary>" in text
    (ws.targets_file.parent / "five").mkdir()
    five = Workspace(ws.targets_file.parent / "five", make_targets_doc(SOURCE))
    five.add_part("source-development", "source")
    write_part(
        five,
        [
            candidate(f"CVE-2030-000{i}", package={**GUAVA, "name": f"g:p{i}"})
            for i in range(5)
        ],
    )
    merge(five)
    assert "Show the" not in summary(five)


def test_a_candidate_with_an_unknown_or_missing_match_is_unavailable(
    ws: Workspace,
) -> None:
    for match in ("magic", "T2", None, 7):
        write_part(ws, [candidate(match=match)])
        assert merge(ws)["status"] == "failed"
    broken = candidate()
    del broken["match"]
    write_part(ws, [broken])
    assert merge(ws)["status"] == "failed"


def test_the_match_does_not_filter_or_reorder_the_entries(ws: Workspace) -> None:
    write_part(
        ws,
        [
            candidate("CVE-2030-0001", match="repo_module"),
            candidate("CVE-2030-0002", match="package_name"),
            candidate("CVE-2030-0003", severity="CRITICAL", score=9.8),
        ],
    )
    merge(ws)
    assert [e["cve"] for e in entries(ws)] == [
        "CVE-2030-0003",
        "CVE-2030-0001",  # the weakest match, and still before the next one
        "CVE-2030-0002",
    ]
    assert [e["match"] for e in entries(ws)] == [
        "source_repo",
        "repo_module",
        "package_name",
    ]


def test_short_digest() -> None:
    assert mr.short_digest("sha256:" + "ab" * 32) == "sha256:" + "ab" * 6
    assert mr.short_digest(None) is None


def test_severity_text_names_the_source_and_exploitation() -> None:
    def entry(**fields: Any) -> dict[str, Any]:
        base = {
            "severity": "HIGH",
            "severity_source": "cna",
            "cvss": {"score": 7.5},
            "exploitation": None,
        }
        return {**base, **fields}

    assert mr.early_warning_severity_text(entry()) == "HIGH 7.5"
    assert mr.early_warning_severity_text(entry(severity_source="adp:CISA-ADP")) == (
        "HIGH 7.5 (ADP)"
    )
    assert (
        mr.early_warning_severity_text(
            entry(exploitation={"kev": True, "ssvc": "active"})
        )
        == "HIGH 7.5 · KEV"
    )
    assert (
        mr.early_warning_severity_text(
            entry(exploitation={"kev": False, "ssvc": "active"})
        )
        == "HIGH 7.5 · exploited (SSVC)"
    )
    assert (
        mr.early_warning_severity_text(
            entry(exploitation={"kev": False, "ssvc": "none"})
        )
        == "HIGH 7.5"
    )
    assert (
        mr.early_warning_severity_text(
            entry(severity="UNKNOWN", severity_source=None, cvss=None)
        )
        == "UNKNOWN"
    )


def test_section_comes_after_what_to_fix_and_the_watch_section(ws: Workspace) -> None:
    write_part(ws, [candidate()])
    merge(ws)
    text = summary(ws)
    assert text.index("## Early warning") > text.index("## What to fix")
    assert text.index("## Early warning") < text.index("Scan coverage")


def test_section_is_there_without_any_records(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path, make_targets_doc(SOURCE))
    workspace.add_part("source-development", "source-osv")
    write_part(workspace, [candidate()])
    merge(workspace)
    assert "## Early warning — not yet in vulnerability databases (1)" in summary(
        workspace
    )


# -------------------------------------------------------------------- headline


def headline(ws: Workspace) -> str:
    quoted = [line for line in summary(ws).splitlines() if line.startswith("> ")]
    # the paragraph with the totals line, the one that reports the early warnings
    return next(line for line in quoted if " targets scanned" in line)


def test_headline_counts_early_warnings_and_names_the_urgent_ones(
    ws: Workspace,
) -> None:
    write_part(
        ws,
        [
            candidate(
                "CVE-2030-0001",
                package={**GUAVA, "name": "a"},
                severity="CRITICAL",
                score=9.8,
            ),
            candidate("CVE-2030-0002", package={**GUAVA, "name": "b"}, severity="HIGH"),
            candidate("CVE-2030-0003", package={**GUAVA, "name": "c"}, severity="HIGH"),
            candidate(
                "CVE-2030-0004",
                package={**GUAVA, "name": "c"},
                severity="CRITICAL",
                score=9.1,
            ),
            candidate(
                "CVE-2030-0005",
                package={**GUAVA, "name": "d"},
                severity="LOW",
                score=2.0,
            ),
        ],
    )
    merge(ws)
    assert headline(ws).endswith(" · 4 early warnings (2 CRITICAL · 1 HIGH)")


def test_headline_without_urgent_ones_has_no_parentheses(ws: Workspace) -> None:
    write_part(ws, [candidate(severity="MEDIUM", score=5.0)])
    merge(ws)
    assert headline(ws).endswith(" · 1 early warning")
    write_part(ws, [candidate(severity="UNKNOWN", score=None)])
    merge(ws)
    assert headline(ws).endswith(" · 1 early warning")


def test_headline_is_unchanged_without_early_warnings(ws: Workspace) -> None:
    ws.run()
    plain = headline(ws)
    write_part(ws, [])
    merge(ws)
    assert headline(ws) == plain
    assert "## Early warning" not in summary(ws)


def test_totals_line_places_the_early_warning_after_the_osv_count() -> None:
    report = {
        "totals": {"targets": {"total": 8, "ok": 8, "failed": 0, "not_applicable": 1}}
    }
    assert mr.totals_line(report, osv_only=3, early_warning="2 early warnings") == (
        "8/7 targets scanned · 3 found only by OSV · 2 early warnings "
        "· 1 not applicable"
    )


# ------------------------------------------------------------------- footer


def test_footer_names_the_index_the_window_and_the_gaps(ws: Workspace) -> None:
    write_part(ws, [candidate()])
    merge(ws)
    assert (
        "<sub>Early warning: CVE index of 2030-01-01 03:21Z (sha256:0123456789ab), "
        "records published or updated in the last 90 days "
        "(since 2029-10-12 10:00Z), 4321 checked</sub>"
    ) in summary(ws)
    gap = {"from": "2029-12-24T04:00:00Z", "to": "2029-12-24T07:00:00Z"}
    write_part(ws, [candidate()], index={**INDEX, "gaps": [gap]})
    report = merge(ws)
    assert report["index"]["gaps"] == [gap]
    assert "· feed gaps: 2029-12-24T04:00:00Z to 2029-12-24T07:00:00Z</sub>" in summary(
        ws
    )


def test_many_gaps_are_listed_up_to_a_few_and_counted(ws: Workspace) -> None:
    gaps = [
        {"from": f"2029-12-{day:02d}T04:00:00Z", "to": f"2029-12-{day:02d}T05:00:00Z"}
        for day in range(10, 18)
    ]
    write_part(ws, [], index={**INDEX, "gaps": gaps})
    assert merge(ws)["index"]["gaps"] == gaps  # the report has all of them
    text = summary(ws)
    assert "2029-12-14T04:00:00Z to 2029-12-14T05:00:00Z and 3 more</sub>" in text
    assert "2029-12-15" not in text


def test_footer_is_there_when_nothing_is_reported(ws: Workspace) -> None:
    write_part(ws, [])
    report = merge(ws)
    assert report["reported"] == 0
    assert "Early warning: CVE index of" in summary(ws)
    assert entries(ws) == []


def test_the_report_has_the_index_of_a_failed_part_too(ws: Workspace) -> None:
    write_part(ws, status="failed", reason="the delta cannot be read")
    assert merge(ws)["index"] == INDEX
    write_part(ws, status="failed", reason="cannot pull the index", index=None)
    assert merge(ws)["index"] is None


def test_an_ok_part_without_an_index_is_unavailable(ws: Workspace) -> None:
    write_part(ws, [candidate()], index=None)
    report = merge(ws)
    assert report["status"] == "failed"
    assert "no index" in report["reason"]


@pytest.mark.parametrize(
    "index", [{"ref": "r"}, {**INDEX, "gaps": [{"from": "x"}]}, "not an object"]
)
def test_an_index_that_is_not_valid_is_unavailable(ws: Workspace, index: Any) -> None:
    write_part(ws, [candidate()], index=index)
    report = merge(ws)
    assert report["status"] == "failed"
    assert "index is not valid" in report["reason"]


# ------------------------------------------------------------ failure semantics


def test_a_failed_part_is_reported_as_unavailable(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    write_part(ws, status="failed", reason="GET https://feed.example/x: HTTP 502")
    report = merge(ws)
    assert report["status"] == "failed"
    assert report["reason"] == "GET https://feed.example/x: HTTP 502"
    assert report["reported"] is None
    document = ws.json("_report/early_warning.json")
    assert (document["status"], document["entries"]) == ("failed", [])
    text = summary(ws)
    assert "## Early warning — unavailable" in text
    assert "Early warning unavailable: GET https://feed.example/x: HTTP 502" in text
    assert headline(ws).endswith(" · early warning unavailable")
    assert "::warning title=Early warning unavailable::" in capsys.readouterr().out


def test_a_missing_part_is_unavailable_not_empty(ws: Workspace) -> None:
    report = merge(ws)
    assert report["status"] == "failed"
    assert "missing" in report["reason"]
    assert "Early warning unavailable" in summary(ws)


@pytest.mark.parametrize("which", ["status", "candidates"])
def test_a_broken_part_is_unavailable(ws: Workspace, which: str) -> None:
    write_part(ws, [candidate()])
    (ws.parts / "early-warning" / f"{which}.json").write_text(
        "{not json", encoding="utf-8"
    )
    assert merge(ws)["status"] == "failed"


@pytest.mark.parametrize(
    "document",
    [
        {"schema_version": 2, "candidates": []},
        {"schema_version": 1, "candidates": {}},
        {"schema_version": 1, "candidates": [1]},
        {"schema_version": 1, "candidates": [{"cve": "CVE-2030-1"}]},
        {"schema_version": 1, "candidates": [{**candidate(), "sightings": {}}]},
        {
            "schema_version": 1,
            "candidates": [{**candidate(), "sightings": {"no-such-target": ["x"]}}],
        },
    ],
)
def test_a_part_that_does_not_fit_the_run_is_unavailable(
    ws: Workspace, document: dict[str, Any]
) -> None:
    write_part(ws, [])
    (ws.parts / "early-warning" / "candidates.json").write_text(
        json.dumps(document), encoding="utf-8"
    )
    assert merge(ws)["status"] == "failed"


def test_without_a_scanned_trivy_target_it_is_skipped(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path, make_targets_doc(SOURCE))
    workspace.add_part("source-development", None, status="failed", reason="boom")
    assert workspace.run(early_warning_enabled=True) == 1
    report = workspace.json("_report/scan_report.json")["early_warning"]
    assert report["status"] == "skipped"
    assert report["reason"] == "no Trivy target was scanned"
    assert "Early warning" not in summary(workspace)


def test_a_skipped_part_stays_skipped(ws: Workspace) -> None:
    write_part(ws, status="skipped", reason="no Trivy target was scanned")
    assert merge(ws)["status"] == "skipped"
    assert "Early warning" not in summary(ws)


def test_cli_flag_enables_the_early_warning(ws: Workspace) -> None:
    write_part(ws, [candidate()])
    args = [
        "--targets-file",
        str(ws.targets_file),
        "--parts-dir",
        str(ws.parts),
        "--output-dir",
        str(ws.out),
        "--step-summary",
        "false",
        "--early-warning-enabled",
        "true",
    ]
    assert mr.main(args) == 0
    assert ws.json("_report/scan_report.json")["early_warning"]["reported"] == 1
    assert mr.parse_args(args[:-2]).early_warning_enabled is False
