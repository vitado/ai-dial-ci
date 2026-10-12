"""Tests of the diff against the baseline run: actions/sca_merge_results/sca_diff.py and
its use in merge_results.py (synthetic fixtures only)."""

from __future__ import annotations

import copy
import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import sca_diff
from test_early_warning_merge import candidate, write_part
from test_merge_results import (
    DEV,
    REL,
    SOURCE,
    Workspace,
    make_targets_doc,
    mr,
)

# ------------------------------------------------------------ classification


def targets(**states: bool) -> dict[str, bool]:
    return states


def test_target_states_need_every_scanner_ok() -> None:
    states = sca_diff.target_states(
        [
            {"id": "a", "scanner": "trivy", "status": "ok"},
            {"id": "a", "scanner": "osv", "status": "failed"},
            {"id": "b", "scanner": "trivy", "status": "ok"},
            {"id": "b", "scanner": "osv", "status": "ok"},
            {"id": "c", "scanner": "trivy", "status": "not_applicable"},
        ]
    )
    assert states == {"a": False, "b": True, "c": False}


def classify(
    current: dict[str, list[str]],
    baseline: dict[str, list[str]],
    current_ok: dict[str, bool],
    baseline_ok: dict[str, bool],
) -> sca_diff.Classification:
    return sca_diff.classify(current, baseline, current_ok, baseline_ok)


def test_new_resolved_unchanged() -> None:
    ok = {"t": True}
    result = classify({"k1": ["t"], "k2": ["t"]}, {"k2": ["t"], "k3": ["t"]}, ok, ok)
    assert result.new == ["k1"]
    assert result.resolved == ["k3"]
    assert result.unchanged == ["k2"]
    assert not result.not_comparable
    assert result.states == {"k1": sca_diff.NEW, "k2": sca_diff.UNCHANGED}


def test_new_needs_every_target_it_is_seen_in_to_be_ok_in_the_baseline() -> None:
    result = classify(
        {"k": ["a", "b"]}, {}, {"a": True, "b": True}, {"a": True, "b": False}
    )
    assert result.new == []
    (item,) = result.not_comparable
    assert (item.key, item.direction, item.targets) == (
        "k",
        sca_diff.APPEARED,
        ["b"],
    )
    assert result.states == {"k": sca_diff.NOT_COMPARABLE}


def test_a_target_that_is_not_in_the_baseline_makes_it_not_comparable() -> None:
    # a new release tag: its findings cannot be told from old ones
    result = classify({"k": ["source-1.2.0"]}, {}, {"source-1.2.0": True}, {})
    assert [n.direction for n in result.not_comparable] == [sca_diff.APPEARED]


def test_resolved_needs_every_target_it_was_seen_in_to_be_ok_now() -> None:
    result = classify(
        {}, {"k": ["a", "b"]}, {"a": True, "b": False}, {"a": True, "b": True}
    )
    assert result.resolved == []
    (item,) = result.not_comparable
    assert (item.direction, item.targets) == (sca_diff.DISAPPEARED, ["b"])


def test_a_target_that_is_gone_makes_it_not_comparable() -> None:
    result = classify({}, {"k": ["source-1.1.0"]}, {}, {"source-1.1.0": True})
    assert [n.direction for n in result.not_comparable] == [sca_diff.DISAPPEARED]


def test_an_item_in_both_runs_is_unchanged_whatever_the_targets_say() -> None:
    result = classify({"k": ["a"]}, {"k": ["b"]}, {"a": True}, {"b": False})
    assert result.unchanged == ["k"]


# ------------------------------------------------------------ differences


def report(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": 1,
        "config": {
            "source": ".github/sca.yml@aaa",
            "overrides": None,
            "non_shipped_paths": ["examples/"],
            "trivy_skip_paths": "as_non_shipped",
        },
        "targets": [
            {"id": "source-development", "scanner": "trivy", "kind": "fs",
             "tag": None, "git_ref": "development"},
            {"id": "source-1.0.0", "scanner": "trivy", "kind": "fs",
             "tag": "1.0.0", "git_ref": "1.0.0"},
            {"id": "source-development", "scanner": "osv", "kind": "fs",
             "tag": None, "git_ref": "development"},
        ],
        "early_warning": {"status": "ok"},
    }  # fmt: skip
    return {**base, **changes}


def test_identical_conditions_do_not_differ() -> None:
    other = report()
    other["config"] = {
        **other["config"],
        "source": ".github/sca.yml@bbb",
    }  # a new commit
    assert sca_diff.baseline_differences(report(), other) == []


def test_a_report_without_a_config_has_the_default_one() -> None:
    # a report of an older version has no config: that is the defaults
    now = report(config={"source": None, "overrides": None, "non_shipped_paths": [],
                         "trivy_skip_paths": "as_non_shipped"})  # fmt: skip
    was = report()
    del was["config"]
    assert sca_diff.baseline_differences(now, was) == []
    assert sca_diff.baseline_differences(report(), was) == [
        "config source: defaults → .github/sca.yml",
        "config non_shipped_paths: [] → ['examples/']",
    ]


def test_differences_name_what_changed() -> None:
    now = report()
    was = report(
        schema_version=2,
        config={
            "source": "input",
            "overrides": ".github/sca.yml@x",
            "non_shipped_paths": [],
            "trivy_skip_paths": "apply",
        },
        targets=[t for t in report()["targets"] if t["id"] == "source-development"
                 and t["scanner"] == "trivy"],
        early_warning=None,
    )  # fmt: skip
    reasons = sca_diff.baseline_differences(now, was)
    assert reasons == [
        "schema_version: 2 → 1",
        "config source: input → .github/sca.yml",
        "config non_shipped_paths: [] → ['examples/']",
        "config trivy_skip_paths: apply → as_non_shipped",
        "osv-enabled: off → on",
        "scan-release-source: off → on",
        "early-warning-enabled: off → on",
    ]


def test_a_new_scanner_is_named() -> None:
    now = report(targets=[*report()["targets"], {"id": "x", "scanner": "grype"}])
    reasons = sca_diff.baseline_differences(now, report())
    assert reasons == ["scanners: trivy → grype, trivy"]


def test_an_unresolved_release_source_counts_as_one() -> None:
    placeholder = {"id": "source-release", "scanner": "trivy", "kind": "fs",
                   "tag": None, "git_ref": None}  # fmt: skip
    now = report(targets=[report()["targets"][0], placeholder])
    was = report(targets=[report()["targets"][0]])
    assert sca_diff.baseline_differences(now, was) == ["scan-release-source: off → on"]


# ------------------------------------------------------------ the merge

GENERATED = "2030-01-02T00:00:00Z"


def make_ws(
    tmp_path: Path,
    run_id: str,
    started: str = "2030-01-01T00:00:00Z",
    **doc: Any,
) -> Workspace:
    """fs + development image + release image, all ok; the run ``run_id``."""
    directory = tmp_path / f"run-{run_id}-{len(list(tmp_path.iterdir()))}"
    directory.mkdir()
    targets_doc = make_targets_doc(SOURCE, DEV, REL)
    targets_doc.update(
        run_id=run_id,
        run_url=f"https://github.com/example/app/actions/runs/{run_id}",
        run_started_at=started,
        **doc,
    )
    ws = Workspace(directory, targets_doc)
    ws.add_part("source-development", "source", lockfiles=3)
    ws.add_part("app-development", "app-development")
    ws.add_part("app-1.0.0", "app-1.0.0")
    return ws


def baseline_of(
    ws: Workspace,
    mutate: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
) -> Path:
    """The sca-report of ``ws`` (merged without a baseline), as the baseline of
    another run; ``mutate(scan_report, vulnerabilities)`` may change it.
    """
    assert ws.run() == 0
    target = ws.out.parent / "baseline"
    shutil.copytree(ws.out, target)
    if mutate:
        report_path = target / "_report" / "scan_report.json"
        vulns_path = target / "_report" / "vulnerabilities.json"
        scan_report = json.loads(report_path.read_text(encoding="utf-8"))
        vulns = json.loads(vulns_path.read_text(encoding="utf-8"))
        mutate(scan_report, vulns)
        report_path.write_text(json.dumps(scan_report), encoding="utf-8")
        vulns_path.write_text(json.dumps(vulns), encoding="utf-8")
    return target


def drop_record(cve: str) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    def mutate(_: dict[str, Any], vulns: dict[str, Any]) -> None:
        vulns["records"] = [r for r in vulns["records"] if r["cve"] != cve]

    return mutate


def merged(
    ws: Workspace, baseline: Path | None, failed: int = 0, **kwargs: Any
) -> dict[str, Any]:
    """Merge ``ws`` against the baseline (``failed``: the failed targets expected)."""
    assert ws.run(baseline_dir=baseline, **kwargs) == failed
    return ws.json("_report/diff.json")


def states(ws: Workspace) -> dict[str, str]:
    return {
        r["cve"]: r["diff"] for r in ws.json("_report/vulnerabilities.json")["records"]
    }


def summary(ws: Workspace) -> str:
    return (ws.out / "summary.md").read_text(encoding="utf-8")


def test_every_class_of_a_record(tmp_path: Path) -> None:
    def mutate(report: dict[str, Any], vulns: dict[str, Any]) -> None:
        # CVE-2000-0001 is new, CVE-9999-0001 is gone, the OS finding of the
        # release image was not scanned in the baseline (not comparable)
        vulns["records"] = [
            r for r in vulns["records"] if r["cve"] not in ("CVE-2000-0001",)
        ]
        gone = copy.deepcopy(vulns["records"][0])
        gone.update(cve="CVE-9999-0001", scan_targets=["app-development"])
        vulns["records"].append(gone)

    baseline = baseline_of(make_ws(tmp_path, "41"), mutate)
    ws = make_ws(tmp_path, "42")
    diff = merged(ws, baseline)

    assert diff["schema_version"] == 1
    assert diff["baseline"] == {
        "run_id": "41",
        "run_url": "https://github.com/example/app/actions/runs/41",
        "run_started_at": "2030-01-01T00:00:00Z",
        "commit_sha": "0123456789abcdef0123456789abcdef01234567",
    }
    assert diff["reason"] is None
    assert [r["cve"] for r in diff["new"]] == ["CVE-2000-0001"]
    assert [r["cve"] for r in diff["resolved"]] == ["CVE-9999-0001"]
    assert diff["not_comparable"] == []
    assert diff["unchanged"] == 4
    assert diff["baseline_differs"] == []
    new = diff["new"][0]
    assert (new["pkg"], new["version"], new["severity"]) == ("lodash", "4.17.0", "HIGH")
    assert new["exposure"] == "development_only"
    assert new["scan_targets"] == ["source-development", "app-development"]
    assert states(ws) == {
        "CVE-2000-0010": "unchanged",
        "CVE-2000-0011": "unchanged",
        "CVE-2000-0001": "new",
        "CVE-2000-0002": "unchanged",
        "CVE-2000-0003": "unchanged",
    }
    report = ws.json("_report/scan_report.json")
    assert report["diff"] == {
        "baseline_run_id": "41",
        "baseline_started_at": "2030-01-01T00:00:00Z",
        "counts": {
            "new": 1,
            "resolved": 1,
            "not_comparable": 0,
            "unchanged": 4,
            "early_warning": None,
        },
        "baseline_differs": [],
        "reason": None,
    }


def test_a_failed_target_in_the_baseline_makes_its_findings_not_comparable(
    tmp_path: Path,
) -> None:
    def mutate(report: dict[str, Any], vulns: dict[str, Any]) -> None:
        for target in report["targets"]:
            if target["id"] == "app-1.0.0":
                target["status"] = "failed"
        # the failed scan found nothing of the release image
        vulns["records"] = [r for r in vulns["records"] if r["cve"] != "CVE-2000-0011"]

    baseline = baseline_of(make_ws(tmp_path, "41"), mutate)
    ws = make_ws(tmp_path, "42")
    diff = merged(ws, baseline)
    assert diff["new"] == []
    (item,) = diff["not_comparable"]
    assert item["cve"] == "CVE-2000-0011"
    assert item["direction"] == "appeared"
    assert item["targets"] == ["app-1.0.0"]
    assert states(ws)["CVE-2000-0011"] == "not_comparable"
    counts = ws.json("_report/scan_report.json")["diff"]["counts"]
    assert counts["not_comparable"] == 1


def test_a_failed_target_now_makes_what_disappeared_not_comparable(
    tmp_path: Path,
) -> None:
    baseline = baseline_of(make_ws(tmp_path, "41"))
    ws = make_ws(tmp_path, "42")
    ws.add_part("app-1.0.0", None, status="failed", reason="boom")
    (ws.trivy_parts / "app-1.0.0.json").unlink()
    diff = merged(ws, baseline, failed=1)
    assert diff["resolved"] == []
    assert {r["cve"] for r in diff["not_comparable"]} == {"CVE-2000-0011"}
    assert all(r["direction"] == "disappeared" for r in diff["not_comparable"])
    # CVE-2000-0010 is still in app-development, so it is unchanged
    assert diff["unchanged"] == 4


def test_a_package_upgrade_is_resolved_and_new(tmp_path: Path) -> None:
    def mutate(report: dict[str, Any], vulns: dict[str, Any]) -> None:
        for record in vulns["records"]:
            if record["cve"] == "CVE-2000-0001":
                record["version"] = "4.16.0"  # the baseline had the older lodash

    baseline = baseline_of(make_ws(tmp_path, "41"), mutate)
    ws = make_ws(tmp_path, "42")
    diff = merged(ws, baseline)
    assert [(r["cve"], r["version"]) for r in diff["new"]] == [
        ("CVE-2000-0001", "4.17.0")
    ]
    assert [(r["cve"], r["version"]) for r in diff["resolved"]] == [
        ("CVE-2000-0001", "4.16.0")
    ]


def test_python_package_names_are_compared_pep_503_style(tmp_path: Path) -> None:
    mako = {"repo": "r", "cve": "C", "pkg": "Mako", "version": "1"}
    assert mr.record_key({**mako, "ecosystem": ["python-pkg"]}) == (
        "r",
        "C",
        "mako",
        "1",
    )
    assert mr.record_key({**mako, "ecosystem": ["npm"]}) == ("r", "C", "Mako", "1")


def test_no_baseline_marks_records_baseline_not_new(tmp_path: Path) -> None:
    ws = make_ws(tmp_path, "42")
    diff = merged(ws, None, baseline_reason="no earlier full run of sca-scan.yml")
    assert diff["baseline"] is None
    assert diff["reason"] == "no earlier full run of sca-scan.yml"
    assert (diff["new"], diff["resolved"], diff["not_comparable"]) == ([], [], [])
    assert diff["unchanged"] is None
    assert set(states(ws).values()) == {"baseline"}
    report = ws.json("_report/scan_report.json")
    assert report["diff"] == {
        "baseline_run_id": None,
        "baseline_started_at": None,
        "counts": None,
        "baseline_differs": [],
        "reason": "no earlier full run of sca-scan.yml",
    }
    assert (
        "> No baseline to compare with: no earlier full run of sca-scan.yml"
        in summary(ws)
    )
    assert " new" not in summary(ws).split("## What to fix")[1].split("\n")[4]


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (lambda b: None, "no baseline report was provided"),
        (
            lambda b: (b / "_report" / "scan_report.json").write_text("{"),
            "the baseline report is unreadable",
        ),
        (
            lambda b: (b / "_report" / "scan_report.json").write_text("[]"),
            "the baseline report is not valid",
        ),
        (
            lambda b: (b / "_report" / "vulnerabilities.json").unlink(),
            "the baseline report is unreadable",
        ),
    ],
)
def test_an_unusable_baseline_is_reported_and_never_fails_the_merge(
    tmp_path: Path, setup: Callable[[Path], None], reason: str
) -> None:
    baseline = baseline_of(make_ws(tmp_path, "41"))
    if reason == "no baseline report was provided":
        shutil.rmtree(baseline)
    setup(baseline)
    ws = make_ws(tmp_path, "42")
    diff = merged(ws, baseline)
    assert diff["baseline"] is None
    assert reason in diff["reason"]


def test_a_baseline_of_another_repository_is_refused(tmp_path: Path) -> None:
    def mutate(report: dict[str, Any], vulns: dict[str, Any]) -> None:
        report["repo"] = "example/other"

    baseline = baseline_of(make_ws(tmp_path, "41"), mutate)
    diff = merged(make_ws(tmp_path, "42"), baseline)
    assert diff["baseline"] is None
    assert "example/other" in diff["reason"]


def test_the_run_is_not_its_own_baseline(tmp_path: Path) -> None:
    baseline = baseline_of(make_ws(tmp_path, "42"))
    diff = merged(make_ws(tmp_path, "42"), baseline)
    assert diff["reason"] == "the baseline is this very run"


def test_baseline_differs_is_flagged_but_the_diff_is_computed(
    tmp_path: Path,
) -> None:
    def mutate(report: dict[str, Any], vulns: dict[str, Any]) -> None:
        report["schema_version"] = 0
        report["config"]["non_shipped_paths"] = ["examples/"]

    baseline = baseline_of(make_ws(tmp_path, "41"), mutate)
    ws = make_ws(tmp_path, "42")
    diff = merged(ws, baseline)
    assert diff["baseline_differs"] == [
        "schema_version: 0 → 1",
        "config non_shipped_paths: ['examples/'] → []",
    ]
    assert diff["unchanged"] == 5
    assert (
        ws.json("_report/scan_report.json")["diff"]["baseline_differs"]
        == (diff["baseline_differs"])
    )
    assert "baseline made under other conditions: schema_version: 0 → 1" in summary(ws)


# ------------------------------------------------------------ summary


def test_summary_line_and_marks(tmp_path: Path) -> None:
    def mutate(report: dict[str, Any], vulns: dict[str, Any]) -> None:
        vulns["records"] = [
            r
            for r in vulns["records"]
            if r["cve"] not in ("CVE-2000-0001", "CVE-2000-0002")
        ]
        gone = copy.deepcopy(vulns["records"][0])
        gone.update(cve="CVE-9999-0001", pkg="gone-pkg", version="9")
        vulns["records"].append(gone)

    baseline = baseline_of(make_ws(tmp_path, "41"), mutate)
    ws = make_ws(tmp_path, "42")
    merged(ws, baseline)
    text = summary(ws)
    line = (
        "> Since 2030-01-01 "
        "([run 41](https://github.com/example/app/actions/runs/41)): "
        "+2 new · −1 resolved"
    )
    assert line in text.splitlines()
    # the line closes the headline
    assert text.index(line) < text.index("## What to fix")
    # What to fix row and the severity rows carry the mark; unchanged ones do not
    assert "| lodash · npm · new |" in text
    assert "CVE-2000-0001](https://example.invalid/CVE-2000-0001) · new" in text
    assert "minimist" in text
    assert "CVE-2000-0002](https://example.invalid/CVE-2000-0002) · new" in text
    assert "CVE-2000-0010](https://example.invalid/CVE-2000-0010) · new" not in text
    # the resolved list
    assert "<summary>Resolved since 2030-01-01 (1)</summary>" in text
    assert "| CVE-9999-0001 | gone-pkg 9 |" in text


def test_the_resolved_list_is_short(tmp_path: Path) -> None:
    def mutate(report: dict[str, Any], vulns: dict[str, Any]) -> None:
        for i in range(mr.MAX_LISTED_RESOLVED + 5):
            gone = copy.deepcopy(vulns["records"][0])
            gone.update(cve=f"CVE-9999-{i:04d}")
            vulns["records"].append(gone)

    baseline = baseline_of(make_ws(tmp_path, "41"), mutate)
    ws = make_ws(tmp_path, "42")
    diff = merged(ws, baseline)
    assert len(diff["resolved"]) == mr.MAX_LISTED_RESOLVED + 5
    text = summary(ws)
    assert "+5 more, see `_report/diff.json`" in text
    assert text.count("| CVE-9999-") == mr.MAX_LISTED_RESOLVED


def test_not_comparable_is_counted_in_the_line(tmp_path: Path) -> None:
    def mutate(report: dict[str, Any], vulns: dict[str, Any]) -> None:
        for target in report["targets"]:
            if target["id"] == "app-1.0.0":
                target["status"] = "failed"
        vulns["records"] = [r for r in vulns["records"] if r["cve"] != "CVE-2000-0011"]

    baseline = baseline_of(make_ws(tmp_path, "41"), mutate)
    ws = make_ws(tmp_path, "42")
    merged(ws, baseline)
    assert "+0 new · −0 resolved · 1 not comparable" in summary(ws)


# ------------------------------------------------------------ early warning

EW_KEY = "CVE-2030-0001"


def ew_baseline(
    tmp_path: Path, candidates: list[dict[str, Any]], mutate: Any = None
) -> Path:
    ws = make_ws(tmp_path, "41")
    write_part(ws, candidates)
    assert ws.run(early_warning_enabled=True) == 0
    target = tmp_path / "baseline"
    shutil.copytree(ws.out, target)
    if mutate:
        mutate(target)
    return target


def ew_run(tmp_path: Path, candidates: list[dict[str, Any]], baseline: Path | None):
    ws = make_ws(tmp_path, "42")
    write_part(ws, candidates)
    assert ws.run(early_warning_enabled=True, baseline_dir=baseline) == 0
    return ws, ws.json("_report/diff.json")


def test_early_warning_diff_classes(tmp_path: Path) -> None:
    baseline = ew_baseline(
        tmp_path, [candidate("CVE-2030-0001"), candidate("CVE-2030-0002")]
    )
    ws, diff = ew_run(
        tmp_path, [candidate("CVE-2030-0002"), candidate("CVE-2030-0003")], baseline
    )
    ew = diff["early_warning"]
    assert ew["status"] == "ok"
    assert [e["cve"] for e in ew["new"]] == ["CVE-2030-0003"]
    assert [e["cve"] for e in ew["resolved"]] == ["CVE-2030-0001"]
    assert ew["unchanged"] == 1
    assert ew["confirmed"] == []
    assert ew["not_comparable"] == []
    counts = ws.json("_report/scan_report.json")["diff"]["counts"]["early_warning"]
    assert counts == {
        "new": 1,
        "resolved": 1,
        "not_comparable": 0,
        "unchanged": 1,
        "confirmed": 0,
    }
    marks = {
        e["cve"]: e["diff"] for e in ws.json("_report/early_warning.json")["entries"]
    }
    assert marks == {"CVE-2030-0002": "unchanged", "CVE-2030-0003": "new"}
    text = summary(ws)
    assert "early warnings: 1 new, 1 resolved" in text
    assert (
        "Early warnings that are gone: "
        "CVE-2030-0001 (com.google.guava:guava 33.4.8-jre)" in text
    )


def test_early_warning_confirmed_by_a_database(tmp_path: Path) -> None:
    # the baseline early warning named a CVE that is a record in this run
    def add_entry(baseline: Path) -> None:
        path = baseline / "_report" / "early_warning.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        entry = dict(document["entries"][0], cve="CVE-2000-0001")
        document["entries"].append(entry)
        path.write_text(json.dumps(document), encoding="utf-8")

    baseline = ew_baseline(tmp_path, [candidate("CVE-2030-0002")], add_entry)
    ws, diff = ew_run(tmp_path, [candidate("CVE-2030-0002")], baseline)
    ew = diff["early_warning"]
    (confirmed,) = ew["confirmed"]
    assert confirmed["cve"] == "CVE-2000-0001"
    assert [r["pkg"] for r in confirmed["records"]] == ["lodash"]
    # confirmed is not also resolved
    assert ew["resolved"] == []
    counts = ws.json("_report/scan_report.json")["diff"]["counts"]["early_warning"]
    assert counts["confirmed"] == 1
    assert "early warnings: 1 confirmed" in summary(ws)
    assert "Early warnings that a database reports now: CVE-2000-0001" in summary(ws)


def test_early_warning_without_a_matching_record_is_resolved_not_confirmed(
    tmp_path: Path,
) -> None:
    baseline = ew_baseline(
        tmp_path, [candidate("CVE-2030-0001", aliases=["GHSA-AAAA-BBBB-CCCC"])]
    )

    ws = make_ws(tmp_path, "42")
    write_part(ws, [])
    assert ws.run(early_warning_enabled=True, baseline_dir=baseline) == 0
    # no record has that id or alias: nothing is confirmed, it is gone
    ew = ws.json("_report/diff.json")["early_warning"]
    assert ew["confirmed"] == []
    assert [e["cve"] for e in ew["resolved"]] == ["CVE-2030-0001"]


def test_early_warning_not_comparable_per_target(tmp_path: Path) -> None:
    def mutate(target: Path) -> None:
        path = target / "_report" / "scan_report.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        for t in data["targets"]:
            if t["id"] == "source-development":
                t["status"] = "failed"
        path.write_text(json.dumps(data), encoding="utf-8")

    baseline = ew_baseline(tmp_path, [], mutate)
    _, diff = ew_run(tmp_path, [candidate("CVE-2030-0003")], baseline)
    ew = diff["early_warning"]
    assert ew["new"] == []
    (item,) = ew["not_comparable"]
    assert (item["cve"], item["direction"], item["targets"]) == (
        "CVE-2030-0003",
        "appeared",
        ["source-development"],
    )


def test_early_warning_diff_is_unavailable_without_a_baseline_result(
    tmp_path: Path,
) -> None:
    baseline = ew_baseline(
        tmp_path,
        [candidate("CVE-2030-0001")],
        lambda b: (b / "_report" / "early_warning.json").unlink(),
    )
    ws, diff = ew_run(tmp_path, [candidate("CVE-2030-0001")], baseline)
    assert diff["early_warning"] == {
        "status": "unavailable",
        "reason": "the baseline has no early warning",
    }
    # nothing is called new
    assert {e["diff"] for e in ws.json("_report/early_warning.json")["entries"]} == {
        "baseline"
    }
    assert (
        ws.json("_report/scan_report.json")["diff"]["counts"]["early_warning"] is None
    )


def test_early_warning_diff_is_unavailable_when_the_early_warning_failed(
    tmp_path: Path,
) -> None:
    baseline = ew_baseline(tmp_path, [candidate("CVE-2030-0001")])
    ws = make_ws(tmp_path, "42")
    write_part(ws, status="failed", reason="feed down")
    assert ws.run(early_warning_enabled=True, baseline_dir=baseline) == 0
    assert ws.json("_report/diff.json")["early_warning"] == {
        "status": "unavailable",
        "reason": "the early warning of this run failed",
    }


def test_no_early_warning_in_this_run_has_no_early_warning_diff(
    tmp_path: Path,
) -> None:
    baseline = baseline_of(make_ws(tmp_path, "41"))
    ws = make_ws(tmp_path, "42")
    diff = merged(ws, baseline)
    assert diff["early_warning"] is None
    assert diff["baseline_differs"] == []


# ------------------------------------------------------------ run kind


def test_run_kind_is_reported_and_validated(tmp_path: Path) -> None:
    ws = make_ws(
        tmp_path, "42", run_kind="partial", run_kind_reasons=["targets filter: x"]
    )
    ws.run()
    report = ws.json("_report/scan_report.json")
    assert report["run_kind"] == "partial"
    assert report["run_kind_reasons"] == ["targets filter: x"]
    assert "> Partial run (targets filter: x): not used as a baseline" in summary(ws)


def test_a_full_run_has_no_partial_note(tmp_path: Path) -> None:
    ws = make_ws(tmp_path, "42")
    ws.run()
    assert "Partial run" not in summary(ws)
    assert ws.json("_report/scan_report.json")["run_kind"] == "full"


@pytest.mark.parametrize("kind", [None, "half"])
def test_an_invalid_run_kind_fails_the_merge(tmp_path: Path, kind: str | None) -> None:
    ws = make_ws(tmp_path, "42", run_kind=kind)
    with pytest.raises(mr.InputError, match="run_kind"):
        ws.run()
