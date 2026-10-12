"""Tests for actions/sca_merge_results/merge_results.py (synthetic fixtures only)."""

from __future__ import annotations

import csv
import importlib.util
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures" / "merge_results"
GENERATED = "2030-01-01T00:00:00Z"


def _load_merge_results():
    path = ROOT / "actions" / "sca_merge_results" / "merge_results.py"
    spec = importlib.util.spec_from_file_location("merge_results", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mr = _load_merge_results()

SOURCE = {
    "id": "source-development",
    "kind": "fs",
    "image": None,
    "tag": None,
    "ref": None,
    "git_ref": "development",
    "commit_sha": "fedcba9876543210fedcba9876543210fedcba98",
}
DEV = {
    "id": "app-development",
    "kind": "image",
    "image": "example/app",
    "tag": "development",
    "ref": "ghcr.io/example/app:development",
    "git_ref": None,
    "commit_sha": None,
}
REL = {
    "id": "app-1.0.0",
    "kind": "image",
    "image": "example/app",
    "tag": "1.0.0",
    "ref": "ghcr.io/example/app:1.0.0",
    "git_ref": None,
    "commit_sha": None,
}


def make_targets_doc(*targets: dict[str, Any]) -> dict[str, Any]:
    """targets.json content with all given targets pending."""
    items = [{"status": "pending", "reason": None, **t} for t in targets]
    return {
        "repo": "example/app",
        "default_branch": "main",
        "commit_sha": "0123456789abcdef0123456789abcdef01234567",
        "registry": "ghcr.io",
        "release_lines": 1,
        "run_id": "42",
        "run_url": "https://github.com/example/app/actions/runs/42",
        "run_started_at": "2030-01-01T00:00:00Z",
        "targets": items,
    }


class Workspace:
    """targets.json + parts dir + output dir in tmp_path."""

    def __init__(self, tmp_path: Path, targets_doc: dict[str, Any]) -> None:
        self.targets_file = tmp_path / "targets.json"
        self.targets_file.write_text(json.dumps(targets_doc), encoding="utf-8")
        self.parts = tmp_path / "parts"
        self.trivy_parts = self.parts / mr.SCANNER_TRIVY
        self.trivy_parts.mkdir(parents=True)
        self.out = tmp_path / "out"

    def add_part(self, tid: str, fixture: str | None, **status: Any) -> None:
        """Add a part: a fixture as <id>.json and an ok status unless overridden."""
        if fixture:
            shutil.copy(FIXTURES / f"{fixture}.json", self.trivy_parts / f"{tid}.json")
        body = {"id": tid, "status": "ok", "reason": None, "lockfiles": None}
        body.update(status)
        (self.trivy_parts / f"{tid}.status.json").write_text(
            json.dumps(body), encoding="utf-8"
        )

    def run(self, generated: str = GENERATED) -> int:
        return mr.run_merge(self.targets_file, self.parts, self.out, generated)

    def json(self, rel: str) -> Any:
        return json.loads((self.out / rel).read_text(encoding="utf-8"))

    @property
    def targets(self) -> dict[str, dict[str, Any]]:
        return {t["id"]: t for t in self.json("_report/scan_report.json")["targets"]}


@pytest.fixture
def full(tmp_path: Path) -> Workspace:
    """fs + two images, all ok."""
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, DEV, REL))
    ws.add_part("source-development", "source", lockfiles=3)
    ws.add_part("app-development", "app-development")
    ws.add_part("app-1.0.0", "app-1.0.0")
    return ws


def records_by_cve(ws: Workspace) -> dict[str, dict[str, Any]]:
    return {r["cve"]: r for r in ws.json("_report/vulnerabilities.json")["records"]}


# ---------------------------------------------------------------- merging


def test_dedup_across_lockfiles_within_one_target(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", "source", lockfiles=3)
    ws.run()
    rec = records_by_cve(ws)["CVE-2000-0003"]
    assert rec["locations"] == ["app/gradle.lockfile", "core/gradle.lockfile"]
    assert rec["scan_targets"] == ["source-development"]
    entry = ws.targets["source-development"]
    # 4 raw rows (the gradle finding appears in two lockfiles), 3 unique
    assert (entry["findings_raw"], entry["findings_unique"]) == (4, 3)
    assert entry["vulnerable_package_versions"] == 3
    assert entry["lockfiles"] == 3


def test_fixed_version_backfilled_from_other_copy(full: Workspace) -> None:
    full.run()
    rec = records_by_cve(full)["CVE-2000-0003"]
    # the first lockfile copy has no FixedVersion, the second one does
    assert rec["fix_available"] is True
    assert rec["fixed_version"] == "1.1"


def test_merge_across_fs_and_images_keeps_targets_file_order(full: Workspace) -> None:
    full.run()
    recs = records_by_cve(full)
    assert recs["CVE-2000-0001"]["scan_targets"] == [
        "source-development",
        "app-development",
    ]
    assert recs["CVE-2000-0001"]["locations"] == ["Node.js", "package-lock.json"]
    assert recs["CVE-2000-0010"]["scan_targets"] == ["app-development", "app-1.0.0"]
    assert recs["CVE-2000-0002"]["scan_targets"] == ["source-development"]


def test_record_fields_and_ordering(full: Workspace) -> None:
    full.run()
    vulns = full.json("_report/vulnerabilities.json")
    assert vulns["merge_key"] == mr.MERGE_KEY
    assert [r["cve"] for r in vulns["records"]] == [
        "CVE-2000-0002",  # CRITICAL
        "CVE-2000-0001",  # HIGH
        "CVE-2000-0003",  # MEDIUM, with fix
        "CVE-2000-0010",  # MEDIUM, with fix
        "CVE-2000-0011",  # LOW
    ]
    openssl = records_by_cve(full)["CVE-2000-0011"]
    assert openssl == {
        "repo": "example/app",
        "cve": "CVE-2000-0011",
        "pkg": "openssl",
        "version": "3.0.0",
        "scan_targets": ["app-1.0.0"],
        "locations": ["ghcr.io/example/app:1.0.0 (alpine 3.19)"],
        "scanners": ["trivy"],
        "severity": "LOW",
        "status": "will_not_fix",
        "pkg_type": "os",
        "ecosystem": ["alpine"],
        "title": "Pipe | in title",
        "fixed_version": None,
        "fix_available": False,
        "cwe": ["CWE-79"],
        "published": "2020-01-01T00:00:00Z",
        "primary_url": "https://example.invalid/CVE-2000-0011",
    }
    assert records_by_cve(full)["CVE-2000-0001"]["pkg_type"] == "library"


def test_no_fix_sorts_after_fix_within_severity() -> None:
    def record(cve: str, fixed: bool) -> dict[str, Any]:
        return {
            "severity": "HIGH",
            "fix_available": fixed,
            "repo": "r",
            "cve": cve,
            "pkg": "p",
            "version": "1",
        }

    ordered = sorted([record("A", False), record("B", True)], key=mr.record_sort_key)
    assert [r["cve"] for r in ordered] == ["B", "A"]


def test_counts_and_per_target(full: Workspace) -> None:
    full.run()
    vulns = full.json("_report/vulnerabilities.json")
    counts = vulns["counts"]
    assert (counts["records"], counts["with_fix"], counts["no_fix"]) == (5, 3, 2)
    assert counts["by_severity"] == {
        "CRITICAL": {"total": 1, "with_fix": 0, "no_fix": 1},
        "HIGH": {"total": 1, "with_fix": 1, "no_fix": 0},
        "MEDIUM": {"total": 2, "with_fix": 2, "no_fix": 0},
        "LOW": {"total": 1, "with_fix": 0, "no_fix": 1},
    }
    assert list(counts["by_severity"]) == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert vulns["per_target"] == {
        "source-development": {"records": 3, "only_in_target": 2},
        "app-development": {"records": 2, "only_in_target": 0},
        "app-1.0.0": {"records": 2, "only_in_target": 1},
    }


def test_image_digest_and_trivy_version(full: Workspace) -> None:
    full.run()
    targets = full.targets
    assert targets["source-development"]["image_digest"] is None
    assert (
        targets["app-development"]["image_digest"]
        == "ghcr.io/example/app@sha256:" + "a" * 64
    )
    assert (
        targets["app-1.0.0"]["image_digest"] == "ghcr.io/example/app@sha256:" + "c" * 64
    )
    report = full.json("_report/scan_report.json")
    assert report["trivy_version"] == "0.0.0-test"
    assert report["repo"] == "example/app"
    assert report["commit_sha"] == "0123456789abcdef0123456789abcdef01234567"
    assert report["default_branch"] == "main"
    assert report["run_id"] == "42"
    assert report["run_started_at"] == "2030-01-01T00:00:00Z"
    assert report["generated_utc"] == GENERATED


def test_trivy_version_null_without_ok_native(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.run()
    assert ws.json("_report/scan_report.json")["trivy_version"] is None


# ---------------------------------------------------------------- statuses


def test_targets_file_failed_and_not_applicable_are_carried_through(
    tmp_path: Path,
) -> None:
    targets_doc = make_targets_doc(SOURCE, DEV, REL)
    targets_doc["targets"][1].update(status="not_applicable", reason="tag not found")
    targets_doc["targets"][2].update(status="failed", reason="registry unreachable")
    ws = Workspace(tmp_path, targets_doc)
    ws.add_part("source-development", "source")
    # stray parts of non-pending targets must not resurrect them
    ws.add_part("app-1.0.0", "app-1.0.0")
    assert ws.run() == 1
    targets = ws.targets
    assert (
        targets["app-development"]["status"],
        targets["app-development"]["reason"],
    ) == (
        "not_applicable",
        "tag not found",
    )
    assert (targets["app-1.0.0"]["status"], targets["app-1.0.0"]["reason"]) == (
        "failed",
        "registry unreachable",
    )
    assert targets["app-1.0.0"]["findings_unique"] is None
    assert set(ws.json("_report/vulnerabilities.json")["per_target"]) == {
        "source-development"
    }


def test_pending_without_status_file_is_failed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    assert ws.run() == 1
    entry = ws.targets["source-development"]
    assert entry["status"] == "failed"
    assert entry["reason"] == "scan job produced no result"
    assert entry["vulnerable_package_versions"] is None


def test_status_failed_uses_its_reason(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part(
        "source-development",
        None,
        status="failed",
        reason="gradle exploded",
        lockfiles=0,
    )
    assert ws.run() == 1
    assert ws.targets["source-development"]["status"] == "failed"
    assert ws.targets["source-development"]["reason"] == "gradle exploded"


def test_status_ok_with_missing_json_is_failed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", None)
    assert ws.run() == 1
    assert ws.targets["source-development"]["status"] == "failed"
    assert "missing" in ws.targets["source-development"]["reason"]


@pytest.mark.parametrize("content", ["", "{not json", "[1, 2]"])
def test_status_ok_with_invalid_json_is_failed(tmp_path: Path, content: str) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", None)
    (ws.trivy_parts / "source-development.json").write_text(content, encoding="utf-8")
    assert ws.run() == 1
    assert ws.targets["source-development"]["status"] == "failed"
    assert "trivy result" in ws.targets["source-development"]["reason"]


def test_unreadable_status_file_is_failed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    (ws.trivy_parts / "source-development.status.json").write_text(
        "oops", encoding="utf-8"
    )
    assert ws.run() == 1
    assert "unreadable status file" in ws.targets["source-development"]["reason"]


def test_failed_target_does_not_hide_the_others(full: Workspace) -> None:
    (full.trivy_parts / "app-1.0.0.json").write_text("{broken", encoding="utf-8")
    assert full.run() == 1
    assert full.targets["source-development"]["status"] == "ok"
    assert full.targets["app-1.0.0"]["status"] == "failed"
    assert "CVE-2000-0011" not in records_by_cve(full)
    assert "failed" in (full.out / "summary.md").read_text(encoding="utf-8")


def test_clean_target_is_ok_with_zero_findings(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", None)
    (ws.trivy_parts / "source-development.json").write_text(
        '{"Results": null}', encoding="utf-8"
    )
    assert ws.run() == 0
    entry = ws.targets["source-development"]
    assert (entry["status"], entry["findings_unique"], entry["findings_raw"]) == (
        "ok",
        0,
        0,
    )


# ---------------------------------------------------------------- outputs


def test_native_files_are_copied(full: Workspace) -> None:
    (full.trivy_parts / "source-development.txt").write_text("table", encoding="utf-8")
    full.run()
    native = full.out / "_native" / "trivy"
    assert [p.name for p in (full.out / "_native").iterdir()] == ["trivy"]
    assert sorted(p.name for p in native.iterdir()) == [
        "app-1.0.0.json",
        "app-development.json",
        "source-development.json",
        "source-development.txt",
    ]
    assert (native / "source-development.json").read_bytes() == (
        FIXTURES / "source.json"
    ).read_bytes()


def test_output_is_deterministic(tmp_path: Path) -> None:
    def build(name: str) -> dict[str, bytes]:
        ws = Workspace(tmp_path / name, make_targets_doc(SOURCE, DEV, REL))
        ws.add_part("source-development", "source", lockfiles=3)
        ws.add_part("app-development", "app-development")
        ws.add_part("app-1.0.0", "app-1.0.0")
        ws.run()
        return {
            p.relative_to(ws.out).as_posix(): p.read_bytes()
            for p in sorted(ws.out.rglob("*"))
            if p.is_file()
        }

    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first, second = build("a"), build("b")
    assert first.keys() == second.keys()
    assert first == second
    assert b"\r" not in first["summary.md"] + first["summary.csv"]


def test_summary_csv_has_one_row_per_target(tmp_path: Path) -> None:
    targets_doc = make_targets_doc(SOURCE, DEV, REL)
    targets_doc["targets"][2].update(status="not_applicable", reason="no release")
    ws = Workspace(tmp_path, targets_doc)
    ws.add_part("source-development", "source")
    ws.add_part("app-development", "app-development")
    ws.run()
    with (ws.out / "summary.csv").open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert [r["target_id"] for r in rows] == [
        "source-development",
        "app-development",
        "app-1.0.0",
    ]
    assert rows[0]["ref"] == "development@fedcba9"
    assert rows[1]["ref"] == "ghcr.io/example/app:development"
    assert rows[0]["findings_unique"] == "3"
    assert rows[0]["findings_raw"] == "4"
    assert rows[2]["status"] == "not_applicable"
    assert rows[2]["findings_unique"] == ""


def test_summary_md_sections(full: Workspace) -> None:
    full.run()
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    for heading in (
        "# SCA scan summary",
        "## Targets",
        "## Per-target coverage (unique findings)",
        "## By severity and fixability",
        "## CRITICAL and HIGH findings (all)",
    ):
        assert heading in md
    assert "[run 42](https://github.com/example/app/actions/runs/42)" in md
    assert "0123456789abcdef0123456789abcdef01234567" in md
    assert (
        "| CRITICAL | CVE-2000-0002 | minimist | 1.0.0 | NO | - | library "
        "| source-development |" in md
    )
    assert (
        "| HIGH | CVE-2000-0001 | lodash | 4.17.0 | yes | 4.17.21 | library "
        "| source-development + app-development |" in md
    )
    assert "CVE-2000-0011" not in md  # LOW is not listed in the detail table


def test_summary_md_ref_column_shows_git_ref_and_short_sha(full: Workspace) -> None:
    full.run()
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert "| source-development | fs | development@fedcba9 |" in md
    assert "| app-development | image | ghcr.io/example/app:development |" in md


def test_report_targets_carry_git_ref_and_commit_sha(full: Workspace) -> None:
    full.run()
    fs = full.targets["source-development"]
    assert fs["git_ref"] == "development"
    assert fs["commit_sha"] == "fedcba9876543210fedcba9876543210fedcba98"
    image = full.targets["app-development"]
    assert image["git_ref"] is None
    assert image["commit_sha"] is None
    # the top-level commit is the default branch freshness, not a per-target value
    report = full.json("_report/scan_report.json")
    assert report["commit_sha"] == "0123456789abcdef0123456789abcdef01234567"


def test_fs_target_is_recognized_by_kind_not_by_id(tmp_path: Path) -> None:
    release = {
        **SOURCE,
        "id": "source-release-1.2",
        "git_ref": "release/1.2",
        "commit_sha": "1" * 40,
    }
    ws = Workspace(tmp_path, make_targets_doc(release))
    ws.add_part("source-release-1.2", "source", lockfiles=3)
    assert ws.run() == 0
    assert ws.targets["source-release-1.2"]["status"] == "ok"
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "| source-release-1.2 | fs | release/1.2@1111111 |" in md


DB_INFO = {
    "vulnerability_db_updated_at": "2030-01-01T06:00:00.123Z",
    "java_db_updated_at": "2029-12-30T01:02:03.456Z",
}


def test_trivy_db_is_unknown_by_default(full: Workspace) -> None:
    full.run()
    report = full.json("_report/scan_report.json")
    assert report["trivy_db"] == {
        "vulnerability_db_updated_at": None,
        "java_db_updated_at": None,
    }
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert "vulnerability DB updated `-`, Java DB updated `-`" in md


def test_trivy_db_is_recorded_in_report_and_summary(full: Workspace) -> None:
    assert (
        mr.run_merge(full.targets_file, full.parts, full.out, GENERATED, DB_INFO) == 0
    )
    assert full.json("_report/scan_report.json")["trivy_db"] == DB_INFO
    assert full.json("_report/scan_report.json")["schema_version"] == 1
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert (
        "vulnerability DB updated `2030-01-01T06:00:00.123Z`, "
        "Java DB updated `2029-12-30T01:02:03.456Z`" in md
    )


def test_main_passes_trivy_db_info(full: Workspace) -> None:
    assert mr.main(cli_args(full, "--trivy-db-info", json.dumps(DB_INFO))) == 0
    assert full.json("_report/scan_report.json")["trivy_db"] == DB_INFO


@pytest.mark.parametrize(
    "raw",
    ["", "  ", "not json", "[1]", '"x"', '{"vulnerability_db_updated_at": 5}'],
)
def test_parse_trivy_db_info_unknown_for_bad_input(raw: str) -> None:
    assert mr.parse_trivy_db_info(raw) == {
        "vulnerability_db_updated_at": None,
        "java_db_updated_at": None,
    }


def test_parse_trivy_db_info_partial() -> None:
    info = mr.parse_trivy_db_info('{"java_db_updated_at": "2030-01-01T00:00:00Z"}')
    assert info == {
        "vulnerability_db_updated_at": None,
        "java_db_updated_at": "2030-01-01T00:00:00Z",
    }


PACKAGES_NATIVE = {
    "Results": [
        {
            "Target": "a/package-lock.json",
            "Type": "npm",
            "Packages": [
                {"Name": "lodash", "Version": "4.17.0"},
                {"Name": "minimist", "Version": "1.0.0"},
            ],
        },
        {
            "Target": "b/package-lock.json",
            "Type": "npm",
            "Packages": [
                {"Name": "lodash", "Version": "4.17.0"},
                {"Name": "lodash", "Version": "4.17.21"},
            ],
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2000-0001",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.0",
                    "Severity": "HIGH",
                }
            ],
        },
        {"Target": "c/empty", "Type": "npm"},
    ]
}


def test_count_packages_distinct_name_and_version() -> None:
    assert mr.count_packages(PACKAGES_NATIVE) == {
        "packages_scanned": 3,
        "locations_scanned": 3,
    }
    assert mr.count_packages({"Results": None}) == {
        "packages_scanned": 0,
        "locations_scanned": 0,
    }
    assert mr.count_packages({}) == {"packages_scanned": 0, "locations_scanned": 0}


def test_report_and_tables_show_packages(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, DEV))
    ws.add_part("source-development", None)
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps(PACKAGES_NATIVE), encoding="utf-8"
    )
    ws.add_part("app-development", None, status="failed", reason="boom")
    ws.run()
    fs = ws.targets["source-development"]
    assert (fs["packages_scanned"], fs["locations_scanned"]) == (3, 3)
    failed = ws.targets["app-development"]
    assert (failed["packages_scanned"], failed["locations_scanned"]) == (None, None)
    assert "::warning title=No packages" not in capsys.readouterr().out
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "| Status | Packages | Unique |" in md
    assert (
        "| source-development | fs | development@fedcba9 | ok | 3 | 1 | 1 | 1 |" in md
    )
    with (ws.out / "summary.csv").open(encoding="utf-8", newline="") as f:
        rows = {r["target_id"]: r for r in csv.DictReader(f)}
    assert rows["source-development"]["packages_scanned"] == "3"
    assert rows["app-development"]["packages_scanned"] == ""


def test_warning_for_ok_target_without_packages(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", None)
    (ws.trivy_parts / "source-development.json").write_text(
        '{"Results": null}', encoding="utf-8"
    )
    assert ws.run() == 0  # suspicious, but not a failure
    assert ws.targets["source-development"]["packages_scanned"] == 0
    out = capsys.readouterr().out
    assert "::warning title=No packages in scan result::source-development" in out


def test_markdown_cells_are_escaped() -> None:
    assert mr.md_cell("a|b") == "a\\|b"
    assert mr.md_cell("line1\nline2") == "line1 line2"
    assert mr.md_cell("back\\slash|x") == "back\\\\slash\\|x"
    assert mr.md_cell(None) == "-"
    assert mr.md_cell(0) == "0"


def test_failure_reason_with_pipe_does_not_break_table(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", None, status="failed", reason="a | b")
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "a \\| b" in md


# ---------------------------------------------------------------- CLI


def cli_args(ws: Workspace, *extra: str) -> list[str]:
    return [
        "--targets-file",
        str(ws.targets_file),
        "--parts-dir",
        str(ws.parts),
        "--output-dir",
        str(ws.out),
        *extra,
    ]


def test_main_writes_github_output_and_step_summary(
    full: Workspace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (full.trivy_parts / "app-1.0.0.status.json").unlink()
    gh_output = tmp_path / "github_output"
    gh_summary = tmp_path / "github_summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh_output))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(gh_summary))
    assert mr.main(cli_args(full, "--step-summary", "true")) == 0
    assert gh_output.read_text(encoding="utf-8").splitlines() == [
        "failed-count=1",
        f"report-dir={full.out}",
    ]
    assert gh_summary.read_text(encoding="utf-8") == (
        full.out / "summary.md"
    ).read_text(encoding="utf-8")


def test_main_skips_step_summary_when_disabled(
    full: Workspace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gh_summary = tmp_path / "github_summary"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(gh_summary))
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    assert mr.main(cli_args(full, "--step-summary", "false")) == 0
    assert not gh_summary.exists()


def test_main_runs_without_github_env(
    full: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert mr.main(cli_args(full)) == 0


def test_main_exits_zero_when_targets_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    gh_output = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh_output))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert mr.main(cli_args(ws)) == 0
    assert "failed-count=1" in gh_output.read_text(encoding="utf-8")


def test_main_fails_without_targets_file(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.targets_file.unlink()
    assert mr.main(cli_args(ws)) == 1
    assert not ws.out.exists()


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"targets": "x"}',
        '{"targets": [{"id": "../x"}]}',
        '{"targets": [{"id": "a"}, {"id": "a"}]}',
    ],
)
def test_main_fails_on_invalid_targets_file(tmp_path: Path, content: str) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.targets_file.write_text(content, encoding="utf-8")
    assert mr.main(cli_args(ws)) == 1


def test_missing_parts_dir_marks_pending_targets_failed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    shutil.rmtree(ws.trivy_parts)
    assert ws.run() == 1


def test_ecosystem_is_a_sorted_list_of_result_types(full: Workspace) -> None:
    full.run()
    recs = records_by_cve(full)
    assert recs["CVE-2000-0002"]["ecosystem"] == ["npm"]
    assert recs["CVE-2000-0003"]["ecosystem"] == ["gradle"]
    assert recs["CVE-2000-0010"]["ecosystem"] == ["alpine"]
    # same finding in an npm lockfile (fs) and a node-pkg result (image)
    assert recs["CVE-2000-0001"]["ecosystem"] == ["node-pkg", "npm"]


# ---------------------------------------------------------------- scanners


def test_schema_version_in_both_reports(full: Workspace) -> None:
    full.run()
    assert mr.SCHEMA_VERSION == 1
    assert full.json("_report/vulnerabilities.json")["schema_version"] == 1
    assert full.json("_report/scan_report.json")["schema_version"] == 1


def test_every_record_names_the_scanner(full: Workspace) -> None:
    full.run()
    records = full.json("_report/vulnerabilities.json")["records"]
    assert records
    assert all(r["scanners"] == ["trivy"] for r in records)


def test_every_target_names_its_scanner(tmp_path: Path) -> None:
    targets_doc = make_targets_doc(SOURCE, DEV, REL)
    targets_doc["targets"][1].update(status="not_applicable", reason="tag not found")
    ws = Workspace(tmp_path, targets_doc)
    ws.add_part("source-development", "source")
    # app-1.0.0 is pending and has no part, so it fails
    assert ws.run() == 1
    assert {tid: t["scanner"] for tid, t in ws.targets.items()} == {
        "source-development": "trivy",
        "app-development": "trivy",
        "app-1.0.0": "trivy",
    }


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
    records = mr.merge_records(
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


def test_parts_outside_the_scanner_directory_are_ignored(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", "source")
    for part in list(ws.trivy_parts.iterdir()):
        part.rename(ws.parts / part.name)
    assert ws.run() == 1
    assert ws.targets["source-development"]["reason"] == "scan job produced no result"
