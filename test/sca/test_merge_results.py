"""Tests for actions/sca_merge_results/merge_results.py (synthetic fixtures only)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

Record = dict[str, Any]
ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures" / "merge_results"
GENERATED = "2030-01-01T00:00:00Z"


def _load_merge_results():
    path = ROOT / "actions" / "sca_merge_results" / "merge_results.py"
    spec = importlib.util.spec_from_file_location("merge_results", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
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
    # 4 raw rows (the gradle finding appears in two lockfiles), 3 unique, 2 of them
    # with a fix (the gradle one only in its second lockfile)
    assert entry["findings"] == {
        "total": 3,
        "fixable": 2,
        "by_severity": {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 1,
            "LOW": 0,
            "UNKNOWN": 0,
        },
    }


def test_fixed_version_backfilled_from_other_copy(full: Workspace) -> None:
    full.run()
    rec = records_by_cve(full)["CVE-2000-0003"]
    # the first lockfile copy has no FixedVersion, the second one does
    assert rec["fix_available"] is True
    assert rec["fixed_versions"] == ["1.1"]
    assert rec["status"] == "fixed"
    assert rec["upgrade_to"] == "1.1"


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
    assert list(vulns) == [
        "schema_version",
        "repo",
        "generated_utc",
        "merge_key",
        "records",
    ]
    assert vulns["merge_key"] == mr.MERGE_KEY
    assert vulns["repo"] == "example/app"
    assert vulns["generated_utc"] == GENERATED
    assert [r["cve"] for r in vulns["records"]] == [
        "CVE-2000-0010",  # release_and_development
        "CVE-2000-0011",  # release_only
        "CVE-2000-0001",  # development_only (source + development image)
        "CVE-2000-0002",  # source_only, CRITICAL
        "CVE-2000-0003",  # source_only, MEDIUM
    ]
    openssl = records_by_cve(full)["CVE-2000-0011"]
    assert openssl == {
        "repo": "example/app",
        "cve": "CVE-2000-0011",
        "aliases": [],
        "pkg": "openssl",
        "version": "3.0.0",
        "pkg_type": "os",
        "ecosystem": ["alpine"],
        "relationship": [],
        "dev": None,
        "introduced_via": [],
        "dependency_paths": [],
        "dependency_paths_total": 0,
        "dependency_paths_truncated": False,
        "scan_targets": ["app-1.0.0"],
        "locations": ["ghcr.io/example/app:1.0.0 (alpine 3.19)"],
        "pkg_paths": [],
        "exposure": "release_only",
        "severity": "LOW",
        "severity_source": None,
        "cvss": None,
        "status": "will_not_fix",
        "fixed_versions": [],
        "fix_available": False,
        "upgrade_to": None,
        "title": "Pipe | in title",
        "cwe": ["CWE-79"],
        "published": "2020-01-01T00:00:00Z",
        "primary_url": "https://example.invalid/CVE-2000-0011",
        "scanners": ["trivy"],
    }
    assert records_by_cve(full)["CVE-2000-0001"]["pkg_type"] == "library"


def test_removed_fields_are_absent(full: Workspace) -> None:
    full.run()
    vulns = full.json("_report/vulnerabilities.json")
    assert "counts" not in vulns
    assert "per_target" not in vulns
    assert all("fixed_version" not in r for r in vulns["records"])
    for entry in full.json("_report/scan_report.json")["targets"]:
        for field in (
            "findings_raw",
            "findings_unique",
            "vulnerable_package_versions",
            "lockfiles",
        ):
            assert field not in entry
    assert not (full.out / "summary.csv").exists()


def test_record_sort_key_orders_exposure_severity_cvss_then_identity() -> None:
    def record(cve: str, exposure: str, severity: str, score: float | None) -> Record:
        return {
            "exposure": exposure,
            "severity": severity,
            "cvss": None if score is None else {"score": score},
            "pkg": "p",
            "version": "1",
            "cve": cve,
        }

    records = [
        record("E", "source_only", "CRITICAL", 9.8),
        record("D", "release_only", "HIGH", None),
        record("C", "release_only", "HIGH", 7.0),
        record("B", "release_only", "HIGH", 8.0),
        record("A", "release_and_development", "LOW", 1.0),
        record("F", "release_only", "HIGH", 8.0),
    ]
    ordered = sorted(records, key=mr.record_sort_key)
    assert [r["cve"] for r in ordered] == ["A", "B", "F", "C", "D", "E"]


def test_totals_by_severity_and_exposure(full: Workspace) -> None:
    full.run()
    assert full.json("_report/scan_report.json")["totals"] == {
        "targets": {"total": 3, "ok": 3, "failed": 0, "not_applicable": 0},
        "findings": {
            "total": 5,
            "fixable": 3,
            "by_severity": {
                "CRITICAL": 1,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 1,
                "UNKNOWN": 0,
            },
            "by_exposure": {
                "release_and_development": 1,
                "release_only": 1,
                "development_only": 1,
                "source_only": 2,
            },
        },
    }
    assert list(full.json("_report/scan_report.json")["targets"][0]) == [
        "id",
        "scanner",
        "kind",
        "image",
        "tag",
        "ref",
        "git_ref",
        "commit_sha",
        "image_digest",
        "status",
        "reason",
        "packages_scanned",
        "locations_scanned",
        "findings",
    ]


def test_totals_present_when_nothing_was_scanned(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.run()
    totals = ws.json("_report/scan_report.json")["totals"]
    assert totals["targets"] == {
        "total": 1,
        "ok": 0,
        "failed": 1,
        "not_applicable": 0,
    }
    assert totals["findings"]["total"] == 0
    assert set(totals["findings"]["by_severity"]) == set(mr.SEVERITIES)
    assert set(totals["findings"]["by_exposure"]) == set(mr.EXPOSURES)


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
    assert targets["app-1.0.0"]["findings"] is None
    assert targets["app-1.0.0"]["packages_scanned"] is None
    assert {
        t
        for r in ws.json("_report/vulnerabilities.json")["records"]
        for t in r["scan_targets"]
    } == {"source-development"}
    assert ws.json("_report/scan_report.json")["totals"]["targets"] == {
        "total": 3,
        "ok": 1,
        "failed": 1,
        "not_applicable": 1,
    }


def test_pending_without_status_file_is_failed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    assert ws.run() == 1
    entry = ws.targets["source-development"]
    assert entry["status"] == "failed"
    assert entry["reason"] == "scan job produced no result"
    assert entry["findings"] is None


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
    assert entry["status"] == "ok"
    assert entry["findings"] == {
        "total": 0,
        "fixable": 0,
        "by_severity": dict.fromkeys(mr.SEVERITIES, 0),
    }


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
    assert b"\r" not in first["summary.md"]
    assert "summary.csv" not in first


def test_summary_md_sections(full: Workspace) -> None:
    full.run()
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert md.startswith("# SCA · example/app\n")
    assert "## What to fix" in md
    assert "<summary>Scan coverage</summary>" in md
    assert "## No fix available — watch" in md  # a CRITICAL is in it
    # CRITICAL and HIGH are expanded, the others collapsed
    assert "<details open>\n<summary>CRITICAL (1)</summary>" in md
    assert "<details open>\n<summary>HIGH (1)</summary>" in md
    assert "<details>\n<summary>MEDIUM (2)</summary>" in md
    assert "<details>\n<summary>LOW (1)</summary>" in md
    assert (
        "| [CVE-2000-0001](https://example.invalid/CVE-2000-0001) | lodash "
        "| 4.17.0 → 4.17.21 | - | 2020-01-01 | development only | Synthetic issue "
        "CVE-2000-0001 |" in md
    )
    # a blank line after </summary> and before </details> for GitHub rendering
    assert "</summary>\n\n|" in md
    assert "|\n\n</details>" in md
    # headline
    assert (
        "> **Released 1.0.0 — exposed: 1 MEDIUM · 1 LOW**, 1 also open in development"
        in md
    )
    assert "> **development — image: 1 HIGH · 1 MEDIUM; source: 1 CRITICAL · " in md
    assert "(2 not in images)" in md
    assert "> 5 findings (3 fixable) · 3/3 targets scanned" in md
    # what to fix: only what an upgrade resolves
    assert (
        "| 1 | zlib · alpine (base image) | 1.2.0 → 1.2.1 | 1 MEDIUM "
        "| Released 1.0.0 + development "
        "| Upgrade in development, backport to release-1.0 "
        "| image :development, :1.0.0 |" in md
    )
    assert (
        "| 3 | org.example:lib · java | 1.0 → 1.1 | 1 MEDIUM "
        "| Source only · not in images "
        "| Upgrade in development — not in published images |" in md
    )
    fix_table = md.split("## What to fix")[1].split("## No fix available")[0]
    assert "minimist" not in fix_table
    assert "openssl" not in fix_table
    # the watch section
    assert (
        "| 1 | openssl 3.0.0 · alpine | 1 LOW | - | - | Released 1.0.0 only "
        "| Mitigate or replace the package; re-check on next scan |" in md
    )
    # coverage
    assert "| source @ development fedcba9 | ok | 0 | 1 | 1 | 1 | 0 | - |" in md
    assert md.rstrip().endswith("</sub>")
    assert (
        "commit 0123456 · [run 42](https://github.com/example/app/actions/runs/42)"
        in md
    )
    assert "generated 2030-01-01 00:00Z" in md


def test_summary_md_omits_sections_without_findings(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, DEV))
    for tid in ("source-development", "app-development"):
        ws.add_part(tid, None)
        (ws.trivy_parts / f"{tid}.json").write_text(
            json.dumps(PACKAGES_NATIVE_CLEAN), encoding="utf-8"
        )
    assert ws.run() == 0
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "> No known vulnerabilities · 4 packages in 2 targets" in md
    assert "## What to fix" not in md
    assert "<summary>No fix available" not in md
    assert "CRITICAL (" not in md
    assert "<summary>Scan coverage</summary>" in md


def test_summary_md_without_unfixed_findings_has_no_no_fix_section(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(DEV))
    ws.add_part("app-development", "app-development")
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "<summary>No fix available" not in md
    assert "<summary>MEDIUM (1)</summary>" in md
    assert "<summary>HIGH (1)</summary>" in md


def test_summary_md_failed_and_not_applicable_targets(tmp_path: Path) -> None:
    targets_doc = make_targets_doc(SOURCE, DEV, REL)
    targets_doc["targets"][1].update(status="not_applicable", reason="tag not found")
    ws = Workspace(tmp_path, targets_doc)
    ws.add_part("source-development", "source")
    ws.add_part("app-1.0.0", None, status="failed", reason="boom | bang")
    assert ws.run() == 1
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "> **Incomplete: 1 target(s) failed** — app-1.0.0 (their findings" in md
    assert "Released" not in md  # the only release image failed
    assert "1/2 targets scanned · 1 not applicable" in md
    assert "| image :1.0.0 | failed | - | - | - | - | - | boom \\| bang |" in md
    assert "| image :development | not_applicable | - |" in md


def test_summary_md_separates_headline_lines(full: Workspace) -> None:
    full.run()
    lines = (full.out / "summary.md").read_text(encoding="utf-8").splitlines()
    # a bare newline would merge the lines into one paragraph
    assert lines[3] == lines[5] == ">"
    assert all(line.startswith(">") for line in lines[2:7])


def test_summary_md_labels_images_by_name_when_there_are_several(
    tmp_path: Path,
) -> None:
    other = {**DEV, "id": "other-development", "image": "example/other"}
    ws = Workspace(tmp_path, make_targets_doc(DEV, other))
    ws.add_part("app-development", "app-development")
    ws.add_part("other-development", "app-development")
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "app :development · other :development" in md
    assert "| other :development | ok |" in md


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
    assert "| source @ release/1.2 1111111 | ok |" in md


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
    assert "DB vuln" not in md


def test_trivy_db_is_recorded_in_report_and_summary(full: Workspace) -> None:
    assert (
        mr.run_merge(full.targets_file, full.parts, full.out, GENERATED, DB_INFO) == 0
    )
    assert full.json("_report/scan_report.json")["trivy_db"] == DB_INFO
    assert full.json("_report/scan_report.json")["schema_version"] == 1
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert "DB vuln 2030-01-01 06:00Z (java 2029-12-30 01:02Z)" in md


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
    assert mr.render_footer(report)[-1] == (
        "<sub>DB vuln 2030-01-01 06:00Z (java 01:02Z)</sub>"
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


PACKAGES_NATIVE_CLEAN = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Type": "npm",
            "Packages": [
                {"Name": "lodash", "Version": "4.17.21"},
                {"Name": "minimist", "Version": "1.2.8"},
            ],
        }
    ]
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
    assert "| Target | Status | Packages | C | H | M | L | Note |" in md
    assert "| source @ development fedcba9 | ok | 3 | 0 | 1 | 0 | 0 | - |" in md


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
    records, sightings = mr.merge_records(
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


def test_parts_outside_the_scanner_directory_are_ignored(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", "source")
    for part in list(ws.trivy_parts.iterdir()):
        part.rename(ws.parts / part.name)
    assert ws.run() == 1
    assert ws.targets["source-development"]["reason"] == "scan job produced no result"


# ---------------------------------------------------------------- exposure


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
    assert mr.classify_exposure(classes, has_images) == expected


def test_target_class() -> None:
    assert mr.target_class(SOURCE) == "source"
    assert mr.target_class(DEV) == "development"
    assert mr.target_class(REL) == "release"
    assert mr.target_class({"kind": "other"}) is None


def test_exposure_classes_end_to_end(full: Workspace) -> None:
    full.run()
    recs = records_by_cve(full)
    assert recs["CVE-2000-0010"]["exposure"] == "release_and_development"
    assert recs["CVE-2000-0011"]["exposure"] == "release_only"
    assert recs["CVE-2000-0001"]["exposure"] == "development_only"
    assert recs["CVE-2000-0002"]["exposure"] == "source_only"


def test_source_findings_of_a_run_without_images_are_development_only(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", "source")
    ws.run()
    exposures = {
        r["exposure"] for r in ws.json("_report/vulnerabilities.json")["records"]
    }
    assert exposures == {"development_only"}
    totals = ws.json("_report/scan_report.json")["totals"]["findings"]
    assert totals["by_exposure"]["source_only"] == 0
    assert totals["by_exposure"]["development_only"] == 3
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "> **development — source: 1 CRITICAL · 1 HIGH · 1 MEDIUM**" in md
    assert "not in any image" not in md


def test_release_headline_suffix() -> None:
    both = {"severity": "HIGH", "exposure": "release_and_development"}
    only = {"severity": "LOW", "exposure": "release_only"}
    assert mr.release_headline("1.0", [], True) == (
        "**Released 1.0 — no known vulnerabilities**"
    )
    assert mr.release_headline("1.0", [only], True) == (
        "**Released 1.0 — exposed: 1 LOW**, all fixed in development"
    )
    assert mr.release_headline("1.0", [both, only], True) == (
        "**Released 1.0 — exposed: 1 HIGH · 1 LOW**, 1 also open in development"
    )
    # nothing is known about development when it was not scanned
    assert mr.release_headline("1.0", [only], False) == (
        "**Released 1.0 — exposed: 1 LOW**"
    )


def test_development_headline() -> None:
    low = {"severity": "LOW", "exposure": "source_only", "dev": True}
    assert mr.development_headline([], [low]) == (
        "**development — image: clean; source: 1 LOW (dev dependencies)**"
    )
    assert mr.development_headline([], None) == "**development — image: clean**"
    assert mr.development_headline(None, None) is None


# ---------------------------------------------------------------- upgrade_to


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0.0", "1.0.0", 0),
        ("1.0", "1.0.0", 0),
        ("1.2.9", "1.10.0", -1),
        ("15.5.27", "15.5.24", 1),
        ("1.3.2-r1", "1.3.2-r0", 1),
        ("1.3.2-r0", "1.3.2", 1),
        ("1.0rc1", "1.0", -1),
        ("2.0.0", "2.0.0-RC1", 1),
        ("v1.2.3", "v1.2.4", -1),
        ("1.0", "abc", None),
        ("1.0", "v", None),
        ("1.a", "1.2", None),
    ],
)
def test_compare_versions(a: str, b: str, expected: int | None) -> None:
    assert mr.compare_versions(a, b) == expected
    if expected is not None:
        assert mr.compare_versions(b, a) == -expected


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
    assert mr.minimal_fix(installed, fixed) == expected


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
    assert mr.upgrade_target(installed, fixed_per_cve) == expected


def native_with(
    *vulns: dict[str, Any], packages: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "Target": "poetry.lock",
        "Class": "lang-pkgs",
        "Type": "poetry",
        "Vulnerabilities": list(vulns),
    }
    if packages is not None:
        result["Packages"] = packages
    return {"Results": [result]}


def vuln(cve: str, fixed: str | None, **extra: Any) -> dict[str, Any]:
    body = {
        "VulnerabilityID": cve,
        "PkgName": "urllib3",
        "InstalledVersion": "2.7.0",
        "Severity": "HIGH",
        **extra,
    }
    if fixed:
        body["FixedVersion"] = fixed
    return body


def test_upgrade_to_is_shared_by_all_records_of_a_package_version(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", None)
    native = native_with(
        vuln("CVE-1", "2.8.0"),
        vuln("CVE-2", "2.9.1, 3.0.0"),
        vuln("CVE-3", "9.9", PkgName="other", InstalledVersion="1.0"),
        vuln("CVE-4", None, PkgName="other", InstalledVersion="1.0"),
    )
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps(native), encoding="utf-8"
    )
    ws.run()
    recs = records_by_cve(ws)
    assert recs["CVE-1"]["upgrade_to"] == recs["CVE-2"]["upgrade_to"] == "2.9.1"
    assert recs["CVE-2"]["fixed_versions"] == ["2.9.1", "3.0.0"]
    assert recs["CVE-3"]["upgrade_to"] == "9.9"  # the unfixable CVE-4 does not count
    assert recs["CVE-3"]["fix_available"] is True
    assert recs["CVE-4"]["upgrade_to"] is None
    assert recs["CVE-4"]["fixed_versions"] == []
    assert recs["CVE-4"]["fix_available"] is False


def test_split_fixed_versions() -> None:
    assert mr.split_fixed_versions("15.5.27, 16.3.8") == ["15.5.27", "16.3.8"]
    assert mr.split_fixed_versions(" 1.0 ,, ") == ["1.0"]
    assert mr.split_fixed_versions(None) == []
    assert mr.split_fixed_versions("") == []


# ---------------------------------------------------------------- cvss


def test_select_cvss_prefers_severity_source() -> None:
    v = {
        "SeveritySource": "ghsa",
        "CVSS": {
            "nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N"},
            "ghsa": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:L"},
        },
    }
    assert mr.select_cvss(v) == {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:L",
        "version": "3.1",
        "source": "ghsa",
    }


def test_select_cvss_falls_back_to_nvd_then_ghsa_then_alphabetical() -> None:
    entry = {"V3Score": 5.0, "V3Vector": "CVSS:3.0/AV:N"}
    both = {"CVSS": {"ghsa": entry, "nvd": entry, "redhat": entry}}
    assert mr.select_cvss(both)["source"] == "nvd"
    no_nvd = {"SeveritySource": "debian", "CVSS": {"redhat": entry, "ghsa": entry}}
    assert mr.select_cvss(no_nvd)["source"] == "ghsa"
    others = {"CVSS": {"redhat": entry, "bitnami": entry}}
    assert mr.select_cvss(others)["source"] == "bitnami"
    assert mr.select_cvss(others)["version"] == "3.0"


def test_select_cvss_prefers_v4_of_the_chosen_source() -> None:
    v = {
        "CVSS": {
            "nvd": {
                "V3Score": 7.0,
                "V3Vector": "CVSS:3.1/AV:N",
                "V40Score": 8.7,
                "V40Vector": "CVSS:4.0/AV:N",
            }
        }
    }
    cvss = mr.select_cvss(v)
    assert (cvss["score"], cvss["version"]) == (8.7, "4.0")


@pytest.mark.parametrize(
    "vulnerability",
    [{}, {"CVSS": None}, {"CVSS": {}}, {"CVSS": {"nvd": {"V2Score": 5.0}}}],
)
def test_select_cvss_none_without_a_usable_score(vulnerability: dict[str, Any]) -> None:
    assert mr.select_cvss(vulnerability) is None


def test_select_cvss_skips_sources_without_a_score() -> None:
    v = {
        "SeveritySource": "redhat",
        "CVSS": {"redhat": {"V2Score": 5.0}, "ghsa": {"V3Score": 4.0}},
    }
    assert mr.select_cvss(v)["source"] == "ghsa"


# ---------------------------------------------------------------- extraction


def test_relationship_pkg_paths_and_aliases_are_extracted(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", None)
    native = native_with(
        vuln(
            "CVE-1",
            "2.8.0",
            VendorIDs=["GHSA-aaaa", "CVE-1"],
            PkgPath="b/site-packages/urllib3",
            SeveritySource="ghsa",
            CVSS={"ghsa": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N"}},
        ),
        vuln("CVE-2", "2.8.0", VendorIDs=["GHSA-bbbb"]),
        packages=[
            {"Name": "urllib3", "Version": "2.7.0", "Relationship": "indirect"},
            {"Name": "urllib3", "Version": "2.7.0", "Relationship": "direct"},
            {"Name": "urllib3", "Version": "1.0", "Relationship": "root"},
        ],
    )
    # the same finding again in a second result, with another path
    second = json.loads(json.dumps(native["Results"][0]))
    second["Target"] = "other/poetry.lock"
    second["Vulnerabilities"] = [
        vuln("CVE-1", "2.8.0", PkgPath="a/site-packages/urllib3")
    ]
    second["Packages"] = []
    native["Results"].append(second)
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps(native), encoding="utf-8"
    )
    ws.run()
    recs = records_by_cve(ws)
    assert recs["CVE-1"]["aliases"] == ["GHSA-aaaa"]  # never the CVE itself
    assert recs["CVE-1"]["relationship"] == ["direct", "indirect"]
    assert recs["CVE-1"]["pkg_paths"] == [
        "a/site-packages/urllib3",
        "b/site-packages/urllib3",
    ]
    assert recs["CVE-1"]["severity_source"] == "ghsa"
    assert recs["CVE-1"]["cvss"]["score"] == 7.5
    assert recs["CVE-2"]["pkg_paths"] == []
    assert recs["CVE-2"]["severity_source"] is None
    assert recs["CVE-2"]["cvss"] is None


def test_relationship_unknown_is_left_out() -> None:
    packages = [{"Name": "a", "Version": "1", "Relationship": "unknown"}]
    assert mr.package_relationships(packages) == set()


def test_unknown_severity_is_normalized(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", None)
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps(native_with(vuln("CVE-1", None, Severity="WEIRD"))),
        encoding="utf-8",
    )
    ws.run()
    assert records_by_cve(ws)["CVE-1"]["severity"] == "UNKNOWN"
    by_severity = ws.targets["source-development"]["findings"]["by_severity"]
    assert by_severity["UNKNOWN"] == 1


def test_format_timestamp() -> None:
    assert mr.format_timestamp("2026-10-12T01:14:57.362085088Z") == "2026-10-12 01:14Z"
    assert mr.format_timestamp("2026-10-12T01:14:57Z", with_date=False) == "01:14Z"
    assert mr.format_timestamp("garbage") is None
    assert mr.format_timestamp(None) is None


def test_truncate() -> None:
    assert mr.truncate("short", 10) == "short"
    assert mr.truncate("x" * 20, 10) == "x" * 9 + "…"
    assert mr.truncate(None) is None


def test_markdown_cells_escape_html() -> None:
    assert mr.md_cell("<b>x</b>") == "&lt;b&gt;x&lt;/b&gt;"


# ---------------------------------------------------------------- v2.1


@pytest.mark.parametrize(
    ("name", "result_type", "expected"),
    [
        ("Mako", "python-pkg", "mako"),
        ("mako", "poetry", "mako"),
        ("Typing_Extensions", "pip", "typing-extensions"),
        ("zope.interface", "uv", "zope-interface"),
        ("a-_.b", "conda-pkg", "a-b"),
        ("Lodash", "npm", "Lodash"),
        ("Org.Example:Lib", "gradle", "Org.Example:Lib"),
        ("Zlib", "alpine", "Zlib"),
        ("Mako", None, "Mako"),
        (None, "poetry", None),
    ],
)
def test_canonical_package_name(
    name: str | None, result_type: str | None, expected: str | None
) -> None:
    assert mr.canonical_package_name(name, result_type) == expected


def python_native(target: str, result_type: str, name: str) -> dict[str, Any]:
    return {
        "Results": [
            {
                "Target": target,
                "Class": "lang-pkgs",
                "Type": result_type,
                "Vulnerabilities": [
                    vuln("CVE-1", "1.4.2", PkgName=name, InstalledVersion="1.3.12")
                ],
            }
        ]
    }


def test_python_package_names_are_one_package_across_ecosystems(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, DEV, REL))
    for tid, native in (
        ("source-development", python_native("poetry.lock", "poetry", "mako")),
        ("app-development", python_native("Python", "python-pkg", "Mako")),
        ("app-1.0.0", python_native("Python", "python-pkg", "Mako")),
    ):
        ws.add_part(tid, None)
        (ws.trivy_parts / f"{tid}.json").write_text(
            json.dumps(native), encoding="utf-8"
        )
    ws.run()
    records = ws.json("_report/vulnerabilities.json")["records"]
    assert len(records) == 1
    record = records[0]
    assert record["pkg"] == "Mako"  # the spelling of the image
    assert record["scan_targets"] == [
        "source-development",
        "app-development",
        "app-1.0.0",
    ]
    assert record["exposure"] == "release_and_development"
    assert record["ecosystem"] == ["poetry", "python-pkg"]
    assert ws.targets["source-development"]["findings"]["total"] == 1
    totals = ws.json("_report/scan_report.json")["totals"]["findings"]
    assert totals["by_exposure"]["source_only"] == 0
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "not in any image" not in md
    assert (
        "| 1 | Mako · python | 1.3.12 → 1.4.2 | 1 HIGH "
        "| Released 1.0.0 + development "
        "| Upgrade in development, backport to release-1.0 "
        "| image :development, :1.0.0 · source poetry.lock |" in md
    )


def test_display_name_falls_back_to_first_seen_without_an_image() -> None:
    records, sightings = mr.merge_records(
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
    records, _ = mr.merge_records(
        "r",
        [
            ("a", "trivy", python_native("package-lock.json", "npm", "Lodash")),
            ("a", "trivy", python_native("package-lock.json", "npm", "lodash")),
        ],
    )
    assert len(records) == 2


def test_package_cell_shows_ecosystem_families() -> None:
    def cell(ecosystem: list[str], pkg_type: str = "library", rel=()) -> str:
        record = {
            "pkg": "p",
            "pkg_type": pkg_type,
            "ecosystem": ecosystem,
            "relationship": list(rel),
        }
        return mr.package_cell([record])

    assert cell(["python-pkg", "poetry"], rel=["indirect"]) == "p · python, indirect"
    assert cell(["node-pkg", "npm"]) == "p · npm"
    assert cell(["gradle", "jar"]) == "p · java"
    assert cell(["alpine"], "os") == "p · alpine (base image)"
    assert cell(["conan"]) == "p · conan"
    assert cell(["npm"], rel=["direct", "indirect"]) == "p · npm"


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
    assert mr.strip_package_prefix(title, pkg) == expected


# ---------------------------------------------------------------- v3


def pkg(
    name: str,
    relationship: str = "indirect",
    deps: tuple[str, ...] = (),
    dev: bool | None = None,
    version: str = "1.0.0",
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "ID": f"{name}@{version}",
        "Name": name,
        "Version": version,
        "Identifier": {"UID": f"uid-{name}"},
        "Relationship": relationship,
        "DependsOn": [f"{d}@1.0.0" for d in deps],
    }
    if dev is not None:
        body["Dev"] = dev
    return body


def info_for(packages: list[dict[str, Any]], name: str) -> Any:
    index = mr.PackageIndex(packages, "npm")
    return index.dependency_info(next(p for p in packages if p["Name"] == name))


def test_dependency_chain_deeper_than_three_levels() -> None:
    packages = [
        pkg("jest", "direct", ("@jest/core",)),
        pkg("@jest/core", deps=("micromatch",)),
        pkg("micromatch", deps=("braces",)),
        pkg("braces"),
    ]
    info = info_for(packages, "braces")
    assert info.paths == [("jest", "@jest/core", "micromatch", "braces")]
    assert (info.total, info.truncated) == (1, False)
    assert info.roots == {"jest"}


def test_dependency_paths_of_a_diamond_shortest_then_alphabetical() -> None:
    packages = [
        pkg("a", "direct", ("c", "b", "long")),
        pkg("e", "direct", ("d",)),
        pkg("b", deps=("d",)),
        pkg("c", deps=("d",)),
        pkg("long", deps=("longer",)),
        pkg("longer", deps=("d",)),
        pkg("d"),
    ]
    info = info_for(packages, "d")
    assert info.paths == [
        ("e", "d"),
        ("a", "b", "d"),
        ("a", "c", "d"),
        ("a", "long", "longer", "d"),
    ]
    assert info.total == 4
    assert info.roots == {"a", "e"}


def test_dependency_paths_stop_at_the_nearest_direct_package() -> None:
    packages = [
        pkg("outer", "direct", ("inner",)),
        pkg("inner", "direct", ("leaf",)),
        pkg("leaf"),
    ]
    info = info_for(packages, "leaf")
    assert info.paths == [("inner", "leaf")]
    assert info.roots == {"inner"}


def test_dependency_paths_survive_a_cycle() -> None:
    packages = [
        pkg("a", "direct", ("b",)),
        pkg("b", deps=("c",)),
        pkg("c", deps=("b", "t")),
        pkg("t"),
    ]
    info = info_for(packages, "t")
    assert info.paths == [("a", "b", "c", "t")]
    assert info.total == 1


def ladder(layers: int) -> list[dict[str, Any]]:
    """root -> (x1, y1) -> (x2, y2) -> ... -> t: 2**layers paths."""
    packages = [pkg("root", "direct", ("x1", "y1"))]
    for n in range(1, layers + 1):
        nxt = ("t",) if n == layers else (f"x{n + 1}", f"y{n + 1}")
        packages += [pkg(f"x{n}", deps=nxt), pkg(f"y{n}", deps=nxt)]
    return [*packages, pkg("t")]


def test_dependency_paths_are_capped_but_counted_exactly() -> None:
    info = info_for(ladder(4), "t")
    assert info.total == 16
    assert info.truncated is False
    assert len(info.paths) == mr.MAX_DEPENDENCY_PATHS
    assert info.paths[0] == ("root", "x1", "x2", "x3", "x4", "t")
    assert list(info.paths) == sorted(info.paths, key=lambda p: (len(p), p))


def test_dependency_path_count_is_bounded_and_marked_truncated() -> None:
    info = info_for(ladder(14), "t")  # 16384 paths
    assert info.total == mr.PATH_COUNT_LIMIT
    assert info.truncated is True
    assert len(info.paths) == mr.MAX_DEPENDENCY_PATHS


def test_introduced_via_lists_all_roots_not_just_the_stored_paths() -> None:
    names = [f"r{n}" for n in range(7)]
    packages = [pkg(n, "direct", ("t",)) for n in names] + [pkg("t")]
    info = info_for(packages, "t")
    assert info.total == 7
    assert len(info.paths) == 5
    assert info.roots == set(names)
    paths, total, truncated, via = mr.combine_dependency_info([info])
    assert (total, truncated) == (7, False)
    assert via == names[:5]
    assert len(paths) == 5


def test_direct_and_graphless_packages() -> None:
    direct = info_for([pkg("lodash", "direct")], "lodash")
    assert (list(direct.paths), direct.total, set(direct.roots)) == (
        [("lodash",)],
        1,
        set(),
    )
    lonely = info_for([pkg("x")], "x")  # indirect, nothing depends on it
    assert (list(lonely.paths), lonely.total, set(lonely.roots)) == ([], 0, set())
    unknown = info_for([pkg("x", "unknown")], "x")
    assert (list(unknown.paths), unknown.total) == ([], 0)


def test_combine_dependency_info_dedupes_paths_and_sums_totals() -> None:
    one = mr.DependencyInfo([("a", "t")], 1, False, frozenset({"a"}))
    two = mr.DependencyInfo([("a", "t"), ("b", "t")], 2, False, frozenset({"a", "b"}))
    paths, total, truncated, via = mr.combine_dependency_info([one, two])
    assert paths == [["a", "t"], ["b", "t"]]
    assert (total, truncated, via) == (3, False, ["a", "b"])
    assert mr.combine_dependency_info([]) == ([], 0, False, [])


def test_package_index_matches_by_uid_then_id_then_name() -> None:
    packages = [
        {"ID": "mako@1", "Name": "mako", "Version": "1", "Identifier": {"UID": "u"}},
    ]
    index = mr.PackageIndex(packages, "poetry")
    assert index.match({"PkgIdentifier": {"UID": "u"}}) == packages
    assert index.match({"PkgID": "mako@1"}) == packages
    assert index.match({"PkgName": "Mako", "InstalledVersion": "1"}) == packages
    assert index.match({"PkgName": "Mako", "InstalledVersion": "2"}) == []


def graph_source(tmp_path: Path, *targets: dict[str, Any]) -> Workspace:
    """Source targets whose lockfile has a dev chain jest > core > braces"""
    packages = [
        pkg("jest", "direct", ("core",), dev=True),
        pkg("core", deps=("braces",), dev=True),
        pkg("braces", dev=True, version="3.0.3"),
        pkg("react", "direct", (), dev=False),
    ]
    packages[2]["ID"] = "braces@3.0.3"
    packages[1]["DependsOn"] = ["braces@3.0.3"]
    native = native_with(
        vuln(
            "CVE-1",
            None,
            PkgName="braces",
            InstalledVersion="3.0.3",
            PkgID="braces@3.0.3",
        ),
        vuln("CVE-2", "9.9", PkgName="react", InstalledVersion="1.0.0"),
        packages=packages,
    )
    native["Results"][0]["Type"] = "npm"
    ws = Workspace(tmp_path, make_targets_doc(*targets))
    for target in targets:
        ws.add_part(target["id"], None)
        (ws.trivy_parts / f"{target['id']}.json").write_text(
            json.dumps(native), encoding="utf-8"
        )
    return ws


def test_dev_flag_and_chains_end_to_end(tmp_path: Path) -> None:
    other = {**SOURCE, "id": "source-release", "git_ref": "release/1.0"}
    ws = graph_source(tmp_path, SOURCE, other)
    ws.run()
    recs = records_by_cve(ws)
    braces, react = recs["CVE-1"], recs["CVE-2"]
    assert braces["dev"] is True
    assert braces["relationship"] == ["indirect"]
    assert braces["introduced_via"] == ["jest"]
    assert braces["dependency_paths"] == [["jest", "core", "braces"]]
    # the same lockfile seen by two targets counts once
    assert braces["dependency_paths_total"] == 1
    assert braces["dependency_paths_truncated"] is False
    assert react["dev"] is False  # a package without Dev is a runtime one
    assert react["dependency_paths"] == [["react"]]
    assert react["introduced_via"] == []


def test_dev_flag_is_null_without_package_entry_and_false_if_any_is_runtime(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, DEV))
    ws.add_part("source-development", None)
    ws.add_part("app-development", None)
    shared = vuln("CVE-1", None)
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps(
            native_with(
                shared, packages=[pkg("urllib3", "direct", dev=True, version="2.7.0")]
            )
        ),
        encoding="utf-8",
    )
    (ws.trivy_parts / "app-development.json").write_text(
        json.dumps(native_with(shared, vuln("CVE-2", None))), encoding="utf-8"
    )
    ws.run()
    recs = records_by_cve(ws)
    assert recs["CVE-1"]["dev"] is True  # the image has no package entry: unknown
    assert recs["CVE-2"]["dev"] is None
    assert recs["CVE-2"]["dependency_paths"] == []
    assert recs["CVE-2"]["dependency_paths_total"] == 0


# ---- markdown


def test_shortest_path_text_and_more_paths() -> None:
    def record(paths: list[list[str]], total: int, truncated: bool = False) -> Record:
        return {
            "dependency_paths": paths,
            "dependency_paths_total": total,
            "dependency_paths_truncated": truncated,
        }

    one = record([["jest", "core", "braces"]], 1)
    assert mr.shortest_path_text([one]) == "jest › core › braces"
    two = record([["b", "t"], ["a", "x", "t"]], 2)
    assert mr.shortest_path_text([two]) == "b › t (+1 more path)"
    many = record([["a", "t"]], 7)
    assert mr.shortest_path_text([many]) == "a › t (+6 more paths)"
    cut = record([["a", "t"]], 1000, True)
    assert mr.shortest_path_text([cut]) == "a › t (+999+ more paths)"
    assert mr.shortest_path_text([record([], 0)]) == ""


def test_summary_md_shows_chains_in_actions_watch_and_paths_section(
    tmp_path: Path,
) -> None:
    ws = graph_source(tmp_path, SOURCE, DEV)
    # the unfixable CVE-1 sits in a lockfile; add a development image without it
    (ws.trivy_parts / "app-development.json").write_text(
        json.dumps({"Results": []}), encoding="utf-8"
    )
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "(1 dev dependency, 1 not in images)" in md
    # braces has no fix: watch section, the chain in "Introduced via"
    assert (
        "| 1 | braces 3.0.3 · npm | 1 HIGH | dev, indirect | jest › core › braces "
        "| Source only · dev dependency |" in md
    )
    assert "## No fix available — watch" in md
    assert "<summary>Dependency paths (1)</summary>" in md
    assert "- **braces 3.0.3** (1 path)\n  - jest › core › braces" in md
    # react is a runtime dependency with a fix and a direct one: no chain in Action
    assert "| react · npm | 1.0.0 → 9.9 | 1 HIGH | Source only · not in images " in md
    assert "| Upgrade in development — not in published images |" in md


def test_what_to_fix_action_names_the_chain_of_a_fixable_indirect_package(
    tmp_path: Path,
) -> None:
    ws = graph_source(tmp_path, SOURCE, DEV)
    (ws.trivy_parts / "app-development.json").write_text(
        json.dumps({"Results": []}), encoding="utf-8"
    )
    native = json.loads((ws.trivy_parts / "source-development.json").read_text("utf-8"))
    native["Results"][0]["Vulnerabilities"][0]["FixedVersion"] = "3.0.4"
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps(native), encoding="utf-8"
    )
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert (
        "| braces · npm, indirect | 3.0.3 → 3.0.4 | 1 HIGH "
        "| Source only · dev dependency "
        "| Upgrade in development via jest › core › braces "
        "— dev dependency, not shipped |" in md
    )
    assert "No fix available" not in md


def test_summary_md_without_indirect_packages_has_no_paths_section(
    full: Workspace,
) -> None:
    full.run()
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert "Dependency paths" not in md


def test_watch_section_is_collapsed_without_high_or_critical(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(DEV))
    ws.add_part("app-development", None)
    (ws.trivy_parts / "app-development.json").write_text(
        json.dumps(native_with(vuln("CVE-1", None, Severity="LOW"))), encoding="utf-8"
    )
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "<details>\n<summary>No fix available — watch (1)</summary>" in md
    assert "## No fix available — watch" not in md
    assert "## What to fix" not in md  # nothing can be fixed by an upgrade


def test_watch_section_is_open_with_high_or_critical(full: Workspace) -> None:
    full.run()
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert "\n## No fix available — watch\n\n| # | Package |" in md
    assert "<summary>No fix available" not in md


def test_watch_suggestion_for_dev_only_packages(tmp_path: Path) -> None:
    ws = graph_source(tmp_path, SOURCE, DEV)
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "Accept as dev-only risk or replace the parent; re-check on next scan" in md


@pytest.mark.parametrize(
    ("tag", "expected"),
    [("1.1.14", "release-1.1"), ("v2.10.0", "release-2.10"), ("rc", "release-rc")],
)
def test_release_line(tag: str, expected: str) -> None:
    assert mr.release_line(tag) == expected


def test_action_texts() -> None:
    both, only = "release_and_development", "release_only"
    assert mr.action_text(both, None, ["1.1.14"]) == (
        "Upgrade in development, backport to release-1.1"
    )
    assert mr.action_text(both, None, ["1.1.14", "1.0.3", "1.0.4"]) == (
        "Upgrade in development, backport to release-1.1, release-1.0"
    )
    assert mr.action_text(only, None, ["0.12.0"]) == (
        "Release a patch from release-0.12 (already fixed in development)"
    )
    assert mr.action_text("development_only", None, []) == (
        "Upgrade in development before the next release"
    )
    assert mr.action_text("source_only", True, [], "jest › braces") == (
        "Upgrade in development via jest › braces — dev dependency, not shipped"
    )
    assert mr.action_text("source_only", False, []) == (
        "Upgrade in development — not in published images"
    )
    assert mr.action_text(both, None, ["1.0.0"], "a › b") == (
        "Upgrade in development via a › b, backport to release-1.0"
    )


def test_exposure_labels() -> None:
    label = mr.exposure_label
    assert label("release_and_development", None, ["1.1.14", "1.0.3"], True) == (
        "Released 1.1.14, 1.0.3 + development"
    )
    assert label("release_only", None, ["0.12.0"], True) == "Released 0.12.0 only"
    assert label("development_only", None, [], True) == "development only"
    assert label("development_only", None, [], False) == "development (source)"
    assert label("source_only", True, [], True) == "Source only · dev dependency"
    assert label("source_only", None, [], True) == "Source only · not in images"


def test_exposure_label_lists_the_release_tags_of_the_images_it_was_found_in() -> None:
    other = {**REL, "id": "app-0.9.0", "tag": "0.9.0"}
    targets = [SOURCE, DEV, REL, other]
    record = {"scan_targets": ["source-development", "app-0.9.0", "app-1.0.0"]}
    assert mr.release_tags_of([record], targets) == ["1.0.0", "0.9.0"]


@pytest.mark.parametrize(
    ("flags", "extra_shared", "expected"),
    [
        ([True], 0, " (dev dependencies)"),
        ([False], 0, " (not in images)"),
        ([None, False], 0, " (not in images)"),
        ([True, False], 0, " (1 dev dependency, 1 not in images)"),
        ([True, True], 0, " (dev dependencies)"),
        ([True, True], 1, " (2 dev dependencies)"),
        ([False], 1, " (1 not in images)"),
        ([], 1, ""),
    ],
)
def test_source_only_note(
    flags: list[bool | None], extra_shared: int, expected: str
) -> None:
    records = [{"exposure": "source_only", "dev": flag} for flag in flags]
    records += [{"exposure": "development_only", "dev": None}] * extra_shared
    assert mr.source_only_note(records) == expected


def test_mixed_package_is_in_what_to_fix_and_in_watch(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(DEV))
    ws.add_part("app-development", None)
    native = native_with(
        vuln("CVE-1", "2.8.0"),
        vuln("CVE-2", None, Severity="MEDIUM"),
        vuln("CVE-3", "2.9.1", Severity="LOW"),
    )
    (ws.trivy_parts / "app-development.json").write_text(
        json.dumps(native), encoding="utf-8"
    )
    ws.run()
    recs = records_by_cve(ws)
    assert recs["CVE-1"]["upgrade_to"] == recs["CVE-3"]["upgrade_to"] == "2.9.1"
    assert recs["CVE-2"]["upgrade_to"] is None
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    fix = md.split("## What to fix")[1].split("<details")[0]
    assert (
        "| 1 | urllib3 · python | 2.7.0 → 2.9.1 | 1 HIGH, 1 LOW "
        "· 1 without fix (see watch) "
        "| development only |" in fix
    )
    assert "No fix available — watch (1)" in md  # collapsed: only a MEDIUM
    assert "| 1 | urllib3 2.7.0 · python | 1 MEDIUM |" in md
