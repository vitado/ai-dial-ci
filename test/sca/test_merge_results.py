"""Tests for actions/sca_merge_results/merge_results.py (synthetic fixtures only)."""

from __future__ import annotations

import importlib.util
import json
import shutil
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
    assert "<summary>No fix available (2)</summary>" in md
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
    assert "(2 not in any image)" in md
    assert "> 5 findings (3 fixable) · 3/3 targets scanned" in md
    # what to fix
    assert (
        "| 1 | Fix in development and backport | zlib · alpine (base image) "
        "| 1.2.0 → 1.2.1 | 1 MEDIUM | image :development, :1.0.0 |" in md
    )
    assert (
        "| 2 | Release a patch (fixed in development) "
        "| openssl · alpine (base image) | 3.0.0 → no fix | 1 LOW | image :1.0.0 |"
        in md
    )
    assert (
        "| 4 | Not in any image (lower priority) | minimist · npm "
        "| 1.0.0 → no fix | 1 CRITICAL | source package-lock.json |" in md
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
    low = {"severity": "LOW", "exposure": "source_only"}
    assert mr.development_headline([], [low]) == (
        "**development — image: clean; source: 1 LOW (not in any image)**"
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
    assert recs["CVE-3"]["upgrade_to"] is None  # CVE-4 has no fix
    assert recs["CVE-3"]["fix_available"] is True
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
    result = {"Packages": [{"Name": "a", "Version": "1", "Relationship": "unknown"}]}
    assert mr.relationship_index(result) == {}


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
        "| 1 | Fix in development and backport | Mako · python | 1.3.12 → 1.4.2 "
        "| 1 HIGH | image :development, :1.0.0 · source poetry.lock |" in md
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
