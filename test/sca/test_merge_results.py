"""Tests for actions/sca_merge_results/merge_results.py (synthetic fixtures only)."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
import urllib.parse
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


def plain(markdown: str) -> str:
    """The Markdown without the backslashes of the cell escapes, as a reader sees it."""
    return re.sub(r"\\([|\[\]()!`])", r"\1", markdown)


def plain_lines(lines: list[str]) -> list[str]:
    return [plain(line) for line in lines]


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
OSV_SOURCE = {**SOURCE, "scanner": "osv"}
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
    """targets.json content with all given targets pending (Trivy by default)."""
    items = [
        {"status": "pending", "reason": None, "scanner": "trivy", **t} for t in targets
    ]
    return {
        "repo": "example/app",
        "default_branch": "main",
        "commit_sha": "0123456789abcdef0123456789abcdef01234567",
        "registry": "ghcr.io",
        "release_lines": 1,
        "run_kind": "full",
        "run_kind_reasons": [],
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
        self.osv_parts = self.parts / mr.SCANNER_OSV
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

    def add_osv_part(self, tid: str, fixture: str | None, **status: Any) -> None:
        """Add an OSV part: a fixture as osv/<id>.json and an ok status by default."""
        self.osv_parts.mkdir(exist_ok=True)
        if fixture:
            shutil.copy(FIXTURES / f"{fixture}.json", self.osv_parts / f"{tid}.json")
        body = {
            "id": tid,
            "status": "ok",
            "reason": None,
            "packages_queried": 5,
            "packages_skipped": 0,
            "queried_at": "2030-01-01T00:10:00Z",
            "scanner_version": "2.6.0",
        }
        body.update(status)
        (self.osv_parts / f"{tid}.status.json").write_text(
            json.dumps(body), encoding="utf-8"
        )

    def run(self, generated: str = GENERATED, **kwargs: Any) -> int:
        return mr.run_merge(
            self.targets_file, self.parts, self.out, generated, **kwargs
        )

    def json(self, rel: str) -> Any:
        return json.loads((self.out / rel).read_text(encoding="utf-8"))

    def targets_of(self, scanner: str) -> dict[str, dict[str, Any]]:
        targets = self.json("_report/scan_report.json")["targets"]
        return {t["id"]: t for t in targets if t["scanner"] == scanner}

    @property
    def targets(self) -> dict[str, dict[str, Any]]:
        return self.targets_of(mr.SCANNER_TRIVY)

    @property
    def osv_targets(self) -> dict[str, dict[str, Any]]:
        return self.targets_of(mr.SCANNER_OSV)


@pytest.fixture
def full(tmp_path: Path) -> Workspace:
    """fs + two images, all ok."""
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, DEV, REL))
    ws.add_part("source-development", "source", lockfiles=3)
    ws.add_part("app-development", "app-development")
    ws.add_part("app-1.0.0", "app-1.0.0")
    return ws


def records_by_id(ws: Workspace) -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in ws.json("_report/vulnerabilities.json")["records"]}


# ---------------------------------------------------------------- merging


def test_dedup_across_lockfiles_within_one_target(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", "source", lockfiles=3)
    ws.run()
    rec = records_by_id(ws)["CVE-2000-0003"]
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
    rec = records_by_id(full)["CVE-2000-0003"]
    # the first lockfile copy has no FixedVersion, the second one does
    assert rec["fix_available"] is True
    assert rec["fixed_versions"] == ["1.1"]
    assert rec["status"] == "fixed"
    assert rec["upgrade_to"] == "1.1"


def test_merge_across_fs_and_images_keeps_targets_file_order(full: Workspace) -> None:
    full.run()
    recs = records_by_id(full)
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
    assert [r["id"] for r in vulns["records"]] == [
        "CVE-2000-0010",  # release_and_development
        "CVE-2000-0011",  # release_only
        "CVE-2000-0001",  # development_only (source + development image)
        "CVE-2000-0002",  # source_only, CRITICAL
        "CVE-2000-0003",  # source_only, MEDIUM
    ]
    openssl = records_by_id(full)["CVE-2000-0011"]
    assert openssl == {
        "repo": "example/app",
        "id": "CVE-2000-0011",
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
    assert records_by_id(full)["CVE-2000-0001"]["pkg_type"] == "library"


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
    ordered = sorted(records, key=mr.record_sort_key)
    assert [r["id"] for r in ordered] == ["A", "B", "F", "C", "D", "E"]


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
        "queried_at",
        "packages_unread",
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
    assert "CVE-2000-0011" not in records_by_id(full)
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
    md = plain((full.out / "summary.md").read_text(encoding="utf-8"))
    assert md.startswith("# SCA · example/app\n")
    assert "<summary>Scan coverage</summary>" in md
    assert "## No fix available — watch" in md  # a CRITICAL is in it
    # CRITICAL and HIGH are expanded, the others collapsed
    assert "<details open>\n<summary>CRITICAL (1)</summary>" in md
    assert "<details open>\n<summary>HIGH (1)</summary>" in md
    assert "<details>\n<summary>MEDIUM (1)</summary>" in md
    # the OS packages are one collapsed block of their own
    assert "<details>\n<summary>Base image (OS packages) (2)</summary>" in md
    assert "<details>\n<summary>LOW (1)</summary>" in md
    assert (
        "| [CVE-2000-0001](https://example.invalid/CVE-2000-0001) | lodash "
        "| 4.17.0 → 4.17.21 | - | 2020-01-01 | development only | Synthetic issue "
        "CVE-2000-0001 |" in md
    )
    # a blank line after </summary> and before </details> for GitHub rendering
    assert "</summary>\n\n|" in md
    assert "|\n\n</details>" in md
    # headline: one action per exposure, the scopes, the coverage
    assert (
        "> **Fix 1 HIGH in development before the next release. "
        "Fix 1 MEDIUM in development and backport to release-1.0**" in md
    )
    assert "> | Scope | CRITICAL | HIGH | MEDIUM | LOW | Fixable | Base image |" in md
    assert "> | 1.0.0 (released) | 0 | 0 | 1 | 1 | 1 | 2 |" in md
    assert "> | development | 0 | 1 | 1 | 0 | 2 | 1 |" in md
    assert "> | Source only (build / test) | 1 | 0 | 1 | 0 | 1 | — |" in md
    assert "> 3/3 targets scanned\n" in md
    assert "## What to fix" not in md
    # the watch section: dependencies, then the OS packages collapsed
    assert (
        "| 1 | minimist 1.0.0 · npm | 1 CRITICAL | - | - | Source only · not in images "
        "| Mitigate or replace the package; re-check on next scan |" in md
    )
    assert "<summary>No fix available — base image (OS packages) (1)</summary>" in md
    assert (
        "| 1 | openssl 3.0.0 | 1 LOW | Released 1.0.0 only "
        "| Wait for a distribution fix or change the base image; "
        "re-check on next scan |" in md
    )
    # coverage: one row per subject
    assert (
        "| Target | Trivy | Note |\n|---|---|---|\n"
        "| source @ development fedcba9 | ok · 0 pkgs · 1/1/1/0 | no packages seen |"
        in md
    )
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
    assert "> **No known vulnerabilities in development**" in md
    assert "> 2/2 targets scanned · 4 packages\n" in md
    assert "| Scope |" not in md
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
    assert "(released)" not in md  # the only release image failed
    assert "> 1/2 targets scanned · 1 not applicable" in md
    assert "| image :1.0.0 | failed · boom \\| bang | - |" in md
    assert "| image :development | not_applicable · tag not found | - |" in md


def test_summary_md_separates_headline_lines(full: Workspace) -> None:
    full.run()
    lines = (full.out / "summary.md").read_text(encoding="utf-8").splitlines()
    quote = lines[2 : lines.index("", 2)]
    # a bare newline would merge the paragraphs into one
    assert quote[0].startswith("> **") and quote[1] == ">"
    assert quote[2].startswith("> | Scope |")
    scanned = quote.index("> 3/3 targets scanned")
    assert quote[scanned - 1] == ">"
    if scanned + 1 < len(quote):  # a paragraph after it is separated as well
        assert quote[scanned + 1] == ">"
    assert all(line.startswith(">") for line in quote)


def test_summary_md_says_that_a_partial_run_is_not_the_state_of_the_repository(
    tmp_path: Path,
) -> None:
    doc = make_targets_doc(SOURCE)
    doc["run_kind"] = "partial"
    doc["run_kind_reasons"] = ["targets filter: source-*"]
    ws = Workspace(tmp_path, doc)
    ws.add_part("source-development", "source", lockfiles=3)
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert (
        "> Partial run (targets filter: source-*): not a full scan of the repository"
        in md
    )
    assert ws.json("_report/scan_report.json")["run_kind"] == "partial"


def test_summary_md_labels_images_by_name_when_there_are_several(
    tmp_path: Path,
) -> None:
    other = {**DEV, "id": "other-development", "image": "example/other"}
    ws = Workspace(tmp_path, make_targets_doc(DEV, other))
    ws.add_part("app-development", "app-development")
    ws.add_part("other-development", "app-development")
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "| other :development | ok · " in md


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
    assert "| source @ release/1.2 1111111 | ok · " in md


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
    assert "| Target | Trivy | Note |" in md
    assert "| source @ development fedcba9 | ok · 3 pkgs · 0/1/0/0 | - |" in md
    assert "| image :development | failed · boom | - |" in md


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
    assert gh_output.read_text(encoding="utf-8").splitlines() == ["failed-count=1"]
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
    recs = records_by_id(full)
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
    records, sightings, _ = mr.merge_records(
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
    recs = records_by_id(full)
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
    # the CRITICAL has no fix: it is watched, not an action
    assert (
        "> **Fix 1 HIGH in development before the next release "
        "· 1 CRITICAL/HIGH without a fix — see watch**" in md
    )
    assert "> | development | 1 | 1 | 1 | 0 | 2 | 0 |" in md
    assert "Source only" not in md


def rec(exposure: str, severity: str = "HIGH", **extra: Any) -> Record:
    return {
        "exposure": exposure,
        "severity": severity,
        "scan_targets": [],
        "fix_available": False,
        "pkg_type": "library",
        "id": "CVE-1",
        "pkg": "p",
        "version": "1",
        **extra,
    }


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
    assert mr.severity_phrase([rec("release_only", s) for s in severities]) == expected


@pytest.mark.parametrize(
    ("names", "expected"),
    [([], ""), (["a"], "a"), (["a", "b"], "a and b"), (["a", "b", "c"], "a, b and c")],
)
def test_join_names(names: list[str], expected: str) -> None:
    assert mr.join_names(names) == expected


@pytest.fixture
def source_and_images() -> dict[str, Any]:
    """A report of a run with images: development and 1.0.0, both scanned."""
    targets = [
        {**SOURCE, "scanner": "trivy", "status": "ok"},
        {**DEV, "scanner": "trivy", "status": "ok"},
        {**REL, "scanner": "trivy", "status": "ok"},
    ]
    return {"targets": targets}


def fixable(*args: Any, **extra: Any) -> Record:
    return rec(*args, fix_available=True, **extra)


def test_verdict_names_one_action_per_exposure(
    source_and_images: dict[str, Any],
) -> None:
    both = fixable("release_and_development", scan_targets=["app-1.0.0"])
    only = fixable("release_only", "LOW", scan_targets=["app-1.0.0"])
    later = fixable("development_only", "CRITICAL", scan_targets=["app-development"])
    verdict = mr.verdict_text
    assert verdict(source_and_images, [both]) == (
        "Fix 1 HIGH in development and backport to release-1.0"
    )
    assert verdict(source_and_images, [only]) == (
        "Release a patch from release-1.0 — 1 LOW already fixed in development"
    )
    assert verdict(source_and_images, [later]) == (
        "Fix 1 CRITICAL in development before the next release"
    )
    # two sentences at most, the most severe action first
    assert verdict(source_and_images, [both, only, later]) == (
        "Fix 1 CRITICAL in development before the next release. "
        "Fix 1 HIGH in development and backport to release-1.0; "
        "release a patch from release-1.0 — 1 LOW already fixed in development"
    )


def test_verdict_orders_equally_severe_actions_by_count_then_exposure(
    source_and_images: dict[str, Any],
) -> None:
    both = fixable("release_and_development", scan_targets=["app-1.0.0"])
    only = [
        fixable("release_only", scan_targets=["app-1.0.0"], id=f"CVE-{i}")
        for i in range(2)
    ]
    development = fixable("development_only", scan_targets=["app-development"])
    assert mr.verdict_text(source_and_images, [both, *only, development]) == (
        "Release a patch from release-1.0 — 2 HIGH already fixed in development. "
        "Fix 1 HIGH in development and backport to release-1.0; "
        "fix 1 HIGH in development before the next release"
    )


def test_verdict_ignores_the_findings_fixed_in_place(
    source_and_images: dict[str, Any],
) -> None:
    fixed = fixable("release_and_development", scan_targets=["app-1.0.0"], id="CVE-9")
    other = fixable("release_only", "LOW", scan_targets=["app-1.0.0"])
    in_place = {("CVE-9", "p", "1")}
    # it makes no clause of its own and does not count in the one of its exposure
    assert mr.verdict_text(source_and_images, [fixed, other], in_place) == (
        "Release a patch from release-1.0 — 1 LOW already fixed in development"
    )
    assert mr.verdict_text(source_and_images, [fixed], in_place) == (
        "No known vulnerabilities in 1.0.0 and development"
    )
    both = fixable("release_and_development", scan_targets=["app-1.0.0"])
    assert mr.verdict_text(source_and_images, [fixed, both], in_place) == (
        "Fix 1 HIGH in development and backport to release-1.0"
    )


def test_verdict_does_not_claim_a_fix_in_development_that_was_not_checked(
    source_and_images: dict[str, Any],
) -> None:
    report = {
        "targets": [
            t
            for t in source_and_images["targets"]
            if t["tag"] != "development" and t["kind"] != "fs"
        ]
    }
    only = fixable("release_only", scan_targets=["app-1.0.0"])
    assert (
        mr.verdict_text(report, [only]) == "Release a patch from release-1.0 — 1 HIGH"
    )


def test_verdict_counts_only_what_has_a_fix(
    source_and_images: dict[str, Any],
) -> None:
    fixed = fixable("release_and_development", scan_targets=["app-1.0.0"])
    os_unfixed = [
        rec(
            "release_and_development",
            "CRITICAL" if i == 0 else "HIGH",
            scan_targets=["app-1.0.0"],
            pkg_type="os",
            id=f"CVE-{i}",
        )
        for i in range(3)
    ]
    library = rec("release_only", scan_targets=["app-1.0.0"], id="CVE-L")
    low = rec("release_only", "LOW", scan_targets=["app-1.0.0"], id="CVE-M")
    verdict = mr.verdict_text
    # one short trailing clause for what has no fix, never in the action counts
    assert verdict(source_and_images, [fixed, *os_unfixed, library]) == (
        "Fix 1 HIGH in development and backport to release-1.0 "
        "· 4 CRITICAL/HIGH without a fix (3 in the base image) — see watch"
    )
    # no clause for the lower severities without a fix
    assert verdict(source_and_images, [fixed, low]) == (
        "Fix 1 HIGH in development and backport to release-1.0"
    )


def test_verdict_with_nothing_to_upgrade_is_not_clean(
    source_and_images: dict[str, Any],
) -> None:
    os_unfixed = rec("release_only", "HIGH", scan_targets=["app-1.0.0"], pkg_type="os")
    low = rec("development_only", "LOW", scan_targets=["app-development"])
    verdict = mr.verdict_text
    assert verdict(source_and_images, [os_unfixed]) == (
        "Nothing to upgrade — 1 HIGH without a fix (1 in the base image) — see watch"
    )
    assert verdict(source_and_images, [low]) == (
        "Nothing to upgrade — 1 LOW without a fix, see watch"
    )
    # in build and test dependencies a finding is no news for the verdict
    only_sources = rec("source_only", scan_targets=["source-development"])
    assert verdict(source_and_images, [low, only_sources]) == (
        "Nothing to upgrade — 1 LOW without a fix, see watch "
        "· 1 only in build / test dependencies"
    )
    assert verdict(source_and_images, [only_sources]) == (
        "No known vulnerabilities in 1.0.0 and development "
        "— 1 only in build / test dependencies"
    )


def test_verdict_is_clean_without_a_shipped_finding(
    source_and_images: dict[str, Any],
) -> None:
    assert mr.verdict_text(source_and_images, []) == (
        "No known vulnerabilities in 1.0.0 and development"
    )
    # a build or test dependency is not a finding in what is shipped
    assert mr.verdict_text(source_and_images, [fixable("source_only")]) == (
        "No known vulnerabilities in 1.0.0 and development "
        "— 1 only in build / test dependencies"
    )
    development_only = {"targets": [source_and_images["targets"][0]]}
    assert mr.verdict_text(development_only, []) == (
        "No known vulnerabilities in development"
    )
    assert mr.verdict_text({"targets": []}, []) == (
        "No known vulnerabilities in the scanned targets"
    )


def test_scope_table_counts_each_record_once_per_scope(
    source_and_images: dict[str, Any],
) -> None:
    records = [
        rec(
            "release_and_development",
            "CRITICAL",
            scan_targets=["app-1.0.0"],
            fix_available=True,
        ),
        rec(
            "release_and_development", "LOW", scan_targets=["app-1.0.0"], pkg_type="os"
        ),
        rec(
            "release_only",
            "HIGH",
            scan_targets=["app-1.0.0"],
            fix_available=True,
            pkg_type="os",
        ),
        rec("development_only", "MEDIUM", scan_targets=["app-development"]),
        rec(
            "source_only",
            "HIGH",
            scan_targets=["source-development"],
            fix_available=True,
        ),
    ]
    assert plain_lines(mr.scope_table(source_and_images, records)) == [
        "| Scope | CRITICAL | HIGH | MEDIUM | LOW | Fixable | Base image |",
        "|---|---:|---:|---:|---:|---:|---:|",
        "| 1.0.0 (released) | 1 | 1 | 0 | 1 | 2 | 2 |",
        "| development | 1 | 0 | 1 | 1 | 1 | 1 |",
        "| Source only (build / test) | 0 | 1 | 0 | 0 | 1 | — |",
    ]


def test_scope_table_has_a_row_per_release_and_an_unknown_column_if_needed() -> None:
    older = {**REL, "id": "app-0.9.0", "tag": "0.9.0"}
    targets = [
        {**t, "scanner": "trivy", "status": "ok"} for t in (SOURCE, DEV, REL, older)
    ]
    records = [
        rec("release_only", "UNKNOWN", scan_targets=["app-1.0.0", "app-0.9.0"]),
        rec("release_only", "HIGH", scan_targets=["app-0.9.0"]),
    ]
    assert plain_lines(mr.scope_table({"targets": targets}, records)) == [
        "| Scope | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Fixable | Base image |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        "| 1.0.0 (released) | 0 | 0 | 0 | 0 | 1 | 0 | 0 |",
        "| 0.9.0 (released) | 0 | 1 | 0 | 0 | 1 | 0 | 0 |",
    ]


def test_scope_table_is_empty_without_findings(
    source_and_images: dict[str, Any],
) -> None:
    assert mr.scope_table(source_and_images, []) == []


def test_totals_line_is_the_coverage_of_the_run() -> None:
    def report(**counts: int) -> dict[str, Any]:
        base = {"total": 8, "ok": 8, "failed": 0, "not_applicable": 0}
        return {"totals": {"targets": {**base, **counts}}}

    assert mr.totals_line(report()) == "8/8 targets scanned"
    assert mr.totals_line(report(), osv_only=3) == (
        "8/8 targets scanned · 3 found only by OSV"
    )
    assert mr.totals_line(report(ok=5, failed=1, not_applicable=2)) == (
        "5/6 targets scanned · 2 not applicable"
    )
    assert mr.totals_line(report(), packages=12) == "8/8 targets scanned · 12 packages"


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
    recs = records_by_id(ws)
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
    recs = records_by_id(ws)
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
    assert records_by_id(ws)["CVE-1"]["severity"] == "UNKNOWN"
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


def test_display_name_falls_back_to_first_seen_without_an_image() -> None:
    records, sightings, _ = mr.merge_records(
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
    records, _, _ = mr.merge_records(
        "r",
        [
            ("a", "trivy", python_native("package-lock.json", "npm", "Lodash")),
            ("a", "trivy", python_native("package-lock.json", "npm", "lodash")),
        ],
    )
    assert len(records) == 2


def test_package_families_group_the_ecosystems_of_a_package() -> None:
    def families(*ecosystems: str) -> str:
        return mr.package_families([{"ecosystem": list(ecosystems)}])

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
    recs = records_by_id(ws)
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
    recs = records_by_id(ws)
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
    md = plain((ws.out / "summary.md").read_text(encoding="utf-8"))
    assert "> | Source only (build / test) | 0 | 2 | 0 | 0 | 1 | — |" in md
    # braces has no fix: watch section, the chain in "Introduced via"
    assert (
        "| 1 | braces 3.0.3 · npm | 1 HIGH | dev, indirect | jest › core › braces "
        "| not in production · dev dependency |" in md
    )
    assert "## No fix available — watch" in md
    assert "<summary>Dependency paths (1)</summary>" in md
    assert "- **braces 3.0.3** (1 path)\n  - jest › core › braces" in md
    # react is a runtime dependency: source only, but not marked as not in production
    assert "| react | 1.0.0 → 9.9 |" in md
    assert "| Source only · not in images |" in md
    assert "## What to fix" not in md


def test_fixable_dev_dependency_is_marked_not_in_production(
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
    assert "| braces | 3.0.3 → 3.0.4 |" in md
    assert "| not in production · dev dependency |" in md
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


def test_watch_section_is_open_with_high_or_critical(full: Workspace) -> None:
    full.run()
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert "\n## No fix available — watch\n\n| # | Package |" in md
    assert "<summary>No fix available — watch" not in md


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


def test_exposure_labels() -> None:
    label = mr.exposure_label
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
    assert mr.release_tags_of([record], targets) == ["1.0.0", "0.9.0"]


def test_mixed_package_is_in_watch_for_its_unfixed_cve_only(tmp_path: Path) -> None:
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
    recs = records_by_id(ws)
    assert recs["CVE-1"]["upgrade_to"] == recs["CVE-3"]["upgrade_to"] == "2.9.1"
    assert recs["CVE-2"]["upgrade_to"] is None
    md = plain((ws.out / "summary.md").read_text(encoding="utf-8"))
    assert "## What to fix" not in md
    assert "No fix available — watch (1)" in md  # collapsed: only a MEDIUM
    assert "| 1 | urllib3 2.7.0 · python | 1 MEDIUM |" in md


# ---------------------------------------------------------------- gradle graph


def gradle_pkg(name: str, version: str = "1.0") -> dict[str, Any]:
    """A package of a gradle lockfile: no Relationship, no DependsOn."""
    return {
        "ID": f"{name}:{version}",
        "Name": name,
        "Version": version,
        "Identifier": {"UID": f"uid-{name}-{version}"},
        "AnalyzedBy": "gradle-lockfile",
    }


def gradle_result(target: str, *names: str, vulns: tuple[str, ...] = ()) -> dict:
    """A gradle Result of the given lockfile with a finding in the package
    ``org.example:vuln`` (a different CVE per lockfile) when ``vulns`` are given.
    """
    return {
        "Target": target,
        "Class": "lang-pkgs",
        "Type": "gradle",
        "Packages": [gradle_pkg(name) for name in names],
        "Vulnerabilities": [
            vuln(
                cve,
                None,
                PkgName="org.example:vuln",
                InstalledVersion="1.0",
                PkgID="org.example:vuln:1.0",
            )
            for cve in vulns
        ],
    }


def graph_file(
    project: str, project_dir: str, modules: dict[str, list[str]], direct: list[str]
) -> dict[str, Any]:
    """A graph file of schema 1 with one configuration."""
    return {
        "schema_version": 1,
        "project": project,
        "project_dir": project_dir,
        "configurations": {
            "runtimeClasspath": {
                "direct": direct,
                "modules": {k: modules[k] for k in sorted(modules)},
            }
        },
    }


def write_graph(ws: Workspace, tid: str, *files: dict[str, Any]) -> Path:
    graph_dir = ws.trivy_parts / f"{tid}{mr.GRADLE_GRAPH_SUFFIX}"
    graph_dir.mkdir()
    for index, body in enumerate(files):
        (graph_dir / f"graph-{index}.json").write_text(
            json.dumps(body), encoding="utf-8"
        )
    return graph_dir


def gradle_workspace(tmp_path: Path, with_graph: bool = True) -> Workspace:
    """A source target with three lockfiles: ``app`` and ``lib`` (graphs given by
    ``with_graph``) and ``other`` (never has a graph).

    In ``app`` the vulnerable module comes in through ``web > core`` and through
    ``util``; in ``lib`` it is a direct dependency.
    """
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", None, lockfiles=3)
    native = {
        "Results": [
            gradle_result(
                "app/gradle.lockfile",
                "org.example:web",
                "org.example:core",
                "org.example:util",
                "org.example:vuln",
                vulns=("CVE-1",),
            ),
            gradle_result("lib/gradle.lockfile", "org.example:vuln", vulns=("CVE-1",)),
            gradle_result(
                "other/gradle.lockfile", "org.example:vuln", vulns=("CVE-2",)
            ),
        ]
    }
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps(native), encoding="utf-8"
    )
    if with_graph:
        # app depends on lib (a project, transparent): the modules of lib are
        # direct dependencies of app as well
        write_graph(
            ws,
            "source-development",
            graph_file(
                ":app",
                "app",
                {
                    "org.example:web:1.0": ["org.example:core:1.0"],
                    "org.example:core:1.0": [
                        "org.example:vuln:1.0",
                        "org.example:phantom:1.0",  # not in the lockfile
                    ],
                    "org.example:util:1.0": ["org.example:vuln:1.0"],
                    "org.example:vuln:1.0": [],
                },
                ["org.example:web:1.0", "org.example:util:1.0"],
            ),
            graph_file(
                ":lib",
                "lib",
                {"org.example:vuln:1.0": []},
                ["org.example:vuln:1.0"],
            ),
        )
    return ws


def test_gradle_graph_gives_relationship_and_chains(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = gradle_workspace(tmp_path)
    ws.run()
    rec = records_by_id(ws)["CVE-1"]
    # direct in lib, indirect in app: both, as for any lockfile pair
    assert rec["relationship"] == ["direct", "indirect"]
    # shortest first, through the direct dependency of lib and both routes of app
    assert rec["dependency_paths"] == [
        ["org.example:vuln"],
        ["org.example:util", "org.example:vuln"],
        ["org.example:web", "org.example:core", "org.example:vuln"],
    ]
    assert rec["dependency_paths_total"] == 3
    # a direct dependency introduces itself (lib), so only app names its roots
    assert rec["introduced_via"] == ["org.example:util", "org.example:web"]
    # the lockfile without a graph is as before: unknown relationship, no chains
    other = records_by_id(ws)["CVE-2"]
    assert other["relationship"] == []
    assert other["dependency_paths"] == []
    out = capsys.readouterr().out
    assert out.count("::warning title=No Gradle dependency graph::") == 1
    assert "source-development: other/gradle.lockfile" in out


def test_gradle_graph_keeps_the_native_copy_unchanged(tmp_path: Path) -> None:
    ws = gradle_workspace(tmp_path)
    original = (ws.trivy_parts / "source-development.json").read_bytes()
    ws.run()
    assert (ws.out / "_native" / "trivy" / "source-development.json").read_bytes() == (
        original
    )
    assert not (
        ws.out / "_native" / "trivy" / "source-development.gradle-graph"
    ).exists()


def test_gradle_without_graph_warns_per_lockfile_and_changes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = gradle_workspace(tmp_path, with_graph=False)
    assert ws.run() == 0
    recs = records_by_id(ws)
    assert recs["CVE-1"]["relationship"] == []
    assert recs["CVE-1"]["dependency_paths"] == []
    assert recs["CVE-1"]["introduced_via"] == []
    out = capsys.readouterr().out
    assert out.count("::warning title=No Gradle dependency graph::") == 3
    for lockfile in ("app", "lib", "other"):
        assert f"source-development: {lockfile}/gradle.lockfile" in out


def test_gradle_graph_file_that_cannot_be_used_is_skipped_with_a_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = gradle_workspace(tmp_path)
    graph_dir = ws.trivy_parts / "source-development.gradle-graph"
    (graph_dir / "graph-2.json").write_text("{not json", encoding="utf-8")
    (graph_dir / "graph-3.json").write_text(
        json.dumps({"schema_version": 2}), encoding="utf-8"
    )
    assert ws.run() == 0  # the graph is an enrichment: the target stays ok
    assert records_by_id(ws)["CVE-1"]["relationship"] == ["direct", "indirect"]
    out = capsys.readouterr().out
    assert out.count("::warning title=Gradle dependency graph ignored::") == 2
    assert "graph-2.json" in out
    assert "unsupported schema_version 2" in out


def test_gradle_graph_is_not_applied_to_images_or_other_ecosystems(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(DEV))
    ws.add_part("app-development", None)
    native = native_with(vuln("CVE-1", None))
    native["Results"].append(gradle_result("app.jar", "org.example:vuln"))
    (ws.trivy_parts / "app-development.json").write_text(
        json.dumps(native), encoding="utf-8"
    )
    ws.run()
    assert "No Gradle dependency graph" not in capsys.readouterr().out


def test_enrich_gradle_results_marks_direct_and_drops_foreign_edges() -> None:
    native = {
        "Results": [
            gradle_result("gradle.lockfile", "g:a", "g:b"),
            {"Target": "package-lock.json", "Type": "npm", "Packages": [pkg("x")]},
        ]
    }
    graphs, problems = mr.load_gradle_graphs(Path("does-not-exist"))
    assert (graphs, problems) == ({}, [])
    graph = mr.ProjectGraph(
        direct={"g:a:1.0"},
        edges={"g:a:1.0": {"g:b:1.0", "g:gone:1.0"}, "g:b:1.0": {"g:a:1.0"}},
    )
    assert mr.enrich_gradle_results(native, {".": graph}) == []
    by_name = {p["Name"]: p for p in native["Results"][0]["Packages"]}
    assert by_name["g:a"]["Relationship"] == "direct"
    assert by_name["g:a"]["DependsOn"] == ["g:b:1.0"]
    assert by_name["g:b"]["Relationship"] == "indirect"
    assert by_name["g:b"]["DependsOn"] == ["g:a:1.0"]
    # not a gradle Result: untouched
    assert "Relationship" in native["Results"][1]["Packages"][0]
    assert native["Results"][1]["Packages"][0]["DependsOn"] == []


def test_enrich_gradle_results_leaves_packages_unknown_to_the_graph() -> None:
    native = {"Results": [gradle_result("server/gradle.lockfile", "g:a", "g:b")]}
    graph = mr.ProjectGraph(direct={"g:a:1.0"}, edges={"g:a:1.0": set()})
    assert mr.enrich_gradle_results(native, {"server": graph}) == []
    unknown = native["Results"][0]["Packages"][1]
    assert "Relationship" not in unknown and "DependsOn" not in unknown


def test_lockfile_project_dir_and_graph_project_dir_are_comparable() -> None:
    assert mr.lockfile_project_dir("gradle.lockfile") == "."
    assert mr.lockfile_project_dir("nested/util/gradle.lockfile") == "nested/util"
    assert mr.normalize_project_dir("") == "."
    assert mr.normalize_project_dir("./app") == "app"
    data = graph_file(":", ".", {"g:a:1.0": []}, ["g:a:1.0"])
    assert mr.parse_project_graph(data)[0] == "."


# ---------------------------------------------------------------- release sources

RELEASE_SOURCE = {
    "id": "source-1.0.0",
    "kind": "fs",
    "image": None,
    "tag": "1.0.0",
    "ref": None,
    "git_ref": "1.0.0",
    "commit_sha": "0011223344556677889900112233445566778899",
}
OLDER_RELEASE_SOURCE = {
    **RELEASE_SOURCE,
    "id": "source-0.9.0",
    "tag": "0.9.0",
    "git_ref": "0.9.0",
    "commit_sha": "99aabbccddeeff00112233445566778899aabbcc",
}


def test_target_class_of_release_source() -> None:
    assert mr.target_class(RELEASE_SOURCE) == "release_source"
    assert mr.target_class(SOURCE) == "source"
    assert mr.release_class(True) == "release"
    assert mr.release_class(False) == "release_source"


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
    assert mr.classify_exposure(classes, True) == expected


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
    assert mr.classify_exposure(classes, False) == expected


def release_source_workspace(
    tmp_path: Path, *targets: dict[str, Any], image_pkg: bool = True
) -> Workspace:
    """An image with urllib3 and PyJWT as installed packages (no graph) and the
    poetry.lock of a release tag with the graph of both: the image finding must get
    the paths from the lockfile.
    """
    packages = [
        pkg("pyjwt", "direct", ("urllib3",), version="2.7.0"),
        pkg("urllib3", "indirect", (), version="2.7.0"),
        pkg("requests", "direct", ("urllib3",), version="2.7.0"),
    ]
    packages[1]["ID"] = "urllib3@2.7.0"
    packages[0]["DependsOn"] = ["urllib3@2.7.0"]
    packages[2]["DependsOn"] = ["urllib3@2.7.0"]
    lock = native_with(
        vuln("CVE-9", "2.8.0", PkgName="urllib3", PkgID="urllib3@2.7.0"),
        packages=packages,
    )
    image = {
        "Results": [
            {
                "Target": "Python",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Packages": [{"Name": "urllib3", "Version": "2.7.0"}],
                "Vulnerabilities": [vuln("CVE-9", "2.8.0", PkgName="urllib3")],
            }
        ]
    }
    ws = Workspace(tmp_path, make_targets_doc(*targets))
    for target in targets:
        native = image if target["kind"] == "image" and image_pkg else lock
        ws.add_part(target["id"], None)
        (ws.trivy_parts / f"{target['id']}.json").write_text(
            json.dumps(native), encoding="utf-8"
        )
    return ws


def test_release_image_finding_gets_dependency_paths_from_the_release_source(
    tmp_path: Path,
) -> None:
    ws = release_source_workspace(tmp_path, SOURCE, RELEASE_SOURCE, DEV, REL)
    ws.run()
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["scan_targets"] == [
        "source-development",
        "source-1.0.0",
        "app-development",
        "app-1.0.0",
    ]
    assert record["relationship"] == ["indirect"]
    assert record["introduced_via"] == ["pyjwt", "requests"]
    assert record["dependency_paths"] == [
        ["pyjwt", "urllib3"],
        ["requests", "urllib3"],
    ]
    # the same lockfile seen in the development source and in the tag counts once
    assert record["dependency_paths_total"] == 2
    assert record["exposure"] == "release_and_development"
    assert record["locations"] == ["Python", "poetry.lock"]


def test_release_only_finding_gets_paths_and_the_lockfile_of_its_tag(
    tmp_path: Path,
) -> None:
    ws = release_source_workspace(tmp_path, SOURCE, RELEASE_SOURCE, REL)
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps({"Results": []}), encoding="utf-8"
    )
    ws.run()
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["scan_targets"] == ["source-1.0.0", "app-1.0.0"]
    assert record["exposure"] == "release_only"
    assert record["dependency_paths"] == [
        ["pyjwt", "urllib3"],
        ["requests", "urllib3"],
    ]
    assert record["dependency_paths_total"] == 2
    md = plain((ws.out / "summary.md").read_text(encoding="utf-8"))
    assert (
        "> **Release a patch from release-1.0 — 1 HIGH already fixed in development**"
        in md
    )
    assert "> | 1.0.0 (released) | 0 | 1 | 0 | 0 | 1 | 0 |" in md
    assert "| urllib3 | 2.7.0 → 2.8.0 |" in md
    assert "| Released 1.0.0 only |" in md
    assert "<summary>Dependency paths (1)</summary>" in md


def test_finding_only_in_release_sources_is_source_only_when_there_are_images(
    tmp_path: Path,
) -> None:
    ws = release_source_workspace(tmp_path, SOURCE, RELEASE_SOURCE, DEV, REL)
    for tid in ("source-development", "app-development", "app-1.0.0"):
        (ws.trivy_parts / f"{tid}.json").write_text(
            json.dumps({"Results": []}), encoding="utf-8"
        )
    ws.run()
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["scan_targets"] == ["source-1.0.0"]
    assert record["exposure"] == "source_only"
    md = plain((ws.out / "summary.md").read_text(encoding="utf-8"))
    # a release source does not make a release verdict: the image decides
    assert (
        "> **No known vulnerabilities in 1.0.0 and development "
        "— 1 only in build / test dependencies**" in md
    )
    assert "| Source only · not in images |" in md
    # and it is not a release or development finding either
    assert "(released)" not in md
    assert "> | Source only (build / test) | 0 | 1 | 0 | 0 | 1 | — |" in md
    assert "| development |" not in md


def test_run_without_images_is_classified_and_headlined_by_the_sources(
    tmp_path: Path,
) -> None:
    ws = release_source_workspace(
        tmp_path, SOURCE, RELEASE_SOURCE, OLDER_RELEASE_SOURCE
    )
    # fixed in development, still in both releases; one more CVE only in development
    fresh = native_with(
        vuln("CVE-DEV", None, PkgName="left-pad", InstalledVersion="1.0.0"),
        packages=[pkg("left-pad", "direct", ())],
    )
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps(fresh), encoding="utf-8"
    )
    ws.run()
    recs = records_by_id(ws)
    assert recs["CVE-9"]["scan_targets"] == ["source-1.0.0", "source-0.9.0"]
    assert recs["CVE-9"]["exposure"] == "release_only"
    assert recs["CVE-DEV"]["exposure"] == "development_only"
    totals = ws.json("_report/scan_report.json")["totals"]["findings"]
    assert totals["by_exposure"] == {
        "release_and_development": 0,
        "release_only": 1,
        "development_only": 1,
        "source_only": 0,
    }
    md = plain((ws.out / "summary.md").read_text(encoding="utf-8"))
    assert (
        "> **Release a patch from release-1.0, release-0.9 — 1 HIGH already fixed "
        "in development · 1 CRITICAL/HIGH without a fix — see watch**" in md
    )
    assert "> | 1.0.0 (released) | 0 | 1 | 0 | 0 | 1 | 0 |" in md
    assert "> | 0.9.0 (released) | 0 | 1 | 0 | 0 | 1 | 0 |" in md
    assert "> | development | 0 | 1 | 0 | 0 | 0 | 0 |" in md
    assert "Released 1.0.0, 0.9.0 only" in md
    assert "release-1.0, release-0.9" in md


def test_run_without_images_finding_in_tag_and_development_is_open_in_both(
    tmp_path: Path,
) -> None:
    ws = release_source_workspace(tmp_path, SOURCE, RELEASE_SOURCE)
    ws.run()
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["exposure"] == "release_and_development"
    md = plain((ws.out / "summary.md").read_text(encoding="utf-8"))
    assert "> **Fix 1 HIGH in development and backport to release-1.0**" in md
    assert "> | 1.0.0 (released) | 0 | 1 | 0 | 0 | 1 | 0 |" in md
    assert "> | development | 0 | 1 | 0 | 0 | 1 | 0 |" in md
    assert "| Released 1.0.0 + development |" in md


def test_release_source_has_its_own_coverage_label(tmp_path: Path) -> None:
    ws = release_source_workspace(tmp_path, SOURCE, RELEASE_SOURCE, DEV)
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "| source @ development fedcba9 | ok · " in md
    assert "| source @ 1.0.0 0011223 | ok · " in md
    target = ws.targets["source-1.0.0"]
    assert (target["kind"], target["tag"], target["git_ref"]) == (
        "fs",
        "1.0.0",
        "1.0.0",
    )
    assert target["commit_sha"] == RELEASE_SOURCE["commit_sha"]


def test_failed_release_source_is_incomplete_but_does_not_hide_the_rest(
    tmp_path: Path,
) -> None:
    failed = {**RELEASE_SOURCE, "commit_sha": None}
    ws = release_source_workspace(tmp_path, SOURCE, DEV, REL, image_pkg=True)
    doc = json.loads(ws.targets_file.read_text(encoding="utf-8"))
    doc["targets"].append(
        {
            "status": "failed",
            "reason": "cannot resolve release tag 1.0.0",
            "scanner": "trivy",
            **failed,
        }
    )
    ws.targets_file.write_text(json.dumps(doc), encoding="utf-8")
    assert ws.run() == 1
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "**Incomplete: 1 target(s) failed** — source-1.0.0" in md
    assert "> **Fix 1 HIGH in development and backport to release-1.0**" in md
    assert "| source @ 1.0.0 | failed · cannot resolve release tag 1.0.0 | - |" in md


def test_release_tags_of_uses_release_sources_only_without_images() -> None:
    record = {"scan_targets": ["source-1.0.0", "source-0.9.0", "app-1.0.0"]}
    sources = [SOURCE, RELEASE_SOURCE, OLDER_RELEASE_SOURCE]
    assert mr.release_tags_of([record], sources) == ["1.0.0", "0.9.0"]
    with_images = [*sources, DEV, REL]
    assert mr.release_tags_of([record], with_images) == ["1.0.0"]


def test_without_release_sources_the_report_is_as_before(full: Workspace) -> None:
    full.run()
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert "source @ development" in md
    assert "source @ 1.0.0" not in md
    assert all(r["exposure"] != "release_source" for r in records_by_id(full).values())


# ------------------------------------------------------------------------- OSV


@pytest.fixture
def with_osv(tmp_path: Path) -> Workspace:
    """fs + two images (Trivy, all ok) and the OSV twin of the fs target (ok).

    The Trivy fs result lists the packages that OSV was asked about.
    """
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, DEV, REL, OSV_SOURCE))
    ws.add_part("source-development", "source-osv", lockfiles=3)
    ws.add_part("app-development", "app-development")
    ws.add_part("app-1.0.0", "app-1.0.0")
    ws.add_osv_part("source-development", "osv-source")
    return ws


def trivy_only_twin(tmp_path: Path) -> Workspace:
    """The `with_osv` run without its OSV target: the Trivy parts alone."""
    (tmp_path / "trivy-only").mkdir()
    ws = Workspace(tmp_path / "trivy-only", make_targets_doc(SOURCE, DEV, REL))
    ws.add_part("source-development", "source-osv", lockfiles=3)
    ws.add_part("app-development", "app-development")
    ws.add_part("app-1.0.0", "app-1.0.0")
    return ws


def package_entry(**fields: Any) -> dict[str, Any]:
    """A package entry of an osv-scanner result, with the given fields on top."""
    package = {"ecosystem": "npm", "name": "a", "version": "1.0.0"}
    return {"package": package, **fields}


def osv_native() -> dict[str, Any]:
    return json.loads((FIXTURES / "osv-source.json").read_text(encoding="utf-8"))


def write_osv_native(ws: Workspace, native: Any, tid: str = "source-development"):
    ws.add_osv_part(tid, None)
    (ws.osv_parts / f"{tid}.json").write_text(json.dumps(native), encoding="utf-8")


def test_osv_target_entry_counts_queried_packages_and_findings(
    with_osv: Workspace,
) -> None:
    assert with_osv.run() == 0
    entry = with_osv.osv_targets["source-development"]
    assert entry["scanner"] == "osv"
    assert (entry["status"], entry["reason"]) == ("ok", None)
    # 5 queried purls, one of them without a vulnerability; no locations in OSV
    assert entry["packages_scanned"] == 5
    assert entry["locations_scanned"] is None
    # 5 distinct (purl, id) pairs. Severity: the database's own rating (MODERATE is
    # MEDIUM), else the CVSS 3 vector of the record, else UNKNOWN. A fix is a
    # "fixed" version event of an entry of this very package (GIT ranges and other
    # packages of the advisory do not count)
    assert entry["findings"] == {
        "total": 5,
        "fixable": 3,
        "by_severity": {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 1,
            "LOW": 1,
            "UNKNOWN": 1,
        },
    }
    assert entry["queried_at"] == "2030-01-01T00:10:00Z"
    assert entry["image_digest"] is None
    assert entry["commit_sha"] == SOURCE["commit_sha"]
    assert entry["git_ref"] == "development"


def test_target_entries_of_both_scanners_have_the_same_keys(
    with_osv: Workspace,
) -> None:
    with_osv.run()
    targets = with_osv.json("_report/scan_report.json")["targets"]
    assert len({tuple(t) for t in targets}) == 1
    assert [t["queried_at"] for t in targets if t["scanner"] == "trivy"] == [None] * 3


def test_osv_scanner_version_comes_from_the_status(with_osv: Workspace) -> None:
    with_osv.run()
    assert with_osv.json("_report/scan_report.json")["osv"] == {
        "scanner_version": "2.6.0"
    }


def test_osv_metadata_is_null_without_osv_targets(full: Workspace) -> None:
    full.run()
    assert full.json("_report/scan_report.json")["osv"] is None


def test_osv_metadata_with_unknown_scanner_version(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(OSV_SOURCE))
    assert ws.run() == 1  # no part: failed, so no version either
    assert ws.json("_report/scan_report.json")["osv"] == {"scanner_version": None}


def test_osv_findings_are_records_next_to_the_trivy_ones(
    with_osv: Workspace,
) -> None:
    with_osv.run()
    records = records_by_id(with_osv)
    scanners = {cve: r["scanners"] for cve, r in records.items()}
    # CVE-2000-0001 and CVE-2000-0003 are alias-matched Trivy records, CVE-2000-0002
    # is Trivy's alone, the rest are the OSV-only ones (one OSV id each here)
    assert scanners == {
        "CVE-2000-0001": ["osv", "trivy"],
        "CVE-2000-0002": ["trivy"],
        "CVE-2000-0003": ["osv", "trivy"],
        "CVE-2000-0010": ["trivy"],
        "CVE-2000-0011": ["trivy"],
        "CVE-2030-0002": ["osv"],
        "CVE-2030-0003": ["osv"],
        "CVE-2030-0004": ["osv"],
    }
    assert records["CVE-2000-0001"]["aliases"] == ["GHSA-aaaa-aaaa-0001"]
    assert records["CVE-2030-0004"]["aliases"] == ["PYSEC-2030-1"]


def test_osv_target_findings_in_the_report_stay_the_osv_counts(
    with_osv: Workspace, tmp_path: Path
) -> None:
    # the per-target counts are what each scanner said, not what was merged
    full = trivy_only_twin(tmp_path)
    with_osv.run()
    full.run()
    assert with_osv.targets == full.targets
    assert with_osv.osv_targets["source-development"]["findings"]["total"] == 5


def test_totals_count_the_merged_records_including_osv_only_ones(
    with_osv: Workspace, tmp_path: Path
) -> None:
    full = trivy_only_twin(tmp_path)
    with_osv.run()
    full.run()
    totals = with_osv.json("_report/scan_report.json")["totals"]
    reference = full.json("_report/scan_report.json")["totals"]
    assert totals["targets"] == {
        "total": 4,
        "ok": 4,
        "failed": 0,
        "not_applicable": 0,
    }
    # three records only OSV knows: CVE-2030-0002 (LOW), -0003 (HIGH), -0004 (UNKNOWN)
    assert reference["findings"]["total"] == 5
    assert totals["findings"]["total"] == 8
    assert totals["findings"]["fixable"] == reference["findings"]["fixable"] + 2
    assert totals["findings"]["by_severity"] == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 2,
        "LOW": 2,
        "UNKNOWN": 1,
    }
    assert sum(totals["findings"]["by_exposure"].values()) == 8


def test_trivy_output_is_unchanged_when_osv_finds_nothing(tmp_path: Path) -> None:
    def build(name: str, osv: bool) -> Workspace:
        (tmp_path / name).mkdir()
        targets = (SOURCE, DEV, REL, *([OSV_SOURCE] if osv else []))
        ws = Workspace(tmp_path / name, make_targets_doc(*targets))
        ws.add_part("source-development", "source-osv", lockfiles=3)
        ws.add_part("app-development", "app-development")
        ws.add_part("app-1.0.0", "app-1.0.0")
        if osv:
            write_osv_native(
                ws,
                osv_part({"pkg:npm/lodash@4.17.0": []}),
            )
        ws.run()
        return ws

    without, clean = build("without", False), build("clean", True)
    assert (clean.out / "_report" / "vulnerabilities.json").read_bytes() == (
        without.out / "_report" / "vulnerabilities.json"
    ).read_bytes()
    assert clean.targets == without.targets
    # no marker and no OSV-only count in the summary
    md = (clean.out / "summary.md").read_text(encoding="utf-8")
    assert "OSV only" not in md
    assert "found only by OSV" not in md
    # the findings part of summary.md does not move either
    split = "<details>\n<summary>Scan coverage"
    reference = (without.out / "summary.md").read_text(encoding="utf-8")
    assert (
        md.split(split)[0].replace("4/4 targets scanned", "3/3 targets scanned")
        == reference.split(split)[0]
    )


def test_osv_natives_are_copied_next_to_the_trivy_ones(with_osv: Workspace) -> None:
    with_osv.run()
    native = with_osv.out / "_native"
    assert sorted(p.name for p in native.iterdir()) == ["osv", "trivy"]
    assert [p.name for p in (native / "osv").iterdir()] == ["source-development.json"]
    assert (native / "osv" / "source-development.json").read_bytes() == (
        FIXTURES / "osv-source.json"
    ).read_bytes()
    # the Trivy native of the same id is another file
    assert (native / "trivy" / "source-development.json").read_bytes() == (
        FIXTURES / "source-osv.json"
    ).read_bytes()


def test_osv_target_without_a_part_is_failed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, OSV_SOURCE))
    ws.add_part("source-development", "source")
    assert ws.run() == 1
    assert ws.targets["source-development"]["status"] == "ok"
    entry = ws.osv_targets["source-development"]
    assert (entry["status"], entry["reason"]) == (
        "failed",
        "scan job produced no result",
    )
    assert (entry["packages_scanned"], entry["findings"], entry["queried_at"]) == (
        None,
        None,
        None,
    )


def test_a_trivy_part_does_not_satisfy_the_osv_target(tmp_path: Path) -> None:
    # same id, but the part of the other scanner: identity is (scanner, id)
    ws = Workspace(tmp_path, make_targets_doc(OSV_SOURCE))
    ws.add_part("source-development", "source")
    assert ws.run() == 1
    assert ws.osv_targets["source-development"]["status"] == "failed"


def test_osv_status_failed_uses_its_reason_and_keeps_the_native_for_audit(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, OSV_SOURCE))
    ws.add_part("source-development", "source")
    ws.add_osv_part(
        "source-development",
        "osv-source",
        status="failed",
        reason="OSV API unavailable: HTTP 503",
    )
    assert ws.run() == 1
    entry = ws.osv_targets["source-development"]
    assert (entry["status"], entry["reason"]) == (
        "failed",
        "OSV API unavailable: HTTP 503",
    )
    assert entry["findings"] is None
    assert (ws.out / "_native" / "osv" / "source-development.json").is_file()


def test_osv_target_not_applicable_by_its_part_is_not_a_failure(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, OSV_SOURCE))
    ws.add_part("source-development", "source", status="failed", reason="boom")
    ws.add_osv_part(
        "source-development",
        None,
        status="not_applicable",
        reason="trivy target failed",
    )
    assert ws.run() == 1  # only the Trivy target failed
    assert ws.targets["source-development"]["status"] == "failed"
    entry = ws.osv_targets["source-development"]
    assert (entry["status"], entry["reason"]) == (
        "not_applicable",
        "trivy target failed",
    )
    assert entry["findings"] is None
    assert entry["packages_scanned"] is None


def test_osv_target_not_applicable_in_targets_file_is_not_a_failure(
    tmp_path: Path,
) -> None:
    # The resolve step marks the twin of a Trivy target it could not resolve itself
    doc = make_targets_doc(
        SOURCE,
        {**OSV_SOURCE, "status": "not_applicable", "reason": "trivy target failed"},
    )
    ws = Workspace(tmp_path, doc)
    ws.add_part("source-development", "source")
    assert ws.run() == 0
    entry = ws.osv_targets["source-development"]
    assert (entry["status"], entry["reason"]) == (
        "not_applicable",
        "trivy target failed",
    )


@pytest.mark.parametrize(
    ("native", "reason"),
    [
        ({}, "osv result has no results list"),
        ({"results": None}, "osv result has no results list"),
        ({"results": ["oops"]}, "osv result has a malformed result entry"),
        ({"results": [{"packages": None}]}, "osv result has a malformed result entry"),
        (
            {"results": [{"packages": [{"package": {"name": "a"}}]}]},
            "osv result has a malformed package entry",
        ),
        (
            {"results": [{"packages": [package_entry(vulnerabilities=["x"])]}]},
            "osv result has a malformed vulnerability record",
        ),
        (
            {"results": [{"packages": [package_entry(groups=[{"ids": []}])]}]},
            "osv result has a malformed group",
        ),
        (
            {"results": [{"packages": [package_entry(groups=[{"ids": ["GHSA-x"]}])]}]},
            "osv result has no record of GHSA-x",
        ),
        (
            {
                "results": [
                    {"packages": [package_entry(vulnerabilities=[{"id": "GHSA-x"}])]}
                ]
            },
            "osv result has no group of GHSA-x",
        ),
    ],
)
def test_osv_result_that_is_incomplete_is_failed(
    tmp_path: Path, native: dict[str, Any], reason: str
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(OSV_SOURCE))
    write_osv_native(ws, native)
    assert ws.run() == 1
    assert ws.osv_targets["source-development"]["reason"].startswith(reason)


def test_osv_status_ok_with_invalid_json_is_failed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(OSV_SOURCE))
    write_osv_native(ws, None)
    (ws.osv_parts / "source-development.json").write_text("{", encoding="utf-8")
    assert ws.run() == 1
    assert ws.osv_targets["source-development"]["reason"].startswith(
        "osv result is not valid JSON"
    )


def test_osv_clean_result_is_ok_with_zero_findings(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(OSV_SOURCE))
    write_osv_native(ws, osv_part({"pkg:npm/a@1.0.0": []}))
    assert ws.run() == 0
    entry = ws.osv_targets["source-development"]
    assert entry["status"] == "ok"
    assert entry["findings"]["total"] == 0
    assert entry["packages_scanned"] == 1


def test_osv_target_with_no_queried_packages_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(OSV_SOURCE))
    write_osv_native(ws, osv_part({}))
    assert ws.run() == 0
    assert ws.osv_targets["source-development"]["packages_scanned"] == 0
    assert "::warning title=No packages in scan result::source-development (osv)" in (
        capsys.readouterr().out
    )


def test_failed_osv_target_makes_the_summary_incomplete_and_is_annotated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, OSV_SOURCE))
    ws.add_part("source-development", "source")
    assert ws.run() == 1
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert (
        "> **Incomplete: 1 target(s) failed** — source-development (osv) "
        "(their findings are missing)" in md
    )
    out = capsys.readouterr().out
    assert (
        "::error title=Scan target failed::source-development (osv): "
        "scan job produced no result" in out
    )


def test_failed_trivy_target_is_annotated_with_its_scanner(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    assert ws.run() == 1
    assert (
        "::error title=Scan target failed::source-development (trivy): "
        "scan job produced no result" in capsys.readouterr().out
    )


def test_summary_coverage_has_a_scanner_column_and_osv_rows(
    with_osv: Workspace,
) -> None:
    with_osv.run()
    md = (with_osv.out / "summary.md").read_text(encoding="utf-8")
    assert "| Target | Trivy | OSV | Note |" in md
    # one row per subject, a cell per scanner
    assert (
        "| source @ development fedcba9 | ok · 7 pkgs · 1/1/1/0 | ok · 5 pkgs · 5 | - |"
        in md
    )
    assert md.count("| source @ development fedcba9 |") == 1
    assert "OSV: status · language packages only (not the OS packages" in md


def test_summary_coverage_is_as_before_without_osv(full: Workspace) -> None:
    full.run()
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert "| Target | Trivy | Note |" in md
    assert "OSV" not in md


def test_summary_footer_has_the_osv_scope_and_the_query_time(
    with_osv: Workspace,
) -> None:
    with_osv.run()
    md = (with_osv.out / "summary.md").read_text(encoding="utf-8")
    assert md.rstrip().endswith("</sub>")
    footer = md.rstrip().splitlines()[-1]
    assert (
        footer == "<sub>OSV: language packages only · queried 2030-01-01 00:10Z</sub>"
    )


def test_summary_headline_without_trivy_scan_but_with_an_osv_one(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, OSV_SOURCE))
    write_osv_native(ws, osv_part({"pkg:npm/a@1.0.0": []}))
    assert ws.run() == 1  # the Trivy part is missing
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "> No Trivy target was scanned" in md


def test_summary_without_any_scanned_target_is_unchanged(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, OSV_SOURCE))
    assert ws.run() == 2
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "> No target was scanned" in md


def test_osv_target_does_not_change_the_no_findings_headline(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, OSV_SOURCE))
    ws.add_part("source-development", None)
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps({"Results": []}), encoding="utf-8"
    )
    write_osv_native(ws, osv_part({"pkg:npm/a@1.0.0": []}))
    assert ws.run() == 0
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "> **No known vulnerabilities in development**" in md
    assert "> 2/2 targets scanned · 0 packages\n" in md


def test_targets_file_identity_is_scanner_and_id(tmp_path: Path) -> None:
    # the same id for two scanners is fine
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, OSV_SOURCE))
    mr.load_targets_file(ws.targets_file)
    # twice for one scanner is not
    doc = make_targets_doc(OSV_SOURCE, OSV_SOURCE)
    ws.targets_file.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(mr.InputError, match="duplicate osv target id"):
        mr.load_targets_file(ws.targets_file)


@pytest.mark.parametrize("scanner", [None, "", "grype", "dependabot"])
def test_targets_file_needs_a_known_scanner(
    tmp_path: Path, scanner: str | None
) -> None:
    doc = make_targets_doc({**SOURCE, "scanner": scanner})
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(mr.InputError, match="invalid scanner"):
        mr.load_targets_file(path)


# ---- OSV: severity, fixes, findings


def vulnerability(*records: dict[str, Any], max_severity: float | None = None) -> Any:
    """The vulnerability (a group) of the given records."""
    ordered = sorted(records, key=mr.osv_record_order)
    ids = tuple(sorted(r["id"] for r in records))
    return mr.OsvVulnerability(ids, frozenset(ids), tuple(ordered), max_severity)


def test_osv_database_rating_maps_moderate_to_medium() -> None:
    def rating(value: Any) -> str | None:
        return mr.osv_database_rating({"database_specific": {"severity": value}})

    assert [
        rating(v) for v in ("MODERATE", "moderate", "MEDIUM", "HIGH", "CRITICAL", "LOW")
    ] == ["MEDIUM", "MEDIUM", "MEDIUM", "HIGH", "CRITICAL", "LOW"]
    assert [rating(v) for v in ("BOGUS", 7, None, "UNKNOWN")] == [None] * 4
    assert mr.osv_database_rating({"database_specific": None}) is None
    assert mr.osv_database_rating({}) is None


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
    assert mr.score_rating(score) == rating


def test_osv_group_severity_takes_the_database_rating_before_the_score() -> None:
    ghsa = osv_record("GHSA-a", database_specific={"severity": "LOW"})
    pysec = osv_record("PYSEC-1")
    # the database rating wins over the score of the group
    assert mr.osv_group_severity(vulnerability(ghsa, max_severity=9.8)) == "LOW"
    assert mr.osv_group_severity(vulnerability(ghsa, pysec, max_severity=9.8)) == "LOW"
    other = osv_record("GHSA-b", database_specific={"severity": "HIGH"})
    assert mr.osv_group_severity(vulnerability(ghsa, other)) == "HIGH"
    # no rating of the database: the rating of the score (v3 and v4 alike)
    assert mr.osv_group_severity(vulnerability(pysec, max_severity=9.8)) == "CRITICAL"
    assert mr.osv_group_severity(vulnerability(pysec, max_severity=5.3)) == "MEDIUM"
    assert mr.osv_group_severity(vulnerability(pysec)) == "UNKNOWN"


@pytest.mark.parametrize(
    ("value", "score"),
    [("8.7", 8.7), (7, 7.0), ("", None), (None, None), ("x", None), ("0", None)],
)
def test_osv_score_reads_max_severity(value: Any, score: float | None) -> None:
    assert mr.osv_score(value) == score


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:npm/lodash@4.17.0", ("npm", "", "lodash")),
        ("pkg:npm/%40babel/traverse@7.20.0", ("npm", "@babel", "traverse")),
        ("pkg:pypi/Requests@2.0.0", ("pypi", "", "Requests")),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
            ("maven", "org.apache.logging.log4j", "log4j-core"),
        ),
        ("pkg:golang/github.com/a/b@v1#sub/path", ("golang", "github.com/a", "b")),
        ("pkg:NPM/x", ("npm", "", "x")),
        ("lodash@1", None),
        ("pkg:npm", None),
        ("pkg:npm//x", None),
    ],
)
def test_parse_purl(purl: str, expected: tuple[str, str, str] | None) -> None:
    assert mr.parse_purl(purl) == expected


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
    assert mr.purl_identity(purl) == identity


def test_osv_fixed_versions_need_a_fixed_event_of_this_package() -> None:
    record = {
        "affected": [
            affected_range("PyPI", "requests", {"fixed": "2.31.0"}),
            affected_range("PyPI", "other", {"last_affected": "1.0"}),
        ]
    }
    assert mr.osv_fixed_versions(record, ("PyPI", "requests")) == ["2.31.0"]
    assert mr.osv_fixed_versions(record, ("PyPI", "other")) == []
    assert mr.osv_fixed_versions(record, ("PyPI", "unlisted")) == []


def test_osv_fixed_versions_ignore_git_ranges() -> None:
    record = {"affected": [affected_range("npm", "a", {"fixed": "abc123"}, kind="GIT")]}
    assert mr.osv_fixed_versions(record, ("npm", "a")) == []
    record = {
        "affected": [affected_range("npm", "a", {"fixed": "1.2.3"}, kind="SEMVER")]
    }
    assert mr.osv_fixed_versions(record, ("npm", "a")) == ["1.2.3"]
    assert mr.osv_fixed_versions({}, ("npm", "a")) == []


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
    assert mr.osv_fixed_versions(by_purl, identity) == ["2.0"]
    suffixed = {
        "affected": [
            affected_range("Maven:https://repo", "org.example:lib", {"fixed": "2"})
        ]
    }
    assert mr.osv_fixed_versions(suffixed, identity) == ["2"]
    broken = {"affected": [{"package": {"ecosystem": "npm"}}, {"ranges": []}]}
    assert mr.osv_fixed_versions(broken, ("npm", "a")) == []


def test_osv_packages_are_distinct_by_ecosystem_name_and_version() -> None:
    native = osv_native()
    entry = native["results"][0]["packages"][0]
    native["results"].append({"packages": [entry]})
    packages = mr.osv_packages(native)
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
    groups = mr.osv_packages(native)[(("npm", "lib"), "1.0")].vulnerabilities
    assert [(v.ids, sorted(v.names), v.max_severity) for v in groups] == [
        (("GHSA-b", "PYSEC-1"), ["CVE-1", "GHSA-b", "OTHER-9", "PYSEC-1"], 8.7),
        (("GHSA-c", "RUSTSEC-d"), ["GHSA-c", "RUSTSEC-d"], None),
    ]
    # GHSA records come first, then by id
    assert [r["id"] for r in groups[0].records] == ["GHSA-b", "PYSEC-1"]
    assert [r["id"] for r in groups[1].records] == ["GHSA-c", "RUSTSEC-d"]


def test_osv_findings_are_distinct_by_package_and_group() -> None:
    found = mr.osv_findings(osv_native())
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


# ---- OSV: findings as records

GHSA_DB = {"severity": "HIGH"}
VECTOR_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"  # 7.5
VECTOR_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
VECTOR_V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def lang_package(
    name: str,
    version: str,
    purl: str,
    relationship: str | None = None,
    depends_on: tuple[str, ...] = (),
    dev: bool = False,
) -> dict[str, Any]:
    """A Trivy package of a language result; its ID is ``name@version``."""
    package: dict[str, Any] = {
        "ID": f"{name}@{version}",
        "Name": name,
        "Version": version,
        "Identifier": {"PURL": purl},
    }
    if relationship:
        package["Relationship"] = relationship
    if depends_on:
        package["DependsOn"] = list(depends_on)
    if dev:
        package["Dev"] = True
    return package


def trivy_vuln(
    cve: str, name: str, version: str, severity: str = "MEDIUM", **extra: Any
) -> dict[str, Any]:
    return {
        "VulnerabilityID": cve,
        "PkgName": name,
        "InstalledVersion": version,
        "Severity": severity,
        "Status": "affected",
        "Title": f"Trivy title of {cve}",
        **extra,
    }


def lang_result(
    result_type: str,
    target: str,
    packages: list[dict[str, Any]],
    vulns: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "Target": target,
        "Class": "lang-pkgs",
        "Type": result_type,
        "Packages": packages,
    }
    if vulns:
        result["Vulnerabilities"] = vulns
    return result


def affected_range(
    ecosystem: str, name: str, *events: dict[str, str], kind: str = "ECOSYSTEM"
) -> dict[str, Any]:
    return {
        "package": {"ecosystem": ecosystem, "name": name},
        "ranges": [{"type": kind, "events": [{"introduced": "0"}, *events]}],
    }


def osv_record(vuln_id: str, **fields: Any) -> dict[str, Any]:
    return {"id": vuln_id, **fields}


def purl_version(purl: str) -> str:
    return urllib.parse.unquote(purl.split("?")[0].rsplit("@", 1)[1])


def alias_groups(records: dict[str, dict[str, Any]], ids: list[str]) -> list[Any]:
    """Ids that alias each other, as the groups of osv-scanner (smallest id first)."""
    groups: list[tuple[list[str], set[str]]] = []
    for vuln_id in sorted(set(ids)):
        names = {vuln_id, *records[vuln_id].get("aliases", [])}
        linked = [g for g in groups if g[1] & names]
        merged = ([vuln_id], names)
        for group in linked:
            groups.remove(group)
            merged = (merged[0] + group[0], merged[1] | group[1])
        groups.append((sorted(merged[0]), merged[1]))
    return sorted(groups)


def osv_part(
    packages: dict[str, list[str]],
    *records: dict[str, Any],
    scores: dict[str, str] | None = None,
) -> dict[str, Any]:
    """An osv-scanner result (``--format json --all-packages``) of one BOM.

    ``packages``: purl -> ids found for it (ids that alias each other are one
    group); ``scores``: the ``max_severity`` of the group of an id.
    """
    by_id = {r["id"]: r for r in records}
    entries = []
    for purl, ids in packages.items():
        ecosystem, name = mr.purl_identity(purl)
        entry: dict[str, Any] = {
            "package": {
                "name": name,
                "version": purl_version(purl),
                "ecosystem": ecosystem,
            }
        }
        if ids:
            entry["vulnerabilities"] = [by_id[i] for i in sorted(set(ids))]
            entry["groups"] = [
                {
                    "ids": members,
                    "aliases": sorted(names),
                    "max_severity": (scores or {}).get(members[0], ""),
                }
                for members, names in alias_groups(by_id, ids)
            ]
        entries.append(entry)
    source = {"path": "source-development.cdx.json", "type": "sbom"}
    return {"results": [{"source": source, "packages": entries}]}


def merge_scan(
    tmp_path: Path,
    trivy: dict[str, dict[str, Any]],
    osv: dict[str, dict[str, Any]],
    *targets: dict[str, Any],
) -> Workspace:
    """Merge natives written as parts: ``trivy`` and ``osv`` by target id."""
    doc = make_targets_doc(
        *targets, *({**t, "scanner": "osv"} for t in targets if t["id"] in osv)
    )
    ws = Workspace(tmp_path, doc)
    for tid, native in trivy.items():
        ws.add_part(tid, None)
        (ws.trivy_parts / f"{tid}.json").write_text(json.dumps(native), "utf-8")
    for tid, native in osv.items():
        write_osv_native(ws, native, tid)
    ws.run()
    return ws


def source_with(*results: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {"source-development": {"Results": list(results)}}


def test_osv_joins_the_trivy_record_by_a_cve_alias(tmp_path: Path) -> None:
    lib = lang_package("lib", "1.0", "pkg:npm/lib@1.0", "direct")
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lib],
            [
                trivy_vuln(
                    "CVE-2030-1",
                    "lib",
                    "1.0",
                    "HIGH",
                    PrimaryURL="https://example.invalid/CVE-2030-1",
                    CweIDs=["CWE-1"],
                )
            ],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record(
                "GHSA-aaaa-aaaa-aaaa",
                aliases=["CVE-2030-1"],
                summary="OSV title",
                database_specific={"severity": "CRITICAL", "cwe_ids": ["CWE-2"]},
                affected=[affected_range("npm", "lib", {"fixed": "1.5"})],
            ),
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE)
    records = records_by_id(ws)
    assert list(records) == ["CVE-2030-1"]
    record = records["CVE-2030-1"]
    assert record["scanners"] == ["osv", "trivy"]
    assert record["aliases"] == ["GHSA-aaaa-aaaa-aaaa"]
    assert record["scan_targets"] == ["source-development"]
    # what Trivy said wins: severity, title, URL, CWE; its (missing) fix is not
    # filled in from OSV
    assert record["severity"] == "HIGH"
    assert record["title"] == "Trivy title of CVE-2030-1"
    assert record["primary_url"] == "https://example.invalid/CVE-2030-1"
    assert record["cwe"] == ["CWE-1"]
    assert (record["status"], record["fix_available"]) == ("affected", False)
    assert record["fixed_versions"] == []


def test_osv_joins_a_trivy_record_by_an_id_in_its_aliases(tmp_path: Path) -> None:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
            [trivy_vuln("CVE-2030-1", "lib", "1.0", VendorIDs=["GHSA-aaaa-aaaa-aaaa"])],
        )
    )
    # the GHSA record does not list the CVE; Trivy lists the GHSA as its vendor id
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record("GHSA-aaaa-aaaa-aaaa"),
        )
    }
    records = records_by_id(merge_scan(tmp_path, trivy, osv, SOURCE))
    assert list(records) == ["CVE-2030-1"]
    assert records["CVE-2030-1"]["scanners"] == ["osv", "trivy"]
    assert records["CVE-2030-1"]["aliases"] == ["GHSA-aaaa-aaaa-aaaa"]


def test_an_alias_group_is_one_vulnerability_matching_by_any_of_its_ids(
    tmp_path: Path,
) -> None:
    trivy = source_with(
        lang_result(
            "poetry",
            "poetry.lock",
            [lang_package("lib", "1.0", "pkg:pypi/lib@1.0")],
            [trivy_vuln("CVE-2030-1", "lib", "1.0")],
        )
    )
    # PYSEC and GHSA both alias the CVE: one record, joined with Trivy's
    osv = {
        "source-development": osv_part(
            {"pkg:pypi/lib@1.0": ["GHSA-aaaa-aaaa-aaaa", "PYSEC-2030-1"]},
            osv_record("PYSEC-2030-1", aliases=["CVE-2030-1"]),
            osv_record("GHSA-aaaa-aaaa-aaaa", aliases=["CVE-2030-1"]),
        )
    }
    records = records_by_id(merge_scan(tmp_path, trivy, osv, SOURCE))
    assert list(records) == ["CVE-2030-1"]
    assert records["CVE-2030-1"]["aliases"] == ["GHSA-aaaa-aaaa-aaaa", "PYSEC-2030-1"]
    assert records["CVE-2030-1"]["scanners"] == ["osv", "trivy"]


def test_a_vulnerability_matches_every_record_it_shares_an_id_with(
    tmp_path: Path,
) -> None:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
            [
                trivy_vuln("CVE-2030-1", "lib", "1.0"),
                trivy_vuln("CVE-2030-2", "lib", "1.0"),
            ],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record("GHSA-aaaa-aaaa-aaaa", aliases=["CVE-2030-1", "CVE-2030-2"]),
        )
    }
    records = records_by_id(merge_scan(tmp_path, trivy, osv, SOURCE))
    assert len(records) == 2
    # each is joined, and the CVE of the other is not an alias of it
    assert records["CVE-2030-1"]["scanners"] == ["osv", "trivy"]
    assert records["CVE-2030-1"]["aliases"] == ["GHSA-aaaa-aaaa-aaaa"]
    assert records["CVE-2030-2"]["scanners"] == ["osv", "trivy"]
    assert records["CVE-2030-2"]["aliases"] == ["GHSA-aaaa-aaaa-aaaa"]


def test_only_the_same_package_version_matches(tmp_path: Path) -> None:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [
                lang_package("lib", "1.0", "pkg:npm/lib@1.0"),
                lang_package("lib", "2.0", "pkg:npm/lib@2.0"),
                lang_package("other", "1.0", "pkg:npm/other@1.0"),
            ],
            [
                trivy_vuln("CVE-2030-1", "lib", "2.0"),
                trivy_vuln("CVE-2030-1", "other", "1.0"),
            ],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record("GHSA-aaaa-aaaa-aaaa", aliases=["CVE-2030-1"]),
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE)
    found = {
        (r["pkg"], r["version"]): r["scanners"]
        for r in ws.json("_report/vulnerabilities.json")["records"]
    }
    # lib 1.0 is a new OSV-only record; lib 2.0 and other 1.0 stay Trivy's
    assert found == {
        ("lib", "1.0"): ["osv"],
        ("lib", "2.0"): ["trivy"],
        ("other", "1.0"): ["trivy"],
    }


def test_osv_related_does_not_join_vulnerabilities(tmp_path: Path) -> None:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"]},
            osv_record("GHSA-aaaa-aaaa-aaaa", related=["GHSA-bbbb-bbbb-bbbb"]),
            osv_record("GHSA-bbbb-bbbb-bbbb", related=["GHSA-aaaa-aaaa-aaaa"]),
        )
    }
    records = records_by_id(merge_scan(tmp_path, trivy, osv, SOURCE))
    assert sorted(records) == ["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"]


# ---- OSV-only records


def vulnerabilities(*records: dict[str, Any]) -> list[Any]:
    native = osv_part({"pkg:npm/p@1": [r["id"] for r in records]}, *records)
    return list(mr.osv_packages(native)[(("npm", "p"), "1")].vulnerabilities)


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
    assert mr.osv_primary_id(group) == expected


def test_osv_only_record_fields_from_the_osv_records(tmp_path: Path) -> None:
    trivy = source_with(
        lang_result(
            "poetry",
            "poetry.lock",
            [lang_package("Foo_Bar", "1.0", "pkg:pypi/foo-bar@1.0", "direct")],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:pypi/foo-bar@1.0": ["GHSA-aaaa-aaaa-aaaa", "PYSEC-2030-1"]},
            osv_record(
                "PYSEC-2030-1",
                aliases=["CVE-2030-1", "GHSA-aaaa-aaaa-aaaa"],
                published="2030-01-05T00:00:00Z",
                details="long text",
                references=[
                    {"type": "WEB", "url": "https://example.invalid/web"},
                    {"type": "ADVISORY", "url": "https://example.invalid/pysec"},
                ],
                affected=[affected_range("PyPI", "foo-bar", {"fixed": "1.2"})],
            ),
            osv_record(
                "GHSA-aaaa-aaaa-aaaa",
                aliases=["CVE-2030-1"],
                summary=" The GHSA summary ",
                published="2030-01-03T00:00:00Z",
                database_specific={
                    "severity": "MODERATE",
                    "cwe_ids": ["CWE-79", "CWE-20"],
                },
                severity=[{"type": "CVSS_V3", "score": VECTOR_CRITICAL}],
                references=[
                    {"type": "ADVISORY", "url": "https://example.invalid/ghsa"}
                ],
                affected=[affected_range("PyPI", "foo-bar", {"fixed": "1.1"})],
            ),
            scores={"GHSA-aaaa-aaaa-aaaa": "9.8"},
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE)
    records = ws.json("_report/vulnerabilities.json")["records"]
    assert len(records) == 1
    record = records[0]
    # the package context is the Trivy package's: its name, not the purl's
    assert (record["repo"], record["pkg"], record["version"]) == (
        "example/app",
        "Foo_Bar",
        "1.0",
    )
    assert (record["id"], record["cve"]) == ("CVE-2030-1", "CVE-2030-1")
    assert record["aliases"] == ["GHSA-aaaa-aaaa-aaaa", "PYSEC-2030-1"]
    assert record["scanners"] == ["osv"]
    assert record["scan_targets"] == ["source-development"]
    assert record["locations"] == ["poetry.lock"]
    assert record["ecosystem"] == ["poetry"]
    assert record["pkg_type"] == "library"
    assert record["relationship"] == ["direct"]
    # GHSA first: its database rating (MODERATE is MEDIUM) wins over the score
    assert (record["severity"], record["severity_source"]) == ("MEDIUM", "osv")
    assert record["cvss"] == {
        "score": 9.8,
        "vector": VECTOR_CRITICAL,
        "version": "3.1",
        "source": "osv",
    }
    assert (record["status"], record["fix_available"]) == ("fixed", True)
    assert record["fixed_versions"] == ["1.1", "1.2"]
    # the databases name two fixes: the lower one is the minimal upgrade
    assert record["upgrade_to"] == "1.1"
    assert record["title"] == "The GHSA summary"
    assert record["published"] == "2030-01-03T00:00:00Z"
    assert record["primary_url"] == "https://example.invalid/ghsa"
    assert record["cwe"] == ["CWE-20", "CWE-79"]
    assert record["pkg_paths"] == []
    assert record["exposure"] == "development_only"


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
    assert mr.cve_of({"id": vuln_id, "aliases": aliases}) == expected


def test_a_record_known_by_another_id_than_a_cve_has_its_cve_when_it_has_one(
    tmp_path: Path,
) -> None:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
            [
                trivy_vuln(
                    "DSA-5000-1", "lib", "1.0", VendorIDs=["CVE-2030-9", "CVE-2030-2"]
                ),
                trivy_vuln("TEMP-0000-ABC", "lib", "1.0"),
                # its own id among the vendor ids is not an alias
                trivy_vuln("CVE-2030-1", "lib", "1.0", VendorIDs=["CVE-2030-1", "G-1"]),
            ],
        )
    )
    records = records_by_id(merge_scan(tmp_path, trivy, {}, SOURCE))
    shown = {i: (r["cve"], r["aliases"]) for i, r in records.items()}
    assert shown == {
        "DSA-5000-1": ("CVE-2030-2", ["CVE-2030-2", "CVE-2030-9"]),
        "TEMP-0000-ABC": (None, []),
        "CVE-2030-1": ("CVE-2030-1", ["G-1"]),
    }


def test_osv_only_record_without_optional_fields(tmp_path: Path) -> None:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["PYSEC-2030-1"]}, osv_record("PYSEC-2030-1")
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert (record["id"], record["cve"]) == ("PYSEC-2030-1", None)
    assert record["aliases"] == []
    assert (record["severity"], record["severity_source"]) == ("UNKNOWN", None)
    assert record["cvss"] is None
    assert (record["status"], record["fix_available"]) == ("affected", False)
    assert record["fixed_versions"] == []
    assert record["title"] is None
    assert record["published"] is None
    assert record["cwe"] is None
    assert record["primary_url"] == "https://osv.dev/vulnerability/PYSEC-2030-1"


def test_osv_only_record_has_the_keys_of_a_trivy_record(tmp_path: Path) -> None:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
            [trivy_vuln("CVE-2030-9", "lib", "1.0")],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["PYSEC-2030-1"]}, osv_record("PYSEC-2030-1")
        )
    }
    records = merge_scan(tmp_path, trivy, osv, SOURCE).json(
        "_report/vulnerabilities.json"
    )["records"]
    assert len(records) == 2
    assert len({tuple(r) for r in records}) == 1


def severity_of(
    tmp_path: Path, max_severity: str = "", **fields: Any
) -> dict[str, Any]:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record("GHSA-aaaa-aaaa-aaaa", **fields),
            scores={"GHSA-aaaa-aaaa-aaaa": max_severity},
        )
    }
    (record,) = merge_scan(tmp_path, trivy, osv, SOURCE).json(
        "_report/vulnerabilities.json"
    )["records"]
    return record


def test_osv_only_severity_from_the_ghsa_database_rating(tmp_path: Path) -> None:
    record = severity_of(
        tmp_path,
        "9.8",
        database_specific=GHSA_DB,
        severity=[{"type": "CVSS_V3", "score": VECTOR_CRITICAL}],
    )
    assert (record["severity"], record["severity_source"]) == ("HIGH", "osv")
    # the CVSS block is the vector's, whatever decided the severity
    assert record["cvss"]["score"] == 9.8


@pytest.mark.parametrize(
    ("score", "severity"),
    [("9.8", "CRITICAL"), ("8.7", "HIGH"), ("5.3", "MEDIUM"), ("2.1", "LOW")],
)
def test_osv_only_severity_from_the_max_severity_of_the_group(
    tmp_path: Path, score: str, severity: str
) -> None:
    record = severity_of(
        tmp_path, score, severity=[{"type": "CVSS_V3", "score": VECTOR_HIGH}]
    )
    assert (record["severity"], record["severity_source"]) == (severity, "osv")
    assert record["cvss"] == {
        "score": float(score),
        "vector": VECTOR_HIGH,
        "version": "3.1",
        "source": "osv",
    }


def test_osv_only_cvss4_vector_alone_is_rated_by_the_max_severity(
    tmp_path: Path,
) -> None:
    record = severity_of(
        tmp_path,
        "8.7",
        severity=[
            {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
            {"type": "CVSS_V4", "score": VECTOR_V4},
        ],
    )
    assert (record["severity"], record["severity_source"]) == ("HIGH", "osv")
    assert record["cvss"] == {
        "score": 8.7,
        "vector": VECTOR_V4,
        "version": "4.0",
        "source": "osv",
    }


def test_osv_only_cvss4_vector_is_shown_before_a_cvss3_one(tmp_path: Path) -> None:
    record = severity_of(
        tmp_path,
        "8.7",
        severity=[
            {"type": "CVSS_V3", "score": VECTOR_HIGH},
            {"type": "CVSS_V4", "score": VECTOR_V4},
        ],
    )
    # the score is the group's maximum over its vectors, the vector the latest one
    assert (record["cvss"]["score"], record["cvss"]["vector"]) == (8.7, VECTOR_V4)


def test_osv_only_without_a_score_is_unknown_and_keeps_the_vector(
    tmp_path: Path,
) -> None:
    record = severity_of(
        tmp_path, "", severity=[{"type": "CVSS_V4", "score": VECTOR_V4}]
    )
    assert (record["severity"], record["severity_source"]) == ("UNKNOWN", None)
    assert record["cvss"] == {
        "score": None,
        "vector": VECTOR_V4,
        "version": "4.0",
        "source": "osv",
    }


def test_osv_only_cvss2_vector_alone_gives_no_cvss(tmp_path: Path) -> None:
    record = severity_of(
        tmp_path,
        "6.8",
        severity=[{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}],
    )
    # osv-scanner rated it, nothing is shown without a CVSS 3 / 4 vector
    assert (record["severity"], record["cvss"]) == ("MEDIUM", None)


def fix_of(tmp_path: Path, version: str, *affected: dict[str, Any]) -> dict[str, Any]:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", version, f"pkg:npm/lib@{version}")],
        )
    )
    osv = {
        "source-development": osv_part(
            {f"pkg:npm/lib@{version}": ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record("GHSA-aaaa-aaaa-aaaa", affected=list(affected)),
        )
    }
    (record,) = merge_scan(tmp_path, trivy, osv, SOURCE).json(
        "_report/vulnerabilities.json"
    )["records"]
    return record


def test_osv_only_fixed_event_is_a_fix(tmp_path: Path) -> None:
    record = fix_of(
        tmp_path, "1.0", affected_range("npm", "lib", {"fixed": "1.4"}, kind="SEMVER")
    )
    assert (record["status"], record["fix_available"]) == ("fixed", True)
    assert (record["fixed_versions"], record["upgrade_to"]) == (["1.4"], "1.4")


def test_osv_only_last_affected_without_fixed_is_affected(tmp_path: Path) -> None:
    record = fix_of(
        tmp_path, "1.0", affected_range("npm", "lib", {"last_affected": "1.9"})
    )
    assert (record["status"], record["fix_available"]) == ("affected", False)
    assert (record["fixed_versions"], record["upgrade_to"]) == ([], None)


def test_osv_only_fixes_of_other_packages_and_git_ranges_do_not_count(
    tmp_path: Path,
) -> None:
    record = fix_of(
        tmp_path,
        "1.0",
        affected_range("npm", "other", {"fixed": "9.0"}),
        affected_range("npm", "lib", {"fixed": "abc123"}, kind="GIT"),
    )
    assert (record["status"], record["fix_available"]) == ("affected", False)


def test_osv_only_fixes_of_another_branch_are_left_out(tmp_path: Path) -> None:
    # fixed in 1.5 for 1.x and in 0.9 for the old 0.x branch: 1.5 is the fix of 1.2
    record = fix_of(
        tmp_path,
        "1.2",
        affected_range("npm", "lib", {"fixed": "0.9"}, {"fixed": "1.5"}),
    )
    assert record["fixed_versions"] == ["1.5"]
    assert record["upgrade_to"] == "1.5"


def test_osv_only_fixes_all_below_the_installed_version_mean_no_fix(
    tmp_path: Path,
) -> None:
    record = fix_of(tmp_path, "1.2", affected_range("npm", "lib", {"fixed": "0.9"}))
    assert (record["status"], record["fix_available"]) == ("affected", False)


def test_osv_group_fixes_keeps_incomparable_versions() -> None:
    record = osv_record(
        "GHSA-a", affected=[affected_range("npm", "lib", {"fixed": "next"})]
    )
    assert mr.osv_group_fixes([record], ("npm", "lib"), "1.0") == ["next"]
    assert mr.osv_group_fixes([record], ("npm", "lib"), None) == ["next"]


# ---- OSV-only records: package context


def image_native(*results: dict[str, Any]) -> dict[str, Any]:
    return {"Metadata": {"RepoDigests": []}, "Results": list(results)}


def test_osv_only_on_an_image_python_package(tmp_path: Path) -> None:
    image = image_native(
        lang_result(
            "python-pkg",
            "Python",
            [lang_package("Mako", "1.3.0", "pkg:pypi/mako@1.3.0")],
        )
    )
    osv = {
        "app-development": osv_part(
            {"pkg:pypi/mako@1.3.0": ["PYSEC-2030-1"]},
            osv_record(
                "PYSEC-2030-1",
                aliases=["CVE-2030-1"],
                affected=[affected_range("PyPI", "mako", {"fixed": "1.3.1"})],
            ),
        )
    }
    ws = merge_scan(tmp_path, {"app-development": image}, osv, DEV)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert (record["id"], record["pkg"], record["version"]) == (
        "CVE-2030-1",
        "Mako",
        "1.3.0",
    )
    assert record["scanners"] == ["osv"]
    assert record["scan_targets"] == ["app-development"]
    assert record["ecosystem"] == ["python-pkg"]
    assert record["locations"] == ["Python"]
    assert record["exposure"] == "development_only"
    assert record["relationship"] == []
    assert record["dependency_paths"] == []
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "> **Fix 1 UNKNOWN in development before the next release**" in md
    assert "| UNKNOWN | Fixable | Base image |" in md
    assert "found only by OSV" in md
    assert "| Mako | 1.3.0 → 1.3.1 |" in md


def test_osv_only_on_a_poetry_package_has_the_dependency_paths(
    tmp_path: Path,
) -> None:
    packages = [
        lang_package("web", "1.0", "pkg:pypi/web@1.0", "direct", ("http@2.0",)),
        lang_package("http", "2.0", "pkg:pypi/http@2.0", "indirect", ("Leaf_Pkg@3.0",)),
        lang_package("Leaf_Pkg", "3.0", "pkg:pypi/leaf-pkg@3.0", "indirect"),
    ]
    trivy = source_with(lang_result("poetry", "poetry.lock", packages))
    osv = {
        "source-development": osv_part(
            {"pkg:pypi/leaf-pkg@3.0": ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record(
                "GHSA-aaaa-aaaa-aaaa",
                aliases=["CVE-2030-1"],
                database_specific={"severity": "HIGH"},
                affected=[affected_range("PyPI", "leaf-pkg", {"fixed": "3.1"})],
            ),
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["pkg"] == "Leaf_Pkg"
    assert record["relationship"] == ["indirect"]
    assert record["introduced_via"] == ["web"]
    assert record["dependency_paths"] == [["web", "http", "Leaf_Pkg"]]
    assert record["dependency_paths_total"] == 1
    assert record["dev"] is False
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "<summary>Dependency paths (1)</summary>" in md
    assert "  - web › http › Leaf_Pkg" in md


def test_osv_only_dev_dependency_is_flagged(tmp_path: Path) -> None:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.0", "pkg:npm/lib@1.0", "direct", dev=True)],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record("GHSA-aaaa-aaaa-aaaa"),
        )
    }
    (record,) = merge_scan(tmp_path, trivy, osv, SOURCE).json(
        "_report/vulnerabilities.json"
    )["records"]
    assert record["dev"] is True


def test_the_same_vulnerability_in_two_osv_targets_is_one_record(
    tmp_path: Path,
) -> None:
    source = source_with(
        lang_result(
            "poetry",
            "poetry.lock",
            [lang_package("mako", "1.3.0", "pkg:pypi/mako@1.3.0")],
        )
    )["source-development"]
    image = image_native(
        lang_result(
            "python-pkg",
            "Python",
            [lang_package("Mako", "1.3.0", "pkg:pypi/mako@1.3.0")],
        )
    )
    vuln = osv_part(
        {"pkg:pypi/mako@1.3.0": ["GHSA-aaaa-aaaa-aaaa", "PYSEC-2030-1"]},
        osv_record("PYSEC-2030-1", aliases=["CVE-2030-1"]),
        osv_record("GHSA-aaaa-aaaa-aaaa", aliases=["CVE-2030-1"]),
    )
    ws = merge_scan(
        tmp_path,
        {"source-development": source, "app-development": image},
        {"source-development": vuln, "app-development": vuln},
        SOURCE,
        DEV,
    )
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["scanners"] == ["osv"]
    assert record["scan_targets"] == ["source-development", "app-development"]
    assert record["exposure"] == "development_only"
    # the image shows the package under its own spelling
    assert record["pkg"] == "Mako"
    assert record["ecosystem"] == ["poetry", "python-pkg"]


def test_osv_adds_a_target_to_the_record_trivy_found_elsewhere(
    tmp_path: Path,
) -> None:
    source = source_with(
        lang_result(
            "poetry",
            "poetry.lock",
            [lang_package("mako", "1.3.0", "pkg:pypi/mako@1.3.0")],
        )
    )["source-development"]
    image = image_native(
        lang_result(
            "python-pkg",
            "Python",
            [lang_package("Mako", "1.3.0", "pkg:pypi/mako@1.3.0")],
            [trivy_vuln("CVE-2030-1", "Mako", "1.3.0")],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:pypi/mako@1.3.0": ["PYSEC-2030-1"]},
            osv_record("PYSEC-2030-1", aliases=["CVE-2030-1"]),
        )
    }
    ws = merge_scan(
        tmp_path,
        {"source-development": source, "app-development": image},
        osv,
        SOURCE,
        DEV,
    )
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["scanners"] == ["osv", "trivy"]
    # Trivy saw it in the image, OSV in the source: the record is in both
    assert record["scan_targets"] == ["source-development", "app-development"]
    assert record["locations"] == ["Python", "poetry.lock"]
    assert record["relationship"] == []


def test_a_package_in_two_lockfiles_is_one_osv_record_with_both_locations(
    tmp_path: Path,
) -> None:
    lib = lang_package(
        "org.example:lib", "1.0", "pkg:maven/org.example/lib@1.0", "direct"
    )
    trivy = source_with(
        lang_result("gradle", "app/gradle.lockfile", [lib]),
        lang_result("gradle", "core/gradle.lockfile", [lib]),
    )
    osv = {
        "source-development": osv_part(
            {"pkg:maven/org.example/lib@1.0": ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record(
                "GHSA-aaaa-aaaa-aaaa",
                affected=[affected_range("Maven", "org.example:lib", {"fixed": "1.1"})],
            ),
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["locations"] == ["app/gradle.lockfile", "core/gradle.lockfile"]


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
    assert mr.merge_records("example/app", scans) == mr.merge_records(
        "example/app", scans, (), ()
    )


# ---- OSV results that do not fit the Trivy result


def test_osv_package_missing_in_the_trivy_result_fails_the_osv_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
            [trivy_vuln("CVE-2030-1", "lib", "1.0")],
        )
    )
    osv = {
        "source-development": osv_part(
            {
                "pkg:npm/lib@1.0": ["GHSA-aaaa-aaaa-aaaa"],
                "pkg:npm/gone@2.0": ["GHSA-b"],
            },
            osv_record("GHSA-aaaa-aaaa-aaaa", aliases=["CVE-2030-1"]),
            osv_record("GHSA-b"),
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE)
    entry = ws.osv_targets["source-development"]
    assert entry["status"] == "failed"
    assert entry["reason"] == (
        "osv result does not fit trivy's: 1 package(s) with findings are not in the "
        "trivy result of this target, first: npm gone@2.0"
    )
    assert entry["findings"] is None
    # nothing of the broken result is merged, the native stays for audit
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["scanners"] == ["trivy"]
    assert (ws.out / "_native" / "osv" / "source-development.json").is_file()
    assert "Incomplete: 1 target(s) failed" in (ws.out / "summary.md").read_text(
        "utf-8"
    )
    assert "::error title=Scan target failed::source-development (osv)" in (
        capsys.readouterr().out
    )


def test_osv_findings_without_a_trivy_result_fail_the_osv_target(
    tmp_path: Path,
) -> None:
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record("GHSA-aaaa-aaaa-aaaa"),
        )
    }
    ws = merge_scan(tmp_path, {}, osv, SOURCE)
    entry = ws.osv_targets["source-development"]
    assert entry["status"] == "failed"
    assert "there is no trivy result of this target" in entry["reason"]


def test_osv_packages_are_taken_from_language_results_only(tmp_path: Path) -> None:
    os_result = {
        "Target": "alpine",
        "Class": "os-pkgs",
        "Type": "alpine",
        "Packages": [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
    }
    ws = merge_scan(
        tmp_path,
        {"app-development": image_native(os_result)},
        {
            "app-development": osv_part(
                {"pkg:npm/lib@1.0": ["GHSA-aaaa-aaaa-aaaa"]},
                osv_record("GHSA-aaaa-aaaa-aaaa"),
            )
        },
        DEV,
    )
    assert ws.osv_targets["app-development"]["status"] == "failed"


def test_osv_results_without_findings_need_no_trivy_packages(tmp_path: Path) -> None:
    ws = merge_scan(
        tmp_path,
        source_with(),
        {"source-development": osv_part({"pkg:npm/lib@1.0": []})},
        SOURCE,
    )
    assert ws.osv_targets["source-development"]["status"] == "ok"


# ---- OSV-only in summary.md


def test_summary_marks_the_osv_only_vulnerability_and_counts_them(
    with_osv: Workspace,
) -> None:
    with_osv.run()
    md = plain((with_osv.out / "summary.md").read_text(encoding="utf-8"))
    assert (
        "[CVE-2030-0002](https://osv.dev/vulnerability/GHSA-aaaa-aaaa-0002) · OSV only"
        in md
    )
    assert (
        "[CVE-2030-0004](https://osv.dev/vulnerability/PYSEC-2030-1) · OSV only" in md
    )
    # a record Trivy has too is not marked
    assert "[CVE-2000-0001](https://example.invalid/CVE-2000-0001) |" in md
    assert md.count("OSV only") == 3
    assert "> 4/4 targets scanned · 3 found only by OSV" in md
    # OSV-only findings take part in the sections of the Trivy ones
    assert "| @scope/pkg | 1.0.0 → 1.0.1 |" in md
    assert (
        "| 2 | lodash 4.17.0 · npm | 1 LOW | runtime, indirect | express › lodash |"
        in md
    )
    assert "7.5 (osv)" in md


def test_summary_osv_only_pysec_id_is_shown_when_there_is_no_cve(
    tmp_path: Path,
) -> None:
    trivy = source_with(
        lang_result(
            "poetry",
            "poetry.lock",
            [lang_package("torch", "2.10.0", "pkg:pypi/torch@2.10.0", "direct")],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:pypi/torch@2.10.0": ["PYSEC-2026-139"]},
            osv_record("PYSEC-2026-139", summary="Torch issue"),
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE)
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert (
        "| [PYSEC-2026-139](https://osv.dev/vulnerability/PYSEC-2026-139) · OSV only |"
        in md
    )
    assert "Torch issue" in md
    assert "· 1 found only by OSV" in md


def test_osv_only_cvss4_vector_is_shown_without_a_score(tmp_path: Path) -> None:
    record = severity_of(tmp_path, severity=[{"type": "CVSS_V4", "score": VECTOR_V4}])
    assert mr.cvss_cell(record) == "v4.0 (osv)"
    assert mr.max_cvss_score([record]) is None
    higher = {**record, "cvss": {**record["cvss"], "score": 5.0}}
    assert mr.max_cvss_score([record, higher]) == 5.0
    assert mr.cvss_cell({**record, "cvss": None}) is None


def test_footer_names_the_osv_scope_without_a_query_time_when_none_was_queried(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, OSV_SOURCE))
    ws.add_part("source-development", "source")
    ws.run()
    footer = (
        (ws.out / "summary.md").read_text(encoding="utf-8").rstrip().splitlines()[-1]
    )
    assert footer == "<sub>OSV: language packages only</sub>"


def test_merge_with_osv_is_deterministic(tmp_path: Path) -> None:
    def build(name: str) -> dict[str, bytes]:
        (tmp_path / name).mkdir()
        ws = Workspace(tmp_path / name, make_targets_doc(SOURCE, DEV, REL, OSV_SOURCE))
        ws.add_part("source-development", "source-osv", lockfiles=3)
        ws.add_part("app-development", "app-development")
        ws.add_part("app-1.0.0", "app-1.0.0")
        ws.add_osv_part("source-development", "osv-source")
        ws.run()
        return {
            p.relative_to(ws.out).as_posix(): p.read_bytes()
            for p in sorted(ws.out.rglob("*"))
            if p.is_file()
        }

    assert build("a") == build("b")


def test_osv_only_title_falls_back_to_the_first_line_of_details(
    tmp_path: Path,
) -> None:
    long_line = "A very long first line of a PYSEC advisory. " * 4
    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.0", "pkg:npm/lib@1.0")],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.0": ["PYSEC-2030-1"]},
            osv_record("PYSEC-2030-1", details=f"\n  {long_line}\nsecond line\n"),
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    # the record keeps the full line, the summary truncates it
    assert record["title"] == long_line.strip()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert long_line.strip() not in md
    assert long_line[: mr.TITLE_MAX_LENGTH - 2] in md


@pytest.mark.parametrize(
    "fields",
    [{}, {"summary": "  "}, {"details": " \n "}, {"details": 5}, {"summary": 3}],
)
def test_osv_title_is_empty_without_a_summary_or_details(
    fields: dict[str, Any],
) -> None:
    assert mr.osv_title(osv_record("GHSA-a", **fields)) == ""


def test_osv_title_prefers_the_summary_to_the_details() -> None:
    record = osv_record("GHSA-a", summary=" Short ", details="Long\ntext")
    assert mr.osv_title(record) == "Short"


def test_target_count_and_record_agree_on_what_a_fix_is(tmp_path: Path) -> None:
    # fixed in 0.9 (another branch, below the installed 1.2) and nowhere else
    record = osv_record(
        "GHSA-aaaa-aaaa-aaaa",
        affected=[affected_range("npm", "lib", {"fixed": "0.9"})],
    )
    native = osv_part({"pkg:npm/lib@1.2": ["GHSA-aaaa-aaaa-aaaa"]}, record)
    key = (("npm", "lib"), "1.2")
    assert mr.osv_findings(native)[(key, ("GHSA-aaaa-aaaa-aaaa",))][1] is False
    # the same record at 0.5 has that fix above it
    native = osv_part({"pkg:npm/lib@0.5": ["GHSA-aaaa-aaaa-aaaa"]}, record)
    key = (("npm", "lib"), "0.5")
    assert mr.osv_findings(native)[(key, ("GHSA-aaaa-aaaa-aaaa",))][1] is True

    trivy = source_with(
        lang_result(
            "npm",
            "package-lock.json",
            [lang_package("lib", "1.2", "pkg:npm/lib@1.2")],
        )
    )
    osv = {
        "source-development": osv_part(
            {"pkg:npm/lib@1.2": ["GHSA-aaaa-aaaa-aaaa"]}, record
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE)
    (rec,) = ws.json("_report/vulnerabilities.json")["records"]
    entry = ws.osv_targets["source-development"]
    assert rec["fix_available"] is False
    assert entry["findings"]["fixable"] == 0


# ------------------------------------------------- OSV with the other additions
# Gradle graph (P1) and release sources (P2) apply to OSV-only records as to Trivy's


def test_osv_only_gradle_finding_gets_the_paths_of_the_gradle_graph(
    tmp_path: Path,
) -> None:
    purl = "pkg:maven/org.example/vuln@1.0"
    ws = gradle_workspace(tmp_path)
    native_path = ws.trivy_parts / "source-development.json"
    native = json.loads(native_path.read_text(encoding="utf-8"))
    for result in native["Results"]:
        result.pop("Vulnerabilities")  # Trivy knows nothing, OSV does
        for package in result["Packages"]:
            package["Identifier"]["PURL"] = purl.replace("vuln", package["Name"][12:])
    native_path.write_text(json.dumps(native), encoding="utf-8")
    original = native_path.read_bytes()
    doc = json.loads(ws.targets_file.read_text(encoding="utf-8"))
    doc["targets"].append({**doc["targets"][0], "scanner": "osv"})
    ws.targets_file.write_text(json.dumps(doc), encoding="utf-8")
    write_osv_native(
        ws,
        osv_part(
            {purl: ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record(
                "GHSA-aaaa-aaaa-aaaa",
                aliases=["CVE-2030-1"],
                database_specific={"severity": "HIGH"},
                affected=[
                    affected_range("Maven", "org.example:vuln", {"fixed": "1.1"})
                ],
            ),
        ),
    )
    assert ws.run() == 0
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["scanners"] == ["osv"]
    # the same relationship and chains as a Trivy finding of the module would get
    assert record["relationship"] == ["direct", "indirect"]
    assert record["dependency_paths"] == [
        ["org.example:vuln"],
        ["org.example:util", "org.example:vuln"],
        ["org.example:web", "org.example:core", "org.example:vuln"],
    ]
    assert record["introduced_via"] == ["org.example:util", "org.example:web"]
    # the enrichment is in memory: the native copy stays as Trivy wrote it
    assert (ws.out / "_native" / "trivy" / "source-development.json").read_bytes() == (
        original
    )
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "· OSV only" in md


def release_osv_workspace(
    tmp_path: Path, trivy_ids: tuple[str, ...], osv_ids: tuple[str, ...], *targets
) -> Workspace:
    """Targets without findings of their own, a poetry package ``leaf`` in the
    lockfile of every id of ``trivy_ids`` and an OSV finding of it in every id of
    ``osv_ids`` (the OSV twins of the same targets).
    """
    purl = "pkg:pypi/leaf@1.0"
    lock = source_with(
        lang_result(
            "poetry",
            "poetry.lock",
            [lang_package("leaf", "1.0", purl, "direct")],
        )
    )["source-development"]
    trivy = {
        t["id"]: lock if t["id"] in trivy_ids else {"Results": []} for t in targets
    }
    finding = osv_part(
        {purl: ["GHSA-aaaa-aaaa-aaaa"]},
        osv_record(
            "GHSA-aaaa-aaaa-aaaa",
            aliases=["CVE-2030-1"],
            database_specific={"severity": "HIGH"},
            affected=[affected_range("PyPI", "leaf", {"fixed": "1.1"})],
        ),
    )
    osv = {tid: finding for tid in osv_ids}
    return merge_scan(tmp_path, trivy, osv, *targets)


def test_osv_only_finding_in_a_release_source_is_source_only_with_images(
    tmp_path: Path,
) -> None:
    ws = release_osv_workspace(
        tmp_path,
        ("source-1.0.0",),
        ("source-1.0.0",),
        SOURCE,
        RELEASE_SOURCE,
        DEV,
        REL,
    )
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["scanners"] == ["osv"]
    assert record["scan_targets"] == ["source-1.0.0"]
    # P2 rules: the images decide, a release source never makes a release finding
    assert record["exposure"] == "source_only"
    assert record["dependency_paths"] == [["leaf"]]
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert (
        "> **No known vulnerabilities in 1.0.0 and development "
        "— 1 only in build / test dependencies**" in md
    )
    assert "OSV only" in md
    # the OSV twin of the release source is a row of its own in the coverage
    assert "source @ 1.0.0 0011223" in md


@pytest.mark.parametrize(
    ("osv_ids", "exposure", "verdict"),
    [
        (
            ("source-1.0.0",),
            "release_only",
            "Release a patch from release-1.0 — 1 HIGH already fixed in development",
        ),
        (
            ("source-development", "source-1.0.0"),
            "release_and_development",
            "Fix 1 HIGH in development and backport to release-1.0",
        ),
        (
            ("source-development",),
            "development_only",
            "Fix 1 HIGH in development before the next release",
        ),
    ],
)
def test_osv_only_finding_without_images_is_classified_by_the_sources(
    tmp_path: Path, osv_ids: tuple[str, ...], exposure: str, verdict: str
) -> None:
    ws = release_osv_workspace(tmp_path, osv_ids, osv_ids, SOURCE, RELEASE_SOURCE)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["scanners"] == ["osv"]
    assert record["scan_targets"] == list(reversed(osv_ids)) or record[
        "scan_targets"
    ] == list(osv_ids)
    assert record["exposure"] == exposure
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert md.split("\n")[2] == f"> **{verdict}**"


def test_osv_and_trivy_findings_of_a_release_source_are_one_record(
    tmp_path: Path,
) -> None:
    purl = "pkg:pypi/leaf@1.0"
    package = lang_package("leaf", "1.0", purl, "direct")
    result = lang_result(
        "poetry",
        "poetry.lock",
        [package],
        [vuln("CVE-2030-1", "1.1", PkgName="leaf", InstalledVersion="1.0")],
    )
    trivy = {
        "source-development": {"Results": []},
        "source-1.0.0": {"Results": [result]},
    }
    osv = {
        "source-1.0.0": osv_part(
            {purl: ["GHSA-aaaa-aaaa-aaaa"]},
            osv_record("GHSA-aaaa-aaaa-aaaa", aliases=["CVE-2030-1"]),
        )
    }
    ws = merge_scan(tmp_path, trivy, osv, SOURCE, RELEASE_SOURCE)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["scanners"] == ["osv", "trivy"]
    assert record["scan_targets"] == ["source-1.0.0"]
    assert record["exposure"] == "release_only"
    assert record["aliases"] == ["GHSA-aaaa-aaaa-aaaa"]


# ---------------------------------------------------------------- summary: base image


def os_native(
    family: str, release: str, *vulns: dict[str, Any], lang: Any = None
) -> dict[str, Any]:
    """An image result: its OS, the OS packages with findings, a language result."""
    packages = {(v["PkgName"], v["InstalledVersion"]) for v in vulns}
    result = {
        "Target": f"{family} {release}",
        "Class": "os-pkgs",
        "Type": family,
        "Packages": [
            {"ID": f"{n}@{v}", "Name": n, "Version": v} for n, v in sorted(packages)
        ],
        "Vulnerabilities": list(vulns),
    }
    results = [result] if lang is None else [lang, result]
    return {"Metadata": {"OS": {"Family": family, "Name": release}}, "Results": results}


def os_vuln(
    cve: str,
    name: str,
    installed: str,
    fixed: str | None,
    severity: str = "MEDIUM",
) -> dict[str, Any]:
    body = trivy_vuln(cve, name, installed, severity)
    if fixed:
        body["FixedVersion"] = fixed
        body["Status"] = "fixed"
    return body


def leaf_lang_result() -> dict[str, Any]:
    package = lang_package("leaf", "1.0", "pkg:pypi/leaf@1.0", "direct")
    finding = trivy_vuln("CVE-2030-1", "leaf", "1.0", "HIGH", FixedVersion="1.1")
    return lang_result("poetry", "poetry.lock", [package], [finding])


def test_os_packages_have_a_column_of_their_own_in_the_scope_table(
    tmp_path: Path,
) -> None:
    image = os_native(
        "ubuntu",
        "24.04",
        os_vuln("CVE-A", "openssl", "3.0.0", "3.0.1", "HIGH"),
        os_vuln("CVE-B", "openssl", "3.0.0", "3.0.1", "LOW"),
        os_vuln("CVE-C", "zlib", "1.2", "1.3"),
        os_vuln("CVE-D", "libfoo", "1.0", None, "LOW"),
        lang=leaf_lang_result(),
    )
    trivy = {"app-development": image, "app-1.0.0": image}
    ws = merge_scan(tmp_path, trivy, {}, DEV, REL)
    md = plain((ws.out / "summary.md").read_text(encoding="utf-8"))
    # the headline counts them, in a column of their own
    assert "> | 1.0.0 (released) | 0 | 2 | 1 | 2 | 4 | 4 |" in md


def test_os_packages_without_a_fix_are_watched_apart_from_the_dependencies(
    tmp_path: Path,
) -> None:
    image = os_native(
        "ubuntu",
        "24.04",
        os_vuln("CVE-D", "libfoo", "1.0", None, "HIGH"),
        lang=leaf_lang_result(),
    )
    ws = merge_scan(tmp_path, {"app-development": image}, {}, DEV)
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    # no dependency without a fix, so no watch section of dependencies, even
    # though the OS package is HIGH: the base image part is always collapsed
    assert "## No fix available — watch" not in md
    assert (
        "<details>\n<summary>No fix available — base image (OS packages) (1)"
        "</summary>\n\n| # | Package | Severity | Exposure | Suggested |" in md
    )
    assert (
        "| 1 | libfoo 1.0 | 1 HIGH | development only "
        "| Wait for a distribution fix or change the base image; "
        "re-check on next scan |" in md
    )


def test_dependency_and_os_watch_blocks_are_separate(tmp_path: Path) -> None:
    unfixed = lang_result(
        "poetry",
        "poetry.lock",
        [lang_package("leaf", "1.0", "pkg:pypi/leaf@1.0", "direct")],
        [trivy_vuln("CVE-2030-2", "leaf", "1.0", "CRITICAL")],
    )
    image = os_native(
        "alpine", "3.20", os_vuln("CVE-D", "libfoo", "1.0", None), lang=unfixed
    )
    ws = merge_scan(tmp_path, {"app-development": image}, {}, DEV)
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    watch = md.split("## No fix available — watch")[1]
    dependencies = watch.split("<details>")[0]
    assert "leaf 1.0" in dependencies and "libfoo" not in dependencies
    assert "libfoo 1.0" in watch.split("<summary>No fix available — base image")[1]


def test_findings_by_severity_keep_the_os_packages_in_one_collapsed_block(
    tmp_path: Path,
) -> None:
    image = os_native(
        "alpine",
        "3.20",
        os_vuln("CVE-A", "zlib", "1.2", "1.3", "HIGH"),
        os_vuln("CVE-B", "zlib", "1.2", "1.3", "LOW"),
        lang=leaf_lang_result(),
    )
    ws = merge_scan(tmp_path, {"app-development": image}, {}, DEV)
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    dependencies, base = md.split("<summary>Base image (OS packages) (2)</summary>")
    # the dependency sections count dependencies only
    assert "<details open>\n<summary>HIGH (1)</summary>" in dependencies
    assert "CVE-A" not in dependencies.split("<summary>HIGH (1)</summary>")[1]
    assert "<summary>LOW" not in dependencies
    # the block of the OS packages holds a section per severity
    block = base.split("<summary>Scan coverage</summary>")[0]
    assert "<summary>HIGH (1)</summary>" in block and "CVE-A" in block
    assert "<summary>LOW (1)</summary>" in block and "CVE-B" in block
    assert md.count("<summary>Base image (OS packages)") == 1


def test_summary_without_os_packages_has_no_base_image_blocks(tmp_path: Path) -> None:
    lock = source_with(leaf_lang_result())["source-development"]
    ws = merge_scan(tmp_path, {"source-development": lock}, {}, SOURCE)
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "## What to fix" not in md
    assert "Base image packages" not in md
    assert "Base image (OS packages)" not in md


def test_base_image_findings_have_no_dependency_paths(tmp_path: Path) -> None:
    image = os_native("alpine", "3.20", os_vuln("CVE-A", "zlib", "1.2", "1.3"))
    ws = merge_scan(tmp_path, {"app-development": image}, {}, DEV)
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "Dependency paths" not in md


# ---------------------------------------------------------------- summary: coverage


def test_coverage_has_a_row_per_subject_and_a_cell_per_scanner(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, OSV_SOURCE, DEV))
    ws.add_part("source-development", None)
    (ws.trivy_parts / "source-development.json").write_text(
        json.dumps(PACKAGES_NATIVE_CLEAN), encoding="utf-8"
    )
    ws.add_part("app-development", None, status="failed", reason="no registry access")
    ws.add_osv_part("source-development", None, status="failed", reason="api down")
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert (
        "| Target | Trivy | OSV | Note |\n|---|---|---|---|\n"
        "| source @ development fedcba9 | ok · 2 pkgs · 0/0/0/0 "
        "| failed · api down | - |\n"
        "| image :development | failed · no registry access | — | - |" in md
    )


def test_coverage_shows_unknown_findings_of_a_target(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(DEV))
    ws.add_part("app-development", None)
    native = native_with(vuln("CVE-1", None, Severity="SOMETHING"))
    (ws.trivy_parts / "app-development.json").write_text(
        json.dumps(native), encoding="utf-8"
    )
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "| image :development | ok · 0 pkgs · 0/0/0/0 · 1 UNKNOWN |" in md


# ------------------------------------------------------- upgrade_to: fixed in place


def jar(name: str, version: str, path: str = "app.jar/lib/x.jar") -> dict[str, Any]:
    return {
        "ID": f"{name}:{version}",
        "Name": name,
        "Version": version,
        "FilePath": path,
    }


MSSQL = "com.microsoft.sqlserver:mssql-jdbc"
MSSQL_FIXES = "10.2.4.jre11, 12.10.2.jre11, 13.2.1.jre11"


def jar_image(*packages: dict[str, Any]) -> dict[str, Any]:
    finding = trivy_vuln(
        "CVE-2025-59250",
        MSSQL,
        "12.10.2",
        "HIGH",
        FixedVersion=MSSQL_FIXES,
        PkgPath="app.jar/lib/x.jar",
    )
    result = {
        "Target": "Java",
        "Class": "lang-pkgs",
        "Type": "jar",
        "Packages": list(packages),
        "Vulnerabilities": [finding],
    }
    return {"Results": [result]}


def test_a_jar_listed_under_the_fixed_version_too_needs_no_upgrade(
    tmp_path: Path,
) -> None:
    # Trivy lists the file under the version of its manifest and under the one of
    # its POM; the advisory matches the first, the second is the fix
    image = jar_image(jar(MSSQL, "12.10.2"), jar(MSSQL, "12.10.2.jre11"))
    ws = merge_scan(tmp_path, {"app-development": image}, {}, DEV)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["fix_available"] is True
    assert record["upgrade_to"] is None
    assert record["fixed_versions"] == ["10.2.4.jre11", "12.10.2.jre11", "13.2.1.jre11"]
    md = plain((ws.out / "summary.md").read_text(encoding="utf-8"))
    # no wrong upgrade
    assert "| 12.10.2 → 12.10.2.jre11 |" not in md
    assert "Upgrade in development" not in md
    # the record still counts in the table, but makes no action of the verdict
    assert "> **No known vulnerabilities in development**" in md
    assert "> | development | 0 | 1 | 0 | 0 | 1 | 0 |" in md


def test_the_same_jar_without_the_other_listing_is_upgraded_as_usual(
    tmp_path: Path,
) -> None:
    image = jar_image(jar(MSSQL, "12.10.2"))
    ws = merge_scan(tmp_path, {"app-development": image}, {}, DEV)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["upgrade_to"] == "12.10.2.jre11"


@pytest.mark.parametrize(
    "other",
    [
        jar(MSSQL, "12.10.2.jre11", "app.jar/lib/other.jar"),  # another file
        jar(MSSQL, "12.10.1.jre11"),  # not a fix
        jar("other:lib", "12.10.2.jre11"),  # another package
    ],
)
def test_only_the_same_package_in_the_same_file_counts_as_the_fix(
    tmp_path: Path, other: dict[str, Any]
) -> None:
    image = jar_image(jar(MSSQL, "12.10.2"), other)
    ws = merge_scan(tmp_path, {"app-development": image}, {}, DEV)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["upgrade_to"] == "12.10.2.jre11"


def test_a_lockfile_has_no_other_versions_of_a_package_in_its_file() -> None:
    packages = [
        {"Name": "a", "Version": "1.0"},  # no FilePath
        {"Name": "a", "Version": "1.1"},
    ]
    index = mr.PackageIndex(packages, "npm")
    assert index.other_versions_in_file(packages[0]) == []
    assert mr.fixed_in_place([packages[0]], ["1.1"], index) is False


def test_fixed_in_place_needs_a_package_and_a_comparable_fix() -> None:
    packages = [jar("a", "1.0"), jar("a", "1.2")]
    index = mr.PackageIndex(packages, "jar")
    assert mr.fixed_in_place([packages[0]], ["1.1"], index) is True  # 1.2 is above
    assert mr.fixed_in_place([packages[0]], ["1.2"], index) is True
    assert mr.fixed_in_place([packages[0]], ["1.3"], index) is False
    assert mr.fixed_in_place([packages[0]], ["abc"], index) is False  # incomparable
    assert mr.fixed_in_place([packages[0]], [], index) is False
    assert mr.fixed_in_place([], ["1.1"], index) is False


def test_a_record_needs_the_fix_in_place_in_every_sighting(tmp_path: Path) -> None:
    # shipped twice, in one image with the fixed listing next to it and in the other
    # without: the second one still has to be upgraded
    fixed = jar_image(jar(MSSQL, "12.10.2"), jar(MSSQL, "12.10.2.jre11"))
    plain = jar_image(jar(MSSQL, "12.10.2"))
    trivy = {"app-development": fixed, "app-1.0.0": plain}
    ws = merge_scan(tmp_path, trivy, {}, DEV, REL)
    (record,) = ws.json("_report/vulnerabilities.json")["records"]
    assert record["upgrade_to"] == "12.10.2.jre11"


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
    mr.assign_upgrades(records, {("CVE-1", "lib", "1.0")})
    assert [r["upgrade_to"] for r in records] == [None, "2.0"]
    mr.assign_upgrades(records)
    assert [r["upgrade_to"] for r in records] == ["2.0", "2.0"]


def test_fixed_versions_text_names_the_fixes_above_the_installed_version() -> None:
    fixes = ["2.0.1", "1.9", "1.0", "3.1", "2.5"]
    assert mr.fixed_versions_text(fixes) == "1.0, 1.9, 2.0.1 +2 more"
    assert mr.fixed_versions_text(fixes, "2.0") == "2.0.1, 2.5, 3.1"
    # nothing above it, or nothing comparable: all of them
    assert mr.fixed_versions_text(["1.0", "1.1"], "2.0") == "1.0, 1.1"
    assert mr.fixed_versions_text(["abc", "def"], "1.0") == "abc, def"
    assert mr.fixed_versions_text([]) == ""


# --- the safety of the output ---------------------------------------------------


def test_md_cell_leaves_no_link_image_or_code_span_to_an_outside_text() -> None:
    cell = mr.md_cell("[x](https://e.invalid) ![i](u) `c` a|b <b>")
    assert plain(cell) == "[x](https://e.invalid) ![i](u) `c` a|b &lt;b&gt;"
    for char in "[]()!`|":
        assert all(
            cell[i - 1] == "\\" for i, c in enumerate(cell) if c == char and i > 0
        )
    assert mr.md_cell("a\r\nb") == "a  b"
    assert mr.md_cell(None) == "-"


def test_md_link_is_a_link_that_md_cell_keeps() -> None:
    link = mr.md_link("CVE-1 [x]", "https://e.invalid/a(b) c")
    assert link == "[CVE-1 \\[x\\]](https://e.invalid/a%28b%29%20c)"
    assert mr.md_cell(link) == link
    joined = mr.md_join(", ", [link, "[plain](u)"])
    assert mr.md_cell(joined).endswith(", \\[plain\\]\\(u\\)")


def test_command_data_is_escaped() -> None:
    assert mr.escape_command_data("a%b\r\nc") == "a%25b%0D%0Ac"


def test_a_target_reason_cannot_forge_a_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE))
    ws.add_part("source-development", None, status="failed", reason="a%b\n::error::x")
    assert ws.run() == 1
    lines = capsys.readouterr().out.splitlines()
    (failed,) = [line for line in lines if "Scan target failed" in line]
    assert failed.endswith("a%25b%0A::error::x")
    assert not any(line.startswith("::error::x") for line in lines)


# --- the step summary limit -----------------------------------------------------


def test_a_summary_that_fits_is_written_as_it_is() -> None:
    assert mr.truncate_summary("# SCA\n", None) == "# SCA\n"


def test_a_summary_over_the_limit_is_cut_with_a_note_and_open_blocks_are_closed() -> (
    None
):
    row = "| " + "x" * 100 + " |\n"
    text = "# SCA\n\n<details>\n<summary>big</summary>\n\n" + row * 20000
    assert len(text.encode()) > mr.STEP_SUMMARY_LIMIT_BYTES
    cut = mr.truncate_summary(text, "https://github.com/o/r/actions/runs/1#artifacts")
    assert len(cut.encode()) <= mr.STEP_SUMMARY_LIMIT_BYTES
    assert cut.count("<details>") == cut.count("</details>")
    assert "The summary is cut" in cut
    assert "[this run](https://github.com/o/r/actions/runs/1#artifacts)" in cut
    assert cut.startswith("# SCA")


def test_main_writes_a_cut_summary_to_the_step_summary_and_keeps_the_file(
    full: Workspace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mr, "STEP_SUMMARY_LIMIT_BYTES", 400)
    step = tmp_path / "step.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step))
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_RUN_ID", "7")
    assert mr.main(cli_args(full)) == 0
    whole = (full.out / "summary.md").read_text(encoding="utf-8")
    written = step.read_text(encoding="utf-8")
    assert len(whole.encode()) > 400
    assert len(written.encode()) <= 400
    assert "https://github.com/o/r/actions/runs/7#artifacts" in written


# --- the freshness of the Trivy DB ------------------------------------------------


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
    assert mr.trivy_db_stale_days(db, "2030-01-04T00:00:00Z") == stale


def test_a_stale_db_is_a_line_of_the_report_and_a_warning_and_not_a_failure(
    full: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    old = {"vulnerability_db_updated_at": "2020-01-01T06:00:00Z"}
    assert mr.main(cli_args(full, "--trivy-db-info", json.dumps(old))) == 0
    assert "::warning title=Trivy DB is stale::" in capsys.readouterr().out
    md = (full.out / "summary.md").read_text(encoding="utf-8")
    assert "DB vuln 2020-01-01 06:00Z" in md
    assert " days old" in md


def test_a_fresh_db_has_no_warning(
    full: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    assert mr.main(cli_args(full, "--trivy-db-info", json.dumps(DB_INFO))) == 0
    assert "stale" not in capsys.readouterr().out


# --- the packages that osv-scanner did not read --------------------------------


def test_unread_osv_packages_are_in_the_entry_and_the_coverage_note() -> None:
    target = {"id": "t", "scanner": "osv"}
    state = {"status": "ok", "reason": None, "packages_unread": 3}
    native = {"results": []}
    assert mr.build_target_entry(target, state, native)["packages_unread"] == 3
    ok = {"status": "ok", "packages_unread": 3}
    assert mr.unread_note(ok) == "OSV did not read 3 package(s)"
    assert mr.unread_note({"status": "ok", "packages_unread": 0}) is None
    assert mr.unread_note({"status": "failed", "packages_unread": 3}) is None
    assert mr.unread_note(None) is None
