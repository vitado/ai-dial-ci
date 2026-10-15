"""The SCA merge: target statuses, report.json, the native copies, the CLI."""

import json
from pathlib import Path

import pytest
from merge_results import count_packages, main, run_merge

DB = {"vulnerability_db_updated_at": "2026-10-13T06:41:11Z", "java_db_updated_at": None}

VULN = {
    "VulnerabilityID": "CVE-2026-1",
    "PkgName": "a",
    "PkgID": "a@1",
    "InstalledVersion": "1",
    "Severity": "HIGH",
    "FixedVersion": "2",
}


def trivy_native(vulns=(), packages=None):
    if packages is None:
        packages = [
            {"ID": "a@1", "Name": "a", "Version": "1", "Relationship": "direct"}
        ]
    return {
        "Trivy": {"Version": "0.75.0"},
        "Metadata": {"RepoDigests": ["ghcr.io/o/app@sha256:abc"]},
        "Results": [
            {
                "Target": "package-lock.json",
                "Type": "npm",
                "Class": "lang-pkgs",
                "Packages": packages,
                "Vulnerabilities": list(vulns),
            }
        ],
    }


def osv_native():
    entry = {
        "package": {"name": "a", "version": "1", "ecosystem": "npm"},
        "vulnerabilities": [
            {"id": "GHSA-x", "database_specific": {"severity": "HIGH"}}
        ],
        "groups": [{"ids": ["GHSA-x"], "aliases": ["CVE-2026-1"]}],
    }
    return {"results": [{"packages": [entry]}]}


def target(tid, scanner, kind="fs", status="pending", reason=None):
    return {
        "id": tid,
        "scanner": scanner,
        "kind": kind,
        "image": "o/app" if kind == "image" else None,
        "tag": None,
        "ref": None,
        "git_ref": "development" if kind == "fs" else None,
        "commit_sha": "0123456789abcdef" if kind == "fs" else None,
        "status": status,
        "reason": reason,
    }


class Run:
    """A targets file and a parts directory in a temp directory."""

    def __init__(self, tmp_path: Path, targets):
        self.parts, self.out = tmp_path / "parts", tmp_path / "out"
        self.targets_file = tmp_path / "targets.json"
        self.targets_file.write_text(
            json.dumps(
                {
                    "repo": "o/app",
                    "default_branch": "development",
                    "commit_sha": "0123456789abcdef",
                    "run_id": "1",
                    "run_url": "https://example.test/run/1",
                    "targets": targets,
                }
            )
        )

    def part(self, scanner, tid, native=None, status=None):
        folder = self.parts / scanner
        folder.mkdir(parents=True, exist_ok=True)
        if native is not None:
            (folder / f"{tid}.json").write_text(json.dumps(native))
            (folder / f"{tid}.txt").write_text("table")
        if status is not None:
            (folder / f"{tid}.status.json").write_text(json.dumps(status))

    def merge(self):
        run_merge(self.targets_file, self.parts, self.out, "2026-10-14T00:00:00Z", DB)
        report = json.loads((self.out / "report.json").read_text(encoding="utf-8"))
        failed = sum(t["status"] == "failed" for t in report["targets"])
        return failed, report


def entry(report, tid, scanner="trivy"):
    return next(
        t for t in report["targets"] if t["id"] == tid and t["scanner"] == scanner
    )


def test_report_has_targets_tools_and_one_finding_per_scanner_and_vulnerability(
    tmp_path,
):
    run = Run(
        tmp_path,
        [target("source-development", "trivy"), target("source-development", "osv")],
    )
    run.part("trivy", "source-development", trivy_native([VULN]), {"status": "ok"})
    osv_status = {
        "status": "ok",
        "queried_at": "2026-10-13T11:33:23Z",
        "scanner_version": "2.6.0",
    }
    run.part("osv", "source-development", osv_native(), osv_status)
    failed, report = run.merge()
    assert failed == 0 and report["schema_version"] == 2
    assert report["tools"] == {
        "trivy": "0.75.0",
        "trivy_db": DB["vulnerability_db_updated_at"],
        "trivy_java_db": None,
        "osv_scanner": "2.6.0",
        "osv_queried_at": "2026-10-13T11:33:23Z",
    }
    assert entry(report, "source-development") == {
        "id": "source-development",
        "scanner": "trivy",
        "kind": "fs",
        "ref": "development",
        "commit_sha": "0123456789abcdef",
        "image": None,
        "image_digest": None,
        "status": "ok",
        "reason": None,
        "packages_scanned": 1,
    }
    assert [(f["scanner"], f["id"], f["aliases"]) for f in report["findings"]] == [
        ("trivy", "CVE-2026-1", []),
        ("osv", "CVE-2026-1", ["GHSA-x"]),
    ]
    assert report["findings"][1]["chain"] == ["a"]  # from the Trivy inventory
    native = tmp_path / "out" / "_native" / "trivy"
    assert (native / "source-development.txt").read_text() == "table"
    summary = (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")
    assert "CVE-2026-1" in summary


def test_image_digest_is_taken_from_the_native_result(tmp_path):
    run = Run(tmp_path, [target("app-development", "trivy", "image")])
    run.part("trivy", "app-development", trivy_native(), {"status": "ok"})
    digest = entry(run.merge()[1], "app-development")["image_digest"]
    assert digest == "ghcr.io/o/app@sha256:abc"


@pytest.mark.parametrize(
    ("status", "native", "reason"),
    [
        (None, None, "produced no result"),
        ({"status": "failed", "reason": "boom"}, None, "boom"),
        ({"status": "weird"}, None, "unexpected scan status"),
        ({"status": "ok"}, None, "result file is missing"),
        ({"status": "ok"}, [], "not a JSON object"),
    ],
)
def test_a_broken_scan_is_failed_and_never_clean(tmp_path, status, native, reason):
    run = Run(tmp_path, [target("source-development", "trivy")])
    run.part("trivy", "source-development", native, status)
    failed, report = run.merge()
    assert failed == 1
    assert entry(report, "source-development")["status"] == "failed"
    assert reason in entry(report, "source-development")["reason"]
    assert report["findings"] == []


def test_an_unreadable_native_file_is_failed(tmp_path):
    run = Run(tmp_path, [target("source-development", "trivy")])
    run.part("trivy", "source-development", None, {"status": "ok"})
    (run.parts / "trivy" / "source-development.json").write_text("{broken")
    assert run.merge()[0] == 1


def test_an_osv_result_of_an_unexpected_shape_is_failed(tmp_path):
    run = Run(tmp_path, [target("s", "trivy"), target("s", "osv")])
    run.part("trivy", "s", trivy_native([VULN]), {"status": "ok"})
    run.part("osv", "s", {"unexpected": True}, {"status": "ok"})
    failed, report = run.merge()
    assert failed == 1 and entry(report, "s", "osv")["status"] == "failed"
    assert [f["scanner"] for f in report["findings"]] == ["trivy"]


def test_not_applicable_is_kept_and_is_not_a_failure(tmp_path):
    run = Run(
        tmp_path,
        [
            target("s", "trivy", status="not_applicable", reason="not published"),
            target(
                "s",
                "osv",
                status="not_applicable",
                reason="trivy target not_applicable",
            ),
            target("t", "trivy"),
            target("t", "osv"),
        ],
    )
    run.part("trivy", "t", trivy_native(), {"status": "ok"})
    run.part(
        "osv", "t", None, {"status": "not_applicable", "reason": "nothing to scan"}
    )
    failed, report = run.merge()
    assert failed == 0
    assert entry(report, "s")["status"] == "not_applicable"
    assert entry(report, "t", "osv")["reason"] == "nothing to scan"


def test_zero_packages_is_reported_as_suspicious(tmp_path, capsys):
    run = Run(tmp_path, [target("s", "trivy")])
    run.part("trivy", "s", trivy_native(packages=[]), {"status": "ok"})
    _, report = run.merge()
    assert entry(report, "s")["packages_scanned"] == 0
    assert "No packages in scan result" in capsys.readouterr().out


def test_main_appends_the_summary_and_writes_the_failed_count(tmp_path, monkeypatch):
    run = Run(tmp_path, [target("s", "trivy")])  # no part: the scan produced nothing
    summary, output = tmp_path / "step.md", tmp_path / "output"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    argv = [
        "--targets-file",
        str(run.targets_file),
        "--parts-dir",
        str(run.parts),
        "--output-dir",
        str(run.out),
    ]
    main(argv)
    assert output.read_text() == "failed-count=1\n"
    assert "# SCA · o/app" in summary.read_text(encoding="utf-8")


def test_a_package_of_two_ecosystems_counts_twice():
    pkg = {"Name": "a", "Version": "1"}
    results = [{"Type": t, "Packages": [pkg]} for t in ("npm", "pip")]
    assert count_packages("trivy", {"Results": results}) == 2
    entry = {"package": {"name": "a", "version": "1"}}
    packages = [
        {"package": {**entry["package"], "ecosystem": e}} for e in ("npm", "PyPI")
    ]
    assert count_packages("osv", {"results": [{"packages": packages}]}) == 2
