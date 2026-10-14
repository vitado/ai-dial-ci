"""summary.md of the SCA merge."""

import pytest
from summary import (
    STEP_SUMMARY_LIMIT_BYTES,
    build_summary,
    target_label,
    truncate_summary,
)


def target(
    tid,
    scanner="trivy",
    kind="fs",
    ref="development",
    status="ok",
    reason=None,
    packages=10,
):
    return {
        "id": tid,
        "scanner": scanner,
        "kind": kind,
        "ref": ref,
        "commit_sha": "0123456789abcdef" if kind == "fs" else None,
        "image": "o/app" if kind == "image" else None,
        "image_digest": None,
        "status": status,
        "reason": reason,
        "packages_scanned": packages if status == "ok" else None,
    }


def finding(
    tid, vid, pkg, severity="HIGH", scanner="trivy", cls="lang", fixed="", **extra
):
    return {
        "target": tid,
        "scanner": scanner,
        "id": vid,
        "aliases": [],
        "pkg": pkg,
        "version": "1.3" if cls == "os" else "1.0",
        "ecosystem": "npm",
        "class": cls,
        "locations": ["web/package-lock.json"] if cls == "lang" else [],
        "severity": severity,
        "fixed_version": fixed,
        "dev": False,
        "relationship": None,
        "chain": [],
        "title": "",
        "url": f"https://example.test/{vid}",
        **extra,
    }


def report(targets, findings):
    return {
        "schema_version": 2,
        "repo": "o/app",
        "commit_sha": "0123456789abcdef",
        "default_branch": "development",
        "run_id": "7",
        "run_url": "https://example.test/run/7",
        "generated_utc": "2026-10-14T00:00:00Z",
        "run_kind": "full",
        "run_kind_reasons": [],
        "tools": {
            "trivy": "0.75.0",
            "trivy_db": "2026-10-13T06:41:11.5Z",
            "trivy_java_db": None,
            "osv_scanner": "2.6.0",
            "osv_queried_at": "2026-10-13T11:33:23Z",
        },
        "targets": targets,
        "findings": findings,
    }


def sample():
    src = "source-development"
    lib = {"dev": True}
    targets = [
        target(src),
        target(src, "osv"),
        target("app-1.0", kind="image", ref="1.0", packages=50),
        target(
            "app-1.0",
            "osv",
            kind="image",
            ref="1.0",
            status="failed",
            reason="rate limited",
        ),
        target(
            "app-2.0",
            kind="image",
            ref="2.0",
            status="not_applicable",
            reason="not published",
        ),
    ]
    findings = [
        finding(
            src, "CVE-1", "lib", "CRITICAL", fixed="2.0", chain=["top", "lib"], **lib
        ),
        finding(src, "CVE-2", "lib", "LOW", scanner="osv", fixed="2.1", **lib),
        finding(src, "CVE-1", "lib", "HIGH", scanner="osv", **lib),
        finding(
            src, "CVE-3", "other", "MEDIUM", relationship="direct", chain=["other"]
        ),
        finding("app-1.0", "CVE-3", "other", "MEDIUM"),
        finding("app-1.0", "CVE-4", "zlib", "HIGH", cls="os", fixed="1.4"),
    ]
    return report(targets, findings)


def line(text, prefix):
    return next(row for row in text.splitlines() if row.startswith(prefix))


@pytest.mark.parametrize(
    "repo, image, ref, label",
    [
        ("ai-dial-chat", "ai-dial-chat-bff", "development", "img·bff·dev"),
        (
            "statgpt-backend",
            "statgpt-admin-backend",
            "development",
            "img·statgpt-admin-backend·dev",
        ),
        ("app", "app", "development", "img·dev"),
        ("app", "o/app", "1.0", "img·1.0"),
    ],
)
def test_image_label_drops_the_repo_prefix_only_when_it_is_one(repo, image, ref, label):
    t = {"kind": "image", "image": image, "ref": ref}
    assert target_label(t, repo) == label


def test_packages_differing_in_case_are_one_row_named_as_in_the_source():
    src = "source-development"
    targets = [target(src), target("app-1.0", kind="image", ref="1.0")]
    findings = [
        finding("app-1.0", "CVE-1", "PyJWT", severity="HIGH"),
        finding(src, "CVE-1", "pyjwt", scanner="osv", severity="HIGH"),
        finding("app-1.0", "CVE-2", "Mako"),
        finding(src, "CVE-3", "mako", severity="LOW"),
    ]
    text = build_summary(report(targets, findings))
    assert "PyJWT@1.0" not in text and "pyjwt@1.0" in text
    assert "Mako@1.0" not in text and text.count("mako@1.0") == 1
    assert line(text, "| **All targets**").endswith("| H–2&emsp;L–1 | — |")


def test_fixed_versions_of_both_scanners_are_split_and_deduplicated():
    src = "source-development"
    findings = [
        finding(src, "CVE-1", "lib", fixed="2.18.11, 2.21.7, 2.22.3"),
        finding(src, "CVE-1", "lib", scanner="osv", fixed="2.21.7, 2.22.3, 2.18.11"),
    ]
    text = build_summary(report([target(src)], findings))
    assert "| 2.18.11, 2.21.7, 2.22.3 |" in text
    assert "1 fixable" in text


def test_header_has_the_commit_the_tool_versions_and_the_run():
    text = build_summary(sample())
    header = text.splitlines()[2]
    assert "commit `0123456`" in header and "default branch `development`" in header
    assert "Trivy 0.75.0 (DB 2026-10-13T06:41Z, Java DB n/a)" in header
    assert "osv-scanner 2.6.0 (queried 2026-10-13T11:33:23Z)" in header
    assert "[run 7](https://example.test/run/7)" in header


def test_results_by_target_count_unique_vulnerabilities_per_class():
    text = build_summary(sample())
    # CVE-1 counts once, with Trivy's severity
    assert line(text, "| source-development") == (
        f"| source-development | source | development@0123456 | ok | 10 | "
        "C–1&emsp;M–1&emsp;L–1 | — |"
    )
    assert line(text, "| app-1.0") == (
        "| app-1.0 | image | 1.0 | ok · OSV failed: rate limited | 50 | M–1 | H–1 |"
    )
    assert line(text, "| **All targets**") == (
        "| **All targets** | | | | | C–1&emsp;M–1&emsp;L–1 | H–1 |"
    )
    assert "C critical&emsp;H high&emsp;M medium&emsp;L low&emsp;U unknown — unique" in text


def test_a_target_that_is_not_ok_shows_its_reason_and_empty_counts():
    row = line(build_summary(sample()), "| app-2.0")
    assert row == "| app-2.0 | image | 2.0 | not_applicable (not published) | – |  |  |"


def test_libraries_are_grouped_by_package_in_severity_sections():
    text = build_summary(sample())
    assert "## Libraries — 2 packages, 3 vulnerabilities, 2 fixable" in text
    assert (
        "<details open><summary><b>CRITICAL — 1 packages, 2 vulnerabilities, 2 fixable"
        in text
    )
    assert (
        "<details><summary><b>MEDIUM — 1 packages, 1 vulnerabilities, 0 fixable" in text
    )
    assert text.index("CRITICAL —") < text.index("MEDIUM —")
    # the severities differ inside the row, so each vulnerability carries its letter
    assert line(text, "| lib@1.0") == (
        "| lib@1.0 | C [CVE-1](https://example.test/CVE-1), L [CVE-2](https://example.test/CVE-2)"
        " | 2.0, 2.1 | top → lib · dev | web/package-lock.json | src·dev | T+O |"
    )
    assert line(text, "| other@1.0") == (
        "| other@1.0 | [CVE-3](https://example.test/CVE-3) |  | direct | web/package-lock.json"
        " | src·dev, img·1.0 | T |"
    )


def test_where_shows_two_locations_and_the_rest_as_a_count():
    f = finding("s", "CVE-1", "lib", locations=["a/x.lock", "b/x.lock", "c/x.lock"])
    text = build_summary(report([target("s")], [f]))
    assert "| a/x.lock, b/x.lock +1 |" in text


def test_where_prefers_source_lockfiles_to_image_paths():
    findings = [
        finding("img", "CVE-1", "lib", locations=["usr/lib/lib.jar"]),
        finding("s", "CVE-1", "lib", locations=["web/package-lock.json"]),
    ]
    targets = [target("img", kind="image", ref="1.0"), target("s")]
    assert "| web/package-lock.json |" in build_summary(report(targets, findings))


def test_os_packages_are_a_separate_table_without_chain_columns():
    text = build_summary(sample())
    assert (
        "## Base image (OS packages) — 1 packages, 1 vulnerabilities, 1 fixable" in text
    )
    assert "| Package@version | Vulnerabilities | Fixed | Targets | Scanner |" in text
    assert (
        "| zlib@1.3 | [CVE-4](https://example.test/CVE-4) | 1.4 | img·1.0 | T |" in text
    )


def test_a_run_without_findings_has_empty_sections_and_dashes():
    text = build_summary(report([target("s")], []))
    assert "## Libraries — 0 packages, 0 vulnerabilities, 0 fixable" in text
    assert "Base image" not in text and "| — | — |" in text


def test_summary_ends_with_the_artifact_footer():
    assert (
        build_summary(sample())
        .rstrip()
        .endswith("`_native/trivy/` and `_native/osv/`.")
    )


def test_a_summary_that_fits_is_not_touched():
    assert truncate_summary("short\n", None) == "short\n"


@pytest.mark.parametrize("run_url", [None, "https://example.test/run/7"])
def test_a_long_summary_is_cut_at_a_line_with_open_blocks_closed_and_a_note(run_url):
    text = "<details><summary>x</summary>\n" + "| row |\n" * (
        STEP_SUMMARY_LIMIT_BYTES // 8
    )
    cut = truncate_summary(text, run_url)
    assert len(cut.encode()) <= STEP_SUMMARY_LIMIT_BYTES
    body, _, note = cut.partition("\n> The summary is cut")
    assert body.rstrip().endswith("</details>")
    assert body.count("<details") == body.count("</details>")
    assert f"it is {len(text.encode())} bytes" in note
    assert (run_url in note) if run_url else "artifact of this run" in note
