"""Tests of the not shipped paths in actions/sca_merge_results/merge_results.py:
``non_shipped_paths`` of the SCA configuration and the skip paths of trivy.yaml."""

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
    records_by_cve,
)

SKIP_RECORD = {
    "schema_version": 1,
    "id": "source-development",
    "mode": "as_non_shipped",
    "config_file": "trivy.yaml",
    "skip_dirs": [],
    "skip_files": [],
    "paths_scanned": True,
}


def config(patterns: list[str] | None = None, mode: str = "as_non_shipped") -> dict:
    return {
        "source": ".github/sca.yml@" + "b" * 40,
        "overrides": None,
        "non_shipped_paths": patterns or [],
        "trivy_skip_paths": mode,
    }


def workspace(
    tmp_path: Path, patterns: list[str] | None, *targets: dict[str, Any]
) -> Workspace:
    tmp_path.mkdir(parents=True, exist_ok=True)
    doc = make_targets_doc(*(targets or (SOURCE,)))
    if patterns is not None:
        doc["config"] = config(patterns)
    ws = Workspace(tmp_path, doc)
    ws.add_part("source-development", "source")
    return ws


def add_skip_record(ws: Workspace, **fields: Any) -> None:
    record = {**SKIP_RECORD, **fields}
    (ws.trivy_parts / "source-development.trivy-config.json").write_text(
        json.dumps(record), encoding="utf-8"
    )


# ------------------------------------------------------- repository patterns


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        # a directory: everything below it, from the repository root
        ("examples/", "examples/app/requirements.txt", True),
        ("examples/", "examples/requirements.txt", True),
        ("examples/", "examples-core/requirements.txt", False),
        ("examples/", "a/examples/requirements.txt", False),
        ("examples/", "examples", False),
        ("examples/", "./examples/requirements.txt", True),
        # a file: exactly that path
        ("website/package-lock.json", "website/package-lock.json", True),
        ("website/package-lock.json", "website/a/package-lock.json", False),
        ("package-lock.json", "package-lock.json", True),
        ("package-lock.json", "website/package-lock.json", False),
        # * stays within a segment
        ("*/package-lock.json", "website/package-lock.json", True),
        ("*/package-lock.json", "a/b/package-lock.json", False),
        ("requirements-*.txt", "requirements-dev.txt", True),
        ("requirements-*.txt", "docs/requirements-dev.txt", False),
        # ** across segments
        ("**/examples/", "a/b/examples/x/requirements.txt", True),
        ("**/examples/", "examples/x/requirements.txt", True),
        ("**/examples/", "a/examples-core/requirements.txt", False),
        ("a/**/b/", "a/b/c.txt", True),
        ("a/**/b/", "a/x/y/b/c.txt", True),
        ("a/**/b/", "x/a/b/c.txt", False),
        ("**/package-lock.json", "package-lock.json", True),
        ("**/package-lock.json", "a/b/package-lock.json", True),
        # the Gradle sub-project is not matched by the name prefix of another one
        ("app/", "app/gradle.lockfile", True),
        ("app/", "application/gradle.lockfile", False),
        ("app/", "core/app/gradle.lockfile", False),
        ("app/gradle.lockfile", "app/gradle.lockfile", True),
        # case-sensitive, regex characters are literal
        ("Examples/", "examples/x.txt", False),
        ("a.b/", "a.b/x.txt", True),
        ("a.b/", "axb/x.txt", False),
        ("a+b/", "a+b/x.txt", True),
    ],
)
def test_repository_pattern_matching(pattern: str, path: str, expected: bool) -> None:
    not_shipped = mr.NotShipped([pattern])
    assert not_shipped.matches("source-development", path) is expected


def test_not_shipped_is_falsy_without_patterns_and_skips() -> None:
    assert not mr.NotShipped()
    assert mr.NotShipped(["examples/"])
    assert not mr.NotShipped([], {"t": {**SKIP_RECORD, "mode": "apply"}})


# --------------------------------------------------------- trivy skip globs


@pytest.mark.parametrize(
    ("entry", "directory", "expected"),
    [
        # as Trivy 0.75.0 treated them in a scan of a synthetic repository
        ("examples", "examples", True),
        ("examples", "a/examples", False),
        ("examples", "examples-core", False),
        ("examples/", "examples", True),
        ("./examples", "examples", True),
        ("/examples", "examples", False),
        ("**/examples", "examples", True),
        ("**/examples", "a/examples", True),
        ("**/examples", "examples-core", False),
        ("examples/**", "examples", True),
        ("examples/**", "examples/app", True),
        ("examples/*", "examples/app", True),
        ("examples/*", "examples", False),
        ("*/x", "lib/x", True),
        ("*/x", "a/lib/x", False),
        ("lib/*", "lib/x", True),
        ("exam*", "examples", True),
        ("exam*", "examples-core", True),
        ("e?amples", "examples", True),
        ("e?amples", "eamples", False),
        ("ex[a]mples", "examples", True),
        ("ex[!a]mples", "examples", False),
        ("a/**/examples", "a/examples", True),
        ("a/**/examples", "examples", False),
        ("**", ".", True),
        ("{examples,lib}", "lib", True),
        ("{examples,lib}", "docs", False),
        ("a/{b,c/d}", "a/c/d", True),
    ],
)
def test_trivy_skip_dirs_matching(entry: str, directory: str, expected: bool) -> None:
    regex = mr.trivy_glob_regex(entry)
    assert bool(regex and regex.fullmatch(directory)) is expected


def test_trivy_skips_a_file_below_a_skipped_dir_or_by_file_pattern() -> None:
    dirs = [mr.trivy_glob_regex("examples")]
    files = [mr.trivy_glob_regex("*/*.txt")]
    assert mr.trivy_skips_path("examples/app/r.txt", dirs, []) is True  # type: ignore[arg-type]
    assert mr.trivy_skips_path("a/examples/r.txt", dirs, []) is False  # type: ignore[arg-type]
    assert mr.trivy_skips_path("lib/r.txt", [], files) is True  # type: ignore[arg-type]
    assert mr.trivy_skips_path("r.txt", [], files) is False  # type: ignore[arg-type]
    assert mr.trivy_skips_path("a/b/r.txt", [], files) is False  # type: ignore[arg-type]


def test_trivy_skips_everything_with_a_root_matching_dir_pattern() -> None:
    dirs = [mr.trivy_glob_regex("**")]
    assert mr.trivy_skips_path("requirements.txt", dirs, []) is True  # type: ignore[arg-type]


# ------------------------------------------------------------------ merging


def test_record_only_in_not_shipped_locations_is_source_only_without_images(
    tmp_path: Path,
) -> None:
    ws = workspace(tmp_path, ["app/", "core/"])
    ws.run()
    recs = records_by_cve(ws)
    # CVE-2000-0003 is only in app/ and core/gradle.lockfile; the record is kept
    assert recs["CVE-2000-0003"]["exposure"] == "source_only"
    assert recs["CVE-2000-0003"]["locations"] == [
        "app/gradle.lockfile",
        "core/gradle.lockfile",
    ]
    assert recs["CVE-2000-0003"]["scan_targets"] == ["source-development"]
    # the others are in package-lock.json, which is shipped
    assert recs["CVE-2000-0001"]["exposure"] == "development_only"
    totals = ws.json("_report/scan_report.json")["totals"]["findings"]
    assert totals["by_exposure"]["source_only"] == 1


def test_record_also_seen_in_a_shipped_location_keeps_its_exposure(
    tmp_path: Path,
) -> None:
    ws = workspace(tmp_path, ["app/"])
    ws.run()
    # core/gradle.lockfile holds CVE-2000-0003, too
    assert records_by_cve(ws)["CVE-2000-0003"]["exposure"] == "development_only"


def test_images_are_never_matched_by_not_shipped_paths(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, DEV, REL))
    doc = json.loads(ws.targets_file.read_text())
    # "Node.js" is a result of the image, "package-lock.json" of the source
    doc["config"] = config(["Node.js", "package-lock.json"])
    ws.targets_file.write_text(json.dumps(doc), encoding="utf-8")
    ws.add_part("source-development", "source")
    ws.add_part("app-development", "app-development")
    ws.add_part("app-1.0.0", "app-1.0.0")
    ws.run()
    recs = records_by_cve(ws)
    # CVE-2000-0001: the source lockfile is not shipped, the image still counts
    assert recs["CVE-2000-0001"]["exposure"] == "development_only"
    assert recs["CVE-2000-0010"]["exposure"] == "release_and_development"
    # CVE-2000-0002 is only in the source: source_only, with or without the paths
    assert recs["CVE-2000-0002"]["exposure"] == "source_only"


def test_not_shipped_source_does_not_make_a_record_development_in_a_run_with_images(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path, make_targets_doc(SOURCE, REL))
    ws.add_part("source-development", "source")
    ws.add_part("app-1.0.0", "app-1.0.0")
    ws.run()
    # without the config, a source finding is source_only here anyway
    assert records_by_cve(ws)["CVE-2000-0003"]["exposure"] == "source_only"


def test_without_config_the_outputs_are_those_of_a_run_without_not_shipped_paths(
    tmp_path: Path,
) -> None:
    plain = workspace(tmp_path / "plain", None)
    explicit = workspace(tmp_path / "explicit", None)
    doc = json.loads(explicit.targets_file.read_text())
    doc["config"] = mr.default_config()
    explicit.targets_file.write_text(json.dumps(doc), encoding="utf-8")
    for ws in (plain, explicit):
        ws.run()
    for name in ("_report/vulnerabilities.json", "summary.md"):
        assert (plain.out / name).read_bytes() == (explicit.out / name).read_bytes()
    report = plain.json("_report/scan_report.json")
    assert report["config"] == {
        "source": None,
        "overrides": None,
        "non_shipped_paths": [],
        "trivy_skip_paths": "as_non_shipped",
    }
    assert report["schema_version"] == 1


def test_scan_report_carries_the_config(tmp_path: Path) -> None:
    ws = workspace(tmp_path, ["examples/"])
    ws.run()
    assert ws.json("_report/scan_report.json")["config"] == config(["examples/"])


# ------------------------------------------------------------------ summary


def test_summary_marks_not_shipped_locations_and_names_the_configuration(
    tmp_path: Path,
) -> None:
    ws = workspace(tmp_path, ["app/", "core/"])
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "app/gradle.lockfile (not shipped)" in md
    assert "core/gradle.lockfile (not shipped)" in md
    assert "package-lock.json (not shipped)" not in md
    assert "Source only (build / test / not shipped)" in md
    assert "Source only · not shipped" in md
    assert (
        "<sub>Configuration: .github/sca.yml@bbbbbbb · not shipped: app/, core/</sub>"
        in md
    )


def test_summary_without_not_shipped_paths_has_no_marks(tmp_path: Path) -> None:
    ws = workspace(tmp_path, None)
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "not shipped" not in md
    assert "Configuration" not in md


def test_summary_names_an_input_that_replaces_the_file(tmp_path: Path) -> None:
    ws = workspace(tmp_path, ["app/"])
    doc = json.loads(ws.targets_file.read_text())
    doc["config"].update(source="input", overrides=".github/sca.yml@" + "c" * 40)
    ws.targets_file.write_text(json.dumps(doc), encoding="utf-8")
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert (
        "<sub>Configuration: workflow input (replaces .github/sca.yml@ccccccc)"
        " · not shipped: app/</sub>" in md
    )


def test_headline_of_a_run_whose_only_findings_are_not_shipped(tmp_path: Path) -> None:
    ws = workspace(tmp_path, ["app/", "core/", "package-lock.json"])
    ws.run()
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "> | Source only (build / test / not shipped) |" in md
    assert (
        "> **No known vulnerabilities in development — 3 only in "
        "build / test dependencies or not shipped paths**" in md
    )


# ------------------------------------------------------ trivy skip paths


def test_skip_paths_scanned_as_non_shipped_count_as_not_shipped(
    tmp_path: Path,
) -> None:
    ws = workspace(tmp_path, None)
    add_skip_record(ws, skip_dirs=["app", "core"])
    ws.run()
    recs = records_by_cve(ws)
    assert recs["CVE-2000-0003"]["exposure"] == "source_only"
    assert recs["CVE-2000-0001"]["exposure"] == "development_only"
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "app/gradle.lockfile (not shipped)" in md
    assert (
        "trivy.yaml skip paths scanned, not shipped: app, core" in md
    )  # the coverage note
    entry = ws.targets["source-development"]
    assert entry["trivy_skip_paths"] == {
        "mode": "as_non_shipped",
        "paths_scanned": True,
        "config_file": "trivy.yaml",
        "skip_dirs": ["app", "core"],
        "skip_files": [],
    }


def test_skip_files_count_too(tmp_path: Path) -> None:
    ws = workspace(tmp_path, None)
    add_skip_record(ws, skip_files=["**/gradle.lockfile"])
    ws.run()
    assert records_by_cve(ws)["CVE-2000-0003"]["exposure"] == "source_only"


@pytest.mark.parametrize("mode", ["apply", "ignore"])
def test_skip_paths_of_other_modes_do_not_change_the_classification(
    tmp_path: Path, mode: str
) -> None:
    ws = workspace(tmp_path, None)
    add_skip_record(ws, mode=mode, skip_dirs=["app", "core"], paths_scanned=False)
    ws.run()
    assert records_by_cve(ws)["CVE-2000-0003"]["exposure"] == "development_only"
    md = (ws.out / "summary.md").read_text(encoding="utf-8")
    assert "not shipped" not in md
    assert "trivy.yaml skip paths" in md  # still listed in the coverage
    assert ws.targets["source-development"]["trivy_skip_paths"]["mode"] == mode


def test_skip_paths_note_says_what_trivy_did() -> None:
    def note(mode: str) -> str | None:
        skip = {**SKIP_RECORD, "mode": mode, "skip_dirs": ["a", "b"]}
        return mr.skip_paths_note({"trivy_skip_paths": skip})

    assert note("apply") == "trivy.yaml skip paths skipped by Trivy: a, b"
    assert note("ignore") == "trivy.yaml skip paths scanned: a, b"
    assert note("as_non_shipped") == (
        "trivy.yaml skip paths scanned, not shipped: a, b"
    )
    assert mr.skip_paths_note({"trivy_skip_paths": SKIP_RECORD}) is None
    assert mr.skip_paths_note({}) is None
    many = {**SKIP_RECORD, "skip_dirs": [f"d{i}" for i in range(7)]}
    assert (mr.skip_paths_note({"trivy_skip_paths": many}) or "").endswith("d4 +2 more")


def test_an_empty_skip_list_adds_neither_note_nor_change(tmp_path: Path) -> None:
    plain = workspace(tmp_path / "plain", None)
    recorded = workspace(tmp_path / "recorded", None)
    add_skip_record(recorded)
    for ws in (plain, recorded):
        ws.run()
    for name in ("_report/vulnerabilities.json", "summary.md"):
        assert (plain.out / name).read_bytes() == (recorded.out / name).read_bytes()


def test_absolute_skip_entries_never_match(tmp_path: Path) -> None:
    ws = workspace(tmp_path, None)
    add_skip_record(ws, skip_dirs=["/app"])
    ws.run()
    assert records_by_cve(ws)["CVE-2000-0003"]["exposure"] == "development_only"


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        json.dumps({**SKIP_RECORD, "schema_version": 2}),
        json.dumps({**SKIP_RECORD, "mode": "other"}),
        json.dumps({**SKIP_RECORD, "skip_dirs": "app"}),
        json.dumps({**SKIP_RECORD, "paths_scanned": "yes"}),
    ],
)
def test_unreadable_trivy_config_record_fails_the_target(
    tmp_path: Path, content: str
) -> None:
    ws = workspace(tmp_path, None)
    (ws.trivy_parts / "source-development.trivy-config.json").write_text(content)
    assert ws.run() == 1
    entry = ws.targets["source-development"]
    assert entry["status"] == "failed"
    assert entry["reason"].startswith("unreadable trivy config record")
    assert "trivy_skip_paths" not in entry


def test_image_targets_have_no_trivy_skip_paths(tmp_path: Path) -> None:
    ws = Workspace(tmp_path, make_targets_doc(DEV))
    ws.add_part("app-development", "app-development")
    ws.run()
    assert "trivy_skip_paths" not in ws.targets["app-development"]


# ---------------------------------------------------- targets.json config


@pytest.mark.parametrize(
    "bad",
    [
        "x",
        {"non_shipped_paths": "examples/"},
        {"non_shipped_paths": [1]},
        {"trivy_skip_paths": "sometimes"},
        {"source": 1},
    ],
)
def test_invalid_config_in_targets_file_is_an_input_error(
    tmp_path: Path, bad: Any
) -> None:
    doc = make_targets_doc(SOURCE)
    doc["config"] = bad
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(mr.InputError, match="invalid config"):
        mr.load_targets_file(path)


def test_targets_file_without_config_gets_the_defaults(tmp_path: Path) -> None:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(make_targets_doc(SOURCE)), encoding="utf-8")
    assert mr.load_targets_file(path)["config"] == mr.default_config()
