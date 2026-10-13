"""Tests of the targets filter and of the run kind of sca_resolve_targets (fake
transport, no network)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from test_resolve_targets import (
    CALLER,
    NOW,
    FakeRunner,
    github_routes,
    ok,
    rt,
    run_env,
    run_resolve_targets,
    tag_routes,
    tags_out,
    tags_url,
)


def two_images_with_a_release(t: FakeRunner) -> None:
    github_routes(t, release="1.1.14")
    tag_routes(t, "1.1.14", "c" * 40)
    t.add(tags_url("example/x"), tags_out(["development", "1.1.14"]))
    t.add(tags_url("example/y"), tags_out(["development"]))


def filtered_ids(raw: str, osv_enabled: bool = False) -> list[str]:
    t = FakeRunner()
    two_images_with_a_release(t)
    doc = run_resolve_targets(
        t,
        ["example/x", "example/y"],
        scan_release_source=True,
        osv_enabled=osv_enabled,
        targets_filter=raw,
    )
    return [f"{x['scanner']}:{x['id']}" for x in doc["targets"]]


ALL_IDS = [
    "source-development",
    "source-1.1.14",
    "x-development",
    "x-1.1.14",
    "y-development",
    "y-1.1.14",
]


# ------------------------------------------------------------------ the filter


def test_no_filter_keeps_every_target() -> None:
    assert filtered_ids("") == [f"trivy:{i}" for i in ALL_IDS]
    assert filtered_ids("  \n , ") == [f"trivy:{i}" for i in ALL_IDS]


def test_filter_by_exact_id() -> None:
    assert filtered_ids("x-1.1.14") == ["trivy:x-1.1.14"]


def test_filter_by_pattern_keeps_the_resolve_order() -> None:
    assert filtered_ids("source-*") == [
        "trivy:source-development",
        "trivy:source-1.1.14",
    ]
    assert filtered_ids("*-development") == [
        "trivy:source-development",
        "trivy:x-development",
        "trivy:y-development",
    ]
    assert filtered_ids("?-1.1.14") == ["trivy:x-1.1.14", "trivy:y-1.1.14"]


def test_patterns_are_separated_by_commas_and_newlines() -> None:
    assert filtered_ids("y-development,\n  source-development \n") == [
        "trivy:source-development",
        "trivy:y-development",
    ]


def test_filter_is_case_sensitive() -> None:
    with pytest.raises(rt.ResolveError, match="no target matches 'X-1.1.14'"):
        filtered_ids("X-1.1.14")


def test_osv_twins_follow_their_trivy_target() -> None:
    assert filtered_ids("x-*", osv_enabled=True) == [
        "trivy:x-development",
        "trivy:x-1.1.14",
        "osv:x-development",
        "osv:x-1.1.14",
    ]


def test_filter_keeps_targets_that_are_not_applicable() -> None:
    t = FakeRunner()
    two_images_with_a_release(t)
    doc = run_resolve_targets(t, ["example/x", "example/y"], targets_filter="y-1.1.14")
    (target,) = doc["targets"]
    assert (target["id"], target["status"]) == ("y-1.1.14", "not_applicable")


def test_an_unmatched_pattern_is_an_error_naming_the_targets() -> None:
    with pytest.raises(rt.ResolveError) as error:
        filtered_ids("source-*, sourse-development, nothing-*")
    message = str(error.value)
    assert "'sourse-development', 'nothing-*'" in message
    assert "'source-*'" not in message
    # what the typo could have been
    assert "source-development" in message
    assert "x-development" in message


def test_a_pattern_with_a_separator_missing_matches_nothing() -> None:
    with pytest.raises(rt.ResolveError, match="no target matches 'x-development nope'"):
        filtered_ids("x-development nope")


def test_a_filter_for_a_source_that_is_not_scanned_is_an_error() -> None:
    t = FakeRunner()
    two_images_with_a_release(t)
    with pytest.raises(rt.ResolveError, match=r"no target matches 'source-\*'"):
        run_resolve_targets(
            t, ["example/x"], scan_source=False, targets_filter="source-*"
        )


# ------------------------------------------------------------------- run kind


def kind_of(**kwargs: Any) -> tuple[str, list[str]]:
    t = FakeRunner()
    github_routes(t, release=None)
    doc = run_resolve_targets(t, [], **kwargs)
    return doc["run_kind"], doc["run_kind_reasons"]


def test_a_default_run_on_the_default_branch_is_full() -> None:
    assert kind_of(osv_enabled=True, scan_release_source=True) == ("full", [])


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"targets_filter": "source-*"}, "targets filter: source-*"),
        ({"scan_source": False, "scan_release_source": False}, "scan-source is off"),
        ({"scan_images": False}, "scan-images is off"),
        ({"scan_release_source": False}, "scan-release-source is off"),
        ({"osv_enabled": False}, "osv-enabled is off"),
        (
            {"ref_name": "feature/x"},
            "not the default branch (feature/x, the default is development)",
        ),
    ],
)
def test_a_narrowed_run_is_partial(kwargs: dict[str, Any], reason: str) -> None:
    base: dict[str, Any] = {"osv_enabled": True, "scan_release_source": True}
    kind, reasons = kind_of(**{**base, **kwargs})
    assert kind == "partial"
    assert reason in reasons


def test_every_narrowing_is_listed() -> None:
    kind, reasons = kind_of(
        scan_images=False,
        scan_release_source=False,
        osv_enabled=False,
        ref_name="main",
        targets_filter="source-development",
    )
    assert kind == "partial"
    assert len(reasons) == 5


def test_the_default_branch_is_the_one_of_the_calling_repository() -> None:
    # the scanned repository (a fork scanning epam/*) has another default branch
    t = FakeRunner()
    github_routes(t, release=None, branch="main")
    doc = run_resolve_targets(
        t, [], ref_name="development", osv_enabled=True, scan_release_source=True
    )
    assert doc["default_branch"] == "main"
    assert doc["run_kind"] == "full"
    assert f"repos/{CALLER}" in [url for url in t.urls]


# ------------------------------------------------------------------------ CLI


def test_run_passes_the_filter_and_the_run_kind_on(tmp_path: Path) -> None:
    t = FakeRunner()
    two_images_with_a_release(t)
    env = run_env(
        tmp_path,
        IMAGES="example/x",
        TARGETS="x-development",
    )
    assert rt.run(env, t, NOW) == 0
    doc = json.loads((tmp_path / "targets.json").read_text(encoding="utf-8"))
    assert [x["id"] for x in doc["targets"]] == ["x-development", "x-development"]
    assert [x["scanner"] for x in doc["targets"]] == ["trivy", "osv"]
    assert doc["run_kind"] == "partial"
    assert doc["run_kind_reasons"] == ["targets filter: x-development"]


def test_caller_and_ref_come_from_the_environment(tmp_path: Path) -> None:
    t = FakeRunner()
    github_routes(t, release=None)
    t.add("repos/other/caller", ok({"default_branch": "main"}))
    env = run_env(tmp_path, GITHUB_REPOSITORY="other/caller", GITHUB_REF_NAME="main")
    assert rt.run(env, t, NOW) == 0
    doc = json.loads((tmp_path / "targets.json").read_text(encoding="utf-8"))
    assert doc["run_kind"] == "full"


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"GITHUB_REPOSITORY": ""}, "caller repository must be"),
        ({"GITHUB_REF_NAME": ""}, "no ref name"),
    ],
)
def test_run_needs_the_caller_and_the_ref(
    tmp_path: Path, env: dict[str, str], message: str
) -> None:
    with pytest.raises(rt.ResolveError, match=message):
        rt.run(run_env(tmp_path, **env), FakeRunner(), NOW)
