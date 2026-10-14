"""Tests for sca_resolve_targets/resolve_targets.py (fake transport, no network)."""

import json
import subprocess
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
import resolve_targets as rt

REPOSITORY = "example/app"
SHA = "a" * 40
ENV = {
    "GITHUB_RUN_ID": "42",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "example/caller",
    "GITHUB_REF_NAME": "development",
}
CALLER = "example/caller"


class FakeRunner:
    """Stands in for ``gh`` and ``oras``: routes the last argument (the API path or
    the image reference) to a canned output, and records every call.
    """

    def __init__(self) -> None:
        self.routes: dict[str, Any] = {}
        self.calls: list[tuple[list[str], str | None]] = []

    @property
    def urls(self) -> list[str]:
        return [argv[-1] for argv, _ in self.calls]

    def add(self, url: str, response: Any) -> None:
        """``response``: stdout, a ToolError or a list (consumed in order)."""
        self.routes[url] = response

    def __call__(self, argv: Sequence[str], stdin: str | None = None) -> str:
        self.calls.append((list(argv), stdin))
        route = self.routes.get(argv[-1])
        if route is None:
            raise rt.ToolError("unrouted")
        current = (
            (route.pop(0) if len(route) > 1 else route[0])
            if isinstance(route, list)
            else route
        )
        if isinstance(current, Exception):
            raise current
        return str(current)


def ok(payload: Any) -> str:
    """The stdout of ``gh api`` for a JSON response."""
    return json.dumps(payload)


def http_error(status: int) -> rt.ToolError:
    return rt.ToolError(f"gh: error (HTTP {status})")


def tags_out(tags: list[str]) -> str:
    """The stdout of ``oras repo tags``: one tag per line."""
    return "".join(f"{tag}\n" for tag in tags)


def tags_url(image: str, host: str = "ghcr.io") -> str:
    return f"{host}/{image}"


def github_routes(
    runner: FakeRunner,
    release: str | None = "1.1.14",
    release_status: int | None = None,
    branch: str = "development",
) -> None:
    runner.add(f"repos/{REPOSITORY}", ok({"default_branch": branch}))
    # the repository that runs the workflow, to tell a run on its default branch
    runner.routes.setdefault(f"repos/{CALLER}", ok({"default_branch": "development"}))
    quoted = urllib.parse.quote(branch, safe="")
    runner.add(f"repos/{REPOSITORY}/commits/{quoted}", ok({"sha": "a" * 40}))
    latest = f"repos/{REPOSITORY}/releases/latest"
    if release_status is not None:
        runner.add(latest, http_error(release_status))
    elif release is None:
        runner.add(latest, http_error(404))
    else:
        runner.add(latest, ok({"tag_name": release}))


def tag_routes(runner: FakeRunner, tag: str, sha: str) -> None:
    """A git tag at the commit ``sha`` (the API peels annotated tags itself)."""
    runner.add(f"repos/{REPOSITORY}/commits/refs/tags/{tag}", ok({"sha": sha}))


def run_resolve_targets(
    runner: FakeRunner,
    images: list[str],
    scan_source: bool = True,
    scan_images: bool = True,
    scan_release_source: bool = False,
    osv_enabled: bool = False,
    token: str | None = "tkn",
    **kwargs: Any,
) -> dict[str, Any]:
    inputs = rt.Inputs(
        repository=REPOSITORY,
        caller_repository=CALLER,
        images=images,
        scan_source=scan_source,
        scan_images=scan_images,
        scan_release_source=scan_release_source,
        osv_enabled=osv_enabled,
        **{"ref_name": "development", **kwargs},
    )
    return rt.resolve_targets(
        inputs,
        rt.GitHubClient(runner),
        rt.RegistryClient(runner, "ghcr.io", token),
        ENV,
    )


def run_env(output_dir: Path, **overrides: str) -> dict[str, str]:
    """The environment the action passes to the script."""
    return {**ENV, "REPOSITORY": REPOSITORY, "OUTPUT_DIR": str(output_dir), **overrides}


TARGET_KEYS = {"id", "kind", "ref", "commit_sha"}


def by_id(targets_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {t["id"]: t for t in targets_doc["targets"]}


# --- targets ------------------------------------------------------------------


def test_latest_github_release_is_scanned() -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    t.add(
        tags_url("example/app"),
        tags_out(["development", "1.1.14", "1.2.0", "1.1.13"]),
    )
    targets = by_id(run_resolve_targets(t, ["example/app"]))
    assert list(targets) == [
        "source-development",
        "app-development",
        "app-1.1.14",
    ]
    assert targets["source-development"]["kind"] == "fs"
    assert targets["app-1.1.14"] == {
        "id": "app-1.1.14",
        "scanner": "trivy",
        "kind": "image",
        "image": "example/app",
        "tag": "1.1.14",
        "ref": "ghcr.io/example/app:1.1.14",
        "git_ref": None,
        "commit_sha": None,
        "status": "pending",
        "reason": None,
    }


def test_resolve_document_metadata() -> None:
    t = FakeRunner()
    github_routes(t)
    targets_doc = run_resolve_targets(t, [])
    assert targets_doc["repo"] == REPOSITORY
    assert targets_doc["default_branch"] == "development"
    assert targets_doc["commit_sha"] == "a" * 40
    assert targets_doc["run_id"] == "42"
    assert targets_doc["run_url"] == "https://github.com/example/caller/actions/runs/42"


def test_v_prefixed_release_matches_the_unprefixed_image_tag() -> None:
    t = FakeRunner()
    github_routes(t, release="v1.1.14")
    t.add(tags_url("example/x"), tags_out(["development", "1.1.14"]))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-1.1.14"]["status"] == "pending"
    assert targets["x-1.1.14"]["ref"] == "ghcr.io/example/x:1.1.14"


def test_release_tag_missing_for_image_is_not_applicable() -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app-bff"), tags_out(["development"]))
    targets = by_id(run_resolve_targets(t, ["example/app-bff"]))
    assert targets["app-bff-development"]["status"] == "pending"
    missing = targets["app-bff-1.1.14"]
    assert missing["status"] == "not_applicable"
    assert missing["reason"] == "release 1.1.14 not published for this image"


def test_missing_development_tag_is_not_applicable() -> None:
    t = FakeRunner()
    github_routes(t, release="1.0.0")
    t.add(tags_url("example/x"), tags_out(["1.0.0"]))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "not_applicable"
    assert targets["x-1.0.0"]["status"] == "pending"


def test_no_github_release_gives_single_not_applicable_release_target() -> None:
    t = FakeRunner()
    github_routes(t, release=None)
    t.add(tags_url("example/x"), tags_out(["development", "0.9.1", "1.0.0-rc.1"]))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-release"]["status"] == "not_applicable"
    assert targets["x-release"]["tag"] is None
    assert targets["x-release"]["ref"] is None
    assert targets["x-release"]["reason"] == "no GitHub release"
    assert "x-0.9.1" not in targets


def test_image_without_tags() -> None:
    t = FakeRunner()
    github_routes(t, release=None)
    t.add(tags_url("example/x"), tags_out([]))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "not_applicable"
    assert targets["x-release"]["status"] == "not_applicable"


def test_registry_error_fails_only_that_image() -> None:
    t = FakeRunner()
    github_routes(t, release="1.0.0")
    t.add(tags_url("example/bad"), http_error(404))
    t.add(tags_url("example/good"), tags_out(["development", "1.0.0"]))
    targets = by_id(run_resolve_targets(t, ["example/bad", "example/good"]))
    assert targets["bad-development"]["status"] == "failed"
    assert "HTTP 404" in targets["bad-development"]["reason"]
    assert targets["bad-1.0.0"]["status"] == "failed"
    assert targets["good-development"]["status"] == "pending"
    assert targets["good-1.0.0"]["status"] == "pending"


def test_registry_tool_failure_fails_image() -> None:
    t = FakeRunner()
    github_routes(t, release=None)
    t.add(tags_url("example/x"), rt.ToolError("boom"))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "failed"
    assert "boom" in targets["x-development"]["reason"]


def test_github_release_api_error_fails_release_targets_but_keeps_development() -> None:
    t = FakeRunner()
    github_routes(t, release_status=403)
    t.add(tags_url("example/x"), tags_out(["development", "1.0.0"]))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "pending"
    assert targets["x-release"]["status"] == "failed"
    assert "HTTP 403" in targets["x-release"]["reason"]


@pytest.mark.parametrize("missing", ["repo", "commit"])
def test_snapshot_failure_is_fatal(missing: str) -> None:
    t = FakeRunner()
    github_routes(t)
    t.add(
        f"repos/{REPOSITORY}" + ("/commits/development" if missing == "commit" else ""),
        http_error(404),
    )
    with pytest.raises(rt.ResolveError, match="HTTP 404"):
        run_resolve_targets(t, [])


def test_snapshot_network_failure_is_fatal() -> None:
    t = FakeRunner()
    t.add(f"repos/{REPOSITORY}", rt.ToolError("down"))
    with pytest.raises(rt.ResolveError, match="down"):
        run_resolve_targets(t, [])


def test_empty_images_only_source() -> None:
    t = FakeRunner()
    github_routes(t)
    targets_doc = run_resolve_targets(t, [])
    assert [x["id"] for x in targets_doc["targets"]] == ["source-development"]
    assert not any(url.startswith("ghcr.io/") for url in t.urls)


def test_scan_source_false() -> None:
    t = FakeRunner()
    github_routes(t)
    t.add(tags_url("example/x"), tags_out(["development", "1.1.14"]))
    targets = by_id(run_resolve_targets(t, ["example/x"], scan_source=False))
    assert "source-development" not in targets
    assert "x-development" in targets


def test_scan_images_false() -> None:
    t = FakeRunner()
    github_routes(t)
    targets_doc = run_resolve_targets(t, ["example/x"], scan_images=False)
    assert [x["id"] for x in targets_doc["targets"]] == ["source-development"]


def test_id_collision_rejected() -> None:
    t = FakeRunner()
    github_routes(t, release=None)
    t.add(tags_url("a/x"), tags_out(["development"]))
    t.add(tags_url("b/x"), tags_out(["development"]))
    with pytest.raises(rt.ResolveError, match="collision"):
        run_resolve_targets(t, ["a/x", "b/x"])


def test_matrix_has_only_pending_targets_without_status() -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/bff"), tags_out(["development"]))
    matrix = rt.build_matrix(run_resolve_targets(t, ["example/bff"]))
    assert [m["id"] for m in matrix] == ["source-development", "bff-development"]
    assert all(set(m) == TARGET_KEYS for m in matrix)


def test_target_id_is_sanitized() -> None:
    def source(git_ref: str) -> str:
        return rt.make_target("pending", git_ref=git_ref)["id"]

    def image(name: str, tag: str) -> str:
        return rt.make_target("pending", image=name, tag=tag)["id"]

    assert source("development") == "source-development"
    assert source("release/1.2") == "source-release-1.2"
    assert source("feat/a b") == "source-feat-a-b"
    assert image("example/some_image", "1.2.3") == "some_image-1.2.3"
    assert image("example/x", "a b+c") == "x-a-b-c"


def test_source_target_id_sanitized_and_independent_of_sha() -> None:
    t = FakeRunner()
    github_routes(t, branch="release/1.2")
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-release-1.2"]
    assert targets["source-release-1.2"]["git_ref"] == "release/1.2"
    assert "a" * 40 not in "".join(targets)


def test_fs_target_carries_git_ref_and_commit_sha() -> None:
    t = FakeRunner()
    github_routes(t)
    targets_doc = run_resolve_targets(t, [])
    assert targets_doc["targets"] == [
        {
            "id": "source-development",
            "scanner": "trivy",
            "kind": "fs",
            "image": None,
            "tag": None,
            "ref": None,
            "git_ref": "development",
            "commit_sha": "a" * 40,
            "status": "pending",
            "reason": None,
        }
    ]
    assert targets_doc["default_branch"] == "development"
    assert targets_doc["commit_sha"] == "a" * 40


def test_target_schema_is_uniform() -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), tags_out(["development"]))
    targets_doc = run_resolve_targets(t, ["example/app"])
    kinds = {x["kind"] for x in targets_doc["targets"]}
    assert kinds == {"fs", "image"}
    for target in targets_doc["targets"]:
        assert set(target) == TARGET_KEYS | {
            "scanner",
            "image",
            "tag",
            "git_ref",
            "status",
            "reason",
        }
        assert target["scanner"] == "trivy"
        if target["kind"] == "image":
            assert target["git_ref"] is None
            assert target["commit_sha"] is None
        else:
            assert target["git_ref"]
            assert target["commit_sha"]
    assert all(set(m) == TARGET_KEYS for m in rt.build_matrix(targets_doc))


def test_matrix_carries_commit_sha_of_fs_target() -> None:
    t = FakeRunner()
    github_routes(t)
    (fs,) = rt.build_matrix(run_resolve_targets(t, []))
    assert (fs["id"], fs["commit_sha"]) == ("source-development", "a" * 40)


# --- inputs -------------------------------------------------------------------


def test_parse_images_ignores_blank_lines_and_whitespace() -> None:
    assert rt.parse_images("\n  example/a  \n\n\texample/b\n  \n") == [
        "example/a",
        "example/b",
    ]
    assert rt.parse_images("") == []


@pytest.mark.parametrize(
    "bad", ["ghcr.io/example/a:1.0", "EXAMPLE/a", "example/a:tag", "../a", "example//a"]
)
def test_parse_images_rejects_invalid_names(bad: str) -> None:
    with pytest.raises(rt.ResolveError, match="invalid image name"):
        rt.parse_images(bad)


# --- registry (oras) ----------------------------------------------------------


def test_registry_lists_tags_anonymously_without_a_token() -> None:
    t = FakeRunner()
    t.add("ghcr.io/example/x", tags_out(["a", "b"]))
    assert rt.RegistryClient(t, "ghcr.io").tags("example/x") == ["a", "b"]
    assert t.calls == [(["oras", "repo", "tags", "ghcr.io/example/x"], None)]


def test_registry_logs_in_to_ghcr_with_the_github_token() -> None:
    t = FakeRunner()
    t.add("ghcr.io/example/x", tags_out(["development"]))
    assert rt.RegistryClient(t, "ghcr.io", "gh-token").tags("example/x") == [
        "development"
    ]
    argv, stdin = t.calls[0]
    assert argv == [
        "oras",
        "repo",
        "tags",
        "--username",
        "github-actions",
        "--password-stdin",
        "ghcr.io/example/x",
    ]
    assert stdin == "gh-token"
    assert "gh-token" not in " ".join(argv)


def test_github_token_not_sent_to_foreign_registry() -> None:
    t = FakeRunner()
    t.add("registry-1.docker.io/example/x", tags_out(["development"]))
    assert rt.RegistryClient(t, "docker.io", "gh-token").tags("example/x") == [
        "development"
    ]
    assert t.calls == [
        (["oras", "repo", "tags", "registry-1.docker.io/example/x"], None)
    ]


def test_docker_hub_official_images_use_library_namespace() -> None:
    t = FakeRunner()
    t.add("registry-1.docker.io/library/nginx", tags_out(["1.0.0"]))
    assert rt.RegistryClient(t, "docker.io").tags("nginx") == ["1.0.0"]


def test_registry_failure_is_a_resolve_error() -> None:
    t = FakeRunner()
    t.add("ghcr.io/example/x", rt.ToolError("response status code 401: unauthorized"))
    with pytest.raises(rt.ResolveError, match="listing tags of example/x.*401"):
        rt.RegistryClient(t, "ghcr.io").tags("example/x")


# --- GitHub (gh) --------------------------------------------------------------


def test_github_requests_go_through_gh_api() -> None:
    t = FakeRunner()
    github_routes(t)
    run_resolve_targets(t, [])
    for argv, stdin in t.calls:
        assert argv[:2] == ["gh", "api"]
        assert "X-GitHub-Api-Version: 2022-11-28" in argv
        assert stdin is None


# --- the runner (subprocess) --------------------------------------------------


class FakeProcesses:
    """Replaces ``subprocess.run``: one canned result per call, in order."""

    def __init__(self, *results: Any) -> None:
        self.results = list(results)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> Any:
        self.calls.append({"argv": argv, **kwargs})
        result = self.results.pop(0) if len(self.results) > 1 else self.results[0]
        if isinstance(result, Exception):
            raise result
        return result


def done(returncode: int = 0, stdout: str = "", stderr: str = "") -> Any:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def runner_with(
    monkeypatch: pytest.MonkeyPatch, *results: Any
) -> tuple[Any, FakeProcesses, list[float]]:
    processes = FakeProcesses(*results)
    monkeypatch.setattr(rt.subprocess, "run", processes)
    sleeps: list[float] = []
    return rt.make_runner("secret", sleep=sleeps.append), processes, sleeps


def test_runner_returns_stdout_and_passes_token_and_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, processes, sleeps = runner_with(monkeypatch, done(stdout="out"))
    assert run(["gh", "api", "x"], "input") == "out"
    (call,) = processes.calls
    assert call["env"]["GH_TOKEN"] == "secret"
    assert call["input"] == "input"
    assert call["timeout"] == rt.TOOL_TIMEOUT_SECONDS
    assert sleeps == []


def test_runner_retries_a_transient_failure_with_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, processes, sleeps = runner_with(
        monkeypatch,
        done(1, stderr="gh: Bad Gateway (HTTP 502)"),
        subprocess.TimeoutExpired("gh", 1),
        done(stdout="out"),
    )
    assert run(["gh", "api", "x"], None) == "out"
    assert len(processes.calls) == 3
    assert sleeps == [1.0, 2.0]


def test_runner_gives_up_after_the_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    run, processes, sleeps = runner_with(monkeypatch, done(1, stderr="HTTP 503"))
    with pytest.raises(rt.ToolError, match="HTTP 503"):
        run(["gh", "api", "x"], None)
    assert len(processes.calls) == rt.MAX_ATTEMPTS
    assert len(sleeps) == rt.MAX_ATTEMPTS - 1


@pytest.mark.parametrize("status", [401, 403, 404, 422])
def test_runner_does_not_retry_a_client_error(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    run, processes, _ = runner_with(
        monkeypatch, done(1, stderr=f"gh: x (HTTP {status})")
    )
    with pytest.raises(rt.ToolError, match=f"HTTP {status}"):
        run(["gh", "api", "x"], None)
    assert len(processes.calls) == 1


def test_runner_retries_rate_limiting(monkeypatch: pytest.MonkeyPatch) -> None:
    run, processes, _ = runner_with(
        monkeypatch, done(1, stderr="gh: slow down (HTTP 429)"), done(stdout="out")
    )
    assert run(["gh", "api", "x"], None) == "out"
    assert len(processes.calls) == 2


def test_runner_reports_a_missing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    run, _, _ = runner_with(monkeypatch, FileNotFoundError("no oras"))
    with pytest.raises(rt.ToolError, match="cannot run oras"):
        run(["oras", "repo", "tags", "x"], None)


# --- output formatting and CLI ---------------------------------------------------


def parse_github_output(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines())


def test_run_writes_resolve_json_and_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    tag_routes(t, "1.1.14", "b" * 40)
    t.add(tags_url("example/x"), tags_out(["development"]))
    output_file = tmp_path / "github_output"
    env = run_env(
        tmp_path / "out",
        GITHUB_OUTPUT=str(output_file),
        GITHUB_TOKEN="tkn",
        IMAGES="example/x\n",
        OSV_ENABLED="false",
    )
    rt.run(env, t)

    targets_doc = json.loads(
        (tmp_path / "out" / "targets.json").read_text(encoding="utf-8")
    )
    assert [x["id"] for x in targets_doc["targets"]] == [
        "source-development",
        "source-1.1.14",
        "x-development",
        "x-1.1.14",
    ]
    outputs = parse_github_output(output_file.read_text(encoding="utf-8"))
    assert outputs["targets-file"] == str(tmp_path / "out" / "targets.json")
    assert " " not in outputs["matrix"]
    assert [m["id"] for m in json.loads(outputs["matrix"])] == [
        "source-development",
        "source-1.1.14",
        "x-development",
    ]
    console = capsys.readouterr().out
    assert (
        "::notice title=Scan target x-1.1.14 skipped::release 1.1.14 not published"
        in console
    )
    assert "x-development" in console


def test_run_uses_token_from_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    t = FakeRunner()
    github_routes(t)
    tokens: list[str | None] = []
    monkeypatch.setattr(rt, "make_runner", lambda token: tokens.append(token) or t)
    rt.run(run_env(tmp_path, GITHUB_TOKEN="from-env"), None)
    assert tokens == ["from-env"]


@pytest.mark.parametrize(
    "extra",
    [
        {"REPOSITORY": "nope"},
        {"REPOSITORY": ""},
    ],
)
def test_run_rejects_invalid_inputs(tmp_path: Path, extra: dict[str, str]) -> None:
    with pytest.raises(rt.ResolveError):
        rt.run(run_env(tmp_path, **extra), FakeRunner())


def test_run_defaults_the_registry_and_the_switches(tmp_path: Path) -> None:
    inputs = rt.Inputs.from_environ(run_env(tmp_path))
    assert inputs == rt.Inputs(
        repository=REPOSITORY,
        caller_repository=CALLER,
        ref_name="development",
    )
    assert inputs.registry == "ghcr.io"
    assert inputs.scan_source and inputs.scan_images and inputs.osv_enabled


def test_main_reports_fatal_error_and_exits_non_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    t = FakeRunner()
    t.add(f"repos/{REPOSITORY}", http_error(404))
    monkeypatch.setattr(rt, "make_runner", lambda token: t)
    for name, value in run_env(tmp_path).items():
        monkeypatch.setenv(name, value)
    code = rt.main()
    assert code == 1
    assert "::error" in capsys.readouterr().out
    assert not (tmp_path / "targets.json").exists()


def test_render_table_and_annotations() -> None:
    targets = [
        {
            "id": "source",
            "scanner": "trivy",
            "kind": "fs",
            "ref": None,
            "status": "pending",
            "reason": None,
        },
        {
            "id": "x-1",
            "scanner": "trivy",
            "kind": "image",
            "ref": "ghcr.io/x:1",
            "status": "failed",
            "reason": "boom",
        },
        {
            "id": "x-2",
            "scanner": "trivy",
            "kind": "image",
            "ref": "ghcr.io/x:2",
            "status": "not_applicable",
            "reason": "nope",
        },
    ]
    table = rt.render_table(targets)
    assert "source" in table
    assert "ghcr.io/x:1" in table
    assert rt.annotations(targets) == [
        "::warning title=Scan target x-1 failed to resolve::boom",
        "::notice title=Scan target x-2 skipped::nope",
    ]


# --- release sources ----------------------------------------------------------


def test_release_source_target_of_latest_release() -> None:
    t = FakeRunner()
    github_routes(t, release="0.12.0")
    tag_routes(t, "0.12.0", "c" * 40)
    t.add(tags_url("example/app"), tags_out(["development", "0.12.0"]))
    targets_doc = run_resolve_targets(t, ["example/app"], scan_release_source=True)
    assert [x["id"] for x in targets_doc["targets"]] == [
        "source-development",
        "source-0.12.0",
        "app-development",
        "app-0.12.0",
    ]
    assert by_id(targets_doc)["source-0.12.0"] == {
        "id": "source-0.12.0",
        "scanner": "trivy",
        "kind": "fs",
        "image": None,
        "tag": "0.12.0",
        "ref": None,
        "git_ref": "0.12.0",
        "commit_sha": "c" * 40,
        "status": "pending",
        "reason": None,
    }
    # the development source is not a release one
    assert by_id(targets_doc)["source-development"]["tag"] is None
    matrix = rt.build_matrix(targets_doc)
    assert all(set(m) == TARGET_KEYS for m in matrix)
    assert [m["id"] for m in matrix][:2] == ["source-development", "source-0.12.0"]
    # the GitHub release needs no git tag listing


def test_release_source_tag_that_cannot_be_resolved_is_a_failed_target() -> None:
    t = FakeRunner()
    github_routes(t, release="0.12.0")
    t.add(f"repos/{REPOSITORY}/commits/refs/tags/0.12.0", http_error(404))
    targets_doc = run_resolve_targets(t, [], scan_release_source=True)
    failed = by_id(targets_doc)["source-0.12.0"]
    assert failed["status"] == "failed"
    assert "cannot resolve release tag 0.12.0" in failed["reason"]
    assert "HTTP 404" in failed["reason"]
    assert (failed["kind"], failed["tag"], failed["git_ref"]) == (
        "fs",
        "0.12.0",
        "0.12.0",
    )
    assert [m["id"] for m in rt.build_matrix(targets_doc)] == ["source-development"]
    assert any(
        "source-0.12.0 failed to resolve" in line
        for line in rt.annotations(targets_doc["targets"])
    )


def test_release_source_latest_release_lookup_failure_is_a_failed_target() -> None:
    t = FakeRunner()
    github_routes(t, release_status=500)
    targets = by_id(run_resolve_targets(t, [], scan_release_source=True))
    assert targets["source-development"]["status"] == "pending"
    assert targets["source-release"]["status"] == "failed"
    assert "HTTP 500" in targets["source-release"]["reason"]
    assert targets["source-release"]["git_ref"] is None


def test_release_source_without_images_python_package() -> None:
    t = FakeRunner()
    github_routes(t, release="1.2.3")
    tag_routes(t, "1.2.3", "a1" * 20)
    targets_doc = run_resolve_targets(t, [], scan_release_source=True)
    assert [x["id"] for x in targets_doc["targets"]] == [
        "source-development",
        "source-1.2.3",
    ]
    assert not any(url.startswith("ghcr.io/") for url in t.urls)


def test_release_source_without_github_release_is_not_applicable() -> None:
    t = FakeRunner()
    github_routes(t, release=None)
    targets = by_id(run_resolve_targets(t, [], scan_release_source=True))
    assert targets["source-release"]["status"] == "not_applicable"
    assert targets["source-release"]["reason"] == "no GitHub release"
    assert not any("/tags" in url for url in t.urls)


def test_scan_source_false_disables_release_sources_too() -> None:
    t = FakeRunner()
    github_routes(t, release="0.12.0")
    t.add(tags_url("example/x"), tags_out(["development", "0.12.0"]))
    targets = by_id(
        run_resolve_targets(
            t, ["example/x"], scan_source=False, scan_release_source=True
        )
    )
    assert list(targets) == ["x-development", "x-0.12.0"]
    assert not any("/commits/refs/tags/" in url for url in t.urls)


def test_release_source_off_makes_no_extra_requests() -> None:
    t = FakeRunner()
    github_routes(t, release="0.12.0")
    t.add(tags_url("example/x"), tags_out(["development", "0.12.0"]))
    run_resolve_targets(t, ["example/x"], scan_release_source=False)
    assert not any("/commits/refs/tags/" in url for url in t.urls)


def test_release_source_id_sanitized() -> None:
    t = FakeRunner()
    github_routes(t, release="rel/1.0")
    tag_routes(t, "rel/1.0", "b" * 40)
    targets = by_id(run_resolve_targets(t, [], scan_release_source=True))
    assert targets["source-rel-1.0"]["git_ref"] == "rel/1.0"


def test_run_scan_release_source_flag(tmp_path: Path) -> None:
    t = FakeRunner()
    github_routes(t, release="0.12.0")
    tag_routes(t, "0.12.0", "b" * 40)
    base = run_env(tmp_path, OSV_ENABLED="false")
    rt.run(base, t)  # on by default
    targets_doc = json.loads((tmp_path / "targets.json").read_text(encoding="utf-8"))
    assert [x["id"] for x in targets_doc["targets"]] == [
        "source-development",
        "source-0.12.0",
    ]
    rt.run({**base, "SCAN_RELEASE_SOURCE": "false"}, t)
    targets_doc = json.loads((tmp_path / "targets.json").read_text(encoding="utf-8"))
    assert [x["id"] for x in targets_doc["targets"]] == ["source-development"]


# --- OSV targets --------------------------------------------------------------


def test_every_target_names_its_scanner_trivy_without_osv() -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    targets_doc = run_resolve_targets(t, ["example/app"])
    assert {x["scanner"] for x in targets_doc["targets"]} == {"trivy"}


def test_osv_target_is_the_twin_of_every_trivy_target() -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    targets_doc = run_resolve_targets(t, ["example/app"], osv_enabled=True)
    # Trivy targets as before, then the OSV twins in the same order
    assert [(x["scanner"], x["id"]) for x in targets_doc["targets"]] == [
        ("trivy", "source-development"),
        ("trivy", "app-development"),
        ("trivy", "app-1.1.14"),
        ("osv", "source-development"),
        ("osv", "app-development"),
        ("osv", "app-1.1.14"),
    ]
    trivy, osv = targets_doc["targets"][:3], targets_doc["targets"][3:]
    assert osv == [{**x, "scanner": "osv"} for x in trivy]


def test_osv_twins_cover_release_sources_in_resolve_order() -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    tag_routes(t, "1.1.14", "c" * 40)
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    targets_doc = run_resolve_targets(
        t, ["example/app"], scan_release_source=True, osv_enabled=True
    )
    trivy_ids = ["source-development", "source-1.1.14", "app-development", "app-1.1.14"]
    assert [(x["scanner"], x["id"]) for x in targets_doc["targets"]] == [
        *(("trivy", i) for i in trivy_ids),
        *(("osv", i) for i in trivy_ids),
    ]
    by_identity = {(x["scanner"], x["id"]): x for x in targets_doc["targets"]}
    twin = by_identity[("osv", "source-1.1.14")]
    # the twin carries every field of its Trivy target, `tag` and `commit_sha` included
    assert twin == {**by_identity[("trivy", "source-1.1.14")], "scanner": "osv"}
    assert (twin["tag"], twin["git_ref"], twin["commit_sha"]) == (
        "1.1.14",
        "1.1.14",
        "c" * 40,
    )
    # a release source that failed to resolve has a not_applicable twin
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    t.add(f"repos/{REPOSITORY}/commits/refs/tags/1.1.14", http_error(404))
    failed = {
        (x["scanner"], x["id"]): x
        for x in run_resolve_targets(t, [], scan_release_source=True, osv_enabled=True)[
            "targets"
        ]
    }
    assert failed[("trivy", "source-1.1.14")]["status"] == "failed"
    assert failed[("osv", "source-1.1.14")]["status"] == "not_applicable"
    assert failed[("osv", "source-1.1.14")]["reason"] == "trivy target failed"


def test_osv_twin_of_a_trivy_target_that_will_not_be_scanned_is_not_applicable() -> (
    None
):
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    # No release tag in the registry: the release target is not_applicable
    t.add(tags_url("example/app"), tags_out(["development"]))
    targets_doc = run_resolve_targets(t, ["example/app"], osv_enabled=True)
    by_identity = {(x["scanner"], x["id"]): x for x in targets_doc["targets"]}
    trivy = by_identity[("trivy", "app-1.1.14")]
    osv = by_identity[("osv", "app-1.1.14")]
    assert trivy["status"] == "not_applicable"
    assert osv["status"] == "not_applicable"
    assert osv["reason"] == "trivy target not_applicable"
    assert by_identity[("osv", "source-development")]["status"] == "pending"


def test_osv_twin_of_a_trivy_target_that_failed_to_resolve_is_not_applicable() -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), http_error(404))
    targets_doc = run_resolve_targets(t, ["example/app"], osv_enabled=True)
    osv = [x for x in targets_doc["targets"] if x["scanner"] == "osv"]
    assert [(x["id"], x["status"]) for x in osv] == [
        ("source-development", "pending"),
        ("app-development", "not_applicable"),
        ("app-1.1.14", "not_applicable"),
    ]
    assert {x["reason"] for x in osv[1:]} == {"trivy target failed"}


def test_matrix_holds_only_pending_trivy_targets() -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    targets_doc = run_resolve_targets(t, ["example/app"], osv_enabled=True)
    assert [m["id"] for m in rt.build_matrix(targets_doc)] == [
        "source-development",
        "app-development",
        "app-1.1.14",
    ]


def test_osv_twins_are_not_annotated_twice() -> None:
    t = FakeRunner()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), tags_out(["development"]))
    targets_doc = run_resolve_targets(t, ["example/app"], osv_enabled=True)
    lines = rt.annotations(targets_doc["targets"])
    assert len(lines) == 1
    assert "app-1.1.14" in lines[0]


def test_target_identity_is_scanner_and_id() -> None:
    same_id = {"id": "source-development", "scanner": "trivy"}
    rt.check_unique_ids([same_id, {**same_id, "scanner": "osv"}])
    with pytest.raises(rt.ResolveError, match="collision"):
        rt.check_unique_ids([same_id, dict(same_id)])


def test_render_table_names_the_scanner() -> None:
    t = FakeRunner()
    github_routes(t)
    table = rt.render_table(run_resolve_targets(t, [], osv_enabled=True)["targets"])
    assert [line.split()[:2] for line in table.splitlines()] == [
        ["ID", "SCANNER"],
        ["source-development", "trivy"],
        ["source-development", "osv"],
    ]


def test_run_adds_osv_twins_by_default(tmp_path: Path) -> None:
    t = FakeRunner()
    github_routes(t)
    tag_routes(t, "1.1.14", "b" * 40)
    output_file = tmp_path / "github_output"
    env = {**ENV, "GITHUB_OUTPUT": str(output_file), "GITHUB_TOKEN": "tkn"}
    env = {**run_env(tmp_path / "out"), **env}
    rt.run(env, t)
    outputs = parse_github_output(output_file.read_text(encoding="utf-8"))
    assert [m["id"] for m in json.loads(outputs["matrix"])] == [
        "source-development",
        "source-1.1.14",
    ]
    targets_doc = json.loads(
        (tmp_path / "out" / "targets.json").read_text(encoding="utf-8")
    )
    assert [(x["scanner"], x["id"]) for x in targets_doc["targets"]] == [
        ("trivy", "source-development"),
        ("trivy", "source-1.1.14"),
        ("osv", "source-development"),
        ("osv", "source-1.1.14"),
    ]


def test_run_without_osv_has_trivy_targets_only(tmp_path: Path) -> None:
    t = FakeRunner()
    github_routes(t)
    tag_routes(t, "1.1.14", "b" * 40)
    env = run_env(tmp_path / "out", OSV_ENABLED="false")
    rt.run(env, t)
    targets_doc = json.loads(
        (tmp_path / "out" / "targets.json").read_text(encoding="utf-8")
    )
    assert [x["scanner"] for x in targets_doc["targets"]] == ["trivy", "trivy"]
