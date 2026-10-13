"""Tests of sca_find_baseline/find_baseline.py (fake transport, no network)."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "actions"
    / "sca_find_baseline"
    / "find_baseline.py"
)
_spec = importlib.util.spec_from_file_location("find_baseline", SCRIPT)
assert _spec is not None
assert _spec.loader is not None
fb = importlib.util.module_from_spec(_spec)
sys.modules["find_baseline"] = fb
_spec.loader.exec_module(fb)

API = "https://api.github.test"
REPOSITORY = "example/app"
WORKFLOW_REF = f"{REPOSITORY}/.github/workflows/sca-scan.yml@refs/heads/development"
BLOB = "https://blob.test/signed"
ENV = {
    "GITHUB_API_URL": API,
    "GITHUB_REPOSITORY": REPOSITORY,
    "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
    "GITHUB_RUN_ID": "100",
    "GITHUB_TOKEN": "tkn",
}


class FakeTransport:
    """Routes URLs to canned responses (a list is consumed in order, the last one
    stays) and records every call.
    """

    def __init__(self) -> None:
        self.routes: dict[str, Any] = {}
        self.calls: list[tuple[str, dict[str, str]]] = []

    def add(self, url: str, response: Any) -> None:
        self.routes[url] = response

    def __call__(self, url: str, headers: Mapping[str, str]) -> Any:
        self.calls.append((url, dict(headers)))
        route = self.routes.get(url)
        if route is None:
            return fb.Response(599, {}, b"unrouted")
        current = (
            (route.pop(0) if len(route) > 1 else route[0])
            if isinstance(route, list)
            else route
        )
        if isinstance(current, Exception):
            raise current
        return current


def ok(payload: Any) -> Any:
    return fb.Response(200, {}, json.dumps(payload).encode())


def report_zip(run_kind: Any = "full", member: str = fb.REPORT_MEMBER) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("summary.md", "# SCA\n")
        zf.writestr(member, json.dumps({"run_kind": run_kind}))
    return buffer.getvalue()


def runs_url(page: int = 1, branch: str = "development") -> str:
    return (
        f"{API}/repos/{REPOSITORY}/actions/workflows/sca-scan.yml/runs"
        f"?branch={branch}&status=completed&exclude_pull_requests=true"
        f"&per_page={fb.RUNS_PAGE_SIZE}&page={page}"
    )


def artifacts_url(run_id: int) -> str:
    return (
        f"{API}/repos/{REPOSITORY}/actions/runs/{run_id}/artifacts"
        "?name=sca-report&per_page=100"
    )


def zip_url(artifact_id: int) -> str:
    return f"{API}/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"


def run(run_id: int, branch: str = "development") -> dict[str, Any]:
    return {"id": run_id, "head_branch": branch, "conclusion": "success"}


def artifact(artifact_id: int, expired: bool = False, **fields: Any) -> dict[str, Any]:
    return {
        "id": artifact_id,
        "name": "sca-report",
        "expired": expired,
        "size_in_bytes": 1000,
        **fields,
    }


class Repo:
    """A repository with runs, newest first; each has at most one artifact."""

    def __init__(self) -> None:
        self.t = FakeTransport()
        self.t.add(f"{API}/repos/{REPOSITORY}", ok({"default_branch": "development"}))
        self.runs: list[dict[str, Any]] = []

    def add_run(
        self,
        run_id: int,
        kind: Any = "full",
        *,
        artifact_fields: dict[str, Any] | None = None,
        no_artifact: bool = False,
        branch: str = "development",
        zip_body: bytes | None = None,
    ) -> None:
        self.runs.append(run(run_id, branch))
        found = (
            [] if no_artifact else [artifact(run_id * 10, **(artifact_fields or {}))]
        )
        self.t.add(artifacts_url(run_id), ok({"artifacts": found}))
        if found:
            self.t.add(
                zip_url(run_id * 10),
                fb.Response(302, {"Location": f"{BLOB}/{run_id}"}),
            )
            body = report_zip(kind) if zip_body is None else zip_body
            self.t.add(f"{BLOB}/{run_id}", fb.Response(200, {}, body))

    def publish(self) -> None:
        size = fb.RUNS_PAGE_SIZE
        pages = [self.runs[i : i + size] for i in range(0, len(self.runs), size)]
        for number, page in enumerate(pages or [[]], 1):
            self.t.add(runs_url(number), ok({"workflow_runs": page}))

    def find(self, current: int = 100, max_runs: int = 20) -> Any:
        self.publish()
        log: list[str] = []
        github = fb.GitHubClient(
            fb.HttpClient(self.t, sleep=lambda _: None), "tkn", API
        )
        self.log = log
        return fb.find_baseline(
            github,
            repository=REPOSITORY,
            workflow_ref=WORKFLOW_REF,
            current_run_id=current,
            artifact_name="sca-report",
            max_runs=max_runs,
            log=log.append,
        )


# -------------------------------------------------------------------- selection


def test_the_latest_earlier_full_run_is_the_baseline() -> None:
    repo = Repo()
    repo.add_run(99)
    repo.add_run(98)
    result = repo.find()
    assert result.run_id == 99
    assert result.reason == ""
    # the older run is not even looked at
    assert not any("/runs/98/" in url for url, _ in repo.t.calls)


def test_a_partial_run_is_skipped() -> None:
    repo = Repo()
    repo.add_run(99, kind="partial")
    repo.add_run(98)
    assert repo.find().run_id == 98
    assert "run 99 is not a baseline: partial run" in repo.log


def test_a_report_without_run_kind_is_not_a_baseline() -> None:
    # a report of a version before the diff existed
    repo = Repo()
    repo.add_run(99, kind=None)
    repo.add_run(98)
    assert repo.find().run_id == 98


def test_an_unreadable_report_is_skipped() -> None:
    repo = Repo()
    repo.add_run(99, zip_body=b"not a zip")
    repo.add_run(98, zip_body=report_zip(member="other.json"))
    repo.add_run(97)
    result = repo.find()
    assert result.run_id == 97
    assert result.skipped == {"unreadable report": 2}


def test_a_run_on_another_branch_is_skipped() -> None:
    repo = Repo()
    repo.add_run(99, branch="feature/x")
    repo.add_run(98)
    assert repo.find().run_id == 98
    assert not any("/runs/99/" in url for url, _ in repo.t.calls)


def test_expired_and_missing_artifacts_are_skipped() -> None:
    repo = Repo()
    repo.add_run(99, artifact_fields={"expired": True})
    repo.add_run(98, no_artifact=True)  # e.g. the targets job failed
    repo.add_run(97)
    result = repo.find()
    assert result.run_id == 97
    assert result.skipped == {"expired report": 1, "no report": 1}
    # an expired artifact is not downloaded
    assert not any(url == zip_url(990) for url, _ in repo.t.calls)


def test_an_oversized_artifact_is_skipped() -> None:
    repo = Repo()
    repo.add_run(99, artifact_fields={"size_in_bytes": fb.MAX_ARTIFACT_BYTES + 1})
    repo.add_run(98)
    assert repo.find().run_id == 98
    assert not any(url == zip_url(990) for url, _ in repo.t.calls)


def test_runs_that_are_not_earlier_are_skipped() -> None:
    repo = Repo()
    repo.add_run(101)  # a later run, e.g. completed while this one runs
    repo.add_run(100)  # the run itself
    repo.add_run(99)
    assert repo.find(current=100).run_id == 99


def test_a_red_run_is_a_baseline() -> None:
    repo = Repo()
    repo.add_run(99)
    repo.runs[0]["conclusion"] = "failure"
    assert repo.find().run_id == 99


def test_the_search_is_bounded() -> None:
    repo = Repo()
    for run_id in range(99, 79, -1):
        repo.add_run(run_id, kind="partial")
    repo.add_run(79)  # the 21st: out of reach
    result = repo.find(max_runs=20)
    assert result.run_id is None
    assert "among the 20 latest completed run(s)" in result.reason
    assert "20 partial run" in result.reason
    assert result.skipped == {"partial run": 20}


def test_runs_are_walked_page_by_page() -> None:
    repo = Repo()
    for run_id in range(99, 99 - fb.RUNS_PAGE_SIZE, -1):
        repo.add_run(run_id, kind="partial")
    repo.add_run(60)
    result = repo.find(max_runs=fb.RUNS_PAGE_SIZE + 5)
    assert result.run_id == 60
    assert runs_url(2) in [url for url, _ in repo.t.calls]


def test_the_walk_stops_at_the_last_page() -> None:
    repo = Repo()
    repo.add_run(99, no_artifact=True)
    result = repo.find()
    assert result.run_id is None
    assert [url for url, _ in repo.t.calls if "/runs?" in url] == [runs_url(1)]


def test_no_runs_at_all() -> None:
    result = Repo().find()
    assert result.run_id is None
    assert result.reason == (
        "no earlier full run of sca-scan.yml on development with a live report "
        "among the 0 latest completed run(s)"
    )


def test_the_workflow_file_and_the_branch_are_the_callers() -> None:
    repo = Repo()
    repo.add_run(99)
    repo.find()
    assert runs_url(1) in [url for url, _ in repo.t.calls]


# ------------------------------------------------------------------ the download


def test_the_signed_url_is_fetched_without_the_token() -> None:
    repo = Repo()
    repo.add_run(99)
    repo.find()
    calls = dict(repo.t.calls)
    assert calls[zip_url(990)]["Authorization"] == "Bearer tkn"
    assert calls[f"{BLOB}/99"] == {}


def test_a_download_that_is_not_a_redirect_is_a_failure() -> None:
    repo = Repo()
    repo.add_run(99)
    repo.t.add(zip_url(990), ok({}))
    with pytest.raises(fb.FindError, match="expected a redirect"):
        repo.find()


def test_a_failed_blob_download_is_a_failure() -> None:
    repo = Repo()
    repo.add_run(99)
    repo.t.add(f"{BLOB}/99", fb.Response(403))
    with pytest.raises(fb.FindError, match="HTTP 403"):
        repo.find()


# ------------------------------------------------------------------------ CLI


def run_cli(
    repo: Repo, tmp_path: Path, env: dict[str, str] | None = None, *extra: str
) -> tuple[int, dict[str, str]]:
    repo.publish()
    output = tmp_path / "github_output"
    argv = [*extra]
    code = fb.run(
        fb.parse_args(argv),
        repo.t,
        {**ENV, "GITHUB_OUTPUT": str(output), **(env or {})},
        sleep=lambda _: None,
    )
    values: dict[str, str] = {}
    lines = output.read_text(encoding="utf-8").splitlines() if output.exists() else []
    it = iter(lines)
    for line in it:
        name, _, delimiter = line.partition("<<")
        body = []
        for inner in it:
            if inner == delimiter:
                break
            body.append(inner)
        values[name] = "\n".join(body)
    return code, values


def test_cli_outputs_the_run_id(tmp_path: Path) -> None:
    repo = Repo()
    repo.add_run(99)
    code, outputs = run_cli(repo, tmp_path)
    assert code == 0
    assert outputs == {"run-id": "99", "reason": ""}


def test_cli_outputs_the_reason_when_there_is_no_baseline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Repo()
    repo.add_run(99, kind="partial")
    code, outputs = run_cli(repo, tmp_path)
    assert code == 0
    assert outputs["run-id"] == ""
    assert "no earlier full run of sca-scan.yml on development" in outputs["reason"]
    assert "No baseline:" in capsys.readouterr().out


def test_an_api_failure_is_a_warning_and_no_baseline_not_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Repo()
    repo.add_run(99)
    repo.t.add(artifacts_url(99), fb.Response(403))
    code, outputs = run_cli(repo, tmp_path)
    assert code == 0
    assert outputs["run-id"] == ""
    assert outputs["reason"].startswith("the search for the baseline failed")
    assert "HTTP 403" in outputs["reason"]
    assert "::warning title=No baseline for the diff::" in capsys.readouterr().out


def test_a_network_failure_is_retried_then_reported(tmp_path: Path) -> None:
    repo = Repo()
    repo.t.add(f"{API}/repos/{REPOSITORY}", fb.TransportError("down"))
    code, outputs = run_cli(repo, tmp_path)
    assert code == 0
    assert "GitHub API request failed" in outputs["reason"]


def test_a_transient_error_is_retried() -> None:
    sleeps: list[float] = []
    t = FakeTransport()
    t.add("https://x.test/", [fb.Response(503, {"Retry-After": "7"}), ok({})])
    http = fb.HttpClient(t, sleep=sleeps.append)
    assert http.get("https://x.test/", {}).status == 200
    assert sleeps == [7.0]


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"GITHUB_REPOSITORY": "nope"}, "repository must be"),
        ({"GITHUB_RUN_ID": "x"}, "run id must be a number"),
    ],
)
def test_invalid_arguments_fail(
    tmp_path: Path, env: dict[str, str], message: str
) -> None:
    with pytest.raises(fb.FindError, match=message):
        run_cli(Repo(), tmp_path, env)


def test_invalid_max_runs_fails(tmp_path: Path) -> None:
    with pytest.raises(fb.FindError, match="max-runs"):
        run_cli(Repo(), tmp_path, None, "--max-runs", "0")


@pytest.mark.parametrize(
    ("ref", "message"),
    [
        ("garbage", "cannot read the workflow file"),
        ("other/repo/.github/workflows/x.yml@refs/heads/main", "not a workflow of"),
    ],
)
def test_the_workflow_ref_must_be_the_callers(ref: str, message: str) -> None:
    with pytest.raises(fb.FindError, match=message):
        fb.workflow_file(ref, REPOSITORY)


def test_the_workflow_file_is_the_basename_of_the_path() -> None:
    assert fb.workflow_file(WORKFLOW_REF, REPOSITORY) == "sca-scan.yml"


def test_main_reports_invalid_arguments(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "")
    assert fb.main([]) == 1
    assert capsys.readouterr().out.startswith("::error title=Invalid baseline search::")
