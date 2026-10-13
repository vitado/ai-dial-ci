#!/usr/bin/env python3
"""Find the baseline run of an SCA scheduled scan: the run to compare the report with.

Used by the SCA scheduled scan, in the ``report`` job, before the merge. The baseline
is the latest earlier run of the **same calling workflow file**
(``github.workflow_ref``)
on the **default branch** of the calling repository that

* is completed (any conclusion: a red run still publishes its report),
* has a live (not expired) ``sca-report`` artifact, and
* is a full run: its ``_report/scan_report.json`` says ``run_kind: full``. A partial
  run (a ``targets`` filter, a switched off part of the scan, a branch other than the
  default one) covers only a part of the repository and is never a baseline.

The runs are walked newest first, page by page, and at most ``--max-runs`` earlier
runs are looked at. Talks only to the GitHub REST API; the artifact is downloaded
here to read ``run_kind`` (it is small), and then once more by the workflow with the
official ``actions/download-artifact`` for the merge.

Outputs (``$GITHUB_OUTPUT``): ``run-id`` of the baseline (empty if there is none) and
``reason`` (why there is none; empty otherwise). Not finding a baseline, or a GitHub
API failure while looking for one, is not an error: the report is made without a
diff and says why. The exit status is non-zero only for invalid arguments.

The HTTP layer is injectable (a ``Transport`` is a callable
``(url, headers) -> Response``), so the logic is tested with a fake transport.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

DEFAULT_GITHUB_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
REPORT_MEMBER = "_report/scan_report.json"
RUN_KIND_FULL = "full"
RUNS_PAGE_SIZE = 30
# Pages walked at most, whatever the runs on them are
MAX_PAGES = 10
DEFAULT_MAX_RUNS = 20
# The artifact is a few MB; a size far beyond that is not an sca-report
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 60.0
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 60.0
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
REPOSITORY_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
WORKFLOW_REF = re.compile(r"(?P<repository>[^/]+/[^/]+)/(?P<path>[^@]+)@(?P<ref>.+)")


class FindError(Exception):
    """The baseline cannot be looked for (arguments), or the API failed."""


class TransportError(Exception):
    """A network-level failure (DNS, connection, timeout)."""


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "headers", {k.lower(): v for k, v in self.headers.items()}
        )

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def json(self) -> Any:
        return json.loads(self.body)


Transport = Callable[[str, Mapping[str, str]], Response]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Leaves a redirect to the caller: the artifact download redirects to a signed
    URL that must be fetched without the GitHub token.
    """

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class UrllibTransport:
    """Production transport: a plain HTTPS GET through urllib that does not follow
    redirects, with a timeout.
    """

    def __init__(self, timeout: float = REQUEST_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def __call__(self, url: str, headers: Mapping[str, str]) -> Response:
        if urllib.parse.urlsplit(url).scheme != "https":
            raise TransportError(f"refusing non-HTTPS URL: {url}")
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            with self._opener.open(request, timeout=self._timeout) as resp:
                return Response(resp.status, dict(resp.headers), resp.read())
        except urllib.error.HTTPError as err:
            return Response(err.code, dict(err.headers), err.read())
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            raise TransportError(f"{url}: {err}") from err


class HttpClient:
    """Adds bounded retries with backoff (429/5xx, network errors) to a Transport."""

    def __init__(
        self,
        transport: Transport,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = MAX_ATTEMPTS,
    ) -> None:
        self._transport = transport
        self._sleep = sleep
        self._max_attempts = max_attempts

    def get(self, url: str, headers: Mapping[str, str]) -> Response:
        for attempt in range(1, self._max_attempts + 1):
            delay = BACKOFF_BASE_SECONDS * 2 ** (attempt - 1)
            try:
                response = self._transport(url, headers)
            except TransportError:
                if attempt == self._max_attempts:
                    raise
            else:
                if (
                    response.status not in RETRY_STATUSES
                    or attempt == self._max_attempts
                ):
                    return response
                delay = _retry_after(response) or delay
            self._sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover


def _retry_after(response: Response) -> float | None:
    value = response.header("Retry-After")
    if value is None or not value.strip().isdigit():
        return None
    return min(float(value), MAX_RETRY_AFTER_SECONDS)


class GitHubClient:
    def __init__(self, http: HttpClient, token: str | None, api_url: str) -> None:
        self._http = http
        self._api_url = api_url.rstrip("/")
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    def _get(self, path: str) -> Response:
        try:
            return self._http.get(f"{self._api_url}{path}", self._headers)
        except TransportError as err:
            raise FindError(f"GitHub API request failed: {err}") from err

    def _get_json(self, path: str) -> Any:
        response = self._get(path)
        if response.status != 200:
            raise FindError(f"GitHub API GET {path} returned HTTP {response.status}")
        try:
            return response.json()
        except ValueError as err:
            raise FindError(f"GitHub API GET {path} returned invalid JSON") from err

    def default_branch(self, repo: str) -> str:
        try:
            return str(self._get_json(f"/repos/{repo}")["default_branch"])
        except (KeyError, TypeError) as err:
            raise FindError(f"unexpected GitHub API response for {repo}") from err

    def completed_runs(
        self, repo: str, workflow_file: str, branch: str, page: int
    ) -> list[dict[str, Any]]:
        """A page of the completed runs of a workflow file on a branch, newest first."""
        query = urllib.parse.urlencode(
            {
                "branch": branch,
                "status": "completed",
                "exclude_pull_requests": "true",
                "per_page": RUNS_PAGE_SIZE,
                "page": page,
            }
        )
        file = urllib.parse.quote(workflow_file, safe="")
        body = self._get_json(f"/repos/{repo}/actions/workflows/{file}/runs?{query}")
        runs = body.get("workflow_runs") if isinstance(body, dict) else None
        if not isinstance(runs, list):
            raise FindError(f"unexpected GitHub API response for the runs of {file}")
        return [run for run in runs if isinstance(run, dict)]

    def artifacts(self, repo: str, run_id: int, name: str) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({"name": name, "per_page": 100})
        body = self._get_json(f"/repos/{repo}/actions/runs/{run_id}/artifacts?{query}")
        found = body.get("artifacts") if isinstance(body, dict) else None
        if not isinstance(found, list):
            raise FindError(
                f"unexpected GitHub API response for the artifacts of {run_id}"
            )
        return [a for a in found if isinstance(a, dict)]

    def artifact_zip(self, repo: str, artifact_id: int) -> bytes:
        """The zip of an artifact. The API answers with a redirect to a signed URL,
        which is fetched without the GitHub token.
        """
        path = f"/repos/{repo}/actions/artifacts/{artifact_id}/zip"
        response = self._get(path)
        if response.status not in (301, 302, 303, 307, 308):
            raise FindError(
                f"GitHub API GET {path} returned HTTP {response.status}, "
                "expected a redirect"
            )
        location = response.header("Location")
        if not location:
            raise FindError(f"GitHub API GET {path} redirected without a location")
        try:
            download = self._http.get(location, {})
        except TransportError as err:
            raise FindError(f"artifact download failed: {err}") from err
        if download.status != 200:
            raise FindError(f"artifact download returned HTTP {download.status}")
        return download.body


def workflow_file(workflow_ref: str, repository: str) -> str:
    """The file name of the calling workflow from ``github.workflow_ref``
    (``owner/repo/.github/workflows/sca-scan.yml@refs/heads/main``).
    """
    match = WORKFLOW_REF.fullmatch(workflow_ref)
    if match is None:
        raise FindError(f"cannot read the workflow file from {workflow_ref!r}")
    if match["repository"] != repository:
        raise FindError(
            f"the workflow {workflow_ref!r} is not a workflow of {repository}"
        )
    return match["path"].rsplit("/", 1)[-1]


def run_kind_of(archive: bytes) -> str | None:
    """``run_kind`` of the ``scan_report.json`` in the zip of an ``sca-report``;
    None if the zip holds no readable report.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            info = zf.getinfo(REPORT_MEMBER)
            if info.file_size > MAX_REPORT_BYTES:
                return None
            with zf.open(info) as member:
                report = json.load(member)
    except (KeyError, zipfile.BadZipFile, ValueError, OSError):
        return None
    return report.get("run_kind") if isinstance(report, dict) else None


@dataclass
class Search:
    """The result of the search: the baseline run, or why there is none."""

    run_id: int | None
    reason: str
    skipped: dict[str, int] = field(default_factory=dict)


def find_baseline(
    github: GitHubClient,
    *,
    repository: str,
    workflow_ref: str,
    current_run_id: int,
    artifact_name: str,
    max_runs: int,
    log: Callable[[str], None] = print,
) -> Search:
    """The latest earlier full run of the calling workflow on the default branch that
    has a live report.
    """
    file = workflow_file(workflow_ref, repository)
    branch = github.default_branch(repository)
    skipped: dict[str, int] = {}

    def skip(run_id: int, why: str) -> None:
        skipped[why] = skipped.get(why, 0) + 1
        log(f"run {run_id} is not a baseline: {why}")

    inspected = 0
    page = 1
    while inspected < max_runs and page <= MAX_PAGES:
        runs = github.completed_runs(repository, file, branch, page)
        for run in runs:
            run_id = run.get("id")
            # Runs of the branch only; a run that is not earlier is not a baseline
            if (
                not isinstance(run_id, int)
                or run.get("head_branch") != branch
                or run_id >= current_run_id
            ):
                continue
            if inspected >= max_runs:
                break
            inspected += 1
            artifacts = [
                a
                for a in github.artifacts(repository, run_id, artifact_name)
                if a.get("name") == artifact_name
            ]
            live = [a for a in artifacts if not a.get("expired")]
            if not live:
                skip(run_id, "expired report" if artifacts else "no report")
                continue
            artifact = live[0]
            size = artifact.get("size_in_bytes")
            if not isinstance(artifact.get("id"), int) or (
                isinstance(size, int) and size > MAX_ARTIFACT_BYTES
            ):
                skip(run_id, "unusable report")
                continue
            kind = run_kind_of(github.artifact_zip(repository, artifact["id"]))
            if kind != RUN_KIND_FULL:
                skip(run_id, "partial run" if kind else "unreadable report")
                continue
            log(f"baseline: run {run_id}")
            return Search(run_id, "", skipped)
        if len(runs) < RUNS_PAGE_SIZE:
            break
        page += 1
    summary = ", ".join(f"{count} {why}" for why, count in skipped.items())
    where = f"{file} on {branch}"
    reason = (
        f"no earlier full run of {where} with a live report among the "
        f"{inspected} latest completed run(s)" + (f" ({summary})" if summary else "")
    )
    return Search(None, reason, skipped)


def format_output(name: str, value: str) -> str:
    """One $GITHUB_OUTPUT entry in the delimiter format, safe for multiline values."""
    delimiter = f"ghadelimiter_{secrets.token_hex(16)}"
    return f"{name}<<{delimiter}\n{value}\n{delimiter}\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--repository",
        default=None,
        help="owner/name of the calling repository (default: env GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--workflow-ref",
        default=None,
        help="github.workflow_ref of the run (default: env GITHUB_WORKFLOW_REF)",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="id of the current run (default: env GITHUB_RUN_ID)",
    )
    parser.add_argument(
        "--artifact-name", default="sca-report", help="default: %(default)s"
    )
    parser.add_argument(
        "--max-runs",
        default=str(DEFAULT_MAX_RUNS),
        help="how many earlier runs to look at at most (default: %(default)s)",
    )
    parser.add_argument(
        "--github-token", default=None, help="GitHub token (default: env GITHUB_TOKEN)"
    )
    return parser.parse_args(argv)


def run(
    args: argparse.Namespace,
    transport: Transport,
    environ: Mapping[str, str],
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    repository = args.repository or environ.get("GITHUB_REPOSITORY", "")
    if not REPOSITORY_NAME.fullmatch(repository):
        raise FindError(f"repository must be 'owner/name', got {repository!r}")
    workflow_ref = args.workflow_ref or environ.get("GITHUB_WORKFLOW_REF", "")
    run_id = args.run_id or environ.get("GITHUB_RUN_ID", "")
    if not run_id.strip().isdigit():
        raise FindError(f"run id must be a number, got {run_id!r}")
    if not args.max_runs.strip().isdigit() or int(args.max_runs) < 1:
        raise FindError(f"max-runs must be a positive integer, got {args.max_runs!r}")
    token = args.github_token or environ.get("GITHUB_TOKEN") or None
    github = GitHubClient(
        HttpClient(transport, sleep),
        token,
        environ.get("GITHUB_API_URL") or DEFAULT_GITHUB_API_URL,
    )
    try:
        result = find_baseline(
            github,
            repository=repository,
            workflow_ref=workflow_ref,
            current_run_id=int(run_id),
            artifact_name=args.artifact_name,
            max_runs=int(args.max_runs),
        )
    except FindError as err:
        # Only a diff is lost: the report does not depend on the baseline
        print(f"::warning title=No baseline for the diff::{err}")
        result = Search(None, f"the search for the baseline failed: {err}")
    if result.run_id is None:
        print(f"No baseline: {result.reason}")
    output_path = environ.get("GITHUB_OUTPUT")
    if output_path:
        outputs = {
            "run-id": "" if result.run_id is None else str(result.run_id),
            "reason": result.reason,
        }
        with open(output_path, "a", encoding="utf-8", newline="\n") as out:
            out.writelines(format_output(k, v) for k, v in outputs.items())
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(args, UrllibTransport(), os.environ)
    except FindError as err:
        print(f"::error title=Invalid baseline search::{err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
