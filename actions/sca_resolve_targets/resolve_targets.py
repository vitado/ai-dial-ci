#!/usr/bin/env python3
"""Resolve the scan targets (source snapshot + container images) of one repository.

Used by the SCA scheduled scan. Talks only to the GitHub REST API and to the
OCI distribution API of the image registry; uses the Python standard library only.

The HTTP layer is injectable: every network call goes through a ``Transport``
(a callable ``(url, headers) -> Response``), so the logic can be tested with a
fake transport and no network.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_GITHUB_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
DOCKER_HUB_REGISTRY_HOST = "registry-1.docker.io"
DOCKER_HUB_ALIASES = {
    "docker.io": DOCKER_HUB_REGISTRY_HOST,
    "index.docker.io": DOCKER_HUB_REGISTRY_HOST,
}
GHCR_HOST = "ghcr.io"

TAGS_PAGE_SIZE = 1000
MAX_TAG_PAGES = 100
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 60.0
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

STABLE_SEMVER = re.compile(r"(v?)(\d+)\.(\d+)\.(\d+)", re.ASCII)
_NAME_PART = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
IMAGE_NAME = re.compile(rf"{_NAME_PART}(?:/{_NAME_PART})*", re.ASCII)
REPOSITORY_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
UNSAFE_ID_CHARS = re.compile(r"[^A-Za-z0-9._-]")
CHALLENGE_PARAM = re.compile(r'(\w+)="([^"]*)"')
LINK_NEXT = re.compile(r'<([^>]*)>\s*;[^,]*\brel="?next"?', re.IGNORECASE)


class ResolveError(Exception):
    """A condition that makes the whole resolution impossible."""


class RegistryError(Exception):
    """A registry problem affecting a single image."""


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


class UrllibTransport:
    """Production transport: a plain HTTPS GET through urllib with a timeout."""

    def __init__(self, timeout: float = REQUEST_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    def __call__(self, url: str, headers: Mapping[str, str]) -> Response:
        if urllib.parse.urlsplit(url).scheme != "https":
            raise TransportError(f"refusing non-HTTPS URL: {url}")
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
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
            raise ResolveError(f"GitHub API request failed: {err}") from err

    def _get_json(self, path: str) -> Any:
        response = self._get(path)
        if response.status != 200:
            raise ResolveError(f"GitHub API GET {path} returned HTTP {response.status}")
        return response.json()

    def default_branch(self, repo: str) -> str:
        return str(self._get_json(f"/repos/{repo}")["default_branch"])

    def commit_sha(self, repo: str, ref: str) -> str:
        return str(
            self._get_json(f"/repos/{repo}/commits/{urllib.parse.quote(ref, safe='')}")[
                "sha"
            ]
        )

    def latest_release_tag(self, repo: str) -> str | None:
        """Tag of the latest stable release, or None if the repo has none (HTTP 404)."""
        response = self._get(f"/repos/{repo}/releases/latest")
        if response.status == 404:
            return None
        if response.status != 200:
            raise ResolveError(
                f"GitHub API GET releases/latest of {repo} "
                f"returned HTTP {response.status}"
            )
        return str(response.json()["tag_name"])


class RegistryClient:
    """Lists image tags through the OCI distribution API (any compliant registry)."""

    def __init__(
        self, http: HttpClient, registry: str, github_token: str | None = None
    ) -> None:
        self.registry = registry
        self._host = DOCKER_HUB_ALIASES.get(registry, registry)
        self._http = http
        self._github_token = github_token
        self._bearer: dict[str, str] = {}  # scope -> token
        self._tags_cache: dict[str, list[str]] = {}

    def tags(self, image: str) -> list[str]:
        """All tags of an image (cached). Raises RegistryError on any failure."""
        if image not in self._tags_cache:
            self._tags_cache[image] = self._list_tags(image)
        return self._tags_cache[image]

    def _repository(self, image: str) -> str:
        if self._host == DOCKER_HUB_REGISTRY_HOST and "/" not in image:
            return f"library/{image}"
        return image

    def _list_tags(self, image: str) -> list[str]:
        repository = self._repository(image)
        url: str | None = (
            f"https://{self._host}/v2/{repository}/tags/list?n={TAGS_PAGE_SIZE}"
        )
        tags: list[str] = []
        for _ in range(MAX_TAG_PAGES):
            response = self._get(url, repository)
            if response.status != 200:
                raise RegistryError(
                    f"{self.registry}: listing tags of {image} "
                    f"returned HTTP {response.status}"
                )
            try:
                tags.extend(response.json().get("tags") or [])
            except (ValueError, AttributeError) as err:
                raise RegistryError(
                    f"{self.registry}: invalid tag list for {image}: {err}"
                ) from err
            url = self._next_url(response, url)
            if url is None:
                return tags
        raise RegistryError(
            f"{self.registry}: tag list of {image} exceeds {MAX_TAG_PAGES} pages"
        )

    @staticmethod
    def _next_url(response: Response, current: str) -> str | None:
        link = response.header("Link")
        match = LINK_NEXT.search(link) if link else None
        return urllib.parse.urljoin(current, match.group(1)) if match else None

    def _get(self, url: str, repository: str) -> Response:
        scope = f"repository:{repository}:pull"
        try:
            response = self._http.get(url, self._auth_headers(scope))
            if response.status == 401:
                challenge = response.header("WWW-Authenticate")
                if not challenge:
                    return response
                self._bearer[scope] = self._fetch_token(challenge, scope)
                response = self._http.get(url, self._auth_headers(scope))
            return response
        except TransportError as err:
            raise RegistryError(f"{self.registry}: {err}") from err

    def _auth_headers(self, scope: str) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if scope in self._bearer:
            headers["Authorization"] = f"Bearer {self._bearer[scope]}"
        return headers

    def _fetch_token(self, challenge: str, scope: str) -> str:
        scheme, _, rest = challenge.partition(" ")
        params = dict(CHALLENGE_PARAM.findall(rest))
        if scheme.lower() != "bearer" or "realm" not in params:
            raise RegistryError(
                f"{self.registry}: unsupported authentication challenge: {challenge!r}"
            )
        realm = params["realm"]
        realm_url = urllib.parse.urlsplit(realm)
        if realm_url.scheme != "https":
            raise RegistryError(
                f"{self.registry}: refusing non-HTTPS token realm {realm!r}"
            )
        query = {"scope": params.get("scope", scope)}
        if "service" in params:
            query["service"] = params["service"]
        headers = {"Accept": "application/json"}
        # Credentials go only to ghcr.io's own token endpoint (any username works).
        if (
            self._github_token
            and self._host == GHCR_HOST
            and realm_url.hostname == GHCR_HOST
        ):
            basic = base64.b64encode(
                f"github-actions:{self._github_token}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {basic}"
        separator = "&" if realm_url.query else "?"
        response = self._http.get(
            f"{realm}{separator}{urllib.parse.urlencode(query)}", headers
        )
        if response.status != 200:
            raise RegistryError(
                f"{self.registry}: token endpoint returned HTTP {response.status}"
            )
        body = response.json()
        token = body.get("token") or body.get("access_token")
        if not token:
            raise RegistryError(f"{self.registry}: token endpoint returned no token")
        return str(token)


def parse_stable_semver(tag: str) -> tuple[int, int, int] | None:
    """(major, minor, patch) of a stable ``[v]X.Y.Z`` tag; None for anything else."""
    match = STABLE_SEMVER.fullmatch(tag)
    if not match:
        return None
    return int(match.group(2)), int(match.group(3)), int(match.group(4))


def latest_release_lines(tags: Sequence[str], count: int) -> list[str]:
    """Highest-patch tag of each of the ``count`` highest stable major.minor lines."""
    best: dict[tuple[int, int], tuple[tuple[int, bool], str]] = {}
    for tag in tags:
        version = parse_stable_semver(tag)
        if version is None:
            continue
        line = (version[0], version[1])
        rank = (
            version[2],
            not tag.startswith("v"),
        )  # on a tie prefer the unprefixed tag
        if line not in best or rank > best[line][0]:
            best[line] = (rank, tag)
    return [best[line][1] for line in sorted(best, reverse=True)[:count]]


def find_release_tag(release_tag: str, tags: Sequence[str]) -> str | None:
    """Match a release tag against registry tags: exact, then without leading ``v``."""
    for candidate in (release_tag, release_tag.removeprefix("v")):
        if candidate in tags:
            return candidate
    return None


def target_id(image: str, tag: str) -> str:
    return UNSAFE_ID_CHARS.sub("-", f"{image.rsplit('/', 1)[-1]}-{tag}")


def make_target(
    registry: str,
    image: str,
    tag: str | None,
    status: str,
    reason: str | None = None,
) -> dict[str, Any]:
    """An image target; without a known tag the id is ``<image>-release``."""
    return {
        "id": target_id(image, tag or "release"),
        "kind": "image",
        "image": image,
        "tag": tag,
        "ref": f"{registry}/{image}:{tag}" if tag else None,
        "status": status,
        "reason": reason,
    }


def parse_images(raw: str) -> list[str]:
    images: list[str] = []
    for line in raw.splitlines():
        image = line.strip()
        if not image:
            continue
        if not IMAGE_NAME.fullmatch(image):
            raise ResolveError(
                f"invalid image name {image!r}: "
                "expected a lowercase name without registry or tag"
            )
        if image in images:
            raise ResolveError(f"duplicate image {image!r}")
        images.append(image)
    return images


def parse_bool(value: str, name: str) -> bool:
    lowered = value.strip().lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    raise ResolveError(f"{name} must be 'true' or 'false', got {value!r}")


def resolve_image_targets(
    registry: RegistryClient,
    image: str,
    latest_release: str | None,
    release_lines: int,
    release_error: str | None = None,
) -> list[dict[str, Any]]:
    """Targets of one image: the ``development`` tag plus the release tag(s).

    ``latest_release`` is the tag of the latest GitHub release (only looked up when
    ``release_lines == 1``); ``release_error`` is set if that lookup failed.
    """
    reg = registry.registry
    try:
        tags = registry.tags(image)
    except RegistryError as err:
        reason = str(err)
        return [
            make_target(reg, image, "development", "failed", reason),
            make_target(reg, image, latest_release, "failed", reason),
        ]

    if "development" in tags:
        targets = [make_target(reg, image, "development", "pending")]
    else:
        reason = "tag development not published for this image"
        targets = [make_target(reg, image, "development", "not_applicable", reason)]

    if release_error is not None:
        targets.append(make_target(reg, image, None, "failed", release_error))
    elif latest_release is not None:
        found = find_release_tag(latest_release, tags)
        if found is None:
            reason = f"release {latest_release} not published for this image"
            targets.append(
                make_target(reg, image, latest_release, "not_applicable", reason)
            )
        else:
            targets.append(make_target(reg, image, found, "pending"))
    else:
        selected = latest_release_lines(tags, release_lines)
        if not selected:
            reason = "no stable release tag published for this image"
            targets.append(make_target(reg, image, None, "not_applicable", reason))
        targets.extend(make_target(reg, image, tag, "pending") for tag in selected)
    return targets


def check_unique_ids(targets: Sequence[Mapping[str, Any]]) -> None:
    seen: set[str] = set()
    for target in targets:
        if target["id"] in seen:
            raise ResolveError(f"target id collision: {target['id']!r}")
        seen.add(target["id"])


def resolve_targets(
    *,
    repository: str,
    registry_name: str,
    images: Sequence[str],
    release_lines: int,
    scan_source: bool,
    scan_images: bool,
    github: GitHubClient,
    registry: RegistryClient,
    environ: Mapping[str, str],
    now: datetime,
) -> dict[str, Any]:
    """Build the targets.json document. Raises ResolveError without a snapshot."""
    default_branch = github.default_branch(repository)
    commit_sha = github.commit_sha(repository, default_branch)

    targets: list[dict[str, Any]] = []
    if scan_source:
        targets.append(
            {
                "id": "source",
                "kind": "fs",
                "image": None,
                "tag": None,
                "ref": None,
                "status": "pending",
                "reason": None,
            }
        )
    if scan_images and images:
        latest_release: str | None = None
        release_error: str | None = None
        if release_lines == 1:
            try:
                latest_release = github.latest_release_tag(repository)
            except ResolveError as err:
                release_error = str(err)
        for image in images:
            targets.extend(
                resolve_image_targets(
                    registry, image, latest_release, release_lines, release_error
                )
            )
    check_unique_ids(targets)

    server = environ.get("GITHUB_SERVER_URL", "https://github.com")
    run_id = environ.get("GITHUB_RUN_ID", "")
    run_repository = environ.get("GITHUB_REPOSITORY", "")
    return {
        "repo": repository,
        "default_branch": default_branch,
        "commit_sha": commit_sha,
        "registry": registry_name,
        "release_lines": release_lines,
        "run_id": run_id,
        "run_url": f"{server}/{run_repository}/actions/runs/{run_id}"
        if run_id and run_repository
        else "",
        "run_started_at": now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "targets": targets,
    }


def build_matrix(targets_doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    keys = ("id", "kind", "image", "tag", "ref")
    return [
        {k: t[k] for k in keys}
        for t in targets_doc["targets"]
        if t["status"] == "pending"
    ]


def format_output(name: str, value: str) -> str:
    """One $GITHUB_OUTPUT entry in the delimiter format, safe for multiline values."""
    delimiter = f"ghadelimiter_{secrets.token_hex(16)}"
    return f"{name}<<{delimiter}\n{value}\n{delimiter}\n"


def render_table(targets: Sequence[Mapping[str, Any]]) -> str:
    rows = [("ID", "REF", "STATUS", "REASON")]
    rows += [
        (t["id"], t["ref"] or t["kind"], t["status"], t["reason"] or "")
        for t in targets
    ]
    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    lines = [
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row[:3]))
        + f"  {row[3]}"
        for row in rows
    ]
    return "\n".join(line.rstrip() for line in lines)


def annotations(targets: Sequence[Mapping[str, Any]]) -> list[str]:
    lines = []
    for target in targets:
        if target["status"] == "not_applicable":
            lines.append(
                f"::notice title=Scan target {target['id']} skipped::{target['reason']}"
            )
        elif target["status"] == "failed":
            lines.append(
                f"::warning title=Scan target {target['id']} failed to resolve"
                f"::{target['reason']}"
            )
    return lines


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--repository",
        required=True,
        help="owner/name of the repository to scan",
    )
    parser.add_argument(
        "--registry",
        default=GHCR_HOST,
        help="image registry host (default: %(default)s)",
    )
    parser.add_argument(
        "--images", default="", help="image names without registry, one per line"
    )
    parser.add_argument(
        "--release-lines",
        default="1",
        help="number of latest stable release lines (default: %(default)s)",
    )
    parser.add_argument(
        "--scan-source", default="true", help="true/false (default: %(default)s)"
    )
    parser.add_argument(
        "--scan-images", default="true", help="true/false (default: %(default)s)"
    )
    parser.add_argument(
        "--output-dir", required=True, type=Path, help="directory for targets.json"
    )
    parser.add_argument(
        "--github-token", default=None, help="GitHub token (default: env GITHUB_TOKEN)"
    )
    return parser.parse_args(argv)


def run(
    args: argparse.Namespace,
    transport: Transport,
    environ: Mapping[str, str],
    now: datetime,
) -> int:
    if not REPOSITORY_NAME.fullmatch(args.repository):
        raise ResolveError(f"repository must be 'owner/name', got {args.repository!r}")
    if not args.release_lines.strip().isdigit() or int(args.release_lines) < 1:
        raise ResolveError(
            f"release-lines must be a positive integer, got {args.release_lines!r}"
        )
    release_lines = int(args.release_lines)
    images = parse_images(args.images)
    scan_source = parse_bool(args.scan_source, "scan-source")
    scan_images = parse_bool(args.scan_images, "scan-images")
    token = args.github_token or environ.get("GITHUB_TOKEN") or None

    http = HttpClient(transport)
    github = GitHubClient(
        http, token, environ.get("GITHUB_API_URL") or DEFAULT_GITHUB_API_URL
    )
    registry = RegistryClient(http, args.registry, token)
    targets_doc = resolve_targets(
        repository=args.repository,
        registry_name=args.registry,
        images=images,
        release_lines=release_lines,
        scan_source=scan_source,
        scan_images=scan_images,
        github=github,
        registry=registry,
        environ=environ,
        now=now,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    targets_file = args.output_dir / "targets.json"
    targets_file.write_text(json.dumps(targets_doc, indent=2) + "\n", encoding="utf-8")

    print(
        f"Repository {targets_doc['repo']} @ {targets_doc['default_branch']} "
        f"({targets_doc['commit_sha']})"
    )
    print(render_table(targets_doc["targets"]))
    for line in annotations(targets_doc["targets"]):
        print(line)

    output_path = environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8", newline="\n") as out:
            out.write(
                format_output(
                    "matrix",
                    json.dumps(build_matrix(targets_doc), separators=(",", ":")),
                )
            )
            out.write(format_output("commit-sha", targets_doc["commit_sha"]))
            out.write(format_output("default-branch", targets_doc["default_branch"]))
            out.write(format_output("targets-file", str(targets_file)))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(args, UrllibTransport(), os.environ, datetime.now(UTC))
    except ResolveError as err:
        print(f"::error title=Scan target resolution failed::{err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
