#!/usr/bin/env python3
"""Resolve the scan targets (source snapshot + container images) of one repository.

Used by the SCA scheduled scan. Talks only to the GitHub REST API and to the
OCI distribution API of the image registry. Besides the standard library it needs
PyYAML, for the repository configuration (``.github/sca.yml``, see ``sca_config``).

The HTTP layer is injectable: every network call goes through a ``Transport``
(a callable ``(url, headers) -> Response``), so the logic can be tested with a
fake transport and no network.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
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

import sca_config

DEFAULT_GITHUB_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
DOCKER_HUB_REGISTRY_HOST = "registry-1.docker.io"
DOCKER_HUB_ALIASES = {
    "docker.io": DOCKER_HUB_REGISTRY_HOST,
    "index.docker.io": DOCKER_HUB_REGISTRY_HOST,
}
GHCR_HOST = "ghcr.io"

SCANNER_TRIVY = "trivy"
SCANNER_OSV = "osv"

KIND_FS = "fs"

STATUS_PENDING = "pending"
STATUS_NOT_APPLICABLE = "not_applicable"

TAGS_PAGE_SIZE = 1000
MAX_TAG_PAGES = 100
GITHUB_TAGS_PAGE_SIZE = 100
MAX_TAG_PEEL_DEPTH = 5  # tag objects pointing at tag objects, before a commit
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

    def file_text(self, repo: str, path: str, ref: str) -> str | None:
        """Text of a file of the repository at a commit, or None if there is none."""
        quoted = urllib.parse.quote(path, safe="/")
        ref_query = urllib.parse.quote(ref, safe="")
        response = self._get(f"/repos/{repo}/contents/{quoted}?ref={ref_query}")
        if response.status == 404:
            return None
        if response.status != 200:
            raise ResolveError(
                f"GitHub API GET contents of {path} in {repo}@{ref} "
                f"returned HTTP {response.status}"
            )
        try:
            body = response.json()
            if (
                not isinstance(body, dict)
                or body.get("type") != "file"
                or body.get("encoding") != "base64"
            ):
                raise ResolveError(
                    f"{path} in {repo}@{ref} is not a regular file of up to 1 MB"
                )
            raw = base64.b64decode("".join(body["content"].split()), validate=True)
            return raw.decode("utf-8-sig")
        except (KeyError, TypeError, ValueError, binascii.Error) as err:
            raise ResolveError(f"cannot read {path} in {repo}@{ref}: {err!r}") from err

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

    def repository_tags(self, repo: str) -> list[str]:
        """Names of all git tags of the repository (paginated)."""
        names: list[str] = []
        for page in range(1, MAX_TAG_PAGES + 1):
            batch = self._get_json(
                f"/repos/{repo}/tags?per_page={GITHUB_TAGS_PAGE_SIZE}&page={page}"
            )
            names.extend(str(tag["name"]) for tag in batch)
            if len(batch) < GITHUB_TAGS_PAGE_SIZE:
                return names
        raise ResolveError(
            f"tag list of {repo} exceeds {MAX_TAG_PAGES * GITHUB_TAGS_PAGE_SIZE} tags"
        )

    def tag_commit_sha(self, repo: str, tag: str) -> str:
        """Commit a git tag points to; an annotated tag is peeled to its commit."""
        quoted = urllib.parse.quote(tag, safe="/")
        try:
            target = self._get_json(f"/repos/{repo}/git/ref/tags/{quoted}")["object"]
            for _ in range(MAX_TAG_PEEL_DEPTH):
                if target["type"] == "commit":
                    return str(target["sha"])
                if target["type"] != "tag":
                    raise ResolveError(
                        f"tag {tag} of {repo} points to a {target['type']}, "
                        "not a commit"
                    )
                target = self._get_json(f"/repos/{repo}/git/tags/{target['sha']}")[
                    "object"
                ]
        except (KeyError, TypeError) as err:
            raise ResolveError(
                f"unexpected GitHub API response for tag {tag} of {repo}: {err!r}"
            ) from err
        raise ResolveError(f"tag {tag} of {repo} is nested deeper than expected")


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


def sanitize_id(raw: str) -> str:
    return UNSAFE_ID_CHARS.sub("-", raw)


def target_id(image: str, tag: str) -> str:
    return sanitize_id(f"{image.rsplit('/', 1)[-1]}-{tag}")


def source_target_id(git_ref: str) -> str:
    """Id of a filesystem target; stable across runs, so it never contains the SHA."""
    return sanitize_id(f"source-{git_ref}")


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
        "scanner": SCANNER_TRIVY,
        "kind": "image",
        "image": image,
        "tag": tag,
        "ref": f"{registry}/{image}:{tag}" if tag else None,
        "git_ref": None,
        "commit_sha": None,
        "status": status,
        "reason": reason,
    }


def make_source_target(git_ref: str, commit_sha: str) -> dict[str, Any]:
    """A filesystem target: ``git_ref`` (branch or tag) pinned to ``commit_sha``."""
    return {
        "id": source_target_id(git_ref),
        "scanner": SCANNER_TRIVY,
        "kind": KIND_FS,
        "image": None,
        "tag": None,
        "ref": None,
        "git_ref": git_ref,
        "commit_sha": commit_sha,
        "status": STATUS_PENDING,
        "reason": None,
    }


def make_release_source_target(
    tag: str | None,
    commit_sha: str | None,
    status: str,
    reason: str | None = None,
) -> dict[str, Any]:
    """A filesystem target of a release: the repository at its git ``tag``.

    ``tag`` is what tells a release source from the development one. Without a
    known tag the id is ``source-release``.
    """
    return {
        "id": source_target_id(tag or "release"),
        "scanner": SCANNER_TRIVY,
        "kind": KIND_FS,
        "image": None,
        "tag": tag,
        "ref": None,
        "git_ref": tag,
        "commit_sha": commit_sha,
        "status": status,
        "reason": reason,
    }


def make_osv_target(trivy_target: Mapping[str, Any]) -> dict[str, Any]:
    """The OSV twin of a Trivy target: same subject, another scanner.

    OSV queries the packages Trivy found, so the twin has something to do only if
    the Trivy target is scanned; otherwise there is nothing to query.
    """
    twin = {**trivy_target, "scanner": SCANNER_OSV}
    if trivy_target["status"] != STATUS_PENDING:
        twin.update(
            status=STATUS_NOT_APPLICABLE,
            reason=f"trivy target {trivy_target['status']}",
        )
    return twin


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


def resolve_release_source_targets(
    github: GitHubClient,
    repository: str,
    latest_release: str | None,
    release_lines: int,
    release_error: str | None = None,
) -> list[dict[str, Any]]:
    """Source targets of the releases, newest first: the repository at each tag.

    The releases are those of the image targets (the latest GitHub release for one
    line, else the newest stable ``X.Y.Z`` tag of each line), but taken from the git
    tags of the repository, so that repositories without images have them too.
    ``latest_release`` is the tag of the latest GitHub release (only looked up when
    ``release_lines == 1``); ``release_error`` is set if that lookup failed.
    """
    if release_error is not None:
        return [make_release_source_target(None, None, "failed", release_error)]
    if latest_release is not None:
        tags = [latest_release]
    else:
        try:
            tags = latest_release_lines(
                github.repository_tags(repository), release_lines
            )
        except ResolveError as err:
            return [make_release_source_target(None, None, "failed", str(err))]
        if not tags:
            reason = "no stable release tag in the repository"
            return [make_release_source_target(None, None, "not_applicable", reason)]
    targets = []
    for tag in tags:
        try:
            sha = github.tag_commit_sha(repository, tag)
        except ResolveError as err:
            reason = f"cannot resolve release tag {tag}: {err}"
            targets.append(make_release_source_target(tag, None, "failed", reason))
        else:
            targets.append(make_release_source_target(tag, sha, "pending"))
    return targets


def check_unique_ids(targets: Sequence[Mapping[str, Any]]) -> None:
    """A target is identified by its scanner and id (the id names the subject)."""
    seen: set[tuple[str, str]] = set()
    for target in targets:
        identity = (target["scanner"], target["id"])
        if identity in seen:
            raise ResolveError(f"target id collision: {target['id']!r}")
        seen.add(identity)


def parse_target_patterns(raw: str) -> list[str]:
    """The patterns of the ``targets`` input: separated by commas or newlines."""
    parts = (part.strip() for part in re.split(r"[,\n]", raw))
    return [part for part in parts if part]


def filter_targets(
    targets: Sequence[dict[str, Any]], patterns: Sequence[str]
) -> list[dict[str, Any]]:
    """Keep the targets whose id matches a pattern (``fnmatch``: ``*``, ``?``,
    ``[...]``, case-sensitive). A pattern that matches nothing is an error: a typo
    must not silently scan nothing.
    """
    if not patterns:
        return list(targets)
    unmatched = [
        pattern
        for pattern in patterns
        if not any(fnmatch.fnmatchcase(t["id"], pattern) for t in targets)
    ]
    if unmatched:
        raise ResolveError(
            f"targets: no target matches {', '.join(repr(p) for p in unmatched)}; "
            f"the targets of this repository are: "
            f"{', '.join(t['id'] for t in targets) or 'none'}"
        )
    return [
        t for t in targets if any(fnmatch.fnmatchcase(t["id"], p) for p in patterns)
    ]


def run_kind(
    *,
    patterns: Sequence[str],
    scan_source: bool,
    scan_images: bool,
    scan_release_source: bool,
    osv_enabled: bool,
    early_warning_enabled: bool,
    ref_name: str,
    default_branch: str,
) -> tuple[str, list[str]]:
    """``(kind, reasons)``: ``full`` unless something narrows the scan.

    A run is ``partial`` if the ``targets`` filter is set, if a part of the scan is
    switched off, or if it does not run on the default branch of the calling
    repository.
    """
    narrowing = [
        (bool(patterns), f"targets filter: {', '.join(patterns)}"),
        (not scan_source, "scan-source is off"),
        (not scan_images, "scan-images is off"),
        (not scan_release_source, "scan-release-source is off"),
        (not osv_enabled, "osv-enabled is off"),
        (not early_warning_enabled, "early-warning-enabled is off"),
        (
            ref_name != default_branch,
            f"not the default branch ({ref_name}, the default is {default_branch})",
        ),
    ]
    reasons = [reason for narrows, reason in narrowing if narrows]
    return ("partial" if reasons else "full"), reasons


def resolve_config(
    github: GitHubClient, repository: str, commit_sha: str, override: str
) -> dict[str, Any]:
    """The SCA configuration of the run: the ``config`` input, else the
    ``.github/sca.yml`` of the pinned commit, else the defaults.
    """
    text = github.file_text(repository, sca_config.CONFIG_PATH, commit_sha)
    file_ref = None if text is None else f"{sca_config.CONFIG_PATH}@{commit_sha}"
    return sca_config.build_config(text, file_ref, override)


def resolve_targets(
    *,
    repository: str,
    registry_name: str,
    images: Sequence[str],
    release_lines: int,
    scan_source: bool,
    scan_images: bool,
    scan_release_source: bool,
    osv_enabled: bool,
    github: GitHubClient,
    registry: RegistryClient,
    environ: Mapping[str, str],
    now: datetime,
    caller_repository: str,
    ref_name: str,
    config_input: str = "",
    targets_filter: str = "",
    early_warning_enabled: bool = True,
) -> dict[str, Any]:
    """Build the targets.json document. Raises ResolveError without a snapshot (or
    for a ``targets_filter`` pattern that matches no target) and ConfigError for an
    invalid SCA configuration.

    ``targets_filter`` keeps only the targets whose id matches one of its patterns;
    the OSV twins follow their Trivy targets. The run is ``partial`` (``run_kind``)
    if the filter or a switch narrows the scan, or if ``ref_name`` is not the default
    branch of ``caller_repository``.

    Order: the development source, the release sources (newest first), then the
    images of each image in ``images`` order.
    """
    default_branch = github.default_branch(repository)
    commit_sha = github.commit_sha(repository, default_branch)
    config = resolve_config(github, repository, commit_sha, config_input)

    with_images = scan_images and bool(images)
    with_release_source = scan_source and scan_release_source
    latest_release: str | None = None
    release_error: str | None = None
    if (with_images or with_release_source) and release_lines == 1:
        try:
            latest_release = github.latest_release_tag(repository)
        except ResolveError as err:
            release_error = str(err)

    targets: list[dict[str, Any]] = []
    if scan_source:
        targets.append(make_source_target(default_branch, commit_sha))
    if with_release_source:
        targets.extend(
            resolve_release_source_targets(
                github, repository, latest_release, release_lines, release_error
            )
        )
    if with_images:
        for image in images:
            targets.extend(
                resolve_image_targets(
                    registry, image, latest_release, release_lines, release_error
                )
            )
    patterns = parse_target_patterns(targets_filter)
    targets = filter_targets(targets, patterns)
    kind, kind_reasons = run_kind(
        patterns=patterns,
        scan_source=scan_source,
        scan_images=scan_images,
        scan_release_source=scan_release_source,
        osv_enabled=osv_enabled,
        early_warning_enabled=early_warning_enabled,
        ref_name=ref_name,
        default_branch=github.default_branch(caller_repository),
    )
    if osv_enabled:
        # After all trivy targets, in the same order
        targets.extend([make_osv_target(t) for t in targets])
    check_unique_ids(targets)

    server = environ.get("GITHUB_SERVER_URL", "https://github.com")
    run_id = environ.get("GITHUB_RUN_ID", "")
    run_repository = environ.get("GITHUB_REPOSITORY", "")
    return {
        "repo": repository,
        "default_branch": default_branch,
        "commit_sha": commit_sha,
        "config": config,
        "registry": registry_name,
        "release_lines": release_lines,
        "run_kind": kind,
        "run_kind_reasons": kind_reasons,
        "run_id": run_id,
        "run_url": f"{server}/{run_repository}/actions/runs/{run_id}"
        if run_id and run_repository
        else "",
        "run_started_at": now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "targets": targets,
    }


def build_matrix(targets_doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The pending Trivy targets (the matrix of the trivy job)."""
    keys = ("id", "kind", "image", "tag", "ref", "git_ref", "commit_sha")
    return [
        {k: t[k] for k in keys}
        for t in targets_doc["targets"]
        if t["status"] == STATUS_PENDING and t["scanner"] == SCANNER_TRIVY
    ]


def format_output(name: str, value: str) -> str:
    """One $GITHUB_OUTPUT entry in the delimiter format, safe for multiline values."""
    delimiter = f"ghadelimiter_{secrets.token_hex(16)}"
    return f"{name}<<{delimiter}\n{value}\n{delimiter}\n"


def render_table(targets: Sequence[Mapping[str, Any]]) -> str:
    rows = [("ID", "SCANNER", "REF", "STATUS", "REASON")]
    rows += [
        (t["id"], t["scanner"], t["ref"] or t["kind"], t["status"], t["reason"] or "")
        for t in targets
    ]
    widths = [max(len(row[i]) for row in rows) for i in range(4)]
    lines = [
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row[:4]))
        + f"  {row[4]}"
        for row in rows
    ]
    return "\n".join(line.rstrip() for line in lines)


def annotations(targets: Sequence[Mapping[str, Any]]) -> list[str]:
    """Annotations of the Trivy targets; an OSV twin only mirrors its Trivy target."""
    lines = []
    for target in targets:
        if target["scanner"] != SCANNER_TRIVY:
            continue
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


def describe_config(config: Mapping[str, Any]) -> str:
    """One line on where the SCA configuration came from and what it sets."""
    source = config["source"] or "none, defaults"
    if config["overrides"]:
        source += f" (replaces {config['overrides']})"
    paths = ", ".join(config[sca_config.KEY_NON_SHIPPED_PATHS]) or "none"
    return (
        f"Configuration: {source}; non_shipped_paths: {paths}; "
        f"trivy_skip_paths: {config[sca_config.KEY_TRIVY_SKIP_PATHS]}"
    )


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
        "--scan-release-source",
        default="true",
        help="true/false (default: %(default)s)",
    )
    parser.add_argument(
        "--osv-enabled",
        default="true",
        help="true/false: add an OSV twin of every Trivy target (default: %(default)s)",
    )
    parser.add_argument(
        "--targets",
        default="",
        help=(
            "only the targets whose id matches one of these patterns (commas or "
            "newlines; * and ? work); default: all"
        ),
    )
    parser.add_argument(
        "--early-warning-enabled",
        default="true",
        help="true/false: whether the run has the early warning (default: %(default)s)",
    )
    parser.add_argument(
        "--caller-repository",
        default=None,
        help="owner/name of the repository that runs the workflow "
        "(default: env GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--ref-name",
        default=None,
        help="branch or tag the workflow runs on (default: env GITHUB_REF_NAME)",
    )
    parser.add_argument(
        "--config",
        default="",
        help="SCA configuration (YAML) that replaces .github/sca.yml of the repository",
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
    scan_release_source = parse_bool(args.scan_release_source, "scan-release-source")
    osv_enabled = parse_bool(args.osv_enabled, "osv-enabled")
    early_warning_enabled = parse_bool(
        args.early_warning_enabled, "early-warning-enabled"
    )
    caller_repository = args.caller_repository or environ.get("GITHUB_REPOSITORY", "")
    if not REPOSITORY_NAME.fullmatch(caller_repository):
        raise ResolveError(
            f"caller repository must be 'owner/name', got {caller_repository!r}"
        )
    ref_name = args.ref_name or environ.get("GITHUB_REF_NAME", "")
    if not ref_name:
        raise ResolveError("the branch or tag of the run is unknown (no ref name)")
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
        scan_release_source=scan_release_source,
        osv_enabled=osv_enabled,
        github=github,
        registry=registry,
        environ=environ,
        now=now,
        config_input=args.config,
        targets_filter=args.targets,
        early_warning_enabled=early_warning_enabled,
        caller_repository=caller_repository,
        ref_name=ref_name,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    targets_file = args.output_dir / "targets.json"
    targets_file.write_text(json.dumps(targets_doc, indent=2) + "\n", encoding="utf-8")

    print(
        f"Repository {targets_doc['repo']} @ {targets_doc['default_branch']} "
        f"({targets_doc['commit_sha']})"
    )
    print(describe_config(targets_doc["config"]))
    reasons = "; ".join(targets_doc["run_kind_reasons"])
    print(f"Run kind: {targets_doc['run_kind']}" + (f" ({reasons})" if reasons else ""))
    print(render_table(targets_doc["targets"]))
    for line in annotations(targets_doc["targets"]):
        print(line)

    output_path = environ.get("GITHUB_OUTPUT")
    if output_path:
        outputs = {
            "matrix": json.dumps(build_matrix(targets_doc), separators=(",", ":")),
            "targets-file": str(targets_file),
            "trivy-skip-paths": targets_doc["config"][sca_config.KEY_TRIVY_SKIP_PATHS],
        }
        with open(output_path, "a", encoding="utf-8", newline="\n") as out:
            out.writelines(format_output(k, v) for k, v in outputs.items())
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(args, UrllibTransport(), os.environ, datetime.now(UTC))
    except ResolveError as err:
        print(f"::error title=Scan target resolution failed::{err}")
        return 1
    except sca_config.ConfigError as err:
        print(f"::error title=Invalid SCA configuration::{err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
