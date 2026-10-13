#!/usr/bin/env python3
"""Resolve the scan targets (source snapshot + container images) of one repository.

Used by the SCA scheduled scan. Asks the GitHub REST API through ``gh api`` and the
image registry through ``oras repo tags`` (both are on the runner). Besides the
standard library it needs PyYAML, for the repository configuration
(``.github/sca.yml``, see ``sca_config``).

Every call of an external tool goes through a ``Runner`` (a callable
``(argv, stdin) -> stdout``), so the logic can be tested with a fake runner and no
network.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NamedTuple

import sca_config
from _sca_lib.gha import append_text, escape_command_data, format_output
from _sca_lib.times import format_time

GITHUB_API_VERSION = "2022-11-28"
DOCKER_HUB_REGISTRY_HOST = "registry-1.docker.io"
DOCKER_HUB_ALIASES = {
    "docker.io": DOCKER_HUB_REGISTRY_HOST,
    "index.docker.io": DOCKER_HUB_REGISTRY_HOST,
}
GHCR_HOST = "ghcr.io"
GHCR_USERNAME = "github-actions"  # any username works with a token

SCANNER_TRIVY = "trivy"
SCANNER_OSV = "osv"

KIND_FS = "fs"
KIND_IMAGE = "image"

STATUS_PENDING = "pending"
STATUS_NOT_APPLICABLE = "not_applicable"
STATUS_FAILED = "failed"

TOOL_TIMEOUT_SECONDS = 120.0
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 1.0

_NAME_PART = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
IMAGE_NAME = re.compile(rf"{_NAME_PART}(?:/{_NAME_PART})*", re.ASCII)
REPOSITORY_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
UNSAFE_ID_CHARS = re.compile(r"[^A-Za-z0-9._-]")
# A client error (not rate limiting) will not go away by itself: no retry.
PERMANENT_ERROR = re.compile(r"(?:HTTP|status code:?) (?!429)4\d\d", re.IGNORECASE)
NOT_FOUND = re.compile(r"(?:HTTP|status code:?) 404", re.IGNORECASE)


class ResolveError(Exception):
    """A condition that makes the whole resolution impossible."""


class RegistryError(Exception):
    """A registry problem affecting a single image."""


class ToolError(Exception):
    """An external tool (``gh``, ``oras``) failed; the message is its stderr."""

    @property
    def not_found(self) -> bool:
        return NOT_FOUND.search(str(self)) is not None


Runner = Callable[[Sequence[str], str | None], str]


def make_runner(
    token: str | None,
    sleep: Callable[[float], None] = time.sleep,
    max_attempts: int = MAX_ATTEMPTS,
) -> Runner:
    """The production runner: ``subprocess.run`` with a timeout and bounded retries.

    ``gh`` gets the token as ``GH_TOKEN``. A failure is retried with a growing delay
    unless it is a client error (HTTP 4xx other than 429).
    """
    env = {**os.environ, **({"GH_TOKEN": token} if token else {})}

    def run_tool(argv: Sequence[str], stdin: str | None = None) -> str:
        for attempt in range(1, max_attempts + 1):
            try:
                done = subprocess.run(
                    list(argv),
                    input=stdin,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=TOOL_TIMEOUT_SECONDS,
                    check=False,
                )
                if done.returncode == 0:
                    return done.stdout
                message = done.stderr.strip() or f"{argv[0]} exited {done.returncode}"
            except subprocess.TimeoutExpired:
                message = f"{argv[0]} timed out after {TOOL_TIMEOUT_SECONDS:.0f}s"
            except OSError as err:
                raise ToolError(f"cannot run {argv[0]}: {err}") from err
            if attempt == max_attempts or PERMANENT_ERROR.search(message):
                raise ToolError(message)
            sleep(BACKOFF_BASE_SECONDS * 2 ** (attempt - 1))
        raise AssertionError("unreachable")  # pragma: no cover

    return run_tool


class GitHubClient:
    """The GitHub REST API through ``gh api``."""

    def __init__(self, run: Runner) -> None:
        self._run = run

    def _api(self, path: str, *flags: str, missing_ok: bool = False) -> Any:
        """The JSON response of GET ``path``; None for HTTP 404 if ``missing_ok``."""
        argv = ["gh", "api", "-H", f"X-GitHub-Api-Version: {GITHUB_API_VERSION}"]
        try:
            return json.loads(self._run([*argv, *flags, path], None))
        except ToolError as err:
            if missing_ok and err.not_found:
                return None
            raise ResolveError(f"GitHub API GET {path} failed: {err}") from err
        except ValueError as err:
            raise ResolveError(f"GitHub API GET {path}: invalid JSON: {err}") from err

    def default_branch(self, repo: str) -> str:
        return str(self._api(f"repos/{repo}")["default_branch"])

    def commit_sha(self, repo: str, ref: str) -> str:
        quoted = urllib.parse.quote(ref, safe="")
        return str(self._api(f"repos/{repo}/commits/{quoted}")["sha"])

    def file_text(self, repo: str, path: str, ref: str) -> str | None:
        """Text of a file of the repository at a commit, or None if there is none."""
        quoted = urllib.parse.quote(path, safe="/")
        ref_query = urllib.parse.quote(ref, safe="")
        body = self._api(
            f"repos/{repo}/contents/{quoted}?ref={ref_query}", missing_ok=True
        )
        if body is None:
            return None
        try:
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
        """Tag of the latest GitHub release, or None if the repo has none (HTTP 404)."""
        release = self._api(f"repos/{repo}/releases/latest", missing_ok=True)
        return None if release is None else str(release["tag_name"])

    def tag_commit_sha(self, repo: str, tag: str) -> str:
        """Commit a git tag points to (the API peels an annotated tag to its commit)."""
        quoted = urllib.parse.quote(tag, safe="/")
        return str(self._api(f"repos/{repo}/commits/refs/tags/{quoted}")["sha"])


class RegistryClient:
    """Lists image tags with ``oras repo tags`` (any OCI registry)."""

    def __init__(
        self, run: Runner, registry: str, github_token: str | None = None
    ) -> None:
        self.registry = registry
        self._host = DOCKER_HUB_ALIASES.get(registry, registry)
        self._run = run
        self._github_token = github_token
        self._tags_cache: dict[str, list[str]] = {}

    def tags(self, image: str) -> list[str]:
        """All tags of an image (cached). Raises RegistryError on any failure."""
        if image not in self._tags_cache:
            self._tags_cache[image] = self._list_tags(image)
        return self._tags_cache[image]

    def _list_tags(self, image: str) -> list[str]:
        repository = image
        if self._host == DOCKER_HUB_REGISTRY_HOST and "/" not in image:
            repository = f"library/{image}"
        argv = ["oras", "repo", "tags"]
        stdin = None
        # Credentials go to ghcr.io only; every other registry is asked anonymously.
        if self._github_token and self._host == GHCR_HOST:
            argv += ["--username", GHCR_USERNAME, "--password-stdin"]
            stdin = self._github_token
        argv.append(f"{self._host}/{repository}")
        try:
            return self._run(argv, stdin).split()
        except ToolError as err:
            raise RegistryError(
                f"{self.registry}: listing tags of {image} failed: {err}"
            ) from err


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
    kind: str,
    status: str,
    reason: str | None = None,
    *,
    image: str | None = None,
    tag: str | None = None,
    ref: str | None = None,
    git_ref: str | None = None,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    """A Trivy target: an image, or a filesystem target (``git_ref`` pinned to
    ``commit_sha``; a release source has a ``tag``, the development one has none).

    Without a known tag the id is ``<image>-release`` or ``source-release``.
    """
    if kind == KIND_IMAGE:
        ident = target_id(str(image), tag or "release")
    else:
        ident = source_target_id(git_ref or "release")
    return {
        "id": ident,
        "scanner": SCANNER_TRIVY,
        "kind": kind,
        "image": image,
        "tag": tag,
        "ref": ref,
        "git_ref": git_ref,
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


class Release(NamedTuple):
    """The release of the run: its ``tag``, or the ``error`` of the lookup; both are
    None if the repository has no GitHub release."""

    tag: str | None
    error: str | None = None


def resolve_release(github: GitHubClient, repository: str) -> Release:
    """The release to scan: the latest GitHub release, as it is."""
    try:
        tag = github.latest_release_tag(repository)
    except ResolveError as err:
        return Release(None, str(err))
    return Release(tag)


def resolve_image_targets(
    registry: RegistryClient, image: str, release: Release
) -> list[dict[str, Any]]:
    """Targets of one image: the ``development`` tag and the tag of the release."""

    def image_target(tag: str | None, status: str, reason: str | None = None):
        ref = f"{registry.registry}/{image}:{tag}" if tag else None
        return make_target(KIND_IMAGE, status, reason, image=image, tag=tag, ref=ref)

    try:
        tags = registry.tags(image)
    except RegistryError as err:
        reason = str(err)
        return [
            image_target("development", STATUS_FAILED, reason),
            image_target(release.tag, STATUS_FAILED, reason),
        ]

    if "development" in tags:
        targets = [image_target("development", STATUS_PENDING)]
    else:
        reason = "tag development not published for this image"
        targets = [image_target("development", STATUS_NOT_APPLICABLE, reason)]

    if release.error is not None:
        targets.append(image_target(None, STATUS_FAILED, release.error))
    elif release.tag is None:
        reason = "no GitHub release"
        targets.append(image_target(None, STATUS_NOT_APPLICABLE, reason))
    elif (found := find_release_tag(release.tag, tags)) is None:
        reason = f"release {release.tag} not published for this image"
        targets.append(image_target(release.tag, STATUS_NOT_APPLICABLE, reason))
    else:
        targets.append(image_target(found, STATUS_PENDING))
    return targets


def resolve_release_source_target(
    github: GitHubClient, repository: str, release: Release
) -> dict[str, Any]:
    """The source target of the release: the repository at its git tag, so that
    repositories without images have a release scan too."""

    def source_target(status: str, reason: str | None = None, sha: str | None = None):
        return make_target(
            KIND_FS,
            status,
            reason,
            tag=release.tag,
            git_ref=release.tag,
            commit_sha=sha,
        )

    if release.error is not None:
        return source_target(STATUS_FAILED, release.error)
    if release.tag is None:
        return source_target(STATUS_NOT_APPLICABLE, "no GitHub release")
    try:
        sha = github.tag_commit_sha(repository, release.tag)
    except ResolveError as err:
        reason = f"cannot resolve release tag {release.tag}: {err}"
        return source_target(STATUS_FAILED, reason)
    return source_target(STATUS_PENDING, sha=sha)


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


@dataclass(frozen=True)
class Inputs:
    """The inputs of the action (see ``action.yml``)."""

    repository: str
    output_dir: Path
    caller_repository: str
    ref_name: str
    registry: str = GHCR_HOST
    images: Sequence[str] = ()
    scan_source: bool = True
    scan_images: bool = True
    scan_release_source: bool = True
    osv_enabled: bool = True
    early_warning_enabled: bool = True
    targets_filter: str = ""
    config: str = ""
    token: str | None = None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> Inputs:
        """Read and validate the inputs, which the action passes as environment
        variables (``REPOSITORY``, ``SCAN_SOURCE``, ...)."""

        def flag(name: str) -> bool:
            return parse_bool(environ.get(name, "true"), name.lower().replace("_", "-"))

        repository = environ.get("REPOSITORY", "")
        if not REPOSITORY_NAME.fullmatch(repository):
            raise ResolveError(f"repository must be 'owner/name', got {repository!r}")
        caller_repository = environ.get("GITHUB_REPOSITORY", "")
        if not REPOSITORY_NAME.fullmatch(caller_repository):
            raise ResolveError(
                f"caller repository must be 'owner/name', got {caller_repository!r}"
            )
        ref_name = environ.get("GITHUB_REF_NAME", "")
        if not ref_name:
            raise ResolveError("the branch or tag of the run is unknown (no ref name)")
        if not environ.get("OUTPUT_DIR"):
            raise ResolveError("OUTPUT_DIR is not set")
        return cls(
            repository=repository,
            output_dir=Path(environ["OUTPUT_DIR"]),
            caller_repository=caller_repository,
            ref_name=ref_name,
            registry=environ.get("REGISTRY") or GHCR_HOST,
            images=tuple(parse_images(environ.get("IMAGES", ""))),
            scan_source=flag("SCAN_SOURCE"),
            scan_images=flag("SCAN_IMAGES"),
            scan_release_source=flag("SCAN_RELEASE_SOURCE"),
            osv_enabled=flag("OSV_ENABLED"),
            early_warning_enabled=flag("EARLY_WARNING_ENABLED"),
            targets_filter=environ.get("TARGETS", ""),
            config=environ.get("CONFIG", ""),
            token=environ.get("GITHUB_TOKEN") or None,
        )


def resolve_targets(
    inputs: Inputs,
    github: GitHubClient,
    registry: RegistryClient,
    environ: Mapping[str, str],
    now: datetime,
) -> dict[str, Any]:
    """Build the targets.json document. Raises ResolveError without a snapshot (or
    for a ``targets_filter`` pattern that matches no target) and ConfigError for an
    invalid SCA configuration.

    One release is scanned (``resolve_release``): its source and, in every image, its
    tag. ``targets_filter`` keeps only the targets whose id matches one of its
    patterns; the OSV twins follow their Trivy targets. The run is ``partial``
    (``run_kind``) if the filter or a switch narrows the scan, or if the run is not on
    the default branch of the calling repository.

    Order: the development source, the release source, then the images of each image
    in ``images`` order.
    """
    repository = inputs.repository
    default_branch = github.default_branch(repository)
    commit_sha = github.commit_sha(repository, default_branch)
    config = resolve_config(github, repository, commit_sha, inputs.config)

    with_images = inputs.scan_images and bool(inputs.images)
    with_release_source = inputs.scan_source and inputs.scan_release_source
    release = Release(None)
    if with_images or with_release_source:
        release = resolve_release(github, repository)

    targets: list[dict[str, Any]] = []
    if inputs.scan_source:
        targets.append(
            make_target(
                KIND_FS,
                STATUS_PENDING,
                git_ref=default_branch,
                commit_sha=commit_sha,
            )
        )
    if with_release_source:
        targets.append(resolve_release_source_target(github, repository, release))
    if with_images:
        for image in inputs.images:
            targets.extend(resolve_image_targets(registry, image, release))
    patterns = parse_target_patterns(inputs.targets_filter)
    targets = filter_targets(targets, patterns)
    kind, kind_reasons = run_kind(
        patterns=patterns,
        scan_source=inputs.scan_source,
        scan_images=inputs.scan_images,
        scan_release_source=inputs.scan_release_source,
        osv_enabled=inputs.osv_enabled,
        early_warning_enabled=inputs.early_warning_enabled,
        ref_name=inputs.ref_name,
        default_branch=github.default_branch(inputs.caller_repository),
    )
    if inputs.osv_enabled:
        # After all trivy targets, in the same order
        targets.extend([make_osv_target(t) for t in targets])
    check_unique_ids(targets)

    server = environ.get("GITHUB_SERVER_URL", "https://github.com")
    run_id = environ.get("GITHUB_RUN_ID", "")
    return {
        "repo": repository,
        "default_branch": default_branch,
        "commit_sha": commit_sha,
        "config": config,
        "registry": inputs.registry,
        "run_kind": kind,
        "run_kind_reasons": kind_reasons,
        "run_id": run_id,
        "run_url": f"{server}/{inputs.caller_repository}/actions/runs/{run_id}"
        if run_id
        else "",
        "run_started_at": format_time(now),
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
                f"::notice title=Scan target {target['id']} skipped"
                f"::{escape_command_data(target['reason'])}"
            )
        elif target["status"] == "failed":
            lines.append(
                f"::warning title=Scan target {target['id']} failed to resolve"
                f"::{escape_command_data(target['reason'])}"
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


def run(
    environ: Mapping[str, str],
    runner: Runner | None = None,
    now: datetime | None = None,
) -> int:
    inputs = Inputs.from_environ(environ)
    run_tool = runner or make_runner(inputs.token)
    targets_doc = resolve_targets(
        inputs,
        GitHubClient(run_tool),
        RegistryClient(run_tool, inputs.registry, inputs.token),
        environ,
        now or datetime.now(UTC),
    )

    inputs.output_dir.mkdir(parents=True, exist_ok=True)
    targets_file = inputs.output_dir / "targets.json"
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
            # Decided here, once; the early warning job and the merge follow it
            "early-warning-enabled": "true"
            if inputs.early_warning_enabled
            else "false",
        }
        append_text(
            output_path, "".join(format_output(k, v) for k, v in outputs.items())
        )
    return 0


def main() -> int:
    try:
        return run(os.environ)
    except ResolveError as err:
        print(
            f"::error title=Scan target resolution failed::{escape_command_data(err)}"
        )
        return 1
    except sca_config.ConfigError as err:
        print(f"::error title=Invalid SCA configuration::{escape_command_data(err)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
