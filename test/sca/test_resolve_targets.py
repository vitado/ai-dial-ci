"""Tests for sca_resolve_targets/resolve_targets.py (fake transport, no network)."""

import base64
import importlib.util
import json
import sys
import urllib.parse
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "actions"
    / "sca_resolve_targets"
    / "resolve_targets.py"
)
_spec = importlib.util.spec_from_file_location("resolve_targets", SCRIPT)
assert _spec is not None
assert _spec.loader is not None
rt = importlib.util.module_from_spec(_spec)
sys.modules["resolve_targets"] = rt
_spec.loader.exec_module(rt)

API = "https://api.github.test"
REPOSITORY = "example/app"
NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)
SHA = "a" * 40
CONFIG_URL = f"{API}/repos/{REPOSITORY}/contents/.github/sca.yml?ref={SHA}"
ENV = {
    "GITHUB_API_URL": API,
    "GITHUB_RUN_ID": "42",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "example/caller",
    "GITHUB_REF_NAME": "development",
}
CALLER = "example/caller"


class FakeTransport:
    """Routes URLs to canned responses and records every call."""

    def __init__(self) -> None:
        self.routes: dict[str, Any] = {}
        self.calls: list[tuple[str, dict[str, str]]] = []

    def add(self, url: str, response: Any) -> None:
        """``response``: a Response, an exception or a list (consumed in order)."""
        self.routes[url] = response

    def __call__(self, url: str, headers: Mapping[str, str]) -> Any:
        self.calls.append((url, dict(headers)))
        route = self.routes.get(url)
        if route is None:
            return rt.Response(599, {}, b"unrouted")
        current = (
            (route.pop(0) if len(route) > 1 else route[0])
            if isinstance(route, list)
            else route
        )
        if isinstance(current, Exception):
            raise current
        return current


def ok(payload: Any, headers: Mapping[str, str] | None = None) -> Any:
    return rt.Response(200, headers or {}, json.dumps(payload).encode())


def tags_url(image: str, host: str = "ghcr.io") -> str:
    return f"https://{host}/v2/{image}/tags/list?n=1000"


def github_routes(
    transport: FakeTransport,
    release: str | None = "1.1.14",
    release_status: int | None = None,
    branch: str = "development",
) -> None:
    transport.add(f"{API}/repos/{REPOSITORY}", ok({"default_branch": branch}))
    # the repository that runs the workflow, to tell a run on its default branch
    transport.routes.setdefault(
        f"{API}/repos/{CALLER}", ok({"default_branch": "development"})
    )
    quoted = urllib.parse.quote(branch, safe="")
    transport.add(f"{API}/repos/{REPOSITORY}/commits/{quoted}", ok({"sha": "a" * 40}))
    # no .github/sca.yml: the defaults
    transport.routes.setdefault(CONFIG_URL, rt.Response(404))
    latest = f"{API}/repos/{REPOSITORY}/releases/latest"
    if release_status is not None:
        transport.add(latest, rt.Response(release_status))
    elif release is None:
        transport.add(latest, rt.Response(404))
    else:
        transport.add(latest, ok({"tag_name": release}))


def tag_routes(
    transport: FakeTransport,
    tag: str,
    sha: str,
    annotated_as: str | None = None,
) -> None:
    """A git tag at ``sha``, annotated (via tag object ``annotated_as``) or not."""
    ref = f"{API}/repos/{REPOSITORY}/git/ref/tags/{tag}"
    if annotated_as is None:
        transport.add(ref, ok({"object": {"type": "commit", "sha": sha}}))
        return
    transport.add(ref, ok({"object": {"type": "tag", "sha": annotated_as}}))
    transport.add(
        f"{API}/repos/{REPOSITORY}/git/tags/{annotated_as}",
        ok({"object": {"type": "commit", "sha": sha}}),
    )


def git_tags_route(transport: FakeTransport, names: list[str], page: int = 1) -> None:
    transport.add(
        f"{API}/repos/{REPOSITORY}/tags?per_page=100&page={page}",
        ok([{"name": name} for name in names]),
    )


def no_sleep_http(transport: FakeTransport) -> Any:
    return rt.HttpClient(transport, sleep=lambda _: None)


def run_resolve_targets(
    transport: FakeTransport,
    images: list[str],
    release_lines: int = 1,
    scan_source: bool = True,
    scan_images: bool = True,
    scan_release_source: bool = False,
    osv_enabled: bool = False,
    token: str | None = "tkn",
    **kwargs: Any,
) -> dict[str, Any]:
    http = no_sleep_http(transport)
    return rt.resolve_targets(
        repository=REPOSITORY,
        registry_name="ghcr.io",
        images=images,
        release_lines=release_lines,
        scan_source=scan_source,
        scan_images=scan_images,
        scan_release_source=scan_release_source,
        osv_enabled=osv_enabled,
        github=rt.GitHubClient(http, token, API),
        registry=rt.RegistryClient(http, "ghcr.io", token),
        environ=ENV,
        now=NOW,
        caller_repository=CALLER,
        **{"ref_name": "development", **kwargs},
    )


TARGET_KEYS = {"id", "kind", "image", "tag", "ref", "git_ref", "commit_sha"}


def by_id(targets_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {t["id"]: t for t in targets_doc["targets"]}


# --- semver -------------------------------------------------------------------


def test_semver_numeric_not_lexical() -> None:
    assert rt.latest_release_lines(["0.9.1", "0.12.0", "0.10.3"], 1) == ["0.12.0"]
    assert rt.parse_stable_semver("0.12.0") > rt.parse_stable_semver("0.9.1")


def test_semver_excludes_prereleases_and_noise() -> None:
    tags = [
        "1.2.0-rc.1",
        "1.2.0",
        "1.3.0-rc.0",
        "development",
        "latest",
        "1.2",
        "sha-abc",
        "1.2.3.4",
    ]
    assert rt.latest_release_lines(tags, 5) == ["1.2.0"]


def test_semver_v_prefix_and_max_patch_per_line() -> None:
    tags = ["v1.2.1", "v1.2.10", "v1.2.9", "1.1.5", "1.1.4"]
    assert rt.latest_release_lines(tags, 5) == ["v1.2.10", "1.1.5"]


def test_semver_same_version_prefers_unprefixed() -> None:
    assert rt.latest_release_lines(["v1.0.0", "1.0.0"], 1) == ["1.0.0"]


def test_semver_n_highest_lines() -> None:
    tags = ["0.9.1", "0.9.0", "0.12.0", "0.11.2", "0.11.1", "1.0.0"]
    assert rt.latest_release_lines(tags, 3) == ["1.0.0", "0.12.0", "0.11.2"]


def test_semver_no_stable_tags() -> None:
    assert rt.latest_release_lines(["development", "1.0.0-rc.1"], 2) == []


# --- targets ------------------------------------------------------------------


def test_release_lines_1_uses_github_latest_release() -> None:
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    t.add(
        tags_url("example/app"),
        ok({"tags": ["development", "1.1.14", "1.2.0", "1.1.13"]}),
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
    t = FakeTransport()
    github_routes(t)
    targets_doc = run_resolve_targets(t, [])
    assert targets_doc["repo"] == REPOSITORY
    assert targets_doc["default_branch"] == "development"
    assert targets_doc["commit_sha"] == "a" * 40
    assert targets_doc["registry"] == "ghcr.io"
    assert targets_doc["release_lines"] == 1
    assert targets_doc["run_id"] == "42"
    assert targets_doc["run_url"] == "https://github.com/example/caller/actions/runs/42"
    assert targets_doc["run_started_at"] == "2026-10-11T12:00:00Z"


def test_release_lines_1_matches_v_stripped_tag() -> None:
    t = FakeTransport()
    github_routes(t, release="v1.1.14")
    t.add(tags_url("example/x"), ok({"tags": ["development", "1.1.14"]}))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-1.1.14"]["status"] == "pending"
    assert targets["x-1.1.14"]["ref"] == "ghcr.io/example/x:1.1.14"


def test_release_lines_3_uses_registry_semver_and_skips_github_release() -> None:
    t = FakeTransport()
    github_routes(t)
    tags = [
        "development",
        "0.9.1",
        "0.12.0",
        "0.12.1",
        "0.11.4",
        "0.13.0-rc.1",
        "0.10.0",
    ]
    t.add(tags_url("example/x"), ok({"tags": tags}))
    targets_doc = run_resolve_targets(t, ["example/x"], release_lines=3)
    pending = [x["id"] for x in targets_doc["targets"] if x["status"] == "pending"]
    assert pending == [
        "source-development",
        "x-development",
        "x-0.12.1",
        "x-0.11.4",
        "x-0.10.0",
    ]
    assert not any(url.endswith("/releases/latest") for url, _ in t.calls)


def test_no_github_release_falls_back_to_registry_semver() -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    t.add(
        tags_url("example/x"),
        ok({"tags": ["development", "0.9.1", "0.12.0", "0.12.0-rc.1"]}),
    )
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-0.12.0"]["status"] == "pending"
    assert "x-0.9.1" not in targets


def test_release_tag_missing_for_image_is_not_applicable() -> None:
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app-bff"), ok({"tags": ["development"]}))
    targets = by_id(run_resolve_targets(t, ["example/app-bff"]))
    assert targets["app-bff-development"]["status"] == "pending"
    missing = targets["app-bff-1.1.14"]
    assert missing["status"] == "not_applicable"
    assert missing["reason"] == "release 1.1.14 not published for this image"


def test_missing_development_tag_is_not_applicable() -> None:
    t = FakeTransport()
    github_routes(t, release="1.0.0")
    t.add(tags_url("example/x"), ok({"tags": ["1.0.0"]}))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "not_applicable"
    assert targets["x-1.0.0"]["status"] == "pending"


def test_no_stable_tags_gives_single_not_applicable_release_target() -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    t.add(tags_url("example/x"), ok({"tags": ["development", "1.0.0-rc.1"]}))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-release"]["status"] == "not_applicable"
    assert targets["x-release"]["tag"] is None
    assert targets["x-release"]["ref"] is None


def test_null_tags_in_registry_response() -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    t.add(tags_url("example/x"), ok({"name": "example/x", "tags": None}))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "not_applicable"
    assert targets["x-release"]["status"] == "not_applicable"


def test_registry_error_fails_only_that_image() -> None:
    t = FakeTransport()
    github_routes(t, release="1.0.0")
    t.add(tags_url("example/bad"), rt.Response(404))
    t.add(tags_url("example/good"), ok({"tags": ["development", "1.0.0"]}))
    targets = by_id(run_resolve_targets(t, ["example/bad", "example/good"]))
    assert targets["bad-development"]["status"] == "failed"
    assert "HTTP 404" in targets["bad-development"]["reason"]
    assert targets["bad-1.0.0"]["status"] == "failed"
    assert targets["good-development"]["status"] == "pending"
    assert targets["good-1.0.0"]["status"] == "pending"


def test_registry_network_error_after_retries_fails_image() -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    t.add(tags_url("example/x"), rt.TransportError("boom"))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "failed"
    assert "boom" in targets["x-development"]["reason"]
    assert (
        sum(1 for url, _ in t.calls if url == tags_url("example/x")) == rt.MAX_ATTEMPTS
    )


def test_github_release_api_error_fails_release_targets_but_keeps_development() -> None:
    t = FakeTransport()
    github_routes(t, release_status=403)
    t.add(tags_url("example/x"), ok({"tags": ["development", "1.0.0"]}))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "pending"
    assert targets["x-release"]["status"] == "failed"
    assert "HTTP 403" in targets["x-release"]["reason"]


@pytest.mark.parametrize("missing", ["repo", "commit"])
def test_snapshot_failure_is_fatal(missing: str) -> None:
    t = FakeTransport()
    github_routes(t)
    t.add(
        f"{API}/repos/{REPOSITORY}"
        + ("/commits/development" if missing == "commit" else ""),
        rt.Response(404),
    )
    with pytest.raises(rt.ResolveError, match="HTTP 404"):
        run_resolve_targets(t, [])


def test_snapshot_network_failure_is_fatal() -> None:
    t = FakeTransport()
    t.add(f"{API}/repos/{REPOSITORY}", rt.TransportError("down"))
    with pytest.raises(rt.ResolveError, match="down"):
        run_resolve_targets(t, [])


def test_empty_images_only_source() -> None:
    t = FakeTransport()
    github_routes(t)
    targets_doc = run_resolve_targets(t, [])
    assert [x["id"] for x in targets_doc["targets"]] == ["source-development"]
    assert not any("/v2/" in url for url, _ in t.calls)


def test_scan_source_false() -> None:
    t = FakeTransport()
    github_routes(t)
    t.add(tags_url("example/x"), ok({"tags": ["development", "1.1.14"]}))
    targets = by_id(run_resolve_targets(t, ["example/x"], scan_source=False))
    assert "source-development" not in targets
    assert "x-development" in targets


def test_scan_images_false() -> None:
    t = FakeTransport()
    github_routes(t)
    targets_doc = run_resolve_targets(t, ["example/x"], scan_images=False)
    assert [x["id"] for x in targets_doc["targets"]] == ["source-development"]


def test_id_collision_rejected() -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    t.add(tags_url("a/x"), ok({"tags": ["development"]}))
    t.add(tags_url("b/x"), ok({"tags": ["development"]}))
    with pytest.raises(rt.ResolveError, match="collision"):
        run_resolve_targets(t, ["a/x", "b/x"])


def test_matrix_has_only_pending_targets_without_status() -> None:
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/bff"), ok({"tags": ["development"]}))
    matrix = rt.build_matrix(run_resolve_targets(t, ["example/bff"]))
    assert [m["id"] for m in matrix] == ["source-development", "bff-development"]
    assert all(set(m) == TARGET_KEYS for m in matrix)


def test_source_target_id_from_git_ref() -> None:
    assert rt.source_target_id("development") == "source-development"
    assert rt.source_target_id("release/1.2") == "source-release-1.2"
    assert rt.source_target_id("v1.2.3") == "source-v1.2.3"
    assert rt.source_target_id("feat/a b") == "source-feat-a-b"


def test_source_target_id_sanitized_and_independent_of_sha() -> None:
    t = FakeTransport()
    github_routes(t, branch="release/1.2")
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-release-1.2"]
    assert targets["source-release-1.2"]["git_ref"] == "release/1.2"
    assert "a" * 40 not in "".join(targets)


def test_fs_target_carries_git_ref_and_commit_sha() -> None:
    t = FakeTransport()
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
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), ok({"tags": ["development"]}))
    targets_doc = run_resolve_targets(t, ["example/app"])
    kinds = {x["kind"] for x in targets_doc["targets"]}
    assert kinds == {"fs", "image"}
    for target in targets_doc["targets"]:
        assert set(target) == TARGET_KEYS | {"scanner", "status", "reason"}
        assert target["scanner"] == "trivy"
        if target["kind"] == "image":
            assert target["git_ref"] is None
            assert target["commit_sha"] is None
        else:
            assert target["git_ref"]
            assert target["commit_sha"]
    assert all(set(m) == TARGET_KEYS for m in rt.build_matrix(targets_doc))


def test_matrix_carries_commit_sha_of_fs_target() -> None:
    t = FakeTransport()
    github_routes(t)
    (fs,) = rt.build_matrix(run_resolve_targets(t, []))
    assert (fs["git_ref"], fs["commit_sha"]) == ("development", "a" * 40)


def test_target_id_sanitized() -> None:
    assert rt.target_id("example/some_image", "1.2.3") == "some_image-1.2.3"
    assert rt.target_id("example/x", "a b+c") == "x-a-b-c"


# --- inputs -------------------------------------------------------------------


def test_parse_images_ignores_blank_lines_and_whitespace() -> None:
    assert rt.parse_images("\n  example/a  \n\n\texample/b\n  \n") == [
        "example/a",
        "example/b",
    ]
    assert rt.parse_images("") == []


def test_parse_images_rejects_duplicates() -> None:
    with pytest.raises(rt.ResolveError, match="duplicate"):
        rt.parse_images("example/a\n example/a ")


@pytest.mark.parametrize(
    "bad", ["ghcr.io/example/a:1.0", "EXAMPLE/a", "example/a:tag", "../a", "example//a"]
)
def test_parse_images_rejects_invalid_names(bad: str) -> None:
    with pytest.raises(rt.ResolveError, match="invalid image name"):
        rt.parse_images(bad)


def test_parse_bool() -> None:
    assert rt.parse_bool("True", "x") is True
    assert rt.parse_bool(" false ", "x") is False
    with pytest.raises(rt.ResolveError):
        rt.parse_bool("yes", "x")


# --- registry protocol --------------------------------------------------------

CHALLENGE = 'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:example/x:pull"'
GHCR_TOKEN_URL = (
    "https://ghcr.io/token?scope=repository%3Aexample%2Fx%3Apull&service=ghcr.io"
)


def test_registry_401_token_flow_with_ghcr_basic_auth() -> None:
    t = FakeTransport()
    t.add(
        tags_url("example/x"),
        [
            rt.Response(401, {"WWW-Authenticate": CHALLENGE}),
            ok({"tags": ["development"]}),
        ],
    )
    t.add(GHCR_TOKEN_URL, ok({"token": "BEARER"}))
    client = rt.RegistryClient(no_sleep_http(t), "ghcr.io", "gh-token")
    assert client.tags("example/x") == ["development"]
    (_, first), (token_url, token_headers), (_, retry) = t.calls
    assert "Authorization" not in first
    assert token_url == GHCR_TOKEN_URL
    assert token_headers["Authorization"].startswith("Basic ")
    assert retry["Authorization"] == "Bearer BEARER"


def test_registry_anonymous_token_without_github_token() -> None:
    t = FakeTransport()
    t.add(
        tags_url("example/x"),
        [rt.Response(401, {"WWW-Authenticate": CHALLENGE}), ok({"tags": ["a"]})],
    )
    t.add(GHCR_TOKEN_URL, ok({"token": "T"}))
    client = rt.RegistryClient(no_sleep_http(t), "ghcr.io", None)
    assert client.tags("example/x") == ["a"]
    assert "Authorization" not in t.calls[1][1]


def test_github_token_not_sent_to_foreign_registry() -> None:
    t = FakeTransport()
    challenge = (
        'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'
    )
    url = "https://registry-1.docker.io/v2/example/x/tags/list?n=1000"
    t.add(
        url,
        [
            rt.Response(401, {"WWW-Authenticate": challenge}),
            ok({"tags": ["development"]}),
        ],
    )
    realm = "https://auth.docker.io/token?scope=repository%3Aexample%2Fx%3Apull&service=registry.docker.io"
    t.add(realm, ok({"access_token": "T"}))
    client = rt.RegistryClient(no_sleep_http(t), "docker.io", "gh-token")
    assert client.tags("example/x") == ["development"]
    assert "Authorization" not in t.calls[1][1]
    assert t.calls[2][1]["Authorization"] == "Bearer T"


def test_docker_hub_official_images_use_library_namespace() -> None:
    t = FakeTransport()
    t.add(
        "https://registry-1.docker.io/v2/library/nginx/tags/list?n=1000",
        ok({"tags": ["1.0.0"]}),
    )
    assert rt.RegistryClient(no_sleep_http(t), "docker.io").tags("nginx") == ["1.0.0"]


def test_registry_rejects_unsupported_challenge() -> None:
    t = FakeTransport()
    t.add(
        tags_url("example/x"), rt.Response(401, {"WWW-Authenticate": 'Basic realm="x"'})
    )
    with pytest.raises(rt.RegistryError, match="unsupported"):
        rt.RegistryClient(no_sleep_http(t), "ghcr.io").tags("example/x")


def test_registry_401_without_challenge_is_error() -> None:
    t = FakeTransport()
    t.add(tags_url("example/x"), rt.Response(401))
    with pytest.raises(rt.RegistryError, match="HTTP 401"):
        rt.RegistryClient(no_sleep_http(t), "ghcr.io").tags("example/x")


def test_registry_pagination_via_link_header() -> None:
    t = FakeTransport()
    page2 = "/v2/example/x/tags/list?last=b&n=1000"
    page3 = "https://ghcr.io/v2/example/x/tags/list?last=c&n=1000"
    t.add(
        tags_url("example/x"),
        ok({"tags": ["a", "b"]}, {"Link": f'<{page2}>; rel="next"'}),
    )
    t.add(
        f"https://ghcr.io{page2}",
        ok({"tags": ["c"]}, {"Link": f'<{page3}>; rel="next"'}),
    )
    t.add(page3, ok({"tags": ["d"]}))
    assert rt.RegistryClient(no_sleep_http(t), "ghcr.io").tags("example/x") == [
        "a",
        "b",
        "c",
        "d",
    ]


def test_registry_pagination_loop_is_bounded() -> None:
    t = FakeTransport()
    t.add(
        tags_url("example/x"),
        ok({"tags": ["a"]}, {"Link": f'<{tags_url("example/x")}>; rel="next"'}),
    )
    with pytest.raises(rt.RegistryError, match="pages"):
        rt.RegistryClient(no_sleep_http(t), "ghcr.io").tags("example/x")


def test_registry_tags_cached_per_image() -> None:
    t = FakeTransport()
    t.add(tags_url("example/x"), ok({"tags": ["a"]}))
    client = rt.RegistryClient(no_sleep_http(t), "ghcr.io")
    client.tags("example/x")
    client.tags("example/x")
    assert len(t.calls) == 1


# --- retry --------------------------------------------------------------------


def test_retry_honours_retry_after_and_backoff() -> None:
    t = FakeTransport()
    t.add(
        "https://h/x",
        [rt.Response(429, {"Retry-After": "7"}), rt.Response(503), rt.Response(200)],
    )
    sleeps: list[float] = []
    assert rt.HttpClient(t, sleep=sleeps.append).get("https://h/x", {}).status == 200
    assert sleeps == [7.0, 2.0]


def test_retry_after_is_capped() -> None:
    t = FakeTransport()
    t.add("https://h/x", [rt.Response(429, {"Retry-After": "86400"}), rt.Response(200)])
    sleeps: list[float] = []
    rt.HttpClient(t, sleep=sleeps.append).get("https://h/x", {})
    assert sleeps == [rt.MAX_RETRY_AFTER_SECONDS]


def test_retry_gives_up_and_returns_last_response() -> None:
    t = FakeTransport()
    t.add("https://h/x", rt.Response(500))
    sleeps: list[float] = []
    assert rt.HttpClient(t, sleep=sleeps.append).get("https://h/x", {}).status == 500
    assert len(t.calls) == rt.MAX_ATTEMPTS
    assert len(sleeps) == rt.MAX_ATTEMPTS - 1


def test_no_retry_on_client_error() -> None:
    t = FakeTransport()
    t.add("https://h/x", rt.Response(404))
    assert no_sleep_http(t).get("https://h/x", {}).status == 404
    assert len(t.calls) == 1


def test_github_requests_carry_required_headers() -> None:
    t = FakeTransport()
    github_routes(t)
    run_resolve_targets(t, [], token="secret")
    for _, headers in t.calls:
        assert headers["Accept"] == "application/vnd.github+json"
        assert headers["X-GitHub-Api-Version"] == "2022-11-28"
        assert headers["Authorization"] == "Bearer secret"


# --- output formatting and CLI ---------------------------------------------------


def test_format_output_is_multiline_safe() -> None:
    out = rt.format_output("matrix", "first\nsecond")
    first, *middle, delimiter, trailing = out.split("\n")
    name, _, marker = first.partition("<<")
    assert name == "matrix"
    assert marker == delimiter
    assert middle == ["first", "second"]
    assert trailing == ""


def test_format_output_delimiter_is_unique() -> None:
    assert rt.format_output("a", "x") != rt.format_output("a", "x")


def parse_github_output(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    lines = iter(text.split("\n"))
    for line in lines:
        if not line:
            continue
        name, _, delimiter = line.partition("<<")
        body: list[str] = []
        for body_line in lines:
            if body_line == delimiter:
                break
            body.append(body_line)
        values[name] = "\n".join(body)
    return values


def test_run_writes_resolve_json_and_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    tag_routes(t, "1.1.14", "b" * 40)
    t.add(tags_url("example/x"), ok({"tags": ["development"]}))
    output_file = tmp_path / "github_output"
    env = {**ENV, "GITHUB_OUTPUT": str(output_file), "GITHUB_TOKEN": "tkn"}
    argv = [
        "--repository",
        REPOSITORY,
        "--images",
        "example/x\n",
        "--osv-enabled",
        "false",
        "--output-dir",
        str(tmp_path / "out"),
    ]
    assert rt.run(rt.parse_args(argv), t, env, NOW) == 0

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


def test_run_uses_token_from_environment(tmp_path: Path) -> None:
    t = FakeTransport()
    github_routes(t)
    args = rt.parse_args(["--repository", REPOSITORY, "--output-dir", str(tmp_path)])
    rt.run(args, t, {**ENV, "GITHUB_TOKEN": "from-env"}, NOW)
    assert t.calls[0][1]["Authorization"] == "Bearer from-env"


@pytest.mark.parametrize(
    "extra",
    [
        ["--release-lines", "0"],
        ["--release-lines", "x"],
        ["--scan-source", "maybe"],
        ["--repository", "nope"],
    ],
)
def test_run_rejects_invalid_inputs(tmp_path: Path, extra: list[str]) -> None:
    argv = ["--repository", REPOSITORY, "--output-dir", str(tmp_path), *extra]
    with pytest.raises(rt.ResolveError):
        rt.run(rt.parse_args(argv), FakeTransport(), ENV, NOW)


def test_main_reports_fatal_error_and_exits_non_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    t = FakeTransport()
    t.add(f"{API}/repos/{REPOSITORY}", rt.Response(404))
    monkeypatch.setattr(rt, "UrllibTransport", lambda: t)
    monkeypatch.setenv("GITHUB_API_URL", API)
    code = rt.main(["--repository", REPOSITORY, "--output-dir", str(tmp_path)])
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
    t = FakeTransport()
    github_routes(t, release="0.12.0")
    tag_routes(t, "0.12.0", "c" * 40)
    t.add(tags_url("example/app"), ok({"tags": ["development", "0.12.0"]}))
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
    # one line needs no git tag listing
    assert not any("/tags?" in url for url, _ in t.calls)


def test_release_source_peels_annotated_tag() -> None:
    t = FakeTransport()
    github_routes(t, release="0.12.0")
    tag_routes(t, "0.12.0", "d" * 40, annotated_as="e" * 40)
    targets = by_id(run_resolve_targets(t, [], scan_release_source=True))
    assert targets["source-0.12.0"]["commit_sha"] == "d" * 40
    assert targets["source-0.12.0"]["status"] == "pending"


def test_release_source_tag_pointing_at_a_tree_fails() -> None:
    t = FakeTransport()
    github_routes(t, release="0.12.0")
    t.add(
        f"{API}/repos/{REPOSITORY}/git/ref/tags/0.12.0",
        ok({"object": {"type": "tree", "sha": "f" * 40}}),
    )
    target = by_id(run_resolve_targets(t, [], scan_release_source=True))[
        "source-0.12.0"
    ]
    assert target["status"] == "failed"
    assert "not a commit" in target["reason"]
    assert target["commit_sha"] is None


def test_release_source_tag_that_cannot_be_resolved_is_a_failed_target() -> None:
    t = FakeTransport()
    github_routes(t, release="0.12.0")
    t.add(f"{API}/repos/{REPOSITORY}/git/ref/tags/0.12.0", rt.Response(404))
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
    t = FakeTransport()
    github_routes(t, release_status=500)
    targets = by_id(run_resolve_targets(t, [], scan_release_source=True))
    assert targets["source-development"]["status"] == "pending"
    assert targets["source-release"]["status"] == "failed"
    assert "HTTP 500" in targets["source-release"]["reason"]
    assert targets["source-release"]["git_ref"] is None


def test_release_source_without_images_python_package() -> None:
    t = FakeTransport()
    github_routes(t, release="1.2.3")
    tag_routes(t, "1.2.3", "a1" * 20)
    targets_doc = run_resolve_targets(t, [], scan_release_source=True)
    assert [x["id"] for x in targets_doc["targets"]] == [
        "source-development",
        "source-1.2.3",
    ]
    assert not any("/v2/" in url for url, _ in t.calls)


def test_release_source_falls_back_to_git_tags_without_github_release() -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    git_tags_route(t, ["0.9.1", "0.12.0", "0.12.0-rc.1", "nightly"])
    tag_routes(t, "0.12.0", "b" * 40)
    targets = by_id(run_resolve_targets(t, [], scan_release_source=True))
    assert list(targets) == ["source-development", "source-0.12.0"]


def test_release_source_lines_from_git_tags_newest_first() -> None:
    t = FakeTransport()
    github_routes(t)
    git_tags_route(t, ["0.9.1", "0.10.0", "0.12.0", "0.12.1", "0.11.4", "0.13.0-rc.1"])
    for tag in ("0.12.1", "0.11.4", "0.10.0"):
        tag_routes(t, tag, "b" * 40)
    targets_doc = run_resolve_targets(t, [], release_lines=3, scan_release_source=True)
    assert [x["id"] for x in targets_doc["targets"]] == [
        "source-development",
        "source-0.12.1",
        "source-0.11.4",
        "source-0.10.0",
    ]
    # several lines: the git tags decide, not the latest GitHub release
    assert not any(url.endswith("/releases/latest") for url, _ in t.calls)


def test_release_source_git_tag_listing_is_paginated() -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    git_tags_route(t, [f"0.1.{i}" for i in range(100)], page=1)
    git_tags_route(t, ["0.2.0"], page=2)
    tag_routes(t, "0.2.0", "b" * 40)
    targets = by_id(run_resolve_targets(t, [], scan_release_source=True))
    assert "source-0.2.0" in targets


def test_release_source_no_stable_tag_is_not_applicable() -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    git_tags_route(t, ["0.1.0-rc.1", "nightly"])
    targets = by_id(run_resolve_targets(t, [], scan_release_source=True))
    assert targets["source-release"]["status"] == "not_applicable"
    assert "no stable release tag" in targets["source-release"]["reason"]


def test_release_source_git_tag_listing_failure_is_a_failed_target() -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    t.add(f"{API}/repos/{REPOSITORY}/tags?per_page=100&page=1", rt.Response(403))
    targets = by_id(run_resolve_targets(t, [], scan_release_source=True))
    assert targets["source-release"]["status"] == "failed"
    assert "HTTP 403" in targets["source-release"]["reason"]


def test_scan_source_false_disables_release_sources_too() -> None:
    t = FakeTransport()
    github_routes(t, release="0.12.0")
    t.add(tags_url("example/x"), ok({"tags": ["development", "0.12.0"]}))
    targets = by_id(
        run_resolve_targets(
            t, ["example/x"], scan_source=False, scan_release_source=True
        )
    )
    assert list(targets) == ["x-development", "x-0.12.0"]
    assert not any("/git/" in url for url, _ in t.calls)


def test_release_source_off_makes_no_extra_requests() -> None:
    t = FakeTransport()
    github_routes(t, release="0.12.0")
    t.add(tags_url("example/x"), ok({"tags": ["development", "0.12.0"]}))
    run_resolve_targets(t, ["example/x"], scan_release_source=False)
    assert not any("/git/" in url or "/tags?" in url for url, _ in t.calls)


def test_release_source_id_sanitized() -> None:
    t = FakeTransport()
    github_routes(t, release="rel/1.0")
    tag_routes(t, "rel/1.0", "b" * 40)
    targets = by_id(run_resolve_targets(t, [], scan_release_source=True))
    assert targets["source-rel-1.0"]["git_ref"] == "rel/1.0"


def test_run_scan_release_source_flag(tmp_path: Path) -> None:
    t = FakeTransport()
    github_routes(t, release="0.12.0")
    tag_routes(t, "0.12.0", "b" * 40)
    base = [
        "--repository",
        REPOSITORY,
        "--osv-enabled",
        "false",
        "--output-dir",
        str(tmp_path),
    ]
    assert rt.run(rt.parse_args(base), t, ENV, NOW) == 0  # on by default
    targets_doc = json.loads((tmp_path / "targets.json").read_text(encoding="utf-8"))
    assert [x["id"] for x in targets_doc["targets"]] == [
        "source-development",
        "source-0.12.0",
    ]
    off = [*base, "--scan-release-source", "false"]
    assert rt.run(rt.parse_args(off), t, ENV, NOW) == 0
    targets_doc = json.loads((tmp_path / "targets.json").read_text(encoding="utf-8"))
    assert [x["id"] for x in targets_doc["targets"]] == ["source-development"]
    with pytest.raises(rt.ResolveError, match="scan-release-source"):
        rt.run(rt.parse_args([*base, "--scan-release-source", "maybe"]), t, ENV, NOW)


# --- OSV targets --------------------------------------------------------------


def test_every_target_names_its_scanner_trivy_without_osv() -> None:
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), ok({"tags": ["development", "1.1.14"]}))
    targets_doc = run_resolve_targets(t, ["example/app"])
    assert {x["scanner"] for x in targets_doc["targets"]} == {"trivy"}


def test_osv_target_is_the_twin_of_every_trivy_target() -> None:
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), ok({"tags": ["development", "1.1.14"]}))
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
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    tag_routes(t, "1.1.14", "c" * 40)
    t.add(tags_url("example/app"), ok({"tags": ["development", "1.1.14"]}))
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
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    t.add(f"{API}/repos/{REPOSITORY}/git/ref/tags/1.1.14", rt.Response(404))
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
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    # No release tag in the registry: the release target is not_applicable
    t.add(tags_url("example/app"), ok({"tags": ["development"]}))
    targets_doc = run_resolve_targets(t, ["example/app"], osv_enabled=True)
    by_identity = {(x["scanner"], x["id"]): x for x in targets_doc["targets"]}
    trivy = by_identity[("trivy", "app-1.1.14")]
    osv = by_identity[("osv", "app-1.1.14")]
    assert trivy["status"] == "not_applicable"
    assert osv["status"] == "not_applicable"
    assert osv["reason"] == "trivy target not_applicable"
    assert by_identity[("osv", "source-development")]["status"] == "pending"


def test_osv_twin_of_a_trivy_target_that_failed_to_resolve_is_not_applicable() -> None:
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), rt.Response(404))
    targets_doc = run_resolve_targets(t, ["example/app"], osv_enabled=True)
    osv = [x for x in targets_doc["targets"] if x["scanner"] == "osv"]
    assert [(x["id"], x["status"]) for x in osv] == [
        ("source-development", "pending"),
        ("app-development", "not_applicable"),
        ("app-1.1.14", "not_applicable"),
    ]
    assert {x["reason"] for x in osv[1:]} == {"trivy target failed"}


def test_matrix_holds_only_pending_trivy_targets() -> None:
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), ok({"tags": ["development", "1.1.14"]}))
    targets_doc = run_resolve_targets(t, ["example/app"], osv_enabled=True)
    assert [m["id"] for m in rt.build_matrix(targets_doc)] == [
        "source-development",
        "app-development",
        "app-1.1.14",
    ]


def test_osv_twins_are_not_annotated_twice() -> None:
    t = FakeTransport()
    github_routes(t, release="1.1.14")
    t.add(tags_url("example/app"), ok({"tags": ["development"]}))
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
    t = FakeTransport()
    github_routes(t)
    table = rt.render_table(run_resolve_targets(t, [], osv_enabled=True)["targets"])
    assert [line.split()[:2] for line in table.splitlines()] == [
        ["ID", "SCANNER"],
        ["source-development", "trivy"],
        ["source-development", "osv"],
    ]


def test_run_adds_osv_twins_by_default(tmp_path: Path) -> None:
    t = FakeTransport()
    github_routes(t)
    tag_routes(t, "1.1.14", "b" * 40)
    output_file = tmp_path / "github_output"
    env = {**ENV, "GITHUB_OUTPUT": str(output_file), "GITHUB_TOKEN": "tkn"}
    argv = ["--repository", REPOSITORY, "--output-dir", str(tmp_path / "out")]
    assert rt.run(rt.parse_args(argv), t, env, NOW) == 0
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
    t = FakeTransport()
    github_routes(t)
    tag_routes(t, "1.1.14", "b" * 40)
    argv = [
        "--repository",
        REPOSITORY,
        "--osv-enabled",
        "false",
        "--output-dir",
        str(tmp_path / "out"),
    ]
    assert rt.run(rt.parse_args(argv), t, ENV, NOW) == 0
    targets_doc = json.loads(
        (tmp_path / "out" / "targets.json").read_text(encoding="utf-8")
    )
    assert [x["scanner"] for x in targets_doc["targets"]] == ["trivy", "trivy"]


def test_run_rejects_invalid_osv_enabled(tmp_path: Path) -> None:
    argv = [
        "--repository",
        REPOSITORY,
        "--osv-enabled",
        "maybe",
        "--output-dir",
        str(tmp_path),
    ]
    with pytest.raises(rt.ResolveError):
        rt.run(rt.parse_args(argv), FakeTransport(), ENV, NOW)


# --- repository configuration (.github/sca.yml) ------------------------------

CONFIG_FILE = "schema_version: 1\nnon_shipped_paths:\n  - examples/\n"


def config_file_route(transport: FakeTransport, text: str) -> None:
    """``.github/sca.yml`` of the pinned commit, as the contents API serves it."""
    body = base64.encodebytes(text.encode()).decode()  # wrapped at 60 characters
    transport.add(
        CONFIG_URL,
        ok({"type": "file", "encoding": "base64", "content": body}),
    )


def resolve_config_of(
    transport: FakeTransport, config_input: str = ""
) -> dict[str, Any]:
    github_routes(transport, release=None)
    http = no_sleep_http(transport)
    return rt.resolve_targets(
        repository=REPOSITORY,
        registry_name="ghcr.io",
        images=[],
        release_lines=1,
        scan_source=True,
        scan_images=False,
        scan_release_source=False,
        osv_enabled=False,
        github=rt.GitHubClient(http, "tkn", API),
        registry=rt.RegistryClient(http, "ghcr.io", "tkn"),
        environ=ENV,
        now=NOW,
        caller_repository=CALLER,
        ref_name="development",
        config_input=config_input,
    )["config"]


def test_no_config_file_means_the_defaults() -> None:
    t = FakeTransport()
    assert resolve_config_of(t) == {
        "source": None,
        "overrides": None,
        "non_shipped_paths": [],
        "trivy_skip_paths": "as_non_shipped",
    }
    # the file is looked up at the commit the run is pinned to, via the API
    (headers,) = [h for url, h in t.calls if url == CONFIG_URL]
    assert headers["Authorization"] == "Bearer tkn"


def test_config_file_is_read_at_the_pinned_commit() -> None:
    t = FakeTransport()
    config_file_route(t, CONFIG_FILE)
    config = resolve_config_of(t)
    assert config["source"] == f".github/sca.yml@{SHA}"
    assert config["overrides"] is None
    assert config["non_shipped_paths"] == ["examples/"]


def test_targets_doc_carries_the_config() -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    config_file_route(t, CONFIG_FILE)
    doc = run_resolve_targets(t, [])
    assert doc["config"]["non_shipped_paths"] == ["examples/"]
    assert doc["commit_sha"] == SHA


def test_config_input_replaces_the_file_and_names_it() -> None:
    t = FakeTransport()
    config_file_route(t, CONFIG_FILE)
    config = resolve_config_of(t, "schema_version: 1\nnon_shipped_paths: [docs/]\n")
    assert config["source"] == "input"
    assert config["overrides"] == f".github/sca.yml@{SHA}"
    assert config["non_shipped_paths"] == ["docs/"]


def test_config_input_without_a_file() -> None:
    config = resolve_config_of(FakeTransport(), "schema_version: 1\n")
    assert config["source"] == "input"
    assert config["overrides"] is None


def test_invalid_config_file_fails_with_a_clear_error() -> None:
    t = FakeTransport()
    config_file_route(t, "schema_version: 1\nnon_shiped_paths: [a/]\n")
    with pytest.raises(rt.sca_config.ConfigError, match="unknown key 'non_shiped"):
        resolve_config_of(t)


@pytest.mark.parametrize("status", [401, 403, 500])
def test_contents_api_failure_fails_the_resolution(status: int) -> None:
    t = FakeTransport()
    t.add(CONFIG_URL, rt.Response(status))
    with pytest.raises(rt.ResolveError, match=f"HTTP {status}"):
        resolve_config_of(t)


@pytest.mark.parametrize(
    "body",
    [
        [{"type": "file", "name": "sca.yml"}],  # a directory
        {"type": "symlink", "encoding": "base64", "content": ""},
        {"type": "file", "encoding": "none", "content": ""},  # over 1 MB
        {"type": "file", "encoding": "base64", "content": "!!!"},
        {
            "type": "file",
            "encoding": "base64",
            "content": base64.b64encode(b"\xff").decode(),
        },
    ],
)
def test_unusable_contents_response_fails_the_resolution(body: Any) -> None:
    t = FakeTransport()
    t.add(CONFIG_URL, ok(body))
    with pytest.raises(rt.ResolveError, match="sca.yml"):
        resolve_config_of(t)


def test_config_file_with_a_byte_order_mark_is_read() -> None:
    t = FakeTransport()
    config_file_route(t, "\ufeff" + CONFIG_FILE)
    assert resolve_config_of(t)["non_shipped_paths"] == ["examples/"]


def test_run_passes_the_config_input_and_outputs_the_skip_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    output_file = tmp_path / "github_output"
    argv = [
        "--repository",
        REPOSITORY,
        "--scan-images",
        "false",
        "--scan-release-source",
        "false",
        "--osv-enabled",
        "false",
        "--config",
        "schema_version: 1\ntrivy_skip_paths: apply\n",
        "--output-dir",
        str(tmp_path / "out"),
    ]
    env = {**ENV, "GITHUB_OUTPUT": str(output_file)}
    assert rt.run(rt.parse_args(argv), t, env, NOW) == 0
    doc = json.loads((tmp_path / "out" / "targets.json").read_text())
    assert doc["config"]["source"] == "input"
    assert parse_github_output(output_file.read_text())["trivy-skip-paths"] == "apply"
    assert (
        "Configuration: input; non_shipped_paths: none; trivy_skip_paths: apply"
        in capsys.readouterr().out
    )


def test_run_outputs_the_default_skip_mode_without_config(tmp_path: Path) -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    output_file = tmp_path / "github_output"
    argv = ["--repository", REPOSITORY, "--output-dir", str(tmp_path / "out")]
    rt.run(rt.parse_args(argv), t, {**ENV, "GITHUB_OUTPUT": str(output_file)}, NOW)
    outputs = parse_github_output(output_file.read_text())
    assert outputs["trivy-skip-paths"] == "as_non_shipped"


def test_main_reports_an_invalid_configuration_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    t = FakeTransport()
    github_routes(t, release=None)
    config_file_route(t, "schema_version: 7\n")
    monkeypatch.setattr(rt, "UrllibTransport", lambda: t)
    monkeypatch.setenv("GITHUB_API_URL", API)
    monkeypatch.setenv("GITHUB_REPOSITORY", CALLER)
    monkeypatch.setenv("GITHUB_REF_NAME", "development")
    code = rt.main(["--repository", REPOSITORY, "--output-dir", str(tmp_path)])
    assert code == 1
    out = capsys.readouterr().out
    assert out.startswith("::error title=Invalid SCA configuration::")
    assert f".github/sca.yml@{SHA}: unsupported schema_version 7" in out
    assert "\n" not in out.strip()
    assert not (tmp_path / "targets.json").exists()
