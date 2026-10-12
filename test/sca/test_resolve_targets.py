"""Tests for sca_resolve_targets/resolve_targets.py (fake transport, no network)."""

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
ENV = {
    "GITHUB_API_URL": API,
    "GITHUB_RUN_ID": "42",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "example/caller",
}


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
    quoted = urllib.parse.quote(branch, safe="")
    transport.add(f"{API}/repos/{REPOSITORY}/commits/{quoted}", ok({"sha": "a" * 40}))
    latest = f"{API}/repos/{REPOSITORY}/releases/latest"
    if release_status is not None:
        transport.add(latest, rt.Response(release_status))
    elif release is None:
        transport.add(latest, rt.Response(404))
    else:
        transport.add(latest, ok({"tag_name": release}))


def no_sleep_http(transport: FakeTransport) -> Any:
    return rt.HttpClient(transport, sleep=lambda _: None)


def run_resolve_targets(
    transport: FakeTransport,
    images: list[str],
    release_lines: int = 1,
    scan_source: bool = True,
    scan_images: bool = True,
    token: str | None = "tkn",
) -> dict[str, Any]:
    http = no_sleep_http(transport)
    return rt.resolve_targets(
        repository=REPOSITORY,
        registry_name="ghcr.io",
        images=images,
        release_lines=release_lines,
        scan_source=scan_source,
        scan_images=scan_images,
        github=rt.GitHubClient(http, token, API),
        registry=rt.RegistryClient(http, "ghcr.io", token),
        environ=ENV,
        now=NOW,
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
        assert set(target) == TARGET_KEYS | {"status", "reason"}
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
    t.add(tags_url("example/x"), ok({"tags": ["development"]}))
    output_file = tmp_path / "github_output"
    env = {**ENV, "GITHUB_OUTPUT": str(output_file), "GITHUB_TOKEN": "tkn"}
    argv = [
        "--repository",
        REPOSITORY,
        "--images",
        "example/x\n",
        "--output-dir",
        str(tmp_path / "out"),
    ]
    assert rt.run(rt.parse_args(argv), t, env, NOW) == 0

    targets_doc = json.loads(
        (tmp_path / "out" / "targets.json").read_text(encoding="utf-8")
    )
    assert [x["id"] for x in targets_doc["targets"]] == [
        "source-development",
        "x-development",
        "x-1.1.14",
    ]
    outputs = parse_github_output(output_file.read_text(encoding="utf-8"))
    assert outputs["commit-sha"] == "a" * 40
    assert outputs["default-branch"] == "development"
    assert outputs["targets-file"] == str(tmp_path / "out" / "targets.json")
    assert " " not in outputs["matrix"]
    assert [m["id"] for m in json.loads(outputs["matrix"])] == [
        "source-development",
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
            "kind": "fs",
            "ref": None,
            "status": "pending",
            "reason": None,
        },
        {
            "id": "x-1",
            "kind": "image",
            "ref": "ghcr.io/x:1",
            "status": "failed",
            "reason": "boom",
        },
        {
            "id": "x-2",
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
