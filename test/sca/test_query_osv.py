"""Tests for actions/sca_query_osv/query_osv.py (synthetic data, a fake OSV API)."""

from __future__ import annotations

import importlib.util
import json
import sys
import urllib.parse
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
API = "https://api.osv.dev"


def _load_query_osv():
    path = ROOT / "actions" / "sca_query_osv" / "query_osv.py"
    spec = importlib.util.spec_from_file_location("query_osv", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


qo = _load_query_osv()


# --- fakes and builders -------------------------------------------------------


def ok(payload: Any) -> Any:
    return qo.Response(200, {}, json.dumps(payload).encode())


class FakeOsv:
    """A fake OSV API behind the Transport interface; records every request.

    ``vulns``: purl -> vulnerability ids. ``page_size`` pages the ids of a query
    (``next_page_token`` is the offset of the next page). ``rejected``: purls
    that make a querybatch request answer 400. ``script``: responses (or
    exceptions) consumed before the API logic, in order, for failure injection.
    """

    def __init__(
        self,
        vulns: Mapping[str, Sequence[str]] | None = None,
        records: Mapping[str, Any] | None = None,
        page_size: int | None = None,
        rejected: Sequence[str] = (),
    ) -> None:
        self.vulns = dict(vulns or {})
        self.records = dict(records) if records is not None else None
        self.page_size = page_size
        self.rejected = set(rejected)
        self.script: list[Any] = []
        self.requests: list[tuple[str, str, Any]] = []
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> Any:
        path = url.removeprefix(API)
        payload = json.loads(body) if body else None
        self.requests.append((method, path, payload))
        if self.script:
            step = self.script.pop(0)
            if isinstance(step, Exception):
                raise step
            return step
        if method == "POST" and path == "/v1/querybatch":
            return self.querybatch(payload["queries"])
        if method == "GET" and path.startswith("/v1/vulns/"):
            vuln_id = urllib.parse.unquote(path.removeprefix("/v1/vulns/"))
            records = self.records
            if records is None:
                return ok({"id": vuln_id, "summary": f"record of {vuln_id}"})
            if vuln_id not in records:
                return qo.Response(404, {}, b'{"code":5,"message":"Bug not found."}')
            return ok(records[vuln_id])
        return qo.Response(599, {}, b"unrouted")

    def querybatch(self, queries: Sequence[Mapping[str, Any]]) -> Any:
        if any(q["package"]["purl"] in self.rejected for q in queries):
            return qo.Response(400, {}, b'{"code":3,"message":"error in query"}')
        results = []
        for query in queries:
            ids = list(self.vulns.get(query["package"]["purl"], []))
            start = int(query.get("page_token", 0))
            size = self.page_size or max(len(ids), 1)
            result: dict[str, Any] = {}
            if ids[start : start + size]:
                result["vulns"] = [
                    {"id": i, "modified": "2030-01-01T00:00:00Z"}
                    for i in ids[start : start + size]
                ]
            if start + size < len(ids):
                result["next_page_token"] = str(start + size)
            results.append(result)
        return ok({"results": results})

    def batches(self) -> list[list[Mapping[str, Any]]]:
        return [
            p["queries"] for m, path, p in self.requests if path == "/v1/querybatch"
        ]

    def fetched(self) -> list[str]:
        return [
            urllib.parse.unquote(path.removeprefix("/v1/vulns/"))
            for method, path, _ in self.requests
            if method == "GET"
        ]


def package(name: str, version: str, purl: str | None) -> dict[str, Any]:
    entry: dict[str, Any] = {"Name": name, "Version": version}
    if purl is not None:
        entry["Identifier"] = {"PURL": purl}
    return entry


def npm(name: str, version: str = "1.0.0") -> dict[str, Any]:
    return package(name, version, f"pkg:npm/{name}@{version}")


def trivy_native(
    *lang: dict[str, Any], os_packages: Sequence[dict[str, Any]] = ()
) -> dict[str, Any]:
    results = [
        {
            "Class": "lang-pkgs",
            "Type": "npm",
            "Target": "package-lock.json",
            "Packages": list(lang),
        }
    ]
    if os_packages:
        results.append(
            {
                "Class": "os-pkgs",
                "Type": "alpine",
                "Target": "alpine",
                "Packages": list(os_packages),
            }
        )
    return {"Results": results}


def target(
    scanner: str, tid: str, status: str = "pending", **extra: Any
) -> dict[str, Any]:
    return {
        "id": tid,
        "scanner": scanner,
        "kind": "fs",
        "status": status,
        "reason": None,
        **extra,
    }


class Workspace:
    """targets.json, Trivy parts and an output directory in tmp_path."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.targets: list[dict[str, Any]] = []
        self.trivy = tmp_path / "parts" / "trivy"
        self.trivy.mkdir(parents=True)
        self.out = tmp_path / "out"

    def add(
        self,
        tid: str,
        native: Mapping[str, Any] | None,
        trivy_status: str | None = "ok",
        osv_status: str = "pending",
    ) -> None:
        """A Trivy target with its part and its OSV twin."""
        self.targets.append(target("trivy", tid))
        self.targets.append(target("osv", tid, osv_status))
        if native is not None:
            (self.trivy / f"{tid}.json").write_text(
                json.dumps(native), encoding="utf-8"
            )
        if trivy_status is not None:
            (self.trivy / f"{tid}.status.json").write_text(
                json.dumps({"id": tid, "status": trivy_status, "reason": None}),
                encoding="utf-8",
            )

    def argv(self, *extra: str) -> list[str]:
        targets_file = self.tmp / "targets.json"
        targets_file.write_text(json.dumps({"targets": self.targets}), encoding="utf-8")
        return [
            "--targets-file",
            str(targets_file),
            "--parts-dir",
            str(self.tmp / "parts"),
            "--output-dir",
            str(self.out),
            *extra,
        ]

    def run(self, fake: FakeOsv, *extra: str) -> int:
        args = qo.parse_args(self.argv(*extra))
        return qo.run(args, fake, NOW, fake.sleep)

    def status(self, tid: str) -> dict[str, Any]:
        return json.loads((self.out / "osv" / f"{tid}.status.json").read_text("utf-8"))

    def native(self, tid: str) -> dict[str, Any]:
        return json.loads((self.out / "osv" / f"{tid}.json").read_text("utf-8"))

    def has_native(self, tid: str) -> bool:
        return (self.out / "osv" / f"{tid}.json").exists()


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    return Workspace(tmp_path)


# --- results ------------------------------------------------------------------


def test_ok_target_gets_native_and_status(ws: Workspace) -> None:
    ws.add("source-development", trivy_native(npm("a"), npm("b", "2.0.0")))
    fake = FakeOsv({"pkg:npm/a@1.0.0": ["GHSA-1", "GHSA-2"]})
    assert ws.run(fake) == 0
    assert ws.status("source-development") == {
        "id": "source-development",
        "status": "ok",
        "reason": None,
        "packages_queried": 2,
        "packages_skipped": 0,
    }
    assert ws.native("source-development") == {
        "schema_version": 1,
        "queried_at": "2030-01-01T12:00:00Z",
        "api_url": API,
        "packages": {
            "pkg:npm/a@1.0.0": ["GHSA-1", "GHSA-2"],
            "pkg:npm/b@2.0.0": [],
        },
        "vulnerabilities": {
            "GHSA-1": {"id": "GHSA-1", "summary": "record of GHSA-1"},
            "GHSA-2": {"id": "GHSA-2", "summary": "record of GHSA-2"},
        },
    }


def test_requests_carry_headers_and_the_purl_with_its_version(ws: Workspace) -> None:
    ws.add("t", trivy_native(npm("a", "3.1.4")))
    seen: list[Mapping[str, str]] = []
    fake = FakeOsv({"pkg:npm/a@3.1.4": ["GHSA-1"]})

    def spy(method, url, headers, body):
        seen.append(headers)
        return fake(method, url, headers, body)

    args = qo.parse_args(ws.argv())
    qo.run(args, spy, NOW, fake.sleep)
    assert fake.batches() == [[{"package": {"purl": "pkg:npm/a@3.1.4"}}]]
    assert all(h["Content-Type"] == "application/json" for h in seen)
    assert all("User-Agent" in h for h in seen)


def test_only_language_packages_are_queried_os_packages_are_not(ws: Workspace) -> None:
    os_package = package("zlib", "1.3.2-r0", "pkg:apk/alpine/zlib@1.3.2-r0?arch=x86_64")
    ws.add("img", trivy_native(npm("a"), os_packages=[os_package]))
    fake = FakeOsv()
    assert ws.run(fake) == 0
    assert fake.batches() == [[{"package": {"purl": "pkg:npm/a@1.0.0"}}]]
    assert list(ws.native("img")["packages"]) == ["pkg:npm/a@1.0.0"]
    assert ws.status("img")["packages_queried"] == 1
    assert ws.status("img")["packages_skipped"] == 0


def test_every_language_result_type_is_queried(ws: Workspace) -> None:
    native = {
        "Results": [
            {"Class": "lang-pkgs", "Type": kind, "Packages": [package(kind, "1", purl)]}
            for kind, purl in (
                ("poetry", "pkg:pypi/aidial-client@0.17.0"),
                ("python-pkg", "pkg:pypi/authlib@1.8.0"),
                ("gradle", "pkg:maven/com.ethlo.time/itu@1.10.2"),
                ("jar", "pkg:maven/aopalliance/aopalliance@1.0"),
                ("node-pkg", "pkg:npm/%40borewit/text-codec@0.2.2"),
            )
        ]
    }
    ws.add("img", native)
    assert ws.run(FakeOsv()) == 0
    assert sorted(ws.native("img")["packages"]) == [
        "pkg:maven/aopalliance/aopalliance@1.0",
        "pkg:maven/com.ethlo.time/itu@1.10.2",
        "pkg:npm/%40borewit/text-codec@0.2.2",
        "pkg:pypi/aidial-client@0.17.0",
        "pkg:pypi/authlib@1.8.0",
    ]


def test_packages_without_a_purl_or_a_version_are_skipped_not_queried(
    ws: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    ws.add(
        "src",
        trivy_native(
            npm("a"),
            package("nopurl", "1", None),
            package("nopurl", "1", None),  # the same package again: counted once
            package("nopurl", "2", None),
            package("noversion", "", "pkg:npm/noversion"),
            package("scoped", "", "pkg:npm/%40scope/noversion?x=a@b"),
        ),
    )
    assert ws.run(FakeOsv()) == 0
    status = ws.status("src")
    assert (status["status"], status["packages_queried"]) == ("ok", 1)
    assert status["packages_skipped"] == 4
    assert "src: 4 package(s) without a versioned purl" in capsys.readouterr().out


def test_target_with_no_language_packages_is_ok_without_any_request(
    ws: Workspace,
) -> None:
    ws.add("img", {"Results": [{"Class": "os-pkgs", "Packages": []}]})
    ws.add("empty", {})
    fake = FakeOsv()
    assert ws.run(fake) == 0
    assert fake.requests == []
    for tid in ("img", "empty"):
        assert ws.status(tid)["status"] == "ok"
        native = ws.native(tid)
        assert (native["packages"], native["vulnerabilities"]) == ({}, {})


# --- batching, pagination, dedupe -----------------------------------------------


def test_purls_are_deduplicated_across_targets_and_queried_once(ws: Workspace) -> None:
    ws.add("source-development", trivy_native(npm("a"), npm("b")))
    ws.add("img-development", trivy_native(npm("b"), npm("c")))
    ws.add("img-1.0", trivy_native(npm("c"), npm("b")))
    fake = FakeOsv(
        {"pkg:npm/b@1.0.0": ["GHSA-1"], "pkg:npm/c@1.0.0": ["GHSA-1", "GHSA-2"]}
    )
    assert ws.run(fake) == 0
    (batch,) = fake.batches()
    assert [q["package"]["purl"] for q in batch] == [
        "pkg:npm/a@1.0.0",
        "pkg:npm/b@1.0.0",
        "pkg:npm/c@1.0.0",
    ]
    # each target has the ids of its own packages only
    assert ws.native("source-development")["packages"] == {
        "pkg:npm/a@1.0.0": [],
        "pkg:npm/b@1.0.0": ["GHSA-1"],
    }
    assert ws.native("img-development")["packages"] == {
        "pkg:npm/b@1.0.0": ["GHSA-1"],
        "pkg:npm/c@1.0.0": ["GHSA-1", "GHSA-2"],
    }
    assert sorted(ws.native("source-development")["vulnerabilities"]) == ["GHSA-1"]
    assert sorted(ws.native("img-1.0")["vulnerabilities"]) == ["GHSA-1", "GHSA-2"]


def test_each_distinct_vulnerability_is_fetched_once(ws: Workspace) -> None:
    ws.add("t1", trivy_native(npm("a"), npm("b")))
    ws.add("t2", trivy_native(npm("a"), npm("c")))
    fake = FakeOsv(
        {
            "pkg:npm/a@1.0.0": ["GHSA-1", "GHSA-2"],
            "pkg:npm/b@1.0.0": ["GHSA-2"],
            "pkg:npm/c@1.0.0": ["GHSA-3", "GHSA-1"],
        }
    )
    assert ws.run(fake) == 0
    assert sorted(fake.fetched()) == ["GHSA-1", "GHSA-2", "GHSA-3"]


def test_vulnerability_ids_with_special_characters_are_quoted(ws: Workspace) -> None:
    ws.add("t", trivy_native(npm("a")))
    fake = FakeOsv({"pkg:npm/a@1.0.0": ["OSV/odd id"]})
    assert ws.run(fake) == 0
    assert ("GET", "/v1/vulns/OSV%2Fodd%20id", None) in fake.requests
    assert ws.native("t")["vulnerabilities"]["OSV/odd id"]["id"] == "OSV/odd id"


def test_queries_go_in_chunks_of_at_most_1000(ws: Workspace) -> None:
    packages = [npm(f"p{i:04d}") for i in range(2500)]
    ws.add("big", trivy_native(*packages))
    fake = FakeOsv()
    assert ws.run(fake) == 0
    assert [len(batch) for batch in fake.batches()] == [1000, 1000, 500]
    assert ws.status("big")["packages_queried"] == 2500
    assert len(ws.native("big")["packages"]) == 2500


def test_a_paged_query_is_followed_with_its_token_only(ws: Workspace) -> None:
    ws.add("t", trivy_native(npm("many"), npm("few"), npm("none")))
    fake = FakeOsv(
        {
            "pkg:npm/many@1.0.0": ["G-1", "G-2", "G-3", "G-4", "G-5"],
            "pkg:npm/few@1.0.0": ["G-6"],
        },
        page_size=2,
    )
    assert ws.run(fake) == 0
    first, second, third = fake.batches()
    assert len(first) == 3
    assert second == [{"package": {"purl": "pkg:npm/many@1.0.0"}, "page_token": "2"}]
    assert third == [{"package": {"purl": "pkg:npm/many@1.0.0"}, "page_token": "4"}]
    assert ws.native("t")["packages"]["pkg:npm/many@1.0.0"] == [
        "G-1",
        "G-2",
        "G-3",
        "G-4",
        "G-5",
    ]
    assert ws.native("t")["packages"]["pkg:npm/few@1.0.0"] == ["G-6"]


def test_pagination_that_never_ends_fails_the_packages(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(qo, "MAX_PAGES", 3)
    ws.add("t", trivy_native(npm("a")))
    fake = FakeOsv()
    fake.querybatch = lambda queries: ok(  # type: ignore[method-assign]
        {"results": [{"next_page_token": "again"} for _ in queries]}
    )
    assert ws.run(fake) == 1
    assert "still paged after 3 pages" in ws.status("t")["reason"]
    assert not ws.has_native("t")


# --- failures: never a clean-looking result ---------------------------------------


def test_transient_errors_are_retried_with_backoff(ws: Workspace) -> None:
    ws.add("t", trivy_native(npm("a")))
    fake = FakeOsv({"pkg:npm/a@1.0.0": ["GHSA-1"]})
    fake.script = [
        qo.Response(503, {}, b""),
        qo.TransportError("connection reset"),
        qo.Response(500, {}, b""),
    ]
    assert ws.run(fake) == 0
    assert ws.status("t")["status"] == "ok"
    assert fake.sleeps == [1.0, 2.0, 4.0]
    assert len(fake.batches()) == 4  # 3 failures + the answer


def test_retry_after_is_honoured_and_capped(ws: Workspace) -> None:
    ws.add("t", trivy_native(npm("a")))
    fake = FakeOsv()
    fake.script = [
        qo.Response(429, {"Retry-After": "7"}, b""),
        qo.Response(429, {"Retry-After": "86400"}, b""),
        qo.Response(429, {"Retry-After": "soon"}, b""),
    ]
    assert ws.run(fake) == 0
    assert fake.sleeps == [7.0, 60.0, 4.0]


def test_the_vulnerability_request_is_retried_too(ws: Workspace) -> None:
    ws.add("t", trivy_native(npm("a")))
    fake = FakeOsv({"pkg:npm/a@1.0.0": ["GHSA-1"]})
    calls = {"gets": 0}
    plain = fake.__call__

    def flaky(method, url, headers, body):
        if method == "GET":
            calls["gets"] += 1
            if calls["gets"] == 1:
                return qo.Response(502, {}, b"")
        return plain(method, url, headers, body)

    args = qo.parse_args(ws.argv())
    assert qo.run(args, flaky, NOW, fake.sleep) == 0
    assert calls["gets"] == 2
    assert ws.status("t")["status"] == "ok"


def test_retries_exhausted_fails_every_target_with_the_packages(
    ws: Workspace,
) -> None:
    ws.add("t1", trivy_native(npm("a")))
    ws.add("t2", trivy_native(npm("b")))
    fake = FakeOsv()
    fake.script = [qo.Response(503, {}, b"")] * 4
    assert ws.run(fake) == 2
    for tid in ("t1", "t2"):
        status = ws.status(tid)
        assert status["status"] == "failed"
        assert status["reason"].startswith("OSV query failed for 1 of 1 package(s)")
        assert "HTTP 503" in status["reason"]
        assert not ws.has_native(tid)
    assert len(fake.batches()) == 4
    assert fake.fetched() == []


def test_network_errors_after_all_retries_fail_the_targets(ws: Workspace) -> None:
    ws.add("t", trivy_native(npm("a")))
    fake = FakeOsv()
    fake.script = [qo.TransportError("timed out")] * 4
    assert ws.run(fake) == 1
    assert "timed out" in ws.status("t")["reason"]


@pytest.mark.parametrize("status", [401, 403, 404, 418])
def test_other_http_errors_are_not_retried(ws: Workspace, status: int) -> None:
    ws.add("t", trivy_native(npm("a")))
    fake = FakeOsv()
    fake.script = [qo.Response(status, {}, b"no")]
    assert ws.run(fake) == 1
    assert f"HTTP {status}" in ws.status("t")["reason"]
    assert len(fake.batches()) == 1
    assert fake.sleeps == []


@pytest.mark.parametrize(
    "answer",
    [
        qo.Response(200, {}, b"not json"),
        ok([]),
        ok({}),
        ok({"results": [{}, {}]}),  # two results for one query
        ok({"results": [{"vulns": [{"modified": "x"}]}]}),  # a vuln without an id
        ok({"results": [{"vulns": ["GHSA-1"]}]}),
    ],
)
def test_an_unusable_answer_fails_the_packages(ws: Workspace, answer: Any) -> None:
    ws.add("t", trivy_native(npm("a")))
    fake = FakeOsv()
    fake.script = [answer]
    assert ws.run(fake) == 1
    assert ws.status("t")["status"] == "failed"
    assert not ws.has_native("t")


def test_a_failed_chunk_fails_only_the_targets_with_its_packages(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(qo, "BATCH_SIZE", 2)
    ws.add("first", trivy_native(npm("a"), npm("b")))
    ws.add("second", trivy_native(npm("c"), npm("d")))
    ws.add("mixed", trivy_native(npm("b"), npm("c")))
    fake = FakeOsv({"pkg:npm/a@1.0.0": ["GHSA-1"]})
    first_call = {"done": False}
    plain = fake.__call__

    def fail_second_chunk(method, url, headers, body):
        if method == "POST" and not first_call["done"]:
            first_call["done"] = True
            return plain(method, url, headers, body)
        if method == "POST":
            return qo.Response(404, {}, b"")
        return plain(method, url, headers, body)

    args = qo.parse_args(ws.argv())
    assert qo.run(args, fail_second_chunk, NOW, fake.sleep) == 2
    # chunks: [a, b] ok, [c, d] failed
    assert ws.status("first")["status"] == "ok"
    assert ws.status("second")["status"] == "failed"
    assert ws.status("mixed")["status"] == "failed"
    assert ws.status("mixed")["reason"].startswith(
        "OSV query failed for 1 of 2 package(s)"
    )


def test_a_vulnerability_that_cannot_be_fetched_fails_the_targets_that_have_it(
    ws: Workspace,
) -> None:
    ws.add("hit", trivy_native(npm("a")))
    ws.add("other", trivy_native(npm("b")))
    fake = FakeOsv(
        {"pkg:npm/a@1.0.0": ["GHSA-1", "GHSA-gone"], "pkg:npm/b@1.0.0": ["GHSA-1"]},
        records={"GHSA-1": {"id": "GHSA-1"}},
    )
    assert ws.run(fake) == 1
    assert ws.status("other")["status"] == "ok"
    assert ws.native("other")["vulnerabilities"] == {"GHSA-1": {"id": "GHSA-1"}}
    assert ws.status("hit")["status"] == "failed"
    assert "GET /v1/vulns/GHSA-gone: HTTP 404" in ws.status("hit")["reason"]
    assert not ws.has_native("hit")


def test_a_record_of_another_id_is_not_accepted(ws: Workspace) -> None:
    ws.add("t", trivy_native(npm("a")))
    fake = FakeOsv({"pkg:npm/a@1.0.0": ["GHSA-1"]}, records={"GHSA-1": {"id": "X"}})
    assert ws.run(fake) == 1
    assert "not the record of GHSA-1" in ws.status("t")["reason"]


def test_a_rejected_purl_fails_only_its_target_not_the_whole_run(
    ws: Workspace,
) -> None:
    ws.add("good", trivy_native(*[npm(f"p{i}") for i in range(7)]))
    ws.add("bad", trivy_native(npm("p3"), npm("broken"), npm("p5")))
    fake = FakeOsv({"pkg:npm/p0@1.0.0": ["GHSA-1"]}, rejected=["pkg:npm/broken@1.0.0"])
    assert ws.run(fake) == 1
    assert ws.status("good")["status"] == "ok"
    assert ws.native("good")["packages"]["pkg:npm/p0@1.0.0"] == ["GHSA-1"]
    status = ws.status("bad")
    assert status["status"] == "failed"
    assert status["reason"].startswith("OSV query failed for 1 of 3 package(s)")
    assert "rejected by OSV" in status["reason"]


# --- targets that are not queried ---------------------------------------------------


@pytest.mark.parametrize(
    ("trivy_status", "expected"),
    [
        ("failed", "failed"),
        ("not_applicable", "not_applicable"),
        ("pending", "pending"),
    ],
)
def test_osv_target_of_a_trivy_target_that_was_not_scanned_is_not_applicable(
    ws: Workspace, trivy_status: str, expected: str
) -> None:
    ws.add("broken", trivy_native(npm("a")), trivy_status=trivy_status)
    ws.add("fine", trivy_native(npm("b")))
    fake = FakeOsv()
    assert ws.run(fake) == 0
    assert ws.status("broken") == {
        "id": "broken",
        "status": "not_applicable",
        "reason": f"trivy target {expected}",
        "packages_queried": None,
        "packages_skipped": None,
    }
    assert not ws.has_native("broken")
    # only the other target's package was asked about
    assert fake.batches() == [[{"package": {"purl": "pkg:npm/b@1.0.0"}}]]


def test_a_missing_or_unreadable_trivy_part_makes_the_twin_not_applicable(
    ws: Workspace,
) -> None:
    ws.add("no-part", None, trivy_status=None)
    ws.add("no-native", None)  # status ok, result file missing
    ws.add("bad-native", None)
    (ws.trivy / "bad-native.json").write_text("{", encoding="utf-8")
    ws.add("not-an-object", None)
    (ws.trivy / "not-an-object.json").write_text("[]", encoding="utf-8")
    ws.add("bad-status", trivy_native(npm("a")), trivy_status=None)
    (ws.trivy / "bad-status.status.json").write_text("[]", encoding="utf-8")
    fake = FakeOsv()
    assert ws.run(fake) == 0
    for tid in ("no-part", "no-native", "bad-native", "not-an-object", "bad-status"):
        status = ws.status(tid)
        assert (status["status"], status["reason"]) == (
            "not_applicable",
            "trivy target failed",
        )
    assert fake.requests == []


def test_only_pending_osv_targets_are_processed(ws: Workspace) -> None:
    ws.add("done", trivy_native(npm("a")), osv_status="not_applicable")
    ws.add("todo", trivy_native(npm("b")))
    fake = FakeOsv()
    assert ws.run(fake) == 0
    assert not (ws.out / "osv" / "done.status.json").exists()
    assert ws.status("todo")["status"] == "ok"
    assert fake.batches() == [[{"package": {"purl": "pkg:npm/b@1.0.0"}}]]


def test_without_osv_targets_nothing_is_written_or_asked(ws: Workspace) -> None:
    ws.targets.append(target("trivy", "source-development"))
    fake = FakeOsv()
    assert ws.run(fake) == 0
    assert fake.requests == []
    assert list((ws.out / "osv").iterdir()) == []


# --- outputs and inputs ------------------------------------------------------------


def test_a_custom_api_url_is_used_and_recorded(ws: Workspace) -> None:
    ws.add("t", trivy_native(npm("a")))
    urls: list[str] = []

    def spy(method: str, url: str, headers: Mapping[str, str], body: Any) -> Any:
        urls.append(url)
        return ok({"results": [{}]})

    args = qo.parse_args(ws.argv("--api-url", "https://osv.example.invalid/api/"))
    assert qo.run(args, spy, NOW) == 0
    assert urls == ["https://osv.example.invalid/api/v1/querybatch"]
    assert ws.native("t")["api_url"] == "https://osv.example.invalid/api"


def test_api_url_must_be_https(ws: Workspace) -> None:
    ws.add("t", trivy_native(npm("a")))
    args = qo.parse_args(ws.argv("--api-url", "http://api.osv.dev"))
    with pytest.raises(qo.InputError, match="https"):
        qo.run(args, FakeOsv(), NOW)


def test_transport_refuses_plain_http() -> None:
    with pytest.raises(qo.TransportError, match="non-HTTPS"):
        qo.UrllibTransport()("GET", "http://api.osv.dev/v1/vulns/x", {}, None)


@pytest.mark.parametrize(
    "content", [None, "{", "[]", '{"targets": 1}', '{"targets": [1]}']
)
def test_unusable_targets_file_is_an_input_error(
    tmp_path: Path, content: str | None
) -> None:
    path = tmp_path / "targets.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    with pytest.raises(qo.InputError, match="targets file"):
        qo.load_targets_file(path)


def test_main_reports_invalid_input_and_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = [
        "--targets-file",
        str(tmp_path / "missing.json"),
        "--parts-dir",
        str(tmp_path),
        "--output-dir",
        str(tmp_path / "out"),
    ]
    assert qo.main(argv) == 1
    assert "::error title=Invalid OSV query input::" in capsys.readouterr().err


def test_defaults() -> None:
    args = qo.parse_args(
        ["--targets-file", "t", "--parts-dir", "p", "--output-dir", "o"]
    )
    assert args.api_url == "https://api.osv.dev"
    assert qo.BATCH_SIZE == 1000


@pytest.mark.parametrize(
    ("purl", "versioned"),
    [
        ("pkg:npm/lodash@4.17.20", True),
        ("pkg:npm/%40babel/traverse@7.20.0", True),
        ("pkg:maven/org.example/lib@1.0?type=jar", True),
        ("pkg:npm/lodash", False),
        ("pkg:npm/%40babel/traverse", False),
        ("pkg:npm/lodash?foo=a@b", False),
        ("pkg:npm/lodash#sub@path", False),
    ],
)
def test_has_version(purl: str, versioned: bool) -> None:
    assert qo.has_version(purl) is versioned
