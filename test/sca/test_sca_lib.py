"""Tests of the code the SCA actions share (actions/_sca_lib)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from _sca_lib import http
from _sca_lib.gha import append_text, escape_command_data, format_output
from _sca_lib.jsonio import InputError, dump_json, load_targets_list, read_json
from _sca_lib.purl import parse_purl
from _sca_lib.times import format_time, parse_time
from _sca_lib.versions import compare_tokens, compare_versions

# --- versions (by the ecosystem) -----------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.2.3", "1.2.3", 0),
        ("1.2.3", "1.10.0", -1),
        ("v2.0.0", "2.0", 0),
        ("1.0.0-alpha", "1.0.0", -1),
        ("1.0.0-alpha.2", "1.0.0-alpha.10", -1),
        ("1.0.0-alpha.1", "1.0.0-alpha", 1),
        ("1.0.0-alpha", "1.0.0-beta", -1),
        ("1.0.0-1", "1.0.0-alpha", -1),
        ("1.0.0+build.5", "1.0.0", 0),
        ("1.2.3.4", "1.2.3", None),
        ("latest", "1.0.0", None),
    ],
)
def test_semver_comparison(a: str, b: str, expected: int | None) -> None:
    assert compare_versions("npm", a, b) == expected
    assert compare_versions("cargo", a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0.0", 0),
        ("1.0rc1", "1.0", -1),
        ("1.0a1", "1.0b1", -1),
        ("1.0b2", "1.0rc1", -1),
        ("1.0.dev1", "1.0a1", -1),
        ("1.0", "1.0.post1", -1),
        ("1.0.post1", "1.1", -1),
        ("1.0-1", "1.0.post1", 0),
        ("1!0.5", "2.0", 1),
        ("1.0+local.1", "1.0", 0),
        ("1.0.rc.1", "1.0c1", 0),
        ("2.10", "2.9", 1),
        ("1.0.post1.dev1", "1.0.post1", -1),
        ("not a version", "1.0", None),
    ],
)
def test_pep440_comparison(a: str, b: str, expected: int | None) -> None:
    assert compare_versions("pypi", a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0.0", 0),
        ("1", "1.0.0.0", 0),
        ("33.4.8-jre", "33.7.2", -1),
        ("33.7.2-jre", "33.7.2", 1),
        ("33.7.2-android", "33.7.2-jre", -1),
        ("1.0-alpha-1", "1.0-beta-1", -1),
        ("1.0-beta-1", "1.0-rc-1", -1),
        ("1.0-rc1", "1.0-SNAPSHOT", -1),
        ("1.0-SNAPSHOT", "1.0", -1),
        ("1.0", "1.0-sp1", -1),
        ("1.0-ga", "1.0", 0),
        ("1.0.Final", "1.0", 0),
        ("1.0-cr1", "1.0-rc1", 0),
        ("1.0a1", "1.0-alpha-1", 0),
        ("1.10", "1.9", 1),
        ("1.0.1", "1.0-1", 1),
        ("2.9.10.8", "2.9.10", 1),
        ("1.85", "1.86", -1),
        ("1.0-milestone-2", "1.0-m2", 0),
        ("no-digits", "1.0", None),
    ],
)
def test_maven_comparison(a: str, b: str, expected: int | None) -> None:
    assert compare_versions("maven", a, b) == expected
    if expected is not None:
        assert compare_versions("maven", b, a) == -expected


def test_other_ecosystems_are_not_compared() -> None:
    assert compare_versions("golang", "1.0.0", "1.0.1") is None


# --- versions (tolerant, for OS packages) ---------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0.0", "1.0.0", 0),
        ("1.0", "1.0.0", 0),
        ("1.2.9", "1.10.0", -1),
        ("15.5.27", "15.5.24", 1),
        ("1.3.2-r1", "1.3.2-r0", 1),
        ("1.3.2-r0", "1.3.2", 1),
        ("1.0rc1", "1.0", -1),
        ("2.0.0", "2.0.0-RC1", 1),
        ("v1.2.3", "v1.2.4", -1),
        ("1.0", "abc", None),
        ("1.0", "v", None),
        ("1.a", "1.2", None),
    ],
)
def test_compare_tokens(a: str, b: str, expected: int | None) -> None:
    assert compare_tokens(a, b) == expected
    if expected is not None:
        assert compare_tokens(b, a) == -expected


# --- purl -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:npm/lodash@4.17.0", ("npm", "", "lodash", "4.17.0")),
        ("pkg:npm/%40babel/traverse@7.20.0", ("npm", "@babel", "traverse", "7.20.0")),
        ("pkg:pypi/Requests@2.0.0", ("pypi", "", "Requests", "2.0.0")),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
            ("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"),
        ),
        (
            "pkg:golang/github.com/a/b@v1#sub/path",
            ("golang", "github.com/a", "b", "v1"),
        ),
        ("pkg:NPM/x", ("npm", "", "x", None)),
        ("lodash@1", None),
        ("pkg:npm", None),
        ("pkg:npm//x", None),
    ],
)
def test_parse_purl(
    purl: str, expected: tuple[str, str, str, str | None] | None
) -> None:
    assert parse_purl(purl) == expected


def test_purl_version_is_decoded_and_cut_at_the_qualifiers() -> None:
    parsed = parse_purl("pkg:maven/g/a@1.0%2Bb?type=jar#x")
    assert parsed is not None
    assert parsed.version == "1.0+b"


# --- GitHub Actions -------------------------------------------------------------


def test_command_data_is_escaped() -> None:
    assert escape_command_data("a%b\r\nc") == "a%25b%0D%0Ac"
    assert escape_command_data(ValueError("x\ny")) == "x%0Ay"


def test_format_output_is_multiline_safe() -> None:
    out = format_output("matrix", "first\nsecond")
    first, *middle, delimiter, trailing = out.split("\n")
    name, _, marker = first.partition("<<")
    assert name == "matrix"
    assert marker == delimiter
    assert middle == ["first", "second"]
    assert trailing == ""


def test_format_output_delimiter_is_unique() -> None:
    assert format_output("a", "x") != format_output("a", "x")


def test_append_text_appends_with_lf_line_ends(tmp_path: Path) -> None:
    path = tmp_path / "out"
    append_text(path, "a=1\n")
    append_text(str(path), "b=2\n")
    assert path.read_bytes() == b"a=1\nb=2\n"


# --- JSON files -----------------------------------------------------------------


def test_dump_json_is_utf8_with_lf_and_a_final_newline(tmp_path: Path) -> None:
    path = tmp_path / "a.json"
    data = {"b": "\u00e9", "a": [1]}
    dump_json(path, data)
    assert path.read_bytes() == b'{\n "b": "\xc3\xa9",\n "a": [\n  1\n ]\n}\n'
    dump_json(path, data, indent=2, sort_keys=True, ensure_ascii=True)
    assert path.read_bytes() == b'{\n  "a": [\n    1\n  ],\n  "b": "\\u00e9"\n}\n'
    assert read_json(path) == data


def test_load_targets_list(tmp_path: Path) -> None:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps({"targets": [{"id": "a"}]}), encoding="utf-8")
    assert load_targets_list(path) == [{"id": "a"}]
    for text in ("{", "[]", '{"targets": 1}', '{"targets": [1]}'):
        path.write_text(text, encoding="utf-8")
        with pytest.raises(InputError):
            load_targets_list(path)
    with pytest.raises(InputError, match="cannot read"):
        load_targets_list(tmp_path / "missing.json")


# --- time -----------------------------------------------------------------------


def test_time_is_written_and_read_in_utc() -> None:
    moment = datetime(2030, 1, 10, 12, 30, 5, tzinfo=UTC)
    assert format_time(moment) == "2030-01-10T12:30:05Z"
    assert parse_time("2030-01-10T12:30:05Z") == moment
    assert parse_time("2030-01-10T12:30:05") == moment
    assert parse_time("garbage") is None
    assert parse_time(None) is None


# --- HTTP -----------------------------------------------------------------------


def test_backoff_doubles_and_follows_retry_after() -> None:
    assert [http.backoff_delay(n) for n in (1, 2, 3)] == [1.0, 2.0, 4.0]
    assert http.backoff_delay(2, base=2.0) == 4.0
    assert http.backoff_delay(1, "7") == 7.0
    assert http.backoff_delay(1, "9999") == http.MAX_RETRY_AFTER_SECONDS
    # a date and not seconds, or zero: the backoff
    assert http.backoff_delay(2, "Wed, 21 Oct 2026 07:28:00 GMT") == 2.0
    assert http.backoff_delay(2, "0") == 2.0


class Network:
    """A transport that answers from a script (a response, or an error to raise)."""

    def __init__(self, *script: http.Response | Exception) -> None:
        self.script = list(script)
        self.calls = 0
        self.sleeps: list[float] = []

    def __call__(self, method: str, url: str, headers: Any, body: Any) -> Any:
        self.calls += 1
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def client(network: Network, **kwargs: Any) -> http.HttpClient:
    return http.HttpClient(network, network.sleeps.append, **kwargs)


def get(network: Network, **kwargs: Any) -> http.Response:
    return client(network, **kwargs).request("GET", "https://e.invalid/", {}, None)


def test_http_client_retries_what_can_pass() -> None:
    network = Network(
        http.Response(503, {"Retry-After": "3"}),
        http.TransportError("reset"),
        http.Response(200, {}, b"ok"),
    )
    assert get(network).body == b"ok"
    assert network.sleeps == [3.0, 2.0]


def test_http_client_gives_up_after_the_attempts() -> None:
    network = Network(*[http.Response(500)] * http.MAX_ATTEMPTS)
    assert get(network).status == 500
    assert network.calls == http.MAX_ATTEMPTS
    network = Network(http.TransportError("down"), http.TransportError("down"))
    with pytest.raises(http.TransportError):
        get(network, max_attempts=2)
    assert network.sleeps == [1.0]


def test_http_client_does_not_retry_a_client_error() -> None:
    network = Network(http.Response(404))
    assert get(network).status == 404
    assert network.sleeps == []


def test_the_transport_refuses_plain_http() -> None:
    with pytest.raises(http.TransportError, match="non-HTTPS"):
        http.UrllibTransport()("GET", "http://e.invalid/", {}, None)


def test_response_headers_are_case_insensitive() -> None:
    assert http.Response(200, {"Retry-After": "1"}).header("retry-after") == "1"
