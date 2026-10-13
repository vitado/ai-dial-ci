#!/usr/bin/env python3
"""Early warning of the SCA scheduled scan: CVE records that vulnerability
databases do not map to packages yet.

A CVE record (cvelistV5, published by the CVE Numbering Authority, CNA) names the
affected product, its repository or package and the affected versions. Trivy and
OSV need a database that maps the CVE to a package (GHSA, distribution trackers,
Go/PyPA/RustSec advisories); until it does, they cannot report it. This script
matches the CNA data of recent records directly with the language packages found
by Trivy in the run, and reports the matches that no scanner of the run knows. It
is an informational signal, not a finding: the merge drops an early warning as soon
as a record of the run has its CVE id or an alias, so a CVE that a database maps
disappears from the radar by construction (see sca_merge_results).

Inputs:
  * targets.json written by sca_resolve_targets;
  * a parts directory with the ``trivy/`` parts (``<id>.json`` and
    ``<id>.status.json`` of every Trivy target): the package inventory;
  * the central CVE index (see sca_build_cve_index), an OCI artifact pulled with
    ORAS (``--cve-index``), or a directory that holds one (``--index-dir``, for
    tests and for running the script by hand with no registry): the CVE records of
    the last 180 days. The deltas of the cvelistV5
    releases since the index was built are applied to its records, with the code of
    the builder (the ``end_of_day`` delta of each past day, the hourly deltas of
    today, the delta log for what they lack), so the records are hours old and not
    a day. There is no other source of records: no index, no early warning;
  * the source repository of each package, from deps.dev (API v3).

Outputs (``<output-dir>/early-warning/``):
  * ``status.json`` - ``{status, reason, window_days, records_scanned,
    candidates, index, diagnostics}``; status is ``ok``, ``failed`` or ``skipped``;
    ``index`` is ``{ref, digest, built_at, gaps}`` (``gaps``: the hours of the
    window for which the feed had no delta, the index's and those of the deltas
    applied since), or null if no index was read;
  * ``candidates.json`` (``ok`` only) - ``{schema_version, generated_utc,
    generated_from, candidates[]}``; a candidate is one CVE for one package
    version, with the CNA data it was matched by, how it was matched (``match``) and
    where the package was seen.

Matching (the narrow form recommended by the study of the CVE feed; only npm, PyPI,
Maven and Cargo packages, OS packages are out of scope like in OSV):

  package_name  ``affected[].packageName`` equals the package name
      (``collectionURL`` names the registry: a foreign registry or a repository of
      the entry that differs from the package's one rejects the match);
  source_repo  ``affected[].repo`` equals the source repository of the package AND
      the entry is about this artifact (``packageName`` or ``product`` agrees with
      the artifact; a repository of many artifacts must not match them all);
  product_name  the entry has neither ``packageName`` nor ``repo``: ``product`` is
      the artifact, ``vendor`` is the repository owner (or the artifact), a
      reference of the CVE points at the repository of the package and, for a
      scoped npm package, the scope is the vendor or owner;
  repo_module  ``product`` is the repository (and not the artifact) and the CVE
      text names the artifact itself.

``match`` says how the candidate was matched, not how likely it is right: there is
no threshold on it. When several entries match, the first of these is kept.

The affected versions are checked with the version scheme of the package
ecosystem. A version that cannot be parsed or compared never makes a match
(precision over recall); these are counted in the diagnostics.

A failure of the index, of the deltas or of deps.dev is not a failure of the scan:
the status is ``failed`` with a reason and the script exits 0 (the report says
"Early warning unavailable"). Only an unusable input exits non-zero.

The HTTP layer of deps.dev is injectable: every request goes through a ``Transport``
(a callable ``(method, url, headers, body) -> Response``), the downloads of the
deltas through the ``Downloader`` of the builder and the ORAS call through a
``subprocess.run``-like runner, so the logic can be tested with fakes and no
network. Python standard library only (and the ``oras`` command).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from functools import cmp_to_key
from pathlib import Path
from typing import Any

FEED_URL = "https://github.com/CVEProject/cvelistV5/releases/download"
ORAS_TIMEOUT_SECONDS = 300
DEPSDEV_URL = "https://api.deps.dev"
USER_AGENT = "ai-dial-ci-sca-early-warning"

SCANNER_TRIVY = "trivy"
STATUS_PENDING = "pending"
STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
CLASS_LANGUAGE_PACKAGES = "lang-pkgs"
SCHEMA_VERSION = 1
PART_DIR = "early-warning"

REQUEST_TIMEOUT_SECONDS = 60.0
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 60.0
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
HTTP_OK = 200
HTTP_NOT_FOUND = 404
# deps.dev answers are small; this only stops an answer that is not one
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
DEPSDEV_WORKERS = 4
# deps.dev is considered unavailable after this many failed requests in a row
DEPSDEV_BREAKER = 10
# Versions of a package tried (newest first) until deps.dev knows one of them
DEPSDEV_VERSION_TRIES = 3

ECOSYSTEMS = ("npm", "pypi", "maven", "cargo")
MAX_DESCRIPTION_CHARS = 3000
MAX_REFERENCES = 100
MAX_LOCATIONS = 50

MATCH_PACKAGE_NAME = "package_name"
MATCH_SOURCE_REPO = "source_repo"
MATCH_PRODUCT_NAME = "product_name"
MATCH_REPO_MODULE = "repo_module"
MATCH_PRIORITY = {
    MATCH_PACKAGE_NAME: 0,
    MATCH_SOURCE_REPO: 1,
    MATCH_PRODUCT_NAME: 2,
    MATCH_REPO_MODULE: 3,
}

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
UNKNOWN_SEVERITY = "UNKNOWN"
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
# CVSS metric keys of a CVE record, the version they carry, in the order of
# preference when a source has several (3.1 over 3.0, v3 over v4 for ranking)
CVSS_METRICS = (("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV4_0", "4.0"))
SOURCE_CNA = "cna"
SOURCE_ADP_PREFIX = "adp:"

_GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)
_PURL_RE = re.compile(r"^pkg:([^/]+)/(.+?)@([^?#@]+)(?:[?#].*)?$")


class InputError(Exception):
    """The inputs are unusable, so no meaningful result can be produced."""


class TransportError(Exception):
    """A network-level failure (DNS, connection, timeout)."""


class IndexUnavailable(Exception):
    """The CVE index cannot be pulled, read or brought up to date."""


class DepsDevError(Exception):
    """A deps.dev request that cannot be completed."""


class DepsDevUnavailable(Exception):
    """deps.dev fails persistently: the repositories of the packages are unknown."""


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


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


Transport = Callable[[str, str, Mapping[str, str], bytes | None], Response]


class UrllibTransport:
    """Production transport: an HTTPS request through urllib with a timeout."""

    def __init__(self, timeout: float = REQUEST_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> Response:
        if urllib.parse.urlsplit(url).scheme != "https":
            raise TransportError(f"refusing non-HTTPS URL: {url}")
        request = urllib.request.Request(
            url, data=body, headers=dict(headers), method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                data = resp.read(MAX_DOWNLOAD_BYTES + 1)
                if len(data) > MAX_DOWNLOAD_BYTES:
                    raise TransportError(f"{url}: answer is larger than the limit")
                return Response(resp.status, dict(resp.headers), data)
        except urllib.error.HTTPError as err:
            return Response(err.code, dict(err.headers), err.read(4096))
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

    def request(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> Response:
        for attempt in range(1, self._max_attempts + 1):
            delay = BACKOFF_BASE_SECONDS * 2 ** (attempt - 1)
            try:
                response = self._transport(method, url, headers, body)
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


# --------------------------------------------------------------------------
# Versions: one comparator per ecosystem, None when a version cannot be compared
# --------------------------------------------------------------------------

_SEMVER_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)


def _semver_key(version: str) -> tuple[tuple[int, int, int], list[str] | None] | None:
    match = _SEMVER_RE.match(version.strip().lstrip("="))
    if not match:
        return None
    numbers = tuple(int(part) if part else 0 for part in match.groups()[:3])
    pre = match.group(4)
    return numbers, (pre.split(".") if pre else None)  # type: ignore[return-value]


def _cmp_prerelease(a: list[str] | None, b: list[str] | None) -> int:
    """SemVer 2.0 precedence of pre-release parts (no pre-release is the highest)."""
    if a is None or b is None:
        return (a is None) - (b is None)
    for x, y in zip(a, b, strict=False):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return -1 if int(x) < int(y) else 1
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1
        return -1 if x < y else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def compare_semver(a: str, b: str) -> int | None:
    ka, kb = _semver_key(a), _semver_key(b)
    if ka is None or kb is None:
        return None
    if ka[0] != kb[0]:
        return -1 if ka[0] < kb[0] else 1
    return _cmp_prerelease(ka[1], kb[1])


# PEP 440, Appendix B
_PEP440_RE = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.IGNORECASE | re.VERBOSE,
)
_PEP440_PRE = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "c": 2,
    "rc": 2,
    "pre": 2,
    "preview": 2,
}
_NEG_INF = (-1,)
_POS_INF = (1 << 62,)


def _pep440_key(version: str) -> tuple[Any, ...] | None:
    """Ordering key as of ``packaging``; the local version label is ignored (the
    affected ranges of a CVE are about public versions).
    """
    match = _PEP440_RE.match(version)
    if not match:
        return None
    release = [int(part) for part in match.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = post = dev = None
    if match.group("pre_l"):
        pre = (
            _PEP440_PRE[match.group("pre_l").lower()],
            int(match.group("pre_n") or 0),
        )
    if match.group("post"):
        post = int(match.group("post_n1") or match.group("post_n2") or 0)
    if match.group("dev_l"):
        dev = int(match.group("dev_n") or 0)
    if pre is None and post is None and dev is not None:
        pre_key: tuple[Any, ...] = _NEG_INF
    elif pre is None:
        pre_key = _POS_INF
    else:
        pre_key = pre
    return (
        int(match.group("epoch") or 0),
        tuple(release),
        pre_key,
        _NEG_INF if post is None else (post,),
        _POS_INF if dev is None else (dev,),
    )


def compare_pep440(a: str, b: str) -> int | None:
    ka, kb = _pep440_key(a), _pep440_key(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


# Maven ComparableVersion (Maven 3.x): items are int, str (a qualifier) or list.
_MAVEN_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
_MAVEN_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
_MAVEN_SHORT = {"a": "alpha", "b": "beta", "m": "milestone"}
_MAVEN_RELEASE_KEY = str(_MAVEN_QUALIFIERS.index(""))
_MavenItem = int | str | list


def _maven_qualifier_key(qualifier: str) -> str:
    if qualifier in _MAVEN_QUALIFIERS:
        return str(_MAVEN_QUALIFIERS.index(qualifier))
    return f"{len(_MAVEN_QUALIFIERS)}-{qualifier}"


def _maven_string_item(text: str, followed_by_digit: bool) -> str:
    if followed_by_digit and len(text) == 1:
        text = _MAVEN_SHORT.get(text, text)
    return _MAVEN_ALIASES.get(text, text)


def _maven_is_null(item: _MavenItem) -> bool:
    if isinstance(item, int):
        return item == 0
    if isinstance(item, str):
        return _maven_qualifier_key(item) == _MAVEN_RELEASE_KEY
    return not item


def _maven_normalize(items: list[_MavenItem]) -> None:
    for index in range(len(items) - 1, -1, -1):
        item = items[index]
        if _maven_is_null(item):
            del items[index]
        elif not isinstance(item, list):
            break


def _maven_parse(version: str) -> list[_MavenItem]:
    version = version.strip().lower()
    root: list[_MavenItem] = []
    current = root
    stack = [root]
    is_digit = False
    start = 0

    def item(digit: bool, text: str) -> _MavenItem:
        return int(text) if digit else _maven_string_item(text, False)

    def descend() -> list[_MavenItem]:
        child: list[_MavenItem] = []
        current.append(child)
        stack.append(child)
        return child

    for index, char in enumerate(version):
        if char == ".":
            current.append(
                0 if index == start else item(is_digit, version[start:index])
            )
            start = index + 1
        elif char == "-":
            current.append(
                0 if index == start else item(is_digit, version[start:index])
            )
            start = index + 1
            current = descend()
        elif char.isdigit():
            if not is_digit and index > start:
                current.append(_maven_string_item(version[start:index], True))
                start = index
                current = descend()
            is_digit = True
        else:
            if is_digit and index > start:
                current.append(int(version[start:index]))
                start = index
                current = descend()
            is_digit = False
    if len(version) > start:
        current.append(item(is_digit, version[start:]))
    while stack:
        _maven_normalize(stack.pop())
    return root


def _maven_cmp_item(a: _MavenItem | None, b: _MavenItem | None) -> int:
    """``ComparableVersion.*Item.compareTo``; None is the missing item."""
    if a is None:
        return 0 if b is None else -_maven_cmp_item(b, None)
    if isinstance(a, int):
        if b is None:
            return 0 if a == 0 else 1
        if isinstance(b, int):
            return (a > b) - (a < b)
        return 1
    if isinstance(a, str):
        if b is None:
            ka, kb = _maven_qualifier_key(a), _MAVEN_RELEASE_KEY
        elif isinstance(b, str):
            ka, kb = _maven_qualifier_key(a), _maven_qualifier_key(b)
        else:
            return -1
        return (ka > kb) - (ka < kb)
    if b is None:
        return 0 if not a else _maven_cmp_item(a[0], None)
    if isinstance(b, int):
        return -1
    if isinstance(b, str):
        return 1
    for index in range(max(len(a), len(b))):
        left = a[index] if index < len(a) else None
        right = b[index] if index < len(b) else None
        result = _maven_cmp_item(left, right)
        if result:
            return result
    return 0


def compare_maven(a: str, b: str) -> int | None:
    if not (re.search(r"\d", a) and re.search(r"\d", b)):
        return None
    return _maven_cmp_item(_maven_parse(a), _maven_parse(b))


def compare_versions(ecosystem: str, a: str, b: str) -> int | None:
    """-1, 0 or 1 by the version scheme of the ecosystem; None if either version is
    not valid in it.
    """
    if ecosystem in ("npm", "cargo"):
        return compare_semver(a, b)
    if ecosystem == "pypi":
        return compare_pep440(a, b)
    if ecosystem == "maven":
        return compare_maven(a, b)
    return None


# --------------------------------------------------------------------------
# Affected versions of a CNA entry
# --------------------------------------------------------------------------

STATUS_AFFECTED = "affected"
STATUS_NOT_AFFECTED = "not_affected"
STATUS_UNKNOWN = "unknown"
STATUS_ALL = "affected_all"  # no versions listed, the default status is affected

_WILDCARDS = frozenset({"*", "unspecified", "n/a", "unknown", ""})
_FULL_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_COMPARISON_RE = re.compile(r"^\s*(?:(\S+)\s*(<=?)\s*(\S+)|(<=?|>=?|=)\s*(\S+))\s*$")
_OPERATOR_CHARS_RE = re.compile(r"[<>=;,]")
UNSUPPORTED_VERSION_TYPES = frozenset({"git", "rpm", "deb", "apk"})


def _is_wildcard(value: Any) -> bool:
    return value is None or str(value).strip().lower() in _WILDCARDS


def _free_text_affects(ecosystem: str, version: str, text: str) -> bool | None:
    """Free text of the GitHub CNA style: ``< 2.14.0``, ``>= 1.0, < 1.5``,
    ``7.0.0 < 7.24.0; < 6.24.0`` (``;`` is OR, ``,`` is AND).
    """
    alternatives = []
    for alternative in text.split(";"):
        holds = True
        for part in alternative.split(","):
            match = _COMPARISON_RE.match(part)
            if not match:
                return None
            if match.group(2):
                low, op, high = match.group(1), match.group(2), match.group(3)
                above = compare_versions(ecosystem, version, low)
                below = compare_versions(ecosystem, version, high)
                if above is None or below is None:
                    return None
                holds = (
                    holds and above >= 0 and (below < 0 if op == "<" else below <= 0)
                )
            else:
                op, other = match.group(4), match.group(5)
                result = compare_versions(ecosystem, version, other)
                if result is None:
                    return None
                holds = (
                    holds
                    and {
                        "<": result < 0,
                        "<=": result <= 0,
                        ">": result > 0,
                        ">=": result >= 0,
                        "=": result == 0,
                    }[op]
                )
        alternatives.append(holds)
    return any(alternatives)


def _in_range(ecosystem: str, version: str, item: Mapping[str, Any]) -> bool | None:
    """Whether the version lies in the range of one ``versions[]`` item; None if it
    cannot be told.
    """
    low, less, less_equal = (
        item.get("version"),
        item.get("lessThan"),
        item.get("lessThanOrEqual"),
    )
    if (
        _OPERATOR_CHARS_RE.search(str(low or ""))
        and less is None
        and less_equal is None
    ):
        return _free_text_affects(ecosystem, version, str(low))
    kind = str(item.get("versionType") or "").lower()
    bounds = (low, less, less_equal)
    if kind in UNSUPPORTED_VERSION_TYPES or any(
        b and _FULL_COMMIT_RE.match(str(b)) for b in bounds
    ):
        return None
    if less is None and less_equal is None:
        if _is_wildcard(low):
            return None
        result = compare_versions(ecosystem, version, str(low))
        return None if result is None else result == 0
    holds = True
    if not _is_wildcard(low) and str(low) != "0":
        result = compare_versions(ecosystem, version, str(low))
        if result is None:
            return None
        holds = holds and result >= 0
    if not _is_wildcard(less):
        result = compare_versions(ecosystem, version, str(less))
        if result is None:
            return None
        holds = holds and result < 0
    if not _is_wildcard(less_equal):
        result = compare_versions(ecosystem, version, str(less_equal))
        if result is None:
            return None
        holds = holds and result <= 0
    return holds


def _status_by_changes(
    ecosystem: str, version: str, item: Mapping[str, Any]
) -> str | None:
    """Status at the version by the ``changes`` of an item (``version`` is the first
    point, each change is the next one); None if a point cannot be compared.
    """
    points = [(item.get("version"), item.get("status"))] + [
        (change.get("at"), change.get("status")) for change in item["changes"]
    ]
    current = None
    for at, status in points:
        if at in ("*", "0"):
            current = status
            continue
        result = compare_versions(ecosystem, version, str(at)) if at else None
        if result is None:
            return None
        if result < 0:
            break
        current = status
    return current or STATUS_NOT_AFFECTED


def entry_status(ecosystem: str, version: str, entry: Mapping[str, Any]) -> str:
    """What one ``affected[]`` entry says about a version: ``affected``,
    ``affected_all``, ``not_affected`` or ``unknown``.
    """
    items = entry.get("versions") or []
    default = entry.get("defaultStatus")
    unknown = hit_affected = hit_unaffected = False
    for item in items:
        status = item.get("status")
        if item.get("changes"):
            current = _status_by_changes(ecosystem, version, item)
            if current is None:
                unknown = True
            elif current == STATUS_AFFECTED:
                hit_affected = True
            elif current == "unaffected":
                hit_unaffected = True
            continue
        inside = _in_range(ecosystem, version, item)
        if inside is None:
            unknown = unknown or status != "unaffected"
        elif inside:
            hit_affected = hit_affected or status == STATUS_AFFECTED
            hit_unaffected = hit_unaffected or status == "unaffected"
    if hit_unaffected:
        return STATUS_NOT_AFFECTED
    if hit_affected:
        return STATUS_AFFECTED
    if not items:
        return STATUS_ALL if default == STATUS_AFFECTED else STATUS_UNKNOWN
    if unknown:
        return STATUS_UNKNOWN
    listed_affected = any(i.get("status") == STATUS_AFFECTED for i in items)
    if default == STATUS_AFFECTED and not listed_affected:
        return STATUS_AFFECTED
    return STATUS_NOT_AFFECTED


def describe_range(entry: Mapping[str, Any]) -> str:
    """The affected versions of an entry as the CNA gave them."""
    parts = []
    for item in entry.get("versions") or []:
        if item.get("status") != STATUS_AFFECTED:
            continue
        low, less, less_equal = (
            item.get("version"),
            item.get("lessThan"),
            item.get("lessThanOrEqual"),
        )
        if less is None and less_equal is None:
            text = str(low)
            if not _OPERATOR_CHARS_RE.search(text):
                text = f"= {text}"
            fixed = [
                str(c.get("at"))
                for c in item.get("changes") or []
                if c.get("status") == "unaffected"
            ]
            if fixed:
                text += f" (fixed in {', '.join(fixed)})"
            parts.append(text)
            continue
        upper = f"< {less}" if not _is_wildcard(less) else f"<= {less_equal}"
        if _is_wildcard(less) and _is_wildcard(less_equal):
            upper = ""
        lower = "" if _is_wildcard(low) or str(low) == "0" else f">= {low}"
        parts.append(", ".join(p for p in (lower, upper) if p) or "all versions")
    if not parts:
        return "all versions" if entry.get("defaultStatus") == STATUS_AFFECTED else ""
    return "; ".join(parts)


# --------------------------------------------------------------------------
# Names and repositories
# --------------------------------------------------------------------------


def normalize_repo(url: Any) -> str | None:
    """``host/owner/name`` in lower case, whatever the form of the URL."""
    if not isinstance(url, str) or not url.strip():
        return None
    text = url.strip().lower()
    text = re.sub(r"^git\+", "", text)
    text = re.sub(r"^(https?|git|ssh)://", "", text)
    text = re.sub(r"^[^@/]+@", "", text)
    if re.match(r"^[a-z0-9.-]+:[^/0-9]", text):
        text = text.replace(":", "/", 1)
    text = re.sub(r"^www\.", "", text)
    text = re.sub(r"[#?].*$", "", text)
    text = re.sub(
        r"/(tree|blob|issues|pull|releases|wiki|commit|security)(/.*)?$", "", text
    )
    text = re.sub(r"\.git$", "", text).rstrip("/")
    return text or None


def normalize_name(ecosystem: str, name: str) -> str:
    name = name.strip().lower()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name)
    if ecosystem == "cargo":
        return name.replace("_", "-")
    if ecosystem == "maven":
        return name.replace("/", ":")
    return name


def squash(text: Any) -> str:
    """Lower case letters and digits only: ``Jackson-Core`` == ``jackson_core``."""
    return re.sub(r"[^a-z0-9]", "", str(text or "").lower())


_REGISTRY_HOSTS = (
    ("npmjs.org", "npm"),
    ("npmjs.com", "npm"),
    ("pypi.org", "pypi"),
    ("pythonhosted.org", "pypi"),
    ("maven.org", "maven"),
    ("maven.apache.org", "maven"),
    ("sonatype.com", "maven"),
    ("mvnrepository.com", "maven"),
    ("crates.io", "cargo"),
)
_NEUTRAL_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")
FOREIGN_REGISTRY = "other"
_FOREIGN_HOSTS = (
    "redhat.com",
    "wordpress.org",
    "cpan.org",
    "hex.pm",
    "nuget.org",
    "packagist.org",
    "rubygems.org",
    "conan.io",
    "pkg.go.dev",
    "golang.org",
    "apple.com",
    "microsoft.com",
)


def registry_ecosystem(collection_url: str | None) -> str | None:
    """The ecosystem a ``collectionURL`` names: one of ECOSYSTEMS, FOREIGN_REGISTRY
    (a registry or catalogue of something else) or None (a repository host or an
    unknown URL: no statement about the ecosystem).
    """
    if not collection_url:
        return None
    host = (urllib.parse.urlsplit(collection_url.strip()).hostname or "").lower()
    if any(host == h or host.endswith("." + h) for h in _NEUTRAL_HOSTS):
        return None
    for suffix, ecosystem in _REGISTRY_HOSTS:
        if host == suffix or host.endswith("." + suffix):
            return ecosystem
    if any(host == h or host.endswith("." + h) for h in _FOREIGN_HOSTS):
        return FOREIGN_REGISTRY
    return None


def url_points_at_repo(url: str, repo: str) -> bool:
    """Whether a URL is the repository or a page below it (not a sibling that
    merely starts with the same characters).
    """
    normal = re.sub(r"^git\+", "", url.strip().lower())
    normal = re.sub(r"^[a-z]+://", "", normal)
    normal = re.sub(r"^www\.", "", normal)
    normal = re.sub(r"[#?].*$", "", normal).removesuffix(".git").rstrip("/")
    return normal == repo or normal.startswith(repo + "/")


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str

    @property
    def artifact(self) -> str:
        """The last segment of the name: ``guava`` of ``com.google.guava:guava``,
        ``common`` of ``@nestjs/common``.
        """
        return self.name.split(":")[-1].split("/")[-1]


@dataclass
class Inventory:
    # package -> target id -> locations (lockfiles / image results)
    sightings: dict[Package, dict[str, set[str]]] = field(default_factory=dict)
    unsupported: int = 0
    targets_read: int = 0


def parse_purl(purl: str) -> Package | None:
    """The package of a supported ecosystem a purl names, else None."""
    match = _PURL_RE.match(purl)
    if not match or match.group(1) not in ECOSYSTEMS:
        return None
    ecosystem = match.group(1)
    name = urllib.parse.unquote(match.group(2))
    if ecosystem == "maven":
        name = name.replace("/", ":")
    return Package(ecosystem, name, urllib.parse.unquote(match.group(3)))


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_targets_file(path: Path) -> list[dict[str, Any]]:
    try:
        data = read_json(path)
    except (OSError, ValueError) as err:
        raise InputError(f"cannot read targets file {path}: {err}") from err
    targets = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(targets, list) or not all(isinstance(t, dict) for t in targets):
        raise InputError(f"targets file {path} has no 'targets' list")
    return targets


def trivy_native(trivy_dir: Path, target_id: str) -> dict[str, Any] | None:
    """The native result of a Trivy target, None unless it was scanned fully."""
    try:
        status = read_json(trivy_dir / f"{target_id}.status.json")
        if not isinstance(status, dict) or status.get("status") != STATUS_OK:
            return None
        native = read_json(trivy_dir / f"{target_id}.json")
    except (OSError, ValueError):
        return None
    return native if isinstance(native, dict) else None


def load_inventory(targets: Sequence[Mapping[str, Any]], trivy_dir: Path) -> Inventory:
    """The language packages of every Trivy target that was scanned: where each
    package version was seen. Packages of other ecosystems, or without a versioned
    purl, are counted but not matched.
    """
    inventory = Inventory()
    unsupported: set[tuple[Any, Any]] = set()
    for target in targets:
        if target.get("scanner") != SCANNER_TRIVY or target.get("status") != (
            STATUS_PENDING
        ):
            continue
        native = trivy_native(trivy_dir, target["id"])
        if native is None:
            continue
        inventory.targets_read += 1
        for result in native.get("Results") or []:
            if result.get("Class") != CLASS_LANGUAGE_PACKAGES:
                continue
            for item in result.get("Packages") or []:
                purl = (item.get("Identifier") or {}).get("PURL")
                package = parse_purl(purl) if isinstance(purl, str) else None
                if package is None:
                    unsupported.add((item.get("Name"), item.get("Version")))
                    continue
                places = inventory.sightings.setdefault(package, {})
                places.setdefault(target["id"], set()).add(result.get("Target", ""))
    inventory.unsupported = len(unsupported)
    return inventory


# --------------------------------------------------------------------------
# deps.dev: the source repository of a package
# --------------------------------------------------------------------------


@dataclass
class RepoLookup:
    """Source repositories by (ecosystem, name), and what the lookup met."""

    repos: dict[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)
    requests: int = 0
    without_repo: int = 0
    errors: int = 0


class DepsDevClient:
    def __init__(self, http: HttpClient, api_url: str) -> None:
        self._http = http
        self._api_url = api_url.rstrip("/")
        self._headers = {"Accept": "application/json", "User-Agent": USER_AGENT}

    def source_repos(self, package: Package) -> tuple[str, ...] | None:
        """Normalized source repositories of the package version; None if deps.dev
        does not know the version (404).
        """
        path = "/v3/systems/{}/packages/{}/versions/{}".format(
            package.ecosystem,
            urllib.parse.quote(package.name, safe=""),
            urllib.parse.quote(package.version, safe=""),
        )
        try:
            response = self._http.request(
                "GET", self._api_url + path, self._headers, None
            )
        except TransportError as err:
            raise DepsDevError(f"GET {path}: {err}") from err
        if response.status == HTTP_NOT_FOUND:
            return None
        if response.status != HTTP_OK:
            raise DepsDevError(f"GET {path}: HTTP {response.status}")
        try:
            data = json.loads(response.body)
        except ValueError as err:
            raise DepsDevError(f"GET {path}: answer is not valid JSON: {err}") from err
        if not isinstance(data, dict):
            raise DepsDevError(f"GET {path}: unexpected answer")
        found: set[str] = set()
        for project in data.get("relatedProjects") or []:
            if project.get("relationType") == "SOURCE_REPO":
                found.add(normalize_repo((project.get("projectKey") or {}).get("id")))
        for link in data.get("links") or []:
            if link.get("label") == "SOURCE_REPO":
                found.add(normalize_repo(link.get("url")))
        return tuple(sorted(r for r in found if r))


def newest_first(ecosystem: str, versions: Iterable[str]) -> list[str]:
    def order(a: str, b: str) -> int:
        return compare_versions(ecosystem, a, b) or 0

    return sorted(set(versions), key=cmp_to_key(order), reverse=True)


def resolve_repos(
    client: DepsDevClient,
    inventory: Inventory,
    workers: int = DEPSDEV_WORKERS,
    breaker: int = DEPSDEV_BREAKER,
) -> RepoLookup:
    """The source repository of every package name of the inventory.

    The repository is asked for a version of the name (the newest first; the next
    one only if deps.dev does not know it), with at most ``workers`` requests in
    flight. A request that fails after its retries leaves the name without
    repositories and is counted; ``breaker`` failures in a row mean deps.dev is down
    and raise DepsDevUnavailable.
    """
    versions: dict[tuple[str, str], list[str]] = {}
    for package in inventory.sightings:
        versions.setdefault((package.ecosystem, package.name), []).append(
            package.version
        )
    lookup = RepoLookup()
    lock = threading.Lock()
    state = {"consecutive": 0, "tripped": False, "last": ""}

    def one(key: tuple[str, str]) -> tuple[str, ...]:
        for version in newest_first(key[0], versions[key])[:DEPSDEV_VERSION_TRIES]:
            if state["tripped"]:
                return ()
            try:
                repos = client.source_repos(Package(key[0], key[1], version))
            except DepsDevError as err:
                with lock:
                    lookup.requests += 1
                    lookup.errors += 1
                    state["consecutive"] += 1
                    state["last"] = str(err)
                    state["tripped"] = state["consecutive"] >= breaker
                return ()
            with lock:
                lookup.requests += 1
                state["consecutive"] = 0
            if repos is not None:
                return repos
        return ()

    keys = sorted(versions)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for key, repos in zip(keys, pool.map(one, keys), strict=True):
            lookup.repos[key] = repos
            lookup.without_repo += not repos
    if state["tripped"]:
        raise DepsDevUnavailable(
            f"deps.dev failed {breaker} requests in a row, last: {state['last']}"
        )
    return lookup


# --------------------------------------------------------------------------
# CVE records: severity, the slim form, the names of the feed assets
# --------------------------------------------------------------------------


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def severity_of_score(score: float) -> str:
    """The CVSS rating of a base score (the same bands in v3 and v4)."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return UNKNOWN_SEVERITY


def _cvss_of(source: str, metric: Mapping[str, Any]) -> list[dict[str, Any]]:
    found = []
    for key, version in CVSS_METRICS:
        data = metric.get(key)
        if not isinstance(data, dict):
            continue
        score = data.get("baseScore")
        if isinstance(score, bool) or not isinstance(score, int | float):
            continue
        rating = str(data.get("baseSeverity") or "").upper()
        found.append(
            {
                "score": float(score),
                "vector": data.get("vectorString") or None,
                "version": version,
                "source": source,
                "severity": rating
                if rating in SEVERITY_ORDER and rating != UNKNOWN_SEVERITY
                else severity_of_score(float(score)),
            }
        )
    return found


def _exploitation_of(source: str, metric: Mapping[str, Any]) -> dict[str, Any] | None:
    other = metric.get("other")
    if not isinstance(other, dict):
        return None
    kind = str(other.get("type") or "").lower()
    content = other.get("content")
    if not isinstance(content, dict):
        return None
    if kind == "kev":
        return {
            "kev": True,
            "kev_date_added": content.get("dateAdded"),
            "source": source,
        }
    if kind == "ssvc":
        for option in content.get("options") or []:
            if isinstance(option, dict) and "Exploitation" in option:
                return {"ssvc": str(option["Exploitation"]).lower(), "source": source}
    return None


def extract_metrics(containers: Mapping[str, Any]) -> dict[str, Any]:
    """The CVSS scores and the exploitation signals of a record.

    ``cvss`` is the list of CVSS 3.x / 4.0 scores of the first source that has any
    (the CNA, else an ADP container, by short name); ``exploitation`` is
    ``{"kev": bool, "kev_date_added", "ssvc": "active|poc|none"|None, "source"}``
    or None. CVSS 2 and free-text ratings are not used.
    """
    sources: list[tuple[str, Mapping[str, Any]]] = [
        (SOURCE_CNA, containers.get("cna") or {})
    ]
    adp = [c for c in containers.get("adp") or [] if isinstance(c, dict)]
    adp.sort(key=lambda c: str((c.get("providerMetadata") or {}).get("shortName")))
    for container in adp:
        name = (container.get("providerMetadata") or {}).get("shortName") or "?"
        sources.append((f"{SOURCE_ADP_PREFIX}{name}", container))
    cvss: list[dict[str, Any]] = []
    kev: dict[str, Any] | None = None
    ssvc: dict[str, Any] | None = None
    for source, container in sources:
        found: list[dict[str, Any]] = []
        for metric in container.get("metrics") or []:
            if not isinstance(metric, dict):
                continue
            found += _cvss_of(source, metric)
            signal = _exploitation_of(source, metric)
            if signal and "kev" in signal:
                kev = kev or signal
            elif signal:
                ssvc = ssvc or signal
        cvss = cvss or found
    exploitation = None
    if kev or ssvc:
        exploitation = {
            "kev": bool(kev),
            "kev_date_added": (kev or {}).get("kev_date_added"),
            "ssvc": (ssvc or {}).get("ssvc"),
            "source": (kev or ssvc or {}).get("source"),
        }
    return {"cvss": cvss, "exploitation": exploitation}


def select_severity(metrics: Mapping[str, Any]) -> dict[str, Any]:
    """``severity``, ``severity_source``, ``cvss`` (the score used for ranking:
    3.1 over 3.0 over 4.0 of the chosen source) and ``cvss_v4`` (the 4.0 score, if
    it is not the ranking one) of a record's metrics.
    """
    scores = list(metrics.get("cvss") or [])
    if not scores:
        return {
            "severity": UNKNOWN_SEVERITY,
            "severity_source": None,
            "cvss": None,
            "cvss_v4": None,
        }
    order = {version: index for index, (_, version) in enumerate(CVSS_METRICS)}
    scores.sort(key=lambda s: order[s["version"]])
    main = scores[0]
    v4 = next((s for s in scores if s["version"] == "4.0" and s is not main), None)

    def public(score: Mapping[str, Any] | None) -> dict[str, Any] | None:
        if score is None:
            return None
        return {k: score[k] for k in ("score", "vector", "version", "source")}

    return {
        "severity": main["severity"],
        "severity_source": main["source"],
        "cvss": public(main),
        "cvss_v4": public(v4),
    }


def slim_record(document: Mapping[str, Any]) -> dict[str, Any] | None:
    """What the matcher needs of a CVE record 5 (None: not a usable record)."""
    meta = document.get("cveMetadata")
    containers = document.get("containers")
    if not isinstance(meta, dict) or not isinstance(containers, dict):
        return None
    cna = containers.get("cna") or {}
    descriptions = cna.get("descriptions") or [{}]
    english = [d for d in descriptions if str(d.get("lang", "en")).startswith("en")]
    text = str((english or descriptions)[0].get("value") or "")
    entries = []
    for entry in cna.get("affected") or []:
        if isinstance(entry, dict):
            entries.append(
                {
                    k: entry[k]
                    for k in (
                        "vendor",
                        "product",
                        "packageName",
                        "collectionURL",
                        "repo",
                        "versions",
                        "defaultStatus",
                    )
                    if entry.get(k) is not None
                }
            )
    refs = [
        str(r["url"])
        for r in (cna.get("references") or [])[:MAX_REFERENCES]
        if isinstance(r, dict) and r.get("url")
    ]
    return {
        "cve": meta.get("cveId"),
        "state": meta.get("state"),
        "published": meta.get("datePublished"),
        "updated": meta.get("dateUpdated") or meta.get("datePublished"),
        "assigner": meta.get("assignerShortName"),
        "title": cna.get("title"),
        "description": text[:MAX_DESCRIPTION_CHARS],
        "affected": entries,
        "references": refs,
        "metrics": extract_metrics(containers),
    }


def end_of_day_asset(day: date) -> str:
    return f"cve_{day}_at_end_of_day/{day}_delta_CVEs_at_end_of_day.zip"


def hourly_asset(day: date, hour: int) -> str:
    return f"cve_{day}_{hour:02d}00Z/{day}_delta_CVEs_at_{hour:02d}00Z.zip"


# --------------------------------------------------------------------------
# The CVE index
# --------------------------------------------------------------------------

STATE_PUBLISHED = "PUBLISHED"
_BUILDER_DIR = Path(__file__).resolve().parents[1] / "sca_build_cve_index"

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def builder() -> Any:
    """The module of the index builder, a sibling action: its code reads the index and
    applies the deltas to it. Imported when needed, not at the top: the builder
    imports this module for its helpers (names, versions, the form of a record), and a
    cycle of imports at load time would depend on which of the two runs as a script.
    """
    if str(_BUILDER_DIR) not in sys.path:
        sys.path.insert(0, str(_BUILDER_DIR))
    import build_cve_index

    return build_cve_index


@dataclass
class IndexData:
    """The CVE index as read: the records (the latest version of each), its metadata
    and the gaps of the feed in its window (``{from, to}`` ranges of hours). ``ref``
    and ``digest`` say which artifact it is (no digest for a directory).
    """

    records: dict[str, dict[str, Any]]
    metadata: dict[str, Any]
    ref: str
    digest: str | None = None
    gaps: list[dict[str, str]] = field(default_factory=list)


def pull_index(ref: str, dest: Path, run: Runner = subprocess.run) -> str:
    """Pull the index artifact into ``dest`` with ORAS, anonymously; return its digest.

    The reference is resolved to a digest first and the artifact pulled by that
    digest, so that the digest in the report is that of what was read, even if the
    tag moves in between. ORAS or the registry failing is IndexUnavailable.
    """

    def oras(*arguments: str) -> str:
        try:
            done = run(
                ["oras", *arguments],
                capture_output=True,
                text=True,
                check=False,
                timeout=ORAS_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            raise IndexUnavailable(f"cannot pull {ref}: {err}") from err
        if done.returncode != 0:
            lines = (done.stderr or "").strip().splitlines()
            reason = lines[-1] if lines else f"exit code {done.returncode}"
            raise IndexUnavailable(
                f"cannot pull {ref}: oras {arguments[0]} failed: {reason}"
            )
        return done.stdout.strip()

    digest = oras("resolve", ref)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise IndexUnavailable(f"cannot pull {ref}: no digest ({digest[:80]!r})")
    repository = re.sub(r":[^:/@]+$", "", ref.split("@")[0])
    oras("pull", f"{repository}@{digest}", "--output", str(dest))
    return digest


def read_index(directory: Path, ref: str, digest: str | None) -> IndexData:
    """The index in a directory. An index that cannot be read, or that has another
    schema, is IndexUnavailable: the early warning is not made from a guess.
    """
    bci = builder()
    try:
        previous = bci.read_previous(directory)
        gaps = list(previous.metadata.get("gaps") or [])
        bci.gaps_of(gaps)  # the shape of the gaps is checked here and not later
    except (bci.IndexBuildError, OSError, ValueError) as err:
        raise IndexUnavailable(f"the index {ref} cannot be read: {err}") from err
    return IndexData(previous.records, previous.metadata, ref, digest, gaps)


def catch_up(
    index: IndexData,
    downloader: Any,
    feed_url: str,
    work_dir: Path,
    now: datetime,
) -> None:
    """Bring the records of the index up to ``now``: the deltas of the days since it
    was built, and the records that the delta log lists and the deltas lack (the
    code of the builder). Keeps the records that are published and were updated in
    the window of the index, and sets ``index.gaps`` to the gaps of the feed in that
    window: those of the index before the day it was built, and those of the deltas
    applied now. A delta that cannot be downloaded or read is IndexUnavailable.
    """
    bci = builder()
    now = now.astimezone(UTC).replace(microsecond=0)
    built = parse_time(index.metadata.get("built_at"))
    window_days = index.metadata.get("window_days")
    if built is None or not isinstance(window_days, int) or window_days < 1:
        raise IndexUnavailable(f"the index {index.ref} has no built_at or window")
    cutoff = now - timedelta(days=window_days)
    if built < cutoff:
        raise IndexUnavailable(
            f"the index {index.ref} was built {built:%Y-%m-%d}, before its window of "
            f"{window_days} days: no delta connects it to today"
        )
    since = datetime(built.year, built.month, built.day, tzinfo=UTC)
    feed = bci.Feed()
    try:
        client = bci.FeedClient(downloader, feed_url, work_dir / "feed")
        bci.apply_deltas(index.records, client, since.date(), now, cutoff, feed)
        bci.reconcile(
            index.records, downloader, work_dir / "reconcile", since, now, cutoff, feed
        )
        gaps = feed.gaps | {h for h in bci.gaps_of(index.gaps) if h < since}
    except bci.IndexBuildError as err:
        raise IndexUnavailable(str(err)) from err
    first_hour = cutoff.replace(minute=0, second=0)
    index.gaps = bci.gap_ranges({h for h in gaps if h >= first_hour})
    index.records = {
        cve: record
        for cve, record in index.records.items()
        if record["state"] == STATE_PUBLISHED
        and (parse_time(record["updated"]) or cutoff) >= cutoff
    }


def index_document(index: IndexData) -> dict[str, Any]:
    """What the report says about the index it was made from."""
    return {
        "ref": index.ref,
        "digest": index.digest,
        "built_at": index.metadata.get("built_at"),
        "gaps": index.gaps,
    }


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

CONSISTENT = "consistent"
CONSISTENT_BY_TEXT = "consistent_by_text"
MODULE_UNKNOWN = "module_unknown"
INCONSISTENT = "inconsistent"
_BOUNDARY = r"(?<![A-Za-z0-9-]){}(?![A-Za-z0-9-])"
_JDK_SUFFIX_RE = re.compile(r"jdk\d+\w*|lts\w*")


@dataclass
class Index:
    by_name: dict[tuple[str, str], list[Package]] = field(default_factory=dict)
    by_repo: dict[str, list[Package]] = field(default_factory=dict)
    by_artifact: dict[str, list[Package]] = field(default_factory=dict)
    by_owner_base: dict[tuple[str, str], list[Package]] = field(default_factory=dict)
    repos: dict[Package, tuple[str, ...]] = field(default_factory=dict)


def build_index(
    inventory: Inventory, repos: Mapping[tuple[str, str], tuple[str, ...]]
) -> Index:
    index = Index()
    for package in sorted(
        inventory.sightings, key=lambda p: (p.ecosystem, p.name, p.version)
    ):
        package_repos = repos.get((package.ecosystem, package.name), ())
        index.repos[package] = package_repos
        name = normalize_name(package.ecosystem, package.name)
        index.by_name.setdefault((package.ecosystem, name), []).append(package)
        for key in {squash(package.artifact), squash(package.name)}:
            index.by_artifact.setdefault(key, []).append(package)
        for repo in package_repos:
            index.by_repo.setdefault(repo, []).append(package)
            parts = repo.split("/")
            if len(parts) >= 3:
                owner_base = (squash(parts[1]), squash(parts[-1]))
                index.by_owner_base.setdefault(owner_base, []).append(package)
    return index


def named_in_text(package: Package, text: str) -> bool:
    """Whether the text names the package itself: its full name, or its artifact id
    as a whole word (not for a scoped npm package, whose last segment is too generic
    to mean anything alone).
    """
    needles = {package.name}
    if not (package.ecosystem == "npm" and package.name.startswith("@")):
        needles.add(package.artifact)
    return any(
        re.search(_BOUNDARY.format(re.escape(needle)), text, re.IGNORECASE)
        for needle in needles
        if needle
    )


def name_agrees(package_name: str, package: Package) -> bool:
    """A CNA ``packageName`` is the package, or its artifact id, or the family name of
    a Bouncy-Castle-like artifact (``bcprov`` for ``bcprov-jdk18on``).
    """
    wanted = squash(package_name)
    if wanted in {squash(package.name), squash(package.artifact)}:
        return True
    artifact = squash(package.artifact)
    return artifact.startswith(wanted) and bool(
        _JDK_SUFFIX_RE.fullmatch(artifact[len(wanted) :])
    )


def entry_consistency(
    package: Package, entry: Mapping[str, Any], repo: str | None, text: str
) -> str:
    """Whether a CNA entry is about this artifact and not about another artifact of
    the same repository.
    """
    package_name = entry.get("packageName")
    if package_name:
        return CONSISTENT if name_agrees(package_name, package) else INCONSISTENT
    product = squash(entry.get("product"))
    if not product:
        return INCONSISTENT
    if product in {squash(package.artifact), squash(package.name)}:
        return CONSISTENT
    if repo and product == squash(repo.rsplit("/", 1)[-1]):
        # The product is the repository (many modules): only if the text says which
        return CONSISTENT_BY_TEXT if named_in_text(package, text) else MODULE_UNKNOWN
    return INCONSISTENT


@dataclass
class Hit:
    """One entry of one record meeting one package version."""

    package: Package
    match: str
    status: str
    entry: Mapping[str, Any]


def entry_hits(
    index: Index, record: Mapping[str, Any], entry: Mapping[str, Any], outcomes: Counter
) -> Iterator[Hit]:
    """The packages a CNA entry applies to, with the verdict of its versions.

    ``outcomes`` counts the matches that were rejected, by reason.
    """
    text = f"{record['title'] or ''} {record['description']}"
    package_name = entry.get("packageName")
    entry_repo = normalize_repo(entry.get("repo"))
    collection = entry.get("collectionURL")
    collection_eco = registry_ecosystem(collection)

    if package_name:
        # package_name
        collection_repo = (
            normalize_repo(collection)
            if collection and collection_eco is None
            else None
        )
        wanted_repo = entry_repo or collection_repo
        for ecosystem in ECOSYSTEMS:
            key = (ecosystem, normalize_name(ecosystem, package_name))
            for package in index.by_name.get(key, ()):
                if collection_eco and collection_eco != ecosystem:
                    outcomes["rejected_registry"] += 1
                elif (
                    wanted_repo
                    and index.repos[package]
                    and wanted_repo not in index.repos[package]
                ):
                    outcomes["rejected_repo_conflict"] += 1
                else:
                    yield Hit(
                        package,
                        MATCH_PACKAGE_NAME,
                        entry_status(package.ecosystem, package.version, entry),
                        entry,
                    )

    if entry_repo:
        # source_repo / repo_module
        for package in index.by_repo.get(entry_repo, ()):
            consistency = entry_consistency(package, entry, entry_repo, text)
            if consistency == INCONSISTENT:
                outcomes["wrong_artifact"] += 1
            elif consistency == MODULE_UNKNOWN:
                outcomes["module_unknown"] += 1
            else:
                match = (
                    MATCH_SOURCE_REPO
                    if consistency == CONSISTENT
                    else MATCH_REPO_MODULE
                )
                yield Hit(
                    package,
                    match,
                    entry_status(package.ecosystem, package.version, entry),
                    entry,
                )
        return

    if package_name or not entry.get("product"):
        return
    product = squash(entry["product"])
    vendor = squash(entry.get("vendor"))
    # product_name: the product is the artifact
    for package in index.by_artifact.get(product, ()):
        yield from _product_name_hit(index, record, entry, package, vendor, outcomes)
    # repo_module: vendor/product are the owner/name of the source repository
    for package in index.by_owner_base.get((vendor, product), ()):
        if product in {squash(package.artifact), squash(package.name)}:
            continue  # that is product_name's: the artifact, with its stricter checks
        if named_in_text(package, text):
            yield Hit(
                package,
                MATCH_REPO_MODULE,
                entry_status(package.ecosystem, package.version, entry),
                entry,
            )
        else:
            outcomes["module_unknown"] += 1


def _product_name_hit(
    index: Index,
    record: Mapping[str, Any],
    entry: Mapping[str, Any],
    package: Package,
    vendor: str,
    outcomes: Counter,
) -> Iterator[Hit]:
    repos = index.repos[package]
    owners = {squash(r.split("/")[1]) for r in repos if r.count("/") >= 2}
    if vendor not in owners and vendor != squash(package.artifact):
        outcomes["wrong_vendor"] += 1
        return
    if package.ecosystem == "npm" and package.name.startswith("@"):
        scope = squash(package.name[1:].split("/")[0])
        if scope != vendor and scope not in owners:
            outcomes["wrong_scope"] += 1
            return
    if not any(url_points_at_repo(u, r) for u in record["references"] for r in repos):
        outcomes["uncorroborated"] += 1
        return
    yield Hit(
        package,
        MATCH_PRODUCT_NAME,
        entry_status(package.ecosystem, package.version, entry),
        entry,
    )


def ghsa_aliases(record: Mapping[str, Any]) -> list[str]:
    """GHSA ids the record links to (its references name them)."""
    found = {
        "GHSA-" + m.group(0)[5:].lower()
        for url in record["references"]
        for m in _GHSA_RE.finditer(url)
    }
    return sorted(found)


@dataclass
class MatchResult:
    candidates: list[dict[str, Any]] = field(default_factory=list)
    outcomes: Counter = field(default_factory=Counter)


def match_records(
    records: Iterable[Mapping[str, Any]],
    index: Index,
    inventory: Inventory,
) -> MatchResult:
    """Candidates: one per CVE and package version that the CNA data says is
    affected. When several entries say so, the strongest match (``package_name``,
    ``source_repo``, ``product_name``, ``repo_module``) and its entry are kept.
    """
    result = MatchResult()
    for record in sorted(records, key=lambda r: r["cve"]):
        hits: dict[Package, list[Hit]] = {}
        for entry in record["affected"]:
            for hit in entry_hits(index, record, entry, result.outcomes):
                hits.setdefault(hit.package, []).append(hit)
        for package, package_hits in hits.items():
            affecting = [
                h for h in package_hits if h.status in (STATUS_AFFECTED, STATUS_ALL)
            ]
            if not affecting:
                if any(h.status == STATUS_UNKNOWN for h in package_hits):
                    result.outcomes["version_unknown"] += 1
                else:
                    result.outcomes["version_outside_range"] += 1
                continue
            best = min(affecting, key=lambda h: MATCH_PRIORITY[h.match])
            result.candidates.append(
                candidate_document(record, best, inventory.sightings[package])
            )
    result.candidates.sort(key=candidate_sort_key)
    return result


def candidate_document(
    record: Mapping[str, Any],
    hit: Hit,
    sightings: Mapping[str, set[str]],
) -> dict[str, Any]:
    package = hit.package
    return {
        "cve": record["cve"],
        "aliases": ghsa_aliases(record),
        "cna": record["assigner"],
        "published": record["published"],
        "updated": record["updated"],
        "title": record["title"],
        "package": {
            "ecosystem": package.ecosystem,
            "name": package.name,
            "version": package.version,
        },
        "affected_range": describe_range(hit.entry),
        "match": hit.match,
        **select_severity(record["metrics"]),
        "exploitation": record["metrics"]["exploitation"],
        "sightings": {
            tid: sorted(places)[:MAX_LOCATIONS]
            for tid, places in sorted(sightings.items())
        },
    }


def candidate_sort_key(candidate: Mapping[str, Any]) -> tuple[Any, ...]:
    """Severity, CVSS score (highest first, none last), newest publication first,
    then identity.
    """
    score = (candidate["cvss"] or {}).get("score")
    published = parse_time(candidate["published"])
    return (
        SEVERITY_ORDER.get(candidate["severity"], len(SEVERITIES)),
        score is None,
        -(score or 0),
        -(published.timestamp() if published else 0),
        candidate["package"]["name"],
        candidate["package"]["version"],
        candidate["cve"],
    )


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------


def write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def utc_text(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def status_document(
    status: str,
    reason: str | None,
    window_days: int | None = None,
    records_scanned: int | None = None,
    candidates: int | None = None,
    index: Mapping[str, Any] | None = None,
    diagnostics: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "reason": reason,
        "window_days": window_days,
        "records_scanned": records_scanned,
        "candidates": candidates,
        "index": dict(index) if index else None,
        "diagnostics": dict(diagnostics or {}),
    }


def load_index(
    args: argparse.Namespace, work_dir: Path, run: Runner = subprocess.run
) -> IndexData:
    """The index of ``--index-dir``, or the one of ``--cve-index`` pulled with ORAS."""
    if args.index_dir:
        return read_index(args.index_dir, str(args.index_dir), None)
    destination = work_dir / "index"
    digest = pull_index(args.cve_index, destination, run)
    return read_index(destination, args.cve_index, digest)


def analyse(
    args: argparse.Namespace,
    transport: Transport,
    now: datetime,
    sleep: Callable[[float], None] = time.sleep,
    downloader: Any = None,
    run: Runner = subprocess.run,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """``(status document, candidates document)``; the latter only if ``ok``.

    ``downloader`` fetches the deltas (the builder's ``Downloader``), ``run`` calls
    ORAS; both default to the real ones.
    """
    targets = load_targets_file(args.targets_file)
    inventory = load_inventory(targets, args.parts_dir / SCANNER_TRIVY)
    if not inventory.targets_read:
        return status_document(STATUS_SKIPPED, "no Trivy target was scanned"), None
    http = HttpClient(transport, sleep)
    diagnostics: dict[str, Any] = {
        "packages": len(inventory.sightings),
        "packages_unsupported": inventory.unsupported,
    }
    index: IndexData | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="sca-early-warning-") as work:
            index = load_index(args, Path(work), run)
            catch_up(
                index,
                downloader or builder().UrllibDownloader(),
                args.feed_url,
                Path(work),
                now,
            )
        lookup = resolve_repos(DepsDevClient(http, args.depsdev_url), inventory)
    except (IndexUnavailable, DepsDevUnavailable) as err:
        return status_document(
            STATUS_FAILED,
            str(err),
            index.metadata.get("window_days") if index else None,
            index=index_document(index) if index else None,
            diagnostics=diagnostics,
        ), None
    window_days = index.metadata["window_days"]
    match_index = build_index(inventory, lookup.repos)
    matched = match_records(index.records.values(), match_index, inventory)
    diagnostics.update(
        index_records=len(index.records),
        depsdev_requests=lookup.requests,
        depsdev_names_without_repo=lookup.without_repo,
        depsdev_errors=lookup.errors,
        outcomes=dict(sorted(matched.outcomes.items())),
    )
    candidates_doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": utc_text(now),
        "generated_from": {
            "days": window_days,
            "from": utc_text(now - timedelta(days=window_days)),
            "to": utc_text(now),
        },
        "candidates": matched.candidates,
    }
    status = status_document(
        STATUS_OK,
        None,
        window_days,
        len(index.records),
        len(matched.candidates),
        index_document(index),
        diagnostics,
    )
    return status, candidates_doc


def run(
    args: argparse.Namespace,
    transport: Transport,
    now: datetime,
    sleep: Callable[[float], None] = time.sleep,
    downloader: Any = None,
    runner: Runner = subprocess.run,
) -> str:
    """Write the part; return its status."""
    for name in ("feed_url", "depsdev_url"):
        url = getattr(args, name).rstrip("/")
        if urllib.parse.urlsplit(url).scheme != "https":
            raise InputError(f"{name.replace('_', '-')} must be an https URL")
    if bool(args.cve_index) == bool(args.index_dir):
        raise InputError("exactly one of cve-index and index-dir is needed")
    status, candidates = analyse(args, transport, now, sleep, downloader, runner)
    out_dir = args.output_dir / PART_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "status.json", status)
    if candidates is not None:
        write_json(out_dir / "candidates.json", candidates)
    if status["status"] == STATUS_OK:
        print(
            f"early warning: {status['records_scanned']} CVE record(s) of the last "
            f"{status['window_days']} day(s) from the index of "
            f"{status['index']['built_at']} and the deltas since, "
            f"{status['diagnostics']['packages']} package version(s), "
            f"{status['candidates']} candidate(s)"
        )
        gaps = status["index"]["gaps"]
        if gaps:
            print(
                "::warning title=Early warning feed gaps::no CVE feed delta for "
                + ", ".join(f"{g['from']} to {g['to']}" for g in gaps)
            )
    elif status["status"] == STATUS_FAILED:
        print(
            f"::warning title=Early warning unavailable::{status['reason']} "
            "(the scan itself is not affected)"
        )
    else:
        print(f"early warning skipped: {status['reason']}")
    return status["status"]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--targets-file", required=True, type=Path)
    parser.add_argument(
        "--parts-dir",
        required=True,
        type=Path,
        help="directory with the Trivy parts (trivy/<id>.json, trivy/<id>.status.json)",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="directory to write early-warning/status.json and candidates.json into",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--cve-index",
        help="the CVE index artifact to pull with ORAS, e.g. "
        "ghcr.io/epam/ai-dial-sca-cve-index:1",
    )
    source.add_argument(
        "--index-dir",
        type=Path,
        help="a directory with the index files instead (tests, runs by hand)",
    )
    parser.add_argument("--feed-url", default=FEED_URL, help="cvelistV5 release assets")
    parser.add_argument("--depsdev-url", default=DEPSDEV_URL, help="deps.dev API")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        run(args, UrllibTransport(), datetime.now(UTC))
    except InputError as err:
        print(f"::error title=Invalid early warning input::{err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
