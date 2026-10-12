#!/usr/bin/env python3
"""Check the language packages found by Trivy against OSV (https://osv.dev).

Used by the SCA scheduled scan. Every Trivy target that was scanned successfully
gets an OSV twin target (same id, scanner ``osv``): the packages of its
``lang-pkgs`` Results are queried by their package URL (purl) from Trivy, with
the version inside the purl. OS packages (``os-pkgs``) are not queried: Trivy and
OSV take them from the same distribution feeds, and OSV needs its own
distribution-to-ecosystem mapping for them, where a wrong mapping silently
finds nothing.

Per run: the purls of all targets are deduplicated and sent to
``POST /v1/querybatch`` (in chunks, following ``next_page_token``), then every
distinct vulnerability id is fetched once from ``GET /v1/vulns/{id}`` (the batch
returns ids only; aliases, severity and affected ranges are in the record).

Inputs:
  * targets.json written by sca_resolve_targets (the OSV targets to process);
  * a parts directory with the ``trivy/`` parts: ``<id>.json`` (native JSON) and
    ``<id>.status.json`` of every Trivy target.

Outputs (in the output directory, ``osv/``), per OSV target id:
  * ``<id>.status.json`` - ``{id, status, reason, packages_queried,
    packages_skipped}``; status is ``ok``, ``failed`` or ``not_applicable``;
  * ``<id>.json`` (``ok`` only) - the native result::

      {
        "schema_version": 1,
        "queried_at": "<UTC time of the run>",
        "api_url": "<OSV API base URL>",
        "packages": {"<purl>": ["<OSV id>", ...]},  # every queried purl
        "vulnerabilities": {"<OSV id>": {<OSV record, unmodified>}}
      }

A broken OSV query never looks like a clean result: if any request of a target's
packages cannot be completed (retries exhausted, a rejected purl, an unreadable
answer), the target is ``failed`` with a reason. A target whose Trivy target was
not scanned successfully is ``not_applicable`` and is not queried. The script
exits 0 once the outputs are written (the merge step reports and the workflow
decides about failing the run); the number of failed targets is a GitHub output.

The HTTP layer is injectable: every request goes through a ``Transport`` (a
callable ``(method, url, headers, body) -> Response``), so the logic can be
tested with a fake transport and no network. Python standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_API_URL = "https://api.osv.dev"
USER_AGENT = "ai-dial-ci-sca-query-osv"

SCANNER_TRIVY = "trivy"
SCANNER_OSV = "osv"

STATUS_PENDING = "pending"
STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_NOT_APPLICABLE = "not_applicable"

CLASS_LANGUAGE_PACKAGES = "lang-pkgs"
SCHEMA_VERSION = 1

# POST /v1/querybatch takes up to 1000 queries per request
BATCH_SIZE = 1000
# A query is paged while it returns a next_page_token; a sane API ends long before
MAX_PAGES = 100
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 60.0
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
ERROR_BODY_LIMIT = 200


class InputError(Exception):
    """The inputs are unusable, so no meaningful result can be produced."""


class TransportError(Exception):
    """A network-level failure (DNS, connection, timeout)."""


class OsvError(Exception):
    """An OSV request that cannot be completed; the packages it was for fail."""


class RejectedQueryError(OsvError):
    """OSV answered 400: some query of the request is invalid."""


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


def _describe_body(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace").strip()
    return text[:ERROR_BODY_LIMIT] + ("..." if len(text) > ERROR_BODY_LIMIT else "")


class OsvClient:
    """The two OSV endpoints the scan needs."""

    def __init__(self, http: HttpClient, api_url: str) -> None:
        self._http = http
        self._api_url = api_url.rstrip("/")
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }

    def _call(self, method: str, path: str, payload: Any = None) -> Any:
        """The decoded JSON answer; raises OsvError (400: RejectedQueryError)."""
        url = f"{self._api_url}{path}"
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        try:
            response = self._http.request(method, url, self._headers, body)
        except TransportError as err:
            raise OsvError(f"{method} {path}: {err}") from err
        if response.status == HTTP_BAD_REQUEST:
            raise RejectedQueryError(
                f"{method} {path}: HTTP 400: {_describe_body(response.body)}"
            )
        if response.status != HTTP_OK:
            raise OsvError(f"{method} {path}: HTTP {response.status}")
        try:
            return json.loads(response.body)
        except ValueError as err:
            raise OsvError(f"{method} {path}: answer is not valid JSON: {err}") from err

    def query_batch(self, purls: Sequence[str]) -> dict[str, list[str]]:
        """Vulnerability ids of each purl (one request, plus its further pages).

        A query that returns a ``next_page_token`` is sent again with the token
        (and only those queries are), until no query has one.
        """
        ids: dict[str, set[str]] = {purl: set() for purl in purls}
        pending: list[tuple[str, str | None]] = [(purl, None) for purl in purls]
        pages = 0
        while pending:
            if pages == MAX_PAGES:
                raise OsvError(
                    f"POST /v1/querybatch: results still paged after {MAX_PAGES} pages"
                )
            pages += 1
            queries = [
                {"package": {"purl": purl}, **({"page_token": token} if token else {})}
                for purl, token in pending
            ]
            answer = self._call("POST", "/v1/querybatch", {"queries": queries})
            results = answer.get("results") if isinstance(answer, dict) else None
            if not isinstance(results, list) or len(results) != len(pending):
                raise OsvError(
                    "POST /v1/querybatch: the answer does not hold one result "
                    f"per query ({len(pending)} queries)"
                )
            sent, pending = pending, []
            for (purl, _), result in zip(sent, results, strict=True):
                for vuln in (result or {}).get("vulns") or []:
                    if not isinstance(vuln, dict) or not vuln.get("id"):
                        raise OsvError("POST /v1/querybatch: a result has no id")
                    ids[purl].add(vuln["id"])
                if token := (result or {}).get("next_page_token"):
                    pending.append((purl, token))
        return {purl: sorted(found) for purl, found in ids.items()}

    def get_vulnerability(self, vuln_id: str) -> dict[str, Any]:
        """The full OSV record of one id."""
        path = f"/v1/vulns/{urllib.parse.quote(vuln_id, safe='')}"
        record = self._call("GET", path)
        if not isinstance(record, dict) or record.get("id") != vuln_id:
            raise OsvError(f"GET {path}: the answer is not the record of {vuln_id}")
        return record


# --------------------------------------------------------------------------
# Querying
# --------------------------------------------------------------------------


@dataclass
class Answers:
    """What OSV said about a set of purls: ids and records, or why it could not."""

    ids: dict[str, list[str]] = field(default_factory=dict)
    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    # purl -> why its result is incomplete (a purl in here is not in ``ids``)
    errors: dict[str, str] = field(default_factory=dict)


def query_chunk(
    client: OsvClient, purls: Sequence[str]
) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Ids and errors for one chunk of purls.

    A rejected query (HTTP 400) fails the whole request, so the chunk is halved
    until the rejected purl is alone: only its targets then fail, not all of the
    run. Any other failure fails the whole chunk.
    """
    try:
        return client.query_batch(purls), {}
    except RejectedQueryError as err:
        if len(purls) == 1:
            return {}, {purls[0]: f"rejected by OSV: {err}"}
        middle = len(purls) // 2
        ids, errors = query_chunk(client, purls[:middle])
        more_ids, more_errors = query_chunk(client, purls[middle:])
        return {**ids, **more_ids}, {**errors, **more_errors}
    except OsvError as err:
        return {}, dict.fromkeys(purls, str(err))


def query_osv(client: OsvClient, purls: Iterable[str]) -> Answers:
    """Query the distinct purls and fetch the record of each distinct id."""
    distinct = sorted(set(purls))
    answers = Answers()
    for start in range(0, len(distinct), BATCH_SIZE):
        ids, errors = query_chunk(client, distinct[start : start + BATCH_SIZE])
        answers.ids.update(ids)
        answers.errors.update(errors)

    for vuln_id in sorted({v for found in answers.ids.values() for v in found}):
        try:
            answers.records[vuln_id] = client.get_vulnerability(vuln_id)
        except OsvError as err:
            # Every package that has this vulnerability is incomplete
            for purl, found in list(answers.ids.items()):
                if vuln_id in found:
                    del answers.ids[purl]
                    answers.errors[purl] = str(err)
    return answers


# --------------------------------------------------------------------------
# Reading the Trivy parts
# --------------------------------------------------------------------------


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


def trivy_target_result(
    trivy_dir: Path, target_id: str
) -> tuple[str, dict[str, Any] | None]:
    """``(status, native)`` of a Trivy target; native only if it was scanned.

    Anything short of a complete, valid result counts as ``failed``.
    """
    try:
        status = read_json(trivy_dir / f"{target_id}.status.json")
    except (OSError, ValueError):
        return STATUS_FAILED, None
    if not isinstance(status, dict):
        return STATUS_FAILED, None
    if status.get("status") != STATUS_OK:
        return str(status.get("status") or STATUS_FAILED), None
    try:
        native = read_json(trivy_dir / f"{target_id}.json")
    except (OSError, ValueError):
        return STATUS_FAILED, None
    return (STATUS_OK, native) if isinstance(native, dict) else (STATUS_FAILED, None)


def has_version(purl: str) -> bool:
    """Whether the purl names a version (``pkg:npm/b@1.0`` does, ``pkg:npm/b`` not).

    OSV answers an unversioned purl with every vulnerability of the package ever,
    which would be a finding for a version nobody uses.
    """
    path = purl.split("#", 1)[0].split("?", 1)[0]
    return "@" in path.rsplit("/", 1)[-1]


def collect_packages(native: Mapping[str, Any]) -> tuple[list[str], int]:
    """``(distinct purls, packages skipped)`` of the language packages of a result.

    OS packages are left out. A package without a (versioned) purl cannot be
    queried; it is counted as skipped (distinct by name and version).
    """
    purls: set[str] = set()
    skipped: set[tuple[Any, Any]] = set()
    for result in native.get("Results") or []:
        if result.get("Class") != CLASS_LANGUAGE_PACKAGES:
            continue
        for package in result.get("Packages") or []:
            purl = (package.get("Identifier") or {}).get("PURL")
            if isinstance(purl, str) and has_version(purl):
                purls.add(purl)
            else:
                skipped.add((package.get("Name"), package.get("Version")))
    return sorted(purls), len(skipped)


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass
class TargetPlan:
    """What is known about an OSV target before OSV is asked."""

    target_id: str
    trivy_status: str
    purls: list[str] = field(default_factory=list)
    skipped: int = 0


def plan_targets(
    targets: Sequence[Mapping[str, Any]], trivy_dir: Path
) -> list[TargetPlan]:
    """The pending OSV targets, with the packages of their Trivy twins."""
    plans = []
    for target in targets:
        if target.get("scanner") != SCANNER_OSV or target.get("status") != (
            STATUS_PENDING
        ):
            continue
        target_id = target["id"]
        status, native = trivy_target_result(trivy_dir, target_id)
        plan = TargetPlan(target_id, status)
        if native is not None:
            plan.purls, plan.skipped = collect_packages(native)
        plans.append(plan)
    return plans


def status_document(
    plan: TargetPlan, status: str, reason: str | None
) -> dict[str, Any]:
    applicable = status != STATUS_NOT_APPLICABLE
    return {
        "id": plan.target_id,
        "status": status,
        "reason": reason,
        "packages_queried": len(plan.purls) if applicable else None,
        "packages_skipped": plan.skipped if applicable else None,
    }


def build_result(
    plan: TargetPlan, answers: Answers, queried_at: str, api_url: str
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """``(status document, native result)``; native only for an ``ok`` target."""
    if plan.trivy_status != STATUS_OK:
        reason = f"trivy target {plan.trivy_status}"
        return status_document(plan, STATUS_NOT_APPLICABLE, reason), None
    errors = {p: answers.errors[p] for p in plan.purls if p in answers.errors}
    if errors:
        first = errors[min(errors)]
        reason = (
            f"OSV query failed for {len(errors)} of {len(plan.purls)} package(s): "
            f"{first}"
        )
        return status_document(plan, STATUS_FAILED, reason), None
    packages = {purl: answers.ids[purl] for purl in plan.purls}
    used = {vuln_id for found in packages.values() for vuln_id in found}
    native = {
        "schema_version": SCHEMA_VERSION,
        "queried_at": queried_at,
        "api_url": api_url,
        "packages": packages,
        "vulnerabilities": {i: answers.records[i] for i in sorted(used)},
    }
    return status_document(plan, STATUS_OK, None), native


def write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def format_output(name: str, value: str) -> str:
    """One $GITHUB_OUTPUT entry in the delimiter format, safe for multiline values."""
    delimiter = f"ghadelimiter_{secrets.token_hex(16)}"
    return f"{name}<<{delimiter}\n{value}\n{delimiter}\n"


def run(
    args: argparse.Namespace,
    transport: Transport,
    environ: Mapping[str, str],
    now: datetime,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Write all outputs; return the number of failed OSV targets."""
    api_url = args.api_url.rstrip("/")
    if urllib.parse.urlsplit(api_url).scheme != "https":
        raise InputError(f"api-url must be an https URL, got {args.api_url!r}")
    queried_at = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    plans = plan_targets(
        load_targets_file(args.targets_file), args.parts_dir / SCANNER_TRIVY
    )
    purls = [
        purl for plan in plans if plan.trivy_status == STATUS_OK for purl in plan.purls
    ]
    client = OsvClient(HttpClient(transport, sleep), api_url)
    answers = query_osv(client, purls)
    print(
        f"OSV {api_url}: {len(set(purls))} distinct package(s) queried for "
        f"{len(plans)} target(s), {len(answers.records)} vulnerabilit(ies) fetched"
    )

    out_dir = args.output_dir / SCANNER_OSV
    out_dir.mkdir(parents=True, exist_ok=True)
    failed = 0
    for plan in plans:
        status, native = build_result(plan, answers, queried_at, api_url)
        write_json(out_dir / f"{plan.target_id}.status.json", status)
        if native is not None:
            write_json(out_dir / f"{plan.target_id}.json", native)
        failed += status["status"] == STATUS_FAILED
        print(
            f"{plan.target_id}: {status['status']}"
            + (f" ({status['reason']})" if status["reason"] else "")
        )
        if status["packages_skipped"]:
            print(
                f"::notice title=OSV skipped packages::{plan.target_id}: "
                f"{status['packages_skipped']} package(s) without a versioned purl"
            )

    output_path = environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8", newline="\n") as out:
            out.write(format_output("failed-count", str(failed)))
    return failed


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--targets-file", required=True, type=Path, help="targets.json of the run"
    )
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
        help="directory to write osv/<id>.json and osv/<id>.status.json into",
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help="OSV API base URL (default: %(default)s)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        run(args, UrllibTransport(), os.environ, datetime.now(UTC))
    except InputError as err:
        print(f"::error title=Invalid OSV query input::{err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
