#!/usr/bin/env python3
"""Build the CVE index of the SCA early warning.

The early warning matches CVE records (cvelistV5, published by the CVE Numbering
Authorities, CNAs) with the packages of a scan. Two things are the same for every
caller and are expensive to find out per run, so this script builds them once a
day: the records of the last 180 days, and how far each CNA can be trusted to name
the right package (its reputation). Bulk data only, no per-CVE request:

  * the CVE records: the ``end_of_day`` and hourly delta zips of the cvelistV5
    GitHub releases; to start with, the whole list
    (``*_all_CVEs_at_midnight.zip.zip``) is merged in, too: it loses the claims of
    the records that were rejected, which the deltas keep, and the deltas have
    holes that no check of their assets finds (what was updated around midnight
    is in none of them), which the whole list has not;
  * ``cves/deltaLog.json`` of the cvelistV5 repository, which lists every record
    that changed and when: a record that it lists and that the deltas did not
    bring (such a hole, or a delta that is missing) is fetched on its own;
  * what the vulnerability databases say: the OSV exports of npm, PyPI, Maven and
    crates.io (``<ecosystem>/all.zip``; the reviewed GitHub advisories are in them);
  * the previous index (``--previous-dir``), to which the new deltas are applied.

Outputs (``--output-dir``), ``schema_version: 1``:
  * ``cves.jsonl.gz`` - one slim CVE record per line (what the matcher of the early
    warning reads, in the form of ``early_warning.slim_record``) for the records
    published or updated in the window, and the REJECTED ones that have claims;
  * ``reputation.json`` - per CNA, over the claims of the records published in the
    window: ``confirmed``, ``errors``, ``pending`` (see below);
  * ``evidence.jsonl.gz`` - one line per evaluated claim: why it counts as it does;
  * ``metadata.json`` - when it was built, what it covers, the gaps of the feed,
    the OSV exports used, the counts.

Claims. A CNA entry claims a package (``packageName``, with ``collectionURL``
naming the registry when it does) or a repository (``repo`` of a code host) for
npm, PyPI, Maven or Cargo; one claim per CVE and package or repository. The OSV
exports then say:

  confirmed  an OSV record that has the CVE (its id or an alias) maps a package
             that agrees with the claimed name (the agreement the matcher of the
             early warning requires of a CNA entry), or, for a repository, a
             package of a record that links that repository;
  errors     the CVE is REJECTED, or OSV maps it only to other packages of the
             claimed ecosystems, or the record that confirmed it was withdrawn;
  pending    nothing maps the CVE yet (or, for a repository, nothing that links it).

A confirmed claim whose affected versions disagree with OSV (the CNA says a fixed
version is affected or a version OSV lists as vulnerable is not) is flagged
``range_differs`` in the evidence and is not counted as an error: it is the package
the CNA is trusted for here, and judging ranges across version schemes is a problem
of its own. How far a CNA is believed is not decided here: the early warning shows
the counts of a CNA as the confidence of its signals, without a threshold.

A feed with holes does not fail the build: every hour of every day of the covered
span must be covered by the ``end_of_day`` delta of its day or by its own hourly
delta, and what is not is listed in ``gaps`` of ``metadata.json``. Anything else
that is not as expected (a download that fails after its retries, a file that
cannot be read, a record of an unknown shape, an OSV export without packages)
fails the build, and nothing is written: the index of the day before stays the
latest one.

The download layer is injectable (``Downloader.fetch(url, dest)``), so the logic is
tested with no network. Python standard library only; the helpers of the matcher
(names, repositories, version comparison, the form of a record) are those of
``sca_early_warning``, so that the index and the matcher cannot disagree.
"""

from __future__ import annotations

import argparse
import gzip
import http.client
import json
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sca_early_warning"))
import early_warning as ew  # noqa: E402  (a sibling action, see the docstring)

FEED_URL = ew.FEED_URL
# the changes of the last month, newest first, and the records themselves
DELTA_LOG_URL = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
)
RECORDS_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com"
USER_AGENT = "ai-dial-ci-sca-build-cve-index"

SCHEMA_VERSION = 1
DEFAULT_WINDOW_DAYS = 180
MAX_WINDOW_DAYS = 365
# The deltas of this many days before the previous index ended are fetched again:
# an end_of_day delta is published after midnight and a delta can come late
RESCAN_DAYS = 2

# OSV export name -> ecosystem name of the early warning
OSV_EXPORTS = {"npm": "npm", "PyPI": "pypi", "Maven": "maven", "crates.io": "cargo"}
ECOSYSTEMS = ew.ECOSYSTEMS
# the repositories of packages are those of code hosts (Linux's is git.kernel.org)
CODE_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")

REQUEST_TIMEOUT_SECONDS = 60.0
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 2.0
MAX_RETRY_AFTER_SECONDS = 60.0
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
CHUNK_BYTES = 1 << 20
MAX_DOWNLOAD_BYTES = 2 * 1024**3
MAX_MEMBER_BYTES = 16 * 1024 * 1024

STATE_PUBLISHED = "PUBLISHED"
STATE_REJECTED = "REJECTED"

VERDICT_CONFIRMED = "confirmed"
VERDICT_ERROR = "error"
VERDICT_PENDING = "pending"
REASON_REJECTED = "rejected"
REASON_WITHDRAWN = "withdrawn"
REASON_OTHER_PACKAGE = "other_package"

RECORDS_FILE = "cves.jsonl.gz"
REPUTATION_FILE = "reputation.json"
EVIDENCE_FILE = "evidence.jsonl.gz"
METADATA_FILE = "metadata.json"
INDEX_FILES = (RECORDS_FILE, REPUTATION_FILE, EVIDENCE_FILE, METADATA_FILE)


class IndexBuildError(Exception):
    """The index cannot be built; the message says why."""


class DownloadError(IndexBuildError):
    pass


class FormatError(IndexBuildError):
    """An input is not what it is expected to be."""


# --------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------


class Downloader(Protocol):
    def fetch(self, url: str, dest: Path) -> Mapping[str, str] | None:
        """Save the URL to ``dest``; return its headers (lower-case names), or None
        if it does not exist (404). Any other failure raises DownloadError.
        """


class UrllibDownloader:
    """HTTPS download to a file, with bounded retries (429/5xx, network errors) and
    a check that the whole body came.
    """

    def __init__(
        self,
        opener: Callable[..., Any] = urllib.request.urlopen,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = MAX_ATTEMPTS,
    ) -> None:
        self._opener = opener
        self._sleep = sleep
        self._max_attempts = max_attempts

    def fetch(self, url: str, dest: Path) -> Mapping[str, str] | None:
        if urllib.parse.urlsplit(url).scheme != "https":
            raise DownloadError(f"refusing non-HTTPS URL: {url}")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        for attempt in range(1, self._max_attempts + 1):
            delay = BACKOFF_BASE_SECONDS * 2 ** (attempt - 1)
            try:
                with self._opener(request, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    self._save(url, resp, headers, dest)
                    return headers
            except urllib.error.HTTPError as err:
                if err.code == 404:
                    return None
                if err.code not in RETRY_STATUSES:
                    raise DownloadError(f"GET {url}: HTTP {err.code}") from err
                reason = f"HTTP {err.code}"
                retry_after = (err.headers or {}).get("Retry-After", "")
                if retry_after.strip().isdigit():
                    delay = min(float(retry_after), MAX_RETRY_AFTER_SECONDS)
            except (urllib.error.URLError, http.client.HTTPException, OSError) as err:
                reason = str(err)
            if attempt == self._max_attempts:
                raise DownloadError(f"GET {url}: {reason}")
            self._sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover

    @staticmethod
    def _save(url: str, resp: Any, headers: Mapping[str, str], dest: Path) -> None:
        written = 0
        with open(dest, "wb") as out:
            while chunk := resp.read(CHUNK_BYTES):
                written += len(chunk)
                if written > MAX_DOWNLOAD_BYTES:
                    raise DownloadError(f"{url}: larger than the limit")
                out.write(chunk)
        expected = headers.get("content-length")
        if expected and expected.isdigit() and int(expected) != written:
            raise OSError(f"incomplete body: {written} of {expected} bytes")


# --------------------------------------------------------------------------
# CVE records
# --------------------------------------------------------------------------


def format_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def index_record(document: Any, where: str) -> dict[str, Any]:
    """The record of a CVE record 5 as the index keeps it. A document that is not a
    CVE record is a FormatError: an unknown shape must not pass as a record without
    data.
    """
    record = ew.slim_record(document) if isinstance(document, dict) else None
    if record is None or not record["cve"]:
        raise FormatError(f"{where}: not a CVE record")
    if record["state"] not in (STATE_PUBLISHED, STATE_REJECTED):
        raise FormatError(f"{where}: unexpected state {record['state']!r}")
    meta = document["cveMetadata"]
    record["published"] = record["published"] or meta.get("dateRejected")
    record["updated"] = record["updated"] or record["published"]
    if None in (ew.parse_time(record["published"]), ew.parse_time(record["updated"])):
        raise FormatError(f"{where}: no usable dates")
    if record["state"] == STATE_REJECTED:
        # nothing else of a rejected record is of use
        keep = ("cve", "state", "published", "updated", "assigner", "affected")
        record = {k: record[k] for k in keep}
    return record


def read_cve_zip(path: Path, cutoff: datetime) -> Iterator[dict[str, Any]]:
    """The records of a zip of CVE record files that were updated since the cutoff.
    The members that are not ``CVE-*.json`` (indexes, directories) are skipped.
    """
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as err:
        raise FormatError(f"{path.name}: not a valid zip file: {err}") from err
    with archive:
        for info in archive.infolist():
            base = info.filename.rsplit("/", 1)[-1]
            if not (base.startswith("CVE-") and base.endswith(".json")):
                continue
            where = f"{path.name}:{info.filename}"
            if info.file_size > MAX_MEMBER_BYTES:
                raise FormatError(f"{where}: {info.file_size} bytes")
            try:
                document = json.loads(archive.read(info))
            except (ValueError, zipfile.BadZipFile) as err:
                raise FormatError(f"{where}: unreadable: {err}") from err
            record = index_record(document, where)
            if ew.parse_time(record["updated"]) >= cutoff:  # type: ignore[operator]
                yield record


def merge_record(records: dict[str, dict[str, Any]], new: dict[str, Any]) -> None:
    """Keep the latest version of each record. A REJECTED record keeps the claims of
    the version it replaces (a rejected record has no ``affected`` of its own): a
    CNA that rejects what it claimed made an error, and the reputation counts it.
    """
    known = records.get(new["cve"])
    if known is not None and ew.parse_time(new["updated"]) < ew.parse_time(  # type: ignore[operator]
        known["updated"]
    ):
        return
    if new["state"] == STATE_REJECTED and known is not None:
        new = {**new, "published": known["published"], "affected": known["affected"]}
    records[new["cve"]] = new


# --------------------------------------------------------------------------
# The feed
# --------------------------------------------------------------------------


def baseline_asset(day: date) -> str:
    """The whole list as of the start of ``day``, a zip with ``cves.zip`` in it. It
    is attached to every hourly release of the day from 0100Z on.
    """
    return f"cve_{day}_0100Z/{day}_all_CVEs_at_midnight.zip.zip"


@dataclass
class Feed:
    gaps: set[datetime] = field(default_factory=set)  # hours without a delta
    last_asset: str | None = None


class FeedClient:
    def __init__(self, downloader: Downloader, feed_url: str, work_dir: Path) -> None:
        self._downloader = downloader
        self._feed_url = feed_url.rstrip("/")
        self._dir = work_dir
        work_dir.mkdir(parents=True, exist_ok=True)

    def download(self, asset: str) -> Path | None:
        """The asset in the work directory, or None if the release has none."""
        dest = self._dir / asset.rsplit("/", 1)[-1]
        if self._downloader.fetch(f"{self._feed_url}/{asset}", dest) is None:
            return None
        return dest


def load_baseline(
    client: FeedClient, today: date, cutoff: datetime, records: dict[str, Any]
) -> date:
    """Merge the records of the whole list that were updated since the cutoff into
    ``records``; return the day of the snapshot (today's when it is published, else
    yesterday's).
    """
    for day in (today, today - timedelta(days=1)):
        outer = client.download(baseline_asset(day))
        if outer is None:
            continue
        try:
            with zipfile.ZipFile(outer) as archive:
                names = [i.filename for i in archive.infolist()]
                if names != ["cves.zip"]:
                    raise FormatError(f"{outer.name}: unexpected members {names[:5]}")
                archive.extract("cves.zip", outer.parent)
        except zipfile.BadZipFile as err:
            raise FormatError(f"{outer.name}: not a valid zip file: {err}") from err
        finally:
            outer.unlink()
        inner = outer.parent / "cves.zip"
        try:
            for record in read_cve_zip(inner, cutoff):
                merge_record(records, record)
        finally:
            inner.unlink()
        return day
    raise IndexBuildError(f"no baseline of the CVE list for {today} or the day before")


def apply_deltas(
    records: dict[str, dict[str, Any]],
    client: FeedClient,
    start: date,
    now: datetime,
    cutoff: datetime,
    feed: Feed,
) -> None:
    """Apply the deltas from the day ``start`` to ``now`` and record the gaps.

    A past day is its ``end_of_day`` delta, else its 24 hourly ones; today is its
    hourly ones (the delta of the current hour is not published yet, so only the
    hours before it can be missing). An hour that has no delta and is not covered
    by an ``end_of_day`` delta is a gap.
    """
    feed.gaps = {h for h in feed.gaps if h.date() < start}

    def process(asset: str) -> bool:
        path = client.download(asset)
        if path is None:
            return False
        try:
            for record in read_cve_zip(path, cutoff):
                merge_record(records, record)
        finally:
            path.unlink()
        feed.last_asset = asset.rsplit("/", 1)[-1]
        return True

    day = start
    while day <= now.date():
        past = day < now.date()
        if not (past and process(ew.end_of_day_asset(day))):
            midnight = datetime(day.year, day.month, day.day, tzinfo=UTC)
            for hour in range(24 if past else now.hour + 1):
                if not process(ew.hourly_asset(day, hour)) and (
                    past or hour < now.hour
                ):
                    feed.gaps.add(midnight + timedelta(hours=hour))
        day += timedelta(days=1)


def record_url(records_url: str, cve: str) -> str:
    """Where the repository keeps a record (``2026/108xxx/CVE-2026-108779.json``)."""
    match = re.fullmatch(r"CVE-(\d{4})-(\d{4,})", cve)
    if not match:
        raise FormatError(f"{cve}: not a CVE id")
    return f"{records_url.rstrip('/')}/{match[1]}/{int(match[2]) // 1000}xxx/{cve}.json"


def hour_of(moment: datetime) -> datetime:
    return moment.replace(minute=0, second=0, microsecond=0)


def reconcile(
    records: dict[str, dict[str, Any]],
    downloader: Downloader,
    work_dir: Path,
    since: datetime,
    now: datetime,
    cutoff: datetime,
    feed: Feed,
    log_url: str = DELTA_LOG_URL,
    records_url: str = RECORDS_URL,
) -> int:
    """Fetch the records that ``deltaLog.json`` lists since ``since`` and that
    ``records`` does not have in that version (or at all); return how many.

    The deltas lack records, whole days of them when an asset is missing and a few
    around midnight when it is not; the log lists every change. What cannot be
    reconciled is a gap: the hours of the span when the log cannot be read, the hour
    of a record that cannot be fetched or comes back older than the log says. The
    asset gaps that the log covers (it goes back about 30 days) are cleared.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        log_path = work_dir / "deltaLog.json"
        if downloader.fetch(log_url, log_path) is None:
            raise DownloadError(f"{log_url}: not found")
        try:
            log = json.loads(log_path.read_text(encoding="utf-8"))
        finally:
            log_path.unlink()
        changes: dict[str, datetime] = {}
        horizon = None
        for item in log:
            fetched = ew.parse_time(item.get("fetchTime"))
            if fetched is None:
                raise FormatError("deltaLog.json: an entry without fetchTime")
            horizon = min(horizon or fetched, fetched)
            if fetched < since:
                continue
            for change in [*item.get("new", []), *item.get("updated", [])]:
                updated = ew.parse_time(change.get("dateUpdated"))
                if updated is None or not change.get("cveId"):
                    raise FormatError("deltaLog.json: a change without id or date")
                if updated >= cutoff:
                    cve = change["cveId"]
                    changes[cve] = max(changes.get(cve, updated), updated)
        if horizon is None:
            raise FormatError("deltaLog.json: empty")
    except (IndexBuildError, ValueError, TypeError, AttributeError) as err:
        # the span is not reconciled: say so, whole hours of it
        feed.gaps |= hours_between(since, now)
        print(f"::warning title=CVE delta log::cannot reconcile: {err}")
        return 0
    feed.gaps = {h for h in feed.gaps if h < hour_of(horizon)}
    fetched_records = 0
    for cve, updated in sorted(changes.items()):
        known = records.get(cve)
        if known is not None and ew.parse_time(known["updated"]) >= updated:  # type: ignore[operator]
            continue
        dest = work_dir / f"{cve}.json"
        try:
            if downloader.fetch(record_url(records_url, cve), dest) is None:
                raise DownloadError(f"{cve}: not found")
            try:
                document = json.loads(dest.read_text(encoding="utf-8"))
            finally:
                dest.unlink()
            merge_record(records, index_record(document, cve))
        except (IndexBuildError, ValueError) as err:
            print(f"::warning title=CVE record::{cve} cannot be fetched: {err}")
        fetched_records += 1
        now_known = records.get(cve)
        if now_known is None or ew.parse_time(now_known["updated"]) < updated:  # type: ignore[operator]
            feed.gaps.add(hour_of(updated))
    return fetched_records


def hours_between(start: datetime, end: datetime) -> set[datetime]:
    hours = set()
    hour = hour_of(start)
    while hour < end:
        hours.add(hour)
        hour += timedelta(hours=1)
    return hours


def gap_ranges(gaps: Iterable[datetime]) -> list[dict[str, str]]:
    """Consecutive missing hours as ``{"from", "to"}`` (``to`` is exclusive)."""
    ranges: list[list[datetime]] = []
    for hour in sorted(gaps):
        if ranges and ranges[-1][1] == hour:
            ranges[-1][1] = hour + timedelta(hours=1)
        else:
            ranges.append([hour, hour + timedelta(hours=1)])
    return [{"from": format_time(a), "to": format_time(b)} for a, b in ranges]


def gaps_of(ranges: Iterable[Mapping[str, str]]) -> set[datetime]:
    gaps: set[datetime] = set()
    for item in ranges:
        start, end = ew.parse_time(item.get("from")), ew.parse_time(item.get("to"))
        if start is None or end is None:
            raise FormatError(f"gap {item}: not a time range")
        while start < end:
            gaps.add(start)
            start += timedelta(hours=1)
    return gaps


# --------------------------------------------------------------------------
# What the vulnerability databases say (OSV)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OsvPackage:
    """One package that an OSV record maps a CVE to."""

    osv_id: str
    ecosystem: str
    name: str
    published: datetime | None
    withdrawn: datetime | None
    fixed: tuple[str, ...]  # versions that fix it, by the ranges of the record
    versions: tuple[str, ...]  # versions the record lists as vulnerable
    repos: frozenset[str]  # repositories the record links (references, git ranges)


def osv_repos(document: Mapping[str, Any]) -> frozenset[str]:
    urls = [r.get("url") for r in document.get("references") or []]
    for affected in document.get("affected") or []:
        urls += [r.get("repo") for r in affected.get("ranges") or []]
    return frozenset(r for r in map(ew.normalize_repo, urls) if r)


def osv_packages(document: Mapping[str, Any]) -> dict[tuple[str, str], list[Any]]:
    """The ``affected`` entries of a record by (ecosystem, package name), for the
    packages of the ecosystems of the early warning.
    """
    packages: dict[tuple[str, str], list[Any]] = {}
    for affected in document.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = OSV_EXPORTS.get(str(package.get("ecosystem", "")).split(":")[0])
        if ecosystem and package.get("name"):
            packages.setdefault((ecosystem, package["name"]), []).append(affected)
    return packages


def load_osv(
    exports: Mapping[str, Path], wanted: set[str]
) -> dict[str, list[OsvPackage]]:
    """The packages that OSV maps the ``wanted`` CVEs to, from the exports.

    A record maps a CVE if the CVE is its id or one of its aliases. Only packages
    of npm, PyPI, Maven and crates.io count, in whichever export the record is. An
    export without any package of its ecosystem is a FormatError: the exports
    changed, or the download is not one.
    """
    mapped: dict[str, dict[tuple[str, str, str], OsvPackage]] = {}
    for export, path in exports.items():
        found = 0
        try:
            archive = zipfile.ZipFile(path)
        except zipfile.BadZipFile as err:
            raise FormatError(f"OSV {export}: not a valid zip file: {err}") from err
        with archive:
            for info in archive.infolist():
                if not info.filename.endswith(".json"):
                    continue
                where = f"OSV {export}:{info.filename}"
                if info.file_size > MAX_MEMBER_BYTES:
                    raise FormatError(f"{where}: {info.file_size} bytes")
                try:
                    document = json.loads(archive.read(info))
                except ValueError as err:
                    raise FormatError(f"{where}: unreadable: {err}") from err
                if not isinstance(document, dict) or not document.get("id"):
                    raise FormatError(f"{where}: no id")
                packages = osv_packages(document)
                found += any(e == OSV_EXPORTS[export] for e, _ in packages)
                cves = {i for i in [document["id"], *(document.get("aliases") or [])]}
                cves &= wanted
                if not cves:
                    continue
                for (ecosystem, name), entries in packages.items():
                    fixed = tuple(
                        str(event["fixed"])
                        for entry in entries
                        for rng in entry.get("ranges") or []
                        if rng.get("type") in ("ECOSYSTEM", "SEMVER")
                        for event in rng.get("events") or []
                        if event.get("fixed")
                    )
                    versions = tuple(
                        str(v) for e in entries for v in e.get("versions") or []
                    )
                    package = OsvPackage(
                        document["id"],
                        ecosystem,
                        name,
                        ew.parse_time(document.get("published")),
                        ew.parse_time(document.get("withdrawn")),
                        fixed,
                        versions,
                        osv_repos(document),
                    )
                    for cve in cves:
                        mapped.setdefault(cve, {})[
                            (package.osv_id, ecosystem, name)
                        ] = package
        if not found:
            raise FormatError(f"OSV {export}: no package of its ecosystem in it")
    return {
        cve: sorted(found.values(), key=lambda p: (p.osv_id, p.name))
        for cve, found in mapped.items()
    }


# --------------------------------------------------------------------------
# Claims and reputation
# --------------------------------------------------------------------------


@dataclass
class Claim:
    cve: str
    cna: str
    package: str | None  # the claimed name, or None for a claim of a repository
    repo: str | None
    ecosystems: tuple[str, ...]
    entries: list[Mapping[str, Any]] = field(default_factory=list)


def claims_of(record: Mapping[str, Any]) -> list[Claim]:
    """The package or repository claims of a record, one per package or repository."""
    claims: dict[tuple[Any, ...], Claim] = {}
    cna = record.get("assigner") or "unknown"
    for entry in record["affected"]:
        name = entry.get("packageName")
        repo = ew.normalize_repo(entry.get("repo"))
        if isinstance(name, str) and name.strip():
            registry = ew.registry_ecosystem(entry.get("collectionURL"))
            if registry == ew.FOREIGN_REGISTRY:
                continue
            ecosystems = (registry,) if registry else ECOSYSTEMS
            key: tuple[Any, ...] = ("package", ew.squash(name), ecosystems)
            claim = Claim(record["cve"], cna, name.strip(), None, ecosystems)
        elif repo and repo.split("/")[0] in CODE_HOSTS:
            key = ("repo", repo)
            claim = Claim(record["cve"], cna, None, repo, ECOSYSTEMS)
        else:
            continue
        claims.setdefault(key, claim).entries.append(entry)
    return list(claims.values())


def claims_in_window(
    records: Iterable[Mapping[str, Any]], window_start: datetime, as_of: datetime
) -> Iterator[tuple[Mapping[str, Any], list[Claim]]]:
    for record in sorted(records, key=lambda r: r["cve"]):
        published = ew.parse_time(record["published"])
        if published is None or not window_start <= published <= as_of:
            continue
        claims = claims_of(record)
        if claims:
            yield record, claims


def affected_at(claim: Claim, ecosystem: str, version: str) -> bool | None:
    """What the entries of a claim say about a version: True (affected), False (not
    affected) or None (cannot tell: another version scheme, a commit, nothing).
    """
    statuses = {ew.entry_status(ecosystem, version, entry) for entry in claim.entries}
    if statuses & {ew.STATUS_AFFECTED, ew.STATUS_ALL}:
        return True
    return False if ew.STATUS_NOT_AFFECTED in statuses else None


def ranges_differ(claim: Claim, packages: Iterable[OsvPackage]) -> bool:
    """Whether the CNA says a version that fixes the CVE by OSV is affected, or that
    a version that OSV lists as vulnerable is not.
    """
    for package in packages:
        if any(affected_at(claim, package.ecosystem, v) for v in package.fixed):
            return True
        if any(
            affected_at(claim, package.ecosystem, v) is False for v in package.versions
        ):
            return True
    return False


def judge(
    claim: Claim, rejected: bool, mapped: Sequence[OsvPackage], as_of: datetime
) -> dict[str, Any]:
    """The evidence line of a claim, as the databases said at ``as_of``."""
    line: dict[str, Any] = {
        "cve": claim.cve,
        "cna": claim.cna,
        "package": claim.package,
        "repo": claim.repo,
        "ecosystems": list(claim.ecosystems),
    }
    if rejected:
        return {**line, "verdict": VERDICT_ERROR, "reason": REASON_REJECTED, "osv": []}
    known = [
        p
        for p in mapped
        if p.ecosystem in claim.ecosystems and p.published and p.published <= as_of
    ]

    def supports(package: OsvPackage) -> bool:
        if claim.package is not None:
            return ew.name_agrees(
                claim.package, ew.Package(package.ecosystem, package.name, "")
            )
        return claim.repo in package.repos

    live = [p for p in known if not (p.withdrawn and p.withdrawn <= as_of)]
    confirming = [p for p in live if supports(p)]
    if confirming:
        line.update(
            verdict=VERDICT_CONFIRMED, osv=sorted({p.osv_id for p in confirming})
        )
        if ranges_differ(claim, confirming):
            line["range_differs"] = True
        return line
    withdrawn = [p for p in known if p not in live and supports(p)]
    if withdrawn and not live:
        return {
            **line,
            "verdict": VERDICT_ERROR,
            "reason": REASON_WITHDRAWN,
            "osv": sorted({p.osv_id for p in withdrawn}),
        }
    if live and claim.package is not None:
        # a package claim that OSV maps only to other packages of its ecosystems
        return {
            **line,
            "verdict": VERDICT_ERROR,
            "reason": REASON_OTHER_PACKAGE,
            "osv": sorted({p.osv_id for p in live}),
        }
    return {**line, "verdict": VERDICT_PENDING, "osv": []}


@dataclass
class Reputation:
    evidence: list[dict[str, Any]] = field(default_factory=list)
    cnas: dict[str, dict[str, int]] = field(default_factory=dict)


def evaluate(
    records: Iterable[Mapping[str, Any]],
    osv: Mapping[str, Sequence[OsvPackage]],
    window_start: datetime,
    as_of: datetime,
) -> Reputation:
    """The verdict of every claim of the records published in the window."""
    result = Reputation()
    counted = {
        VERDICT_CONFIRMED: "confirmed",
        VERDICT_ERROR: "errors",
        VERDICT_PENDING: "pending",
    }
    for record, claims in claims_in_window(records, window_start, as_of):
        rejected = record["state"] == STATE_REJECTED
        for claim in claims:
            line = judge(claim, rejected, osv.get(claim.cve, ()), as_of)
            result.evidence.append(line)
            counts = result.cnas.setdefault(
                claim.cna, {"confirmed": 0, "errors": 0, "pending": 0}
            )
            counts[counted[line["verdict"]]] += 1
    return result


# --------------------------------------------------------------------------
# The index on disk
# --------------------------------------------------------------------------


def write_jsonl_gz(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    # no name and no mtime in the header: the same data is the same bytes
    with open(path, "wb") as raw, gzip.GzipFile("", "wb", 9, raw, mtime=0) as out:
        for row in rows:
            out.write(json.dumps(row, separators=(",", ":"), sort_keys=True).encode())
            out.write(b"\n")


def read_jsonl_gz(path: Path) -> Iterator[dict[str, Any]]:
    try:
        with gzip.open(path, "rt", encoding="utf-8") as src:
            for line in src:
                yield json.loads(line)
    except (OSError, ValueError, EOFError) as err:
        raise FormatError(f"{path}: unreadable: {err}") from err


def write_json(path: Path, data: Any) -> None:
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


@dataclass
class Previous:
    records: dict[str, dict[str, Any]]
    metadata: dict[str, Any]


def read_previous(directory: Path) -> Previous:
    """The previous index. One that cannot be read, or of another schema, is an
    error and not a reason to start over: starting over would hide a defect.
    """
    try:
        text = (directory / METADATA_FILE).read_text(encoding="utf-8")
        metadata = json.loads(text)
    except (OSError, ValueError) as err:
        raise FormatError(f"previous index: {METADATA_FILE}: {err}") from err
    if not isinstance(metadata, dict) or metadata.get("schema_version") != (
        SCHEMA_VERSION
    ):
        raise FormatError(f"previous index: schema_version is not {SCHEMA_VERSION}")
    baseline = metadata.get("baseline")
    try:
        if baseline is not None:
            date.fromisoformat(baseline)
    except (TypeError, ValueError) as err:
        raise FormatError(f"previous index: baseline {baseline!r}: {err}") from err
    records = {r["cve"]: r for r in read_jsonl_gz(directory / RECORDS_FILE)}
    return Previous(records, metadata)


@dataclass
class Built:
    records: dict[str, dict[str, Any]]
    reputation: Reputation
    metadata: dict[str, Any]


def build(
    downloader: Downloader,
    work_dir: Path,
    now: datetime,
    window_days: int = DEFAULT_WINDOW_DAYS,
    previous: Previous | None = None,
    feed_url: str = FEED_URL,
    osv_url: str = OSV_URL,
) -> Built:
    now = now.astimezone(UTC).replace(microsecond=0)
    cutoff = now - timedelta(days=window_days)
    client = FeedClient(downloader, feed_url, work_dir / "feed")
    feed = Feed()
    records: dict[str, dict[str, Any]] = {}
    baseline: str | None = None
    start = cutoff.date()
    mode = "bootstrap"
    if previous is not None:
        meta = previous.metadata
        prev_to = ew.parse_time((meta.get("covered") or {}).get("to"))
        if prev_to is None:
            raise FormatError("previous index: no covered.to")
        records = previous.records
        baseline = meta.get("baseline")
        feed.gaps = gaps_of(meta.get("gaps") or [])
        # an index that ends before the window starts is not connected by any delta
        start = max(
            start, min(prev_to.date(), now.date() - timedelta(days=RESCAN_DAYS))
        )
        mode = "incremental"
    apply_deltas(records, client, start, now, cutoff, feed)
    since = datetime(start.year, start.month, start.day, tzinfo=UTC)
    if previous is None or prev_to < cutoff:  # type: ignore[operator]
        # Nothing the deltas connect to. After the deltas: a REJECTED record of the
        # whole list has no claims, the version it replaces in ``records`` has
        snapshot = load_baseline(client, now.date(), cutoff, records)
        baseline = str(snapshot)
        mode = "bootstrap"
        since = datetime(snapshot.year, snapshot.month, snapshot.day, tzinfo=UTC)
        feed.gaps = {h for h in feed.gaps if h >= since}
    # what the deltas missed, and the gaps that are left over from earlier builds
    since = min([since, *feed.gaps])
    reconciled = reconcile(
        records, downloader, work_dir / "reconcile", since, now, cutoff, feed
    )
    records = {
        cve: r
        for cve, r in records.items()
        if ew.parse_time(r["updated"]) >= cutoff  # type: ignore[operator]
    }
    first_hour = cutoff.replace(minute=0, second=0)
    feed.gaps = {h for h in feed.gaps if h >= first_hour}

    osv_dir = work_dir / "osv"
    osv_dir.mkdir(parents=True, exist_ok=True)
    exports: dict[str, Path] = {}
    osv_info: dict[str, dict[str, Any]] = {}
    for export in OSV_EXPORTS:
        dest = osv_dir / f"{export}.zip"
        headers = downloader.fetch(f"{osv_url.rstrip('/')}/{export}/all.zip", dest)
        if headers is None:
            raise DownloadError(f"OSV export {export}: not found")
        exports[export] = dest
        osv_info[export] = {"last_modified": headers.get("last-modified")}
    wanted = {r["cve"] for r, _ in claims_in_window(records.values(), cutoff, now)}
    reputation = evaluate(records.values(), load_osv(exports, wanted), cutoff, now)

    counts = Counter(line["verdict"] for line in reputation.evidence)
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "built_at": format_time(now),
        "mode": mode,
        "window_days": window_days,
        "covered": {
            "from": format_time(cutoff),
            "to": format_time(now.replace(minute=0, second=0)),
        },
        "baseline": baseline,
        "last_asset": feed.last_asset
        or (previous.metadata.get("last_asset") if previous else None),
        "gaps": gap_ranges(feed.gaps),
        "osv": osv_info,
        "counts": {
            "records": len(records),
            "rejected": sum(r["state"] == STATE_REJECTED for r in records.values()),
            "claims": len(reputation.evidence),
            "confirmed": counts[VERDICT_CONFIRMED],
            "errors": counts[VERDICT_ERROR],
            "pending": counts[VERDICT_PENDING],
            "cnas": len(reputation.cnas),
            "reconciled": reconciled,
        },
    }
    return Built(records, reputation, metadata)


def write_index(built: Built, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = built.metadata
    records = (built.records[cve] for cve in sorted(built.records))
    write_jsonl_gz(out_dir / RECORDS_FILE, records)
    write_jsonl_gz(out_dir / EVIDENCE_FILE, built.reputation.evidence)
    write_json(
        out_dir / REPUTATION_FILE,
        {
            "schema_version": SCHEMA_VERSION,
            "as_of": meta["built_at"],
            "window_days": meta["window_days"],
            "window_start": meta["covered"]["from"],
            "cnas": built.reputation.cnas,
        },
    )
    write_json(out_dir / METADATA_FILE, meta)


def summary_markdown(built: Built, out_dir: Path, seconds: float) -> str:
    meta = built.metadata
    counts = meta["counts"]
    sizes = ", ".join(
        f"{name} {(out_dir / name).stat().st_size / 1e6:.1f} MB" for name in INDEX_FILES
    )
    gaps = meta["gaps"]
    listed = ", ".join(f"{g['from']} to {g['to']}" for g in gaps[:10])
    lines = [
        "## CVE index for the early warning",
        "",
        f"- built {meta['built_at']} ({meta['mode']}, {seconds / 60:.1f} min), "
        f"window {meta['window_days']} days, covered to {meta['covered']['to']}",
        f"- {counts['records']} records ({counts['rejected']} rejected), "
        f"{counts['claims']} claims: {counts['confirmed']} confirmed, "
        f"{counts['errors']} errors, {counts['pending']} pending, "
        f"{counts['cnas']} CNAs",
        f"- sizes: {sizes}",
        f"- feed gaps: {len(gaps)}" + (f" ({listed})" if gaps else ""),
    ]
    return "\n".join(lines) + "\n"


def main(
    argv: Sequence[str] | None = None,
    downloader: Downloader | None = None,
    now: datetime | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--work-dir",
        required=True,
        type=Path,
        help="where the downloads go (1.5 GB for a bootstrap); removed at the end",
    )
    parser.add_argument(
        "--previous-dir",
        type=Path,
        help="the previous index; without it the build starts from the whole CVE list",
    )
    parser.add_argument("--window-days", type=int, default=DEFAULT_WINDOW_DAYS)
    parser.add_argument("--summary-file", type=Path, help="append a markdown summary")
    args = parser.parse_args(argv)
    if not 1 <= args.window_days <= MAX_WINDOW_DAYS:
        parser.error(f"--window-days must be 1 to {MAX_WINDOW_DAYS}")
    started = time.monotonic()
    try:
        previous = read_previous(args.previous_dir) if args.previous_dir else None
        built = build(
            downloader or UrllibDownloader(),
            args.work_dir,
            now or datetime.now(UTC),
            args.window_days,
            previous,
        )
        write_index(built, args.output_dir)
    except IndexBuildError as err:
        print(f"::error title=CVE index not built::{err}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(args.work_dir, ignore_errors=True)
    summary = summary_markdown(built, args.output_dir, time.monotonic() - started)
    print(summary)
    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8", newline="\n") as out:
            out.write(summary)
    for gap in built.metadata["gaps"]:
        print(
            f"::warning title=CVE feed gap::no delta for {gap['from']} to {gap['to']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
