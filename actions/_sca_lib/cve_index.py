"""The CVE index of the SCA early warning: its records, the feed they come from
and its files.

Shared by ``sca_build_cve_index`` (builds the index) and ``sca_early_warning``
(reads it and brings it up to date), so that the two cannot disagree on the form of
a record. The download layer is injectable (``Downloader.fetch(url, dest)``).
"""

from __future__ import annotations

import gzip
import http.client
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from _sca_lib.gha import escape_command_data
from _sca_lib.http import (
    MAX_ATTEMPTS,
    REQUEST_TIMEOUT_SECONDS,
    RETRY_STATUSES,
    backoff_delay,
)
from _sca_lib.times import format_time, parse_time

FEED_URL = "https://github.com/CVEProject/cvelistV5/releases/download"
# the changes of the last month, newest first, and the records themselves
DELTA_LOG_URL = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
)
RECORDS_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"

SCHEMA_VERSION = 1
USER_AGENT = "ai-dial-ci-sca-build-cve-index"

DOWNLOAD_BACKOFF_SECONDS = 2.0
CHUNK_BYTES = 1 << 20
MAX_DOWNLOAD_BYTES = 2 * 1024**3
MAX_MEMBER_BYTES = 16 * 1024 * 1024

STATE_PUBLISHED = "PUBLISHED"
STATE_REJECTED = "REJECTED"

RECORDS_FILE = "cves.jsonl.gz"
METADATA_FILE = "metadata.json"
INDEX_FILES = (RECORDS_FILE, METADATA_FILE)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
UNKNOWN_SEVERITY = "UNKNOWN"
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
# CVSS metric keys of a CVE record, the version they carry, in the order of
# preference when a source has several (3.1 over 3.0, v3 over v4 for ranking)
CVSS_METRICS = (("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV4_0", "4.0"))
SOURCE_CNA = "cna"
SOURCE_ADP_PREFIX = "adp:"
MAX_DESCRIPTION_CHARS = 3000
MAX_REFERENCES = 100


# --------------------------------------------------------------------------
# Errors and the download
# --------------------------------------------------------------------------


class IndexBuildError(Exception):
    """The index cannot be built; the message says why."""


class DownloadError(IndexBuildError):
    pass


class FormatError(IndexBuildError):
    """An input is not what it is expected to be."""


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
            delay = backoff_delay(attempt, base=DOWNLOAD_BACKOFF_SECONDS)
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
                delay = backoff_delay(
                    attempt,
                    (err.headers or {}).get("Retry-After"),
                    DOWNLOAD_BACKOFF_SECONDS,
                )
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
# The form of a record
# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------
# CVE records
# --------------------------------------------------------------------------


def index_record(document: Any, where: str) -> dict[str, Any]:
    """The record of a CVE record 5 as the index keeps it. A document that is not a
    CVE record is a FormatError: an unknown shape must not pass as a record without
    data.
    """
    record = slim_record(document) if isinstance(document, dict) else None
    if record is None or not record["cve"]:
        raise FormatError(f"{where}: not a CVE record")
    if record["state"] not in (STATE_PUBLISHED, STATE_REJECTED):
        raise FormatError(f"{where}: unexpected state {record['state']!r}")
    meta = document["cveMetadata"]
    record["published"] = record["published"] or meta.get("dateRejected")
    record["updated"] = record["updated"] or record["published"]
    if None in (parse_time(record["published"]), parse_time(record["updated"])):
        raise FormatError(f"{where}: no usable dates")
    if record["state"] == STATE_REJECTED:
        # nothing else of a rejected record is of use
        keep = ("cve", "state", "published", "updated", "assigner")
        record = {k: record[k] for k in keep}
    return record


def skip_record(skipped: set[str], cve: str, err: Exception) -> None:
    """Leave out a record that is not of a known shape, and say so."""
    skipped.add(cve)
    print(
        "::warning title=CVE record skipped::"
        + escape_command_data(f"{cve} is not indexed: {err}")
    )


def read_cve_zip(
    path: Path, cutoff: datetime, skipped: set[str]
) -> Iterator[dict[str, Any]]:
    """The records of a zip of CVE record files that were updated since the cutoff.
    The members that are not ``CVE-*.json`` (indexes, directories) are skipped, and
    so are, with their ids added to ``skipped``, the records of an unknown shape.
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
            try:
                record = index_record(document, where)
            except FormatError as err:
                skip_record(skipped, base.removesuffix(".json"), err)
                continue
            if parse_time(record["updated"]) >= cutoff:  # type: ignore[operator]
                yield record


def merge_record(records: dict[str, dict[str, Any]], new: dict[str, Any]) -> None:
    """Keep the latest version of each record."""
    known = records.get(new["cve"])
    if known is not None and parse_time(new["updated"]) < parse_time(  # type: ignore[operator]
        known["updated"]
    ):
        return
    records[new["cve"]] = new


# --------------------------------------------------------------------------
# The feed
# --------------------------------------------------------------------------


def end_of_day_asset(day: date) -> str:
    return f"cve_{day}_at_end_of_day/{day}_delta_CVEs_at_end_of_day.zip"


def hourly_asset(day: date, hour: int) -> str:
    return f"cve_{day}_{hour:02d}00Z/{day}_delta_CVEs_at_{hour:02d}00Z.zip"


def baseline_asset(day: date) -> str:
    """The whole list as of the start of ``day``, a zip with ``cves.zip`` in it. It
    is attached to every hourly release of the day from 0100Z on.
    """
    return f"cve_{day}_0100Z/{day}_all_CVEs_at_midnight.zip.zip"


@dataclass
class Feed:
    gaps: set[datetime] = field(default_factory=set)  # hours without a delta
    skipped: set[str] = field(default_factory=set)  # records of an unknown shape
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
    client: FeedClient,
    today: date,
    cutoff: datetime,
    records: dict[str, Any],
    skipped: set[str],
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
            for record in read_cve_zip(inner, cutoff, skipped):
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
            for record in read_cve_zip(path, cutoff, feed.skipped):
                merge_record(records, record)
        finally:
            path.unlink()
        feed.last_asset = asset.rsplit("/", 1)[-1]
        return True

    day = start
    while day <= now.date():
        past = day < now.date()
        if not (past and process(end_of_day_asset(day))):
            midnight = datetime(day.year, day.month, day.day, tzinfo=UTC)
            for hour in range(24 if past else now.hour + 1):
                if not process(hourly_asset(day, hour)) and (past or hour < now.hour):
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
        if downloader.fetch(DELTA_LOG_URL, log_path) is None:
            raise DownloadError(f"{DELTA_LOG_URL}: not found")
        try:
            log = json.loads(log_path.read_text(encoding="utf-8"))
        finally:
            log_path.unlink()
        changes: dict[str, datetime] = {}
        horizon = None
        for item in log:
            fetched = parse_time(item.get("fetchTime"))
            if fetched is None:
                raise FormatError("deltaLog.json: an entry without fetchTime")
            horizon = min(horizon or fetched, fetched)
            if fetched < since:
                continue
            for change in [*item.get("new", []), *item.get("updated", [])]:
                updated = parse_time(change.get("dateUpdated"))
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
        print(
            "::warning title=CVE delta log::"
            + escape_command_data(f"cannot reconcile: {err}")
        )
        return 0
    feed.gaps = {h for h in feed.gaps if h < hour_of(horizon)}
    fetched_records = 0
    for cve, updated in sorted(changes.items()):
        known = records.get(cve)
        if known is not None and parse_time(known["updated"]) >= updated:  # type: ignore[operator]
            continue
        dest = work_dir / f"{cve}.json"
        try:
            if downloader.fetch(record_url(RECORDS_URL, cve), dest) is None:
                raise DownloadError(f"{cve}: not found")
            try:
                document = json.loads(dest.read_text(encoding="utf-8"))
            finally:
                dest.unlink()
            merge_record(records, index_record(document, cve))
        except FormatError as err:
            # fetched, but not a record we can index: nothing a later build can mend
            skip_record(feed.skipped, cve, err)
            continue
        except (IndexBuildError, ValueError) as err:
            print(
                "::warning title=CVE record::"
                + escape_command_data(f"{cve} cannot be fetched: {err}")
            )
        fetched_records += 1
        now_known = records.get(cve)
        if now_known is None or parse_time(now_known["updated"]) < updated:  # type: ignore[operator]
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
        start, end = parse_time(item.get("from")), parse_time(item.get("to"))
        if start is None or end is None:
            raise FormatError(f"gap {item}: not a time range")
        while start < end:
            gaps.add(start)
            start += timedelta(hours=1)
    return gaps


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
