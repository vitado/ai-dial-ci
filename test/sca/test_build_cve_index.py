"""Tests for actions/sca_build_cve_index/build_cve_index.py (synthetic data, fake
download layer).
"""

from __future__ import annotations

import gzip
import importlib.util
import io
import json
import sys
import urllib.error
import zipfile
from datetime import UTC, date, datetime, timedelta
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2030, 1, 10, 12, 30, 0, tzinfo=UTC)
TODAY = NOW.date()
WINDOW = 5  # days: the window of the build at NOW starts 2030-01-05T12:30Z


def _load():
    path = ROOT / "actions" / "sca_build_cve_index" / "build_cve_index.py"
    spec = importlib.util.spec_from_file_location("build_cve_index", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


b = _load()
ew = b.ew
FEED = b.FEED_URL


# --- builders ----------------------------------


def stamp(day: int, hour: int = 10) -> str:
    """A time of January 2030."""
    return f"2030-01-{day:02d}T{hour:02d}:00:00.000Z"


def entry(**fields: Any) -> dict[str, Any]:
    return fields


def pkg_entry(name: str, upper: str = "1.2.2", **fields: Any) -> dict[str, Any]:
    version = {"version": "0", "lessThan": upper, "status": "affected"}
    version["versionType"] = "semver"
    return entry(
        packageName=name, versions=[version], defaultStatus="unaffected", **fields
    )


def repo_entry(repo: str, **fields: Any) -> dict[str, Any]:
    return entry(repo=repo, product="p", **fields)


def cve_doc(
    cve: str,
    *,
    state: str = "PUBLISHED",
    published: str | None = None,
    updated: str | None = None,
    assigner: str = "acme",
    affected: list[dict[str, Any]] | None = None,
    refs: tuple[str, ...] = (),
    text: str = "A flaw.",
) -> dict[str, Any]:
    published = published or stamp(9)
    meta = {
        "cveId": cve,
        "state": state,
        "assignerShortName": assigner,
        "dateUpdated": updated or published,
    }
    if state == "REJECTED":
        meta["dateRejected"] = updated or published
        cna: dict[str, Any] = {"rejectedReasons": [{"lang": "en", "value": "dup"}]}
    else:
        meta["datePublished"] = published
        cna = {
            "title": f"{cve} title",
            "descriptions": [{"lang": "en", "value": text}],
            "affected": affected or [],
            "references": [{"url": url} for url in refs],
        }
    return {"cveMetadata": meta, "containers": {"cna": cna}}


LOG_HORIZON = "2029-12-20T00:00:00.000Z"


def log_change(doc: dict[str, Any]) -> dict[str, str]:
    meta = doc["cveMetadata"]
    return {"cveId": meta["cveId"], "dateUpdated": meta["dateUpdated"]}


def zip_bytes(members: dict[str, Any]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            data = content if isinstance(content, bytes) else json.dumps(content)
            archive.writestr(name, data)
    return out.getvalue()


def delta(*docs: dict[str, Any]) -> bytes:
    members: dict[str, Any] = {"deltaLog.json": []}
    for doc in docs:
        members[f"cves/2030/0xxx/{doc['cveMetadata']['cveId']}.json"] = doc
    return zip_bytes(members)


def whole_list(*docs: dict[str, Any]) -> bytes:
    inner = {f"cves/2030/0xxx/{d['cveMetadata']['cveId']}.json": d for d in docs}
    inner["cves/deltaLog.json"] = []
    return zip_bytes({"cves.zip": zip_bytes(inner)})


class FakeDownloader:
    """The download layer: the files of a dict, 404 for the rest, failures on demand."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.fail: set[str] = set()
        self.requested: list[str] = []

    def fetch(self, url: str, dest: Path) -> dict[str, str] | None:
        self.requested.append(url)
        if url in self.fail:
            raise b.DownloadError(f"GET {url}: HTTP 500")
        if url not in self.files:
            return None
        dest.write_bytes(self.files[url])
        return {"last-modified": "Wed, 09 Jan 2030 00:00:00 GMT"}

    def eod(self, day: date, *docs: dict[str, Any]) -> None:
        self.files[f"{FEED}/{ew.end_of_day_asset(day)}"] = delta(*docs)

    def hour(self, day: date, hour: int, *docs: dict[str, Any]) -> None:
        self.files[f"{FEED}/{ew.hourly_asset(day, hour)}"] = delta(*docs)

    def whole(self, day: date, *docs: dict[str, Any]) -> None:
        self.files[f"{FEED}/{b.baseline_asset(day)}"] = whole_list(*docs)

    def log(
        self,
        *entries: tuple[str, list[dict[str, Any]], list[dict[str, Any]]],
        horizon: str = LOG_HORIZON,
    ) -> None:
        """deltaLog.json: (fetchTime, new docs, updated docs) of each change, and an
        old entry that sets how far back it goes."""
        items = [
            {
                "fetchTime": fetched,
                "numberOfChanges": len(new) + len(updated),
                "new": [log_change(d) for d in new],
                "updated": [log_change(d) for d in updated],
            }
            for fetched, new, updated in entries
        ]
        items.append({"fetchTime": horizon, "new": [], "updated": []})
        self.files[b.DELTA_LOG_URL] = json.dumps(items).encode()

    def raw(self, *docs: dict[str, Any]) -> None:
        """The records as the repository serves them."""
        for doc in docs:
            url = b.record_url(b.RECORDS_URL, doc["cveMetadata"]["cveId"])
            self.files[url] = json.dumps(doc).encode()

    def drop(self, asset: str) -> None:
        del self.files[f"{FEED}/{asset}"]

    def complete_feed(self, now: datetime = NOW, window: int = WINDOW) -> None:
        """Empty deltas (unless there are some) for the window of a build at ``now``:
        an end_of_day delta for each past day, the hourly deltas of today that are
        published before the current hour."""
        day = (now - timedelta(days=window)).date()
        while day < now.date():
            url = f"{FEED}/{ew.end_of_day_asset(day)}"
            self.files.setdefault(url, delta())
            day += timedelta(days=1)
        for hour in range(now.hour):
            self.files.setdefault(
                f"{FEED}/{ew.hourly_asset(now.date(), hour)}", delta()
            )


@pytest.fixture
def net() -> FakeDownloader:
    fake = FakeDownloader()
    fake.complete_feed()
    fake.whole(TODAY)
    fake.log()
    return fake


def run_build(
    net: FakeDownloader,
    tmp_path: Path,
    previous: Any = None,
    now: datetime = NOW,
) -> Any:
    return b.build(net, tmp_path / "work", now, WINDOW, previous)


def previous_of(built: Any, tmp_path: Path) -> Any:
    """The index as the next build reads it."""
    out = tmp_path / "previous"
    b.write_index(built, out)
    return b.read_previous(out)


# --- the feed: completeness -------------------------------------------------------


def deltas(
    net: FakeDownloader,
    tmp_path: Path,
    start: date,
    feed: Any = None,
    records: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], Any]:
    feed = feed or b.Feed()
    records = {} if records is None else records
    client = b.FeedClient(net, FEED, tmp_path / "feed")
    b.apply_deltas(records, client, start, NOW, NOW - timedelta(days=WINDOW), feed)
    return records, feed


def test_complete_feed_has_no_gaps(net: FakeDownloader, tmp_path: Path) -> None:
    _, feed = deltas(net, tmp_path, TODAY - timedelta(days=3))
    assert feed.gaps == set()
    assert feed.last_asset == "2030-01-10_delta_CVEs_at_1100Z.zip"


def test_end_of_day_covers_the_hours_of_its_day(
    net: FakeDownloader, tmp_path: Path
) -> None:
    day = TODAY - timedelta(days=2)
    net.hour(day, 3, cve_doc("CVE-2030-1", updated=stamp(8, 3)))
    records, feed = deltas(net, tmp_path, day)
    assert feed.gaps == set()
    assert records == {}  # the hourly deltas of that day are not looked at
    assert not any(ew.hourly_asset(day, 3) in url for url in net.requested)


def test_missing_end_of_day_is_made_up_by_hourly_deltas(
    net: FakeDownloader, tmp_path: Path
) -> None:
    day = TODAY - timedelta(days=2)
    net.drop(ew.end_of_day_asset(day))
    for hour in set(range(24)) - {5, 6, 20}:
        net.hour(day, hour)
    net.hour(day, 7, cve_doc("CVE-2030-1", published=stamp(8, 7)))
    records, feed = deltas(net, tmp_path, day)
    assert "CVE-2030-1" in records
    assert b.gap_ranges(feed.gaps) == [
        {"from": "2030-01-08T05:00:00Z", "to": "2030-01-08T07:00:00Z"},
        {"from": "2030-01-08T20:00:00Z", "to": "2030-01-08T21:00:00Z"},
    ]


def test_a_day_without_any_delta_is_a_gap_of_24_hours(
    net: FakeDownloader, tmp_path: Path
) -> None:
    day = TODAY - timedelta(days=2)
    net.drop(ew.end_of_day_asset(day))
    _, feed = deltas(net, tmp_path, day)
    assert b.gap_ranges(feed.gaps) == [
        {"from": "2030-01-08T00:00:00Z", "to": "2030-01-09T00:00:00Z"}
    ]


def test_only_hours_of_today_before_the_current_one_can_be_gaps(
    net: FakeDownloader, tmp_path: Path
) -> None:
    net.drop(ew.hourly_asset(TODAY, 3))
    # the delta of the current hour (12) is not published yet: not a gap
    assert f"{FEED}/{ew.hourly_asset(TODAY, 12)}" not in net.files
    _, feed = deltas(net, tmp_path, TODAY)
    assert b.gap_ranges(feed.gaps) == [
        {"from": "2030-01-10T03:00:00Z", "to": "2030-01-10T04:00:00Z"}
    ]


def test_gaps_round_trip_and_a_rescan_recomputes_the_days_it_covers(
    net: FakeDownloader, tmp_path: Path
) -> None:
    old = {"from": "2030-01-06T01:00:00Z", "to": "2030-01-06T02:00:00Z"}
    rescanned = {"from": "2030-01-08T05:00:00Z", "to": "2030-01-08T07:00:00Z"}
    assert b.gap_ranges(b.gaps_of([old, rescanned])) == [old, rescanned]
    with pytest.raises(b.FormatError):
        b.gaps_of([{"from": "yesterday", "to": "today"}])
    # the day of the second gap is complete now, the first is before the rescan
    feed = b.Feed(gaps=b.gaps_of([old, rescanned]))
    deltas(net, tmp_path, date(2030, 1, 7), feed)
    assert b.gap_ranges(feed.gaps) == [old]


def test_a_delta_that_cannot_be_downloaded_fails(
    net: FakeDownloader, tmp_path: Path
) -> None:
    day = TODAY - timedelta(days=1)
    net.fail.add(f"{FEED}/{ew.end_of_day_asset(day)}")
    with pytest.raises(b.DownloadError):
        deltas(net, tmp_path, day)


# --- the records ----------------------------------


def test_the_latest_version_of_a_record_wins(
    net: FakeDownloader, tmp_path: Path
) -> None:
    net.eod(
        TODAY - timedelta(days=2),
        cve_doc("CVE-2030-1", published=stamp(7), updated=stamp(8), text="new"),
    )
    net.hour(
        TODAY,
        1,
        cve_doc("CVE-2030-1", published=stamp(7), updated=stamp(6), text="old"),
    )
    records, _ = deltas(net, tmp_path, TODAY - timedelta(days=2))
    assert records["CVE-2030-1"]["description"] == "new"


def test_a_record_is_slimmed(net: FakeDownloader, tmp_path: Path) -> None:
    doc = cve_doc("CVE-2030-1", affected=[pkg_entry("left-pad")], refs=("https://r/1",))
    doc["containers"]["cna"]["x_internal"] = "dropped"
    doc["containers"]["cna"]["affected"][0]["modules"] = ["dropped"]
    net.eod(TODAY - timedelta(days=1), doc)
    records, _ = deltas(net, tmp_path, TODAY - timedelta(days=1))
    record = records["CVE-2030-1"]
    assert set(record) == {
        *("cve", "state", "published", "updated", "assigner", "title"),
        *("description", "affected", "references", "metrics"),
    }
    assert set(record["affected"][0]) == {"packageName", "versions", "defaultStatus"}
    assert record["references"] == ["https://r/1"]


@pytest.mark.parametrize(
    "member",
    [
        b"{not json",
    ],
)
def test_a_record_that_is_not_json_fails(
    net: FakeDownloader, tmp_path: Path, member: bytes | str
) -> None:
    day = TODAY - timedelta(days=1)
    members = {"cves/2030/0xxx/CVE-2030-1.json": member}
    net.files[f"{FEED}/{ew.end_of_day_asset(day)}"] = zip_bytes(members)
    with pytest.raises(b.FormatError):
        deltas(net, tmp_path, day)


@pytest.mark.parametrize(
    "member",
    [json.dumps({"x": 1}), json.dumps(cve_doc("CVE-2030-1", state="RESERVED"))],
)
def test_a_record_of_an_unusual_shape_is_skipped_and_counted(
    net: FakeDownloader, tmp_path: Path, capsys: Any, member: str
) -> None:
    day = TODAY - timedelta(days=1)
    good = cve_doc("CVE-2030-2", affected=[pkg_entry("a")])
    members = {
        "cves/2030/0xxx/CVE-2030-1.json": member,
        "cves/2030/0xxx/CVE-2030-2.json": good,
    }
    net.files[f"{FEED}/{ew.end_of_day_asset(day)}"] = zip_bytes(members)
    records, feed = deltas(net, tmp_path, day)
    assert list(records) == ["CVE-2030-2"]
    assert feed.skipped == {"CVE-2030-1"}
    assert "::warning title=CVE record skipped::CVE-2030-1 is not indexed" in (
        capsys.readouterr().out
    )


def test_the_skipped_records_are_counted_in_the_metadata(
    net: FakeDownloader, tmp_path: Path
) -> None:
    net.whole(TODAY, cve_doc("CVE-2030-1", state="RESERVED"))
    built = run_build(net, tmp_path)
    assert built.records == {}
    assert built.metadata["counts"]["skipped"] == 1


def test_a_fetched_record_of_an_unusual_shape_is_skipped_and_is_no_gap(
    net: FakeDownloader, tmp_path: Path, capsys: Any
) -> None:
    odd = cve_doc("CVE-2030-1001", published=stamp(10, 0), updated=stamp(10, 7))
    net.log(("2030-01-10T07:40:00.000Z", [odd], []))
    net.files[b.record_url(b.RECORDS_URL, "CVE-2030-1001")] = b'{"x": 1}'
    built = run_build(net, tmp_path)
    assert "CVE-2030-1001" not in built.records
    assert built.metadata["gaps"] == []
    assert built.metadata["counts"]["skipped"] == 1
    assert "CVE-2030-1001 is not indexed" in capsys.readouterr().out


def test_a_delta_that_is_not_a_zip_fails(net: FakeDownloader, tmp_path: Path) -> None:
    day = TODAY - timedelta(days=1)
    net.files[f"{FEED}/{ew.end_of_day_asset(day)}"] = b"<html>rate limited</html>"
    with pytest.raises(b.FormatError):
        deltas(net, tmp_path, day)


def test_a_rejected_record_replaces_the_record_it_follows() -> None:
    published = b.index_record(
        cve_doc("CVE-2030-1", affected=[pkg_entry("left-pad")], updated=stamp(8)), "t"
    )
    rejected = b.index_record(
        cve_doc("CVE-2030-1", state="REJECTED", updated=stamp(9)), "t"
    )
    assert set(rejected) == {*("cve", "state", "published", "updated"), "assigner"}
    records = {"CVE-2030-1": published}
    b.merge_record(records, rejected)
    assert records["CVE-2030-1"]["state"] == "REJECTED"
    # an older version that comes later does not bring it back
    b.merge_record(records, published)
    assert records["CVE-2030-1"]["state"] == "REJECTED"


# --- the build: bootstrap, incremental, resync --------------------------------------


def test_bootstrap_is_the_whole_list_and_the_deltas_from_its_day(
    net: FakeDownloader, tmp_path: Path
) -> None:
    # in the whole list, which has what the deltas lack (updated around midnight)
    midnight = cve_doc("CVE-2030-1", published=stamp(10, 0), affected=[pkg_entry("a")])
    net.whole(TODAY, midnight)
    net.hour(TODAY, 5, cve_doc("CVE-2030-2", published=stamp(10, 5)))
    built = run_build(net, tmp_path)
    assert set(built.records) == {"CVE-2030-1", "CVE-2030-2"}
    # the deltas of the days before the whole list are not needed
    assert not any(
        ew.end_of_day_asset(TODAY - timedelta(days=1)) in url for url in net.requested
    )
    meta = built.metadata
    assert meta["mode"] == "bootstrap"
    assert meta["baseline"] == "2030-01-10"
    assert meta["covered"] == {
        "from": "2030-01-05T12:30:00Z",
        "to": "2030-01-10T12:00:00Z",
    }
    assert meta["gaps"] == []
    assert meta["last_asset"] == "2030-01-10_delta_CVEs_at_1100Z.zip"


def test_the_whole_list_of_yesterday_when_todays_is_not_out_yet(
    net: FakeDownloader, tmp_path: Path
) -> None:
    net.drop(b.baseline_asset(TODAY))
    yesterday = TODAY - timedelta(days=1)
    net.whole(yesterday, cve_doc("CVE-2030-1", affected=[pkg_entry("a")]))
    built = run_build(net, tmp_path)
    assert built.metadata["baseline"] == "2030-01-09"
    assert "CVE-2030-1" in built.records


def test_no_whole_list_fails(net: FakeDownloader, tmp_path: Path) -> None:
    net.drop(b.baseline_asset(TODAY))
    with pytest.raises(b.IndexBuildError, match="no baseline"):
        run_build(net, tmp_path)


def test_a_whole_list_of_another_shape_fails(
    net: FakeDownloader, tmp_path: Path
) -> None:
    net.files[f"{FEED}/{b.baseline_asset(TODAY)}"] = zip_bytes({"other.zip": b"x"})
    with pytest.raises(b.FormatError, match="unexpected members"):
        run_build(net, tmp_path)


def test_incremental_build_updates_rejects_and_prunes(
    net: FakeDownloader, tmp_path: Path
) -> None:
    claim = [pkg_entry("left-pad")]
    net.whole(
        TODAY,
        cve_doc("CVE-2030-1", affected=claim, published=stamp(7)),
        cve_doc("CVE-2030-2", affected=claim, published=stamp(7)),
        cve_doc("CVE-2030-3", affected=claim, published=stamp(5, 13)),
    )
    first = run_build(net, tmp_path)
    assert set(first.records) == {"CVE-2030-1", "CVE-2030-2", "CVE-2030-3"}
    previous = previous_of(first, tmp_path)

    now = datetime(2030, 1, 11, 3, 17, 0, tzinfo=UTC)
    net.complete_feed(now)
    net.eod(
        TODAY,
        cve_doc(
            "CVE-2030-1",
            affected=[pkg_entry("left-pad", "9")],
            published=stamp(7),
            updated=stamp(10, 5),
        ),
        cve_doc("CVE-2030-2", state="REJECTED", updated=stamp(10, 6)),
        cve_doc("CVE-2030-4", affected=claim, published=stamp(10, 7)),
    )
    second = run_build(net, tmp_path, previous, now)

    assert second.metadata["mode"] == "incremental"
    assert second.metadata["baseline"] == "2030-01-10"  # no resync yet
    assert not any(b.baseline_asset(now.date()) in url for url in net.requested)
    assert second.records["CVE-2030-1"]["affected"][0]["versions"][0]["lessThan"] == "9"
    rejected = second.records["CVE-2030-2"]
    assert rejected["state"] == "REJECTED"
    assert "CVE-2030-4" in second.records
    # CVE-2030-3 was updated before the window of the second build starts
    assert "CVE-2030-3" not in second.records
    assert second.metadata["counts"]["rejected"] == 1


def test_incremental_build_fetches_the_last_days_again(
    net: FakeDownloader, tmp_path: Path
) -> None:
    previous = previous_of(run_build(net, tmp_path), tmp_path)
    now = datetime(2030, 1, 11, 3, 17, 0, tzinfo=UTC)
    net.complete_feed(now)
    # the end_of_day delta of 01-10 came out after the last build
    late = cve_doc("CVE-2030-5", published=stamp(10, 0), affected=[pkg_entry("a")])
    net.eod(TODAY, late)
    built = run_build(net, tmp_path, previous, now)
    assert "CVE-2030-5" in built.records
    assert built.metadata["last_asset"] == "2030-01-11_delta_CVEs_at_0200Z.zip"


def test_the_whole_list_is_not_downloaded_by_an_incremental_build(
    net: FakeDownloader, tmp_path: Path
) -> None:
    previous = previous_of(run_build(net, tmp_path), tmp_path)
    previous.metadata["baseline"] = "2030-01-02"  # a long time ago
    net.requested.clear()
    built = run_build(net, tmp_path, previous)
    assert built.metadata["mode"] == "incremental"
    assert not any("all_CVEs_at_midnight" in url for url in net.requested)


def test_a_rejection_of_the_whole_list_replaces_the_published_version(
    net: FakeDownloader, tmp_path: Path
) -> None:
    # the deltas have the published version, the whole list the rejected one
    claim = [pkg_entry("left-pad")]
    net.eod(TODAY - timedelta(days=1), cve_doc("CVE-2030-1", affected=claim))
    net.whole(TODAY, cve_doc("CVE-2030-1", state="REJECTED", updated=stamp(10, 0)))
    built = run_build(net, tmp_path)
    assert built.records["CVE-2030-1"]["state"] == "REJECTED"


def test_an_index_that_ends_before_the_window_starts_is_a_bootstrap(
    net: FakeDownloader, tmp_path: Path
) -> None:
    previous = previous_of(run_build(net, tmp_path), tmp_path)
    later = NOW + timedelta(days=20)
    net.complete_feed(later)
    net.whole(later.date())
    built = run_build(net, tmp_path, previous, later)
    assert built.metadata["mode"] == "bootstrap"
    assert built.metadata["baseline"] == str(later.date())
    # the deltas of the old index are of no use: the whole list starts it again
    first_day = ew.end_of_day_asset(later.date() - timedelta(days=WINDOW))
    assert not any(first_day in url for url in net.requested)


# --- reconciliation with the delta log ---------------------------------------------


def test_a_record_that_the_log_lists_and_the_deltas_lack_is_fetched(
    net: FakeDownloader, tmp_path: Path
) -> None:
    missed = cve_doc("CVE-2030-1001", published=stamp(10, 0), affected=[pkg_entry("a")])
    net.log(("2030-01-10T00:40:00.000Z", [missed], []))
    net.raw(missed)
    built = run_build(net, tmp_path)
    assert "CVE-2030-1001" in built.records
    assert built.metadata["counts"]["reconciled"] == 1
    assert built.metadata["gaps"] == []


def test_records_the_deltas_brought_are_not_fetched_again(
    net: FakeDownloader, tmp_path: Path
) -> None:
    seen = cve_doc("CVE-2030-1001", published=stamp(9), affected=[pkg_entry("a")])
    newer = cve_doc("CVE-2030-1002", published=stamp(9), updated=stamp(9, 12))
    net.eod(TODAY - timedelta(days=1), seen, newer)
    older_log = cve_doc("CVE-2030-1002", published=stamp(9), updated=stamp(9, 11))
    net.log(("2030-01-09T12:40:00.000Z", [seen], [older_log]))
    built = run_build(net, tmp_path)
    assert built.metadata["counts"]["reconciled"] == 0
    assert not any(
        url == b.record_url(b.RECORDS_URL, "CVE-2030-1001") for url in net.requested
    )


def test_a_newer_version_than_the_deltas_have_is_fetched(
    net: FakeDownloader, tmp_path: Path
) -> None:
    old = cve_doc("CVE-2030-1001", published=stamp(7), updated=stamp(8), text="old")
    new = cve_doc("CVE-2030-1001", published=stamp(7), updated=stamp(10, 0), text="new")
    net.eod(TODAY - timedelta(days=2), old)
    net.log(("2030-01-10T00:40:00.000Z", [], [new]))
    net.raw(new)
    assert run_build(net, tmp_path).records["CVE-2030-1001"]["description"] == "new"


def test_record_urls() -> None:
    url = b.record_url("https://r/cves", "CVE-2026-108779")
    assert url == "https://r/cves/2026/108xxx/CVE-2026-108779.json"
    assert b.record_url("https://r/cves", "CVE-2026-6232").endswith(
        "/2026/6xxx/CVE-2026-6232.json"
    )
    assert b.record_url("https://r/cves", "CVE-2015-20107").endswith(
        "/2015/20xxx/CVE-2015-20107.json"
    )
    with pytest.raises(b.FormatError):
        b.record_url("https://r/cves", "../etc/passwd")


def test_asset_gaps_that_the_log_covers_are_cleared_and_older_ones_stay(
    net: FakeDownloader, tmp_path: Path
) -> None:
    net.drop(ew.hourly_asset(TODAY, 3))
    net.drop(ew.hourly_asset(TODAY, 6))
    lost = cve_doc("CVE-2030-1001", published=stamp(10, 6), affected=[pkg_entry("a")])
    net.log(
        ("2030-01-10T06:40:00.000Z", [lost], []), horizon="2030-01-10T05:10:00.000Z"
    )
    net.raw(lost)
    built = run_build(net, tmp_path)
    assert "CVE-2030-1001" in built.records  # what the missing delta of hour 6 held
    # hour 3 is before the log starts: nothing says what was in it
    assert built.metadata["gaps"] == [
        {"from": "2030-01-10T03:00:00Z", "to": "2030-01-10T04:00:00Z"}
    ]


def test_an_old_gap_is_reconciled_when_the_log_reaches_it(
    net: FakeDownloader, tmp_path: Path
) -> None:
    previous = previous_of(run_build(net, tmp_path), tmp_path)
    previous.metadata["gaps"] = [
        {"from": "2030-01-06T01:00:00Z", "to": "2030-01-06T03:00:00Z"}
    ]
    lost = cve_doc("CVE-2030-1001", published=stamp(6, 2), affected=[pkg_entry("a")])
    net.log(("2030-01-06T02:40:00.000Z", [lost], []))
    net.raw(lost)
    built = run_build(net, tmp_path, previous)
    assert "CVE-2030-1001" in built.records
    assert built.metadata["gaps"] == []


def test_an_unreadable_log_is_a_gap_of_the_span_and_not_a_failure(
    net: FakeDownloader, tmp_path: Path, capsys: Any
) -> None:
    previous = previous_of(run_build(net, tmp_path), tmp_path)
    now = datetime(2030, 1, 11, 3, 17, 0, tzinfo=UTC)
    net.complete_feed(now)
    for broken in (b"not json", b"[]", json.dumps([{"x": 1}]).encode(), None):
        if broken is None:
            del net.files[b.DELTA_LOG_URL]
        else:
            net.files[b.DELTA_LOG_URL] = broken
        built = run_build(net, tmp_path, previous, now)
        assert built.metadata["gaps"] == [
            {"from": "2030-01-09T00:00:00Z", "to": "2030-01-11T04:00:00Z"}
        ]
        assert "::warning title=CVE delta log::" in capsys.readouterr().out


def test_a_failing_log_download_is_a_gap_too(
    net: FakeDownloader, tmp_path: Path
) -> None:
    net.fail.add(b.DELTA_LOG_URL)
    built = run_build(net, tmp_path)
    assert built.metadata["gaps"]


def test_a_record_that_cannot_be_fetched_is_a_gap_of_its_hour(
    net: FakeDownloader, tmp_path: Path, capsys: Any
) -> None:
    missed = cve_doc("CVE-2030-1001", published=stamp(10, 0), updated=stamp(10, 7))
    net.log(("2030-01-10T07:40:00.000Z", [missed], []))
    net.fail.add(b.record_url(b.RECORDS_URL, "CVE-2030-1001"))
    built = run_build(net, tmp_path)
    assert "CVE-2030-1001" not in built.records
    assert built.metadata["gaps"] == [
        {"from": "2030-01-10T07:00:00Z", "to": "2030-01-10T08:00:00Z"}
    ]
    assert "CVE-2030-1001 cannot be fetched" in capsys.readouterr().out


def test_a_record_that_comes_back_older_than_the_log_says_is_a_gap(
    net: FakeDownloader, tmp_path: Path
) -> None:
    served = cve_doc("CVE-2030-1001", published=stamp(10, 0), updated=stamp(10, 6))
    listed = cve_doc("CVE-2030-1001", published=stamp(10, 0), updated=stamp(10, 7))
    net.log(("2030-01-10T07:40:00.000Z", [], [listed]))
    net.raw(served)  # a cache that is behind
    built = run_build(net, tmp_path)
    assert built.metadata["gaps"] == [
        {"from": "2030-01-10T07:00:00Z", "to": "2030-01-10T08:00:00Z"}
    ]


# the records that the deltas of 2026-10-05 .. 2026-10-12 did not have, found by
# comparing them with the whole list: updated around midnight
MIDNIGHT_HOLES = [
    ("CVE-2026-51876", "2026-10-05T23:53:01.378Z"),
    ("CVE-2026-51881", "2026-10-05T23:55:02.210Z"),
    ("CVE-2026-51886", "2026-10-05T23:56:49.602Z"),
    ("CVE-2026-103531", "2026-10-05T23:57:51.416Z"),
    ("CVE-2026-103534", "2026-10-05T23:59:43.707Z"),
    ("CVE-2026-103539", "2026-10-06T00:00:48.424Z"),
    ("CVE-2026-103542", "2026-10-06T00:02:30.830Z"),
    ("CVE-2026-103246", "2026-10-06T00:05:36.140Z"),
    ("CVE-2026-103250", "2026-10-06T00:06:13.061Z"),
    ("CVE-2026-103254", "2026-10-06T00:06:56.074Z"),
    ("CVE-2026-103258", "2026-10-06T00:08:00.691Z"),
    ("CVE-2026-103262", "2026-10-06T00:08:58.078Z"),
    ("CVE-2026-103266", "2026-10-06T00:09:55.981Z"),
    ("CVE-2026-103271", "2026-10-06T00:10:32.485Z"),
    ("CVE-2015-20107", "2026-10-08T00:10:26.757Z"),
    ("CVE-2021-45949", "2026-10-08T00:11:09.813Z"),
    ("CVE-2022-31673", "2026-10-08T00:11:44.928Z"),
    ("CVE-2026-12345", "2026-10-10T00:41:17.043Z"),
    ("CVE-2026-82049", "2026-10-11T00:39:42.376Z"),
    ("CVE-2026-108779", "2026-10-12T00:00:16.238Z"),
    ("CVE-2026-108781", "2026-10-12T00:15:17.758Z"),
]


def test_the_21_records_that_the_deltas_lost_around_midnight(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 10, 12, 12, 30, 0, tzinfo=UTC)
    window = 10
    net = FakeDownloader()
    day = (now - timedelta(days=window)).date()
    while day < now.date():
        net.eod(day)  # the deltas are all there, and without those records
        day += timedelta(days=1)
    for hour in range(now.hour):
        net.hour(now.date(), hour)
    docs = [
        cve_doc(cve, published="2026-10-01T10:00:00.000Z", updated=updated)
        for cve, updated in MIDNIGHT_HOLES
    ]
    net.raw(*docs)

    previous = b.Previous(
        {},
        {
            "schema_version": 1,
            "baseline": "2026-09-01",
            "gaps": [],
            "covered": {"to": "2026-10-05T00:00:00Z"},
        },
    )

    # without the log they are lost
    net.log()
    lost = b.build(net, tmp_path / "w1", now, window, previous)
    assert not {c for c, _ in MIDNIGHT_HOLES} & set(lost.records)

    # the log lists them half an hour to an hour after the change
    entries = []
    for doc in docs:
        updated = datetime.fromisoformat(doc["cveMetadata"]["dateUpdated"])
        fetched = (updated + timedelta(minutes=40)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        entries.append((fetched, [], [doc]))
    net.log(*entries)
    built = b.build(net, tmp_path / "w2", now, window, previous)
    assert {c for c, _ in MIDNIGHT_HOLES} <= set(built.records)
    assert built.metadata["counts"]["reconciled"] == 21
    assert built.metadata["gaps"] == []


def test_the_index_round_trips_and_is_deterministic(
    net: FakeDownloader, tmp_path: Path
) -> None:
    claim = cve_doc("CVE-2030-1", affected=[pkg_entry("left-pad")])
    net.eod(TODAY - timedelta(days=1), claim)
    built = run_build(net, tmp_path)
    one, two = tmp_path / "one", tmp_path / "two"
    b.write_index(built, one)
    b.write_index(built, two)
    for name in b.INDEX_FILES:
        assert (one / name).read_bytes() == (two / name).read_bytes()
    previous = b.read_previous(one)
    assert previous.records == built.records
    assert previous.metadata == built.metadata


@pytest.mark.parametrize("change", [{"schema_version": 2}, {"baseline": "yesterday"}])
def test_a_previous_index_that_does_not_fit_fails(
    net: FakeDownloader, tmp_path: Path, change: dict[str, Any]
) -> None:
    out = tmp_path / "previous"
    b.write_index(run_build(net, tmp_path), out)
    meta = json.loads((out / b.METADATA_FILE).read_text(encoding="utf-8"))
    (out / b.METADATA_FILE).write_text(json.dumps({**meta, **change}), encoding="utf-8")
    with pytest.raises(b.FormatError):
        b.read_previous(out)


def test_a_previous_index_that_is_missing_or_broken_fails(
    net: FakeDownloader, tmp_path: Path
) -> None:
    with pytest.raises(b.FormatError):
        b.read_previous(tmp_path / "nothing")
    out = tmp_path / "previous"
    b.write_index(run_build(net, tmp_path), out)
    (out / b.RECORDS_FILE).write_bytes(b"not gzip")
    with pytest.raises(b.FormatError):
        b.read_previous(out)


# --- the downloader ----------------------------------


class FakeResponse:
    def __init__(self, body: bytes, length: int | None = None) -> None:
        self._body = io.BytesIO(body)
        self.headers = Message()
        self.headers["Content-Length"] = str(len(body) if length is None else length)
        self.headers["Last-Modified"] = "Wed, 09 Jan 2030 00:00:00 GMT"

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self._body.read(size)


def http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = Message()
    if retry_after:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("https://x", code, "err", headers, None)


def downloader(*answers: Any) -> tuple[Any, list[float]]:
    """A UrllibDownloader whose requests get the answers in turn (an exception is
    raised), and the sleeps it makes."""
    queue = list(answers)
    sleeps: list[float] = []

    def opener(request: Any, timeout: float) -> Any:
        answer = queue.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    return b.UrllibDownloader(opener, sleeps.append, max_attempts=3), sleeps


def test_the_downloader_saves_the_body_and_returns_the_headers(tmp_path: Path) -> None:
    dl, _ = downloader(FakeResponse(b"data"))
    headers = dl.fetch("https://x/a.zip", tmp_path / "a.zip")
    assert (tmp_path / "a.zip").read_bytes() == b"data"
    assert headers["last-modified"] == "Wed, 09 Jan 2030 00:00:00 GMT"


def test_the_downloader_retries_transient_failures(tmp_path: Path) -> None:
    dl, sleeps = downloader(
        http_error(503, "7"), urllib.error.URLError("reset"), FakeResponse(b"data")
    )
    assert dl.fetch("https://x/a.zip", tmp_path / "a.zip") is not None
    assert sleeps == [7.0, 4.0]


def test_the_downloader_retries_a_truncated_body(tmp_path: Path) -> None:
    dl, _ = downloader(FakeResponse(b"da", length=4), FakeResponse(b"data"))
    assert dl.fetch("https://x/a.zip", tmp_path / "a.zip") is not None
    assert (tmp_path / "a.zip").read_bytes() == b"data"


def test_the_downloader_gives_up_after_its_attempts(tmp_path: Path) -> None:
    dl, sleeps = downloader(*[http_error(502)] * 3)
    with pytest.raises(b.DownloadError, match="HTTP 502"):
        dl.fetch("https://x/a.zip", tmp_path / "a.zip")
    assert len(sleeps) == 2


def test_the_downloader_does_not_retry_what_will_not_change(tmp_path: Path) -> None:
    dl, sleeps = downloader(http_error(404))
    assert dl.fetch("https://x/a.zip", tmp_path / "a.zip") is None
    dl, sleeps = downloader(http_error(403))
    with pytest.raises(b.DownloadError, match="HTTP 403"):
        dl.fetch("https://x/a.zip", tmp_path / "a.zip")
    assert sleeps == []
    with pytest.raises(b.DownloadError, match="HTTPS"):
        dl.fetch("http://x/a.zip", tmp_path / "a.zip")


# --- the command ----------------------------------


def main_args(tmp_path: Path, *extra: str) -> list[str]:
    return [
        *("--output-dir", str(tmp_path / "index")),
        *("--work-dir", str(tmp_path / "work")),
        *("--window-days", str(WINDOW)),
        *extra,
    ]


def test_main_writes_the_index_and_a_summary(
    net: FakeDownloader, tmp_path: Path, capsys: Any
) -> None:
    claim = cve_doc("CVE-2030-1", affected=[pkg_entry("left-pad")])
    net.whole(TODAY, claim)
    summary = tmp_path / "summary.md"
    args = main_args(tmp_path, "--summary-file", str(summary))
    assert b.main(args, net, NOW) == 0
    out = tmp_path / "index"
    assert {p.name for p in out.iterdir()} == set(b.INDEX_FILES)
    assert not (tmp_path / "work").exists()
    with gzip.open(out / b.RECORDS_FILE, "rt", encoding="utf-8") as src:
        assert [json.loads(line)["cve"] for line in src] == ["CVE-2030-1"]
    assert "1 records" in summary.read_text(encoding="utf-8")
    assert "CVE index for the early warning" in capsys.readouterr().out


def test_main_uses_the_previous_index(net: FakeDownloader, tmp_path: Path) -> None:
    previous = tmp_path / "previous"
    b.write_index(run_build(net, tmp_path), previous)
    now = datetime(2030, 1, 11, 3, 17, 0, tzinfo=UTC)
    net.complete_feed(now)
    args = main_args(tmp_path, "--previous-dir", str(previous))
    assert b.main(args, net, now) == 0
    meta = json.loads(
        (tmp_path / "index" / b.METADATA_FILE).read_text(encoding="utf-8")
    )
    assert meta["mode"] == "incremental"


def test_main_fails_without_an_index_when_an_input_fails(
    net: FakeDownloader, tmp_path: Path, capsys: Any
) -> None:
    net.fail.add(f"{FEED}/{b.baseline_asset(TODAY)}")
    assert b.main(main_args(tmp_path), net, NOW) == 1
    assert not (tmp_path / "index").exists()
    assert "::error title=CVE index not built::" in capsys.readouterr().err


def test_main_warns_about_the_gaps_of_the_feed(
    net: FakeDownloader, tmp_path: Path, capsys: Any
) -> None:
    net.drop(ew.hourly_asset(TODAY, 3))
    net.log(horizon="2030-01-10T05:10:00.000Z")  # the log does not reach hour 3
    assert b.main(main_args(tmp_path), net, NOW) == 0
    out = capsys.readouterr().out
    assert "::warning title=CVE feed gap::" in out
    assert "2030-01-10T03:00:00Z" in out


def test_main_rejects_a_window_out_of_range(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        b.main(["--output-dir", "o", "--work-dir", "w", "--window-days", "0"])
