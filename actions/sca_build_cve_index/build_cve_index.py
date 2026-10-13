#!/usr/bin/env python3
"""Build the CVE index of the SCA early warning.

The early warning matches CVE records (cvelistV5, published by the CVE Numbering
Authorities, CNAs) with the packages of a scan. The records of the last 180 days
are the same for every caller and are expensive to find out per run, so this script
builds them once a day. Bulk data only, no per-CVE request:

  * the CVE records: the ``end_of_day`` and hourly delta zips of the cvelistV5
    GitHub releases; to start with, the whole list
    (``*_all_CVEs_at_midnight.zip.zip``) and the deltas from its day on: the deltas
    have holes that no check of their assets finds (what was updated around
    midnight is in none of them), which the whole list has not;
  * ``cves/deltaLog.json`` of the cvelistV5 repository, which lists every record
    that changed and when: a record that it lists and that the deltas did not
    bring (such a hole, or a delta that is missing) is fetched on its own;
  * the previous index (``--previous-dir``), to which the new deltas are applied.

Outputs (``--output-dir``), ``schema_version: 1``:
  * ``cves.jsonl.gz`` - one slim CVE record per line (what the matcher of the early
    warning reads, in the form of ``early_warning.slim_record``) for the records
    published or updated in the window, and the REJECTED ones (a rejection replaces
    the published version of its record);
  * ``metadata.json`` - when it was built, what it covers, the gaps of the feed,
    the counts.

A record of an unusual shape (cvelistV5 is written by many CNAs) does not fail the
build either: it is skipped, with a warning that names it, and counted in
``counts.skipped`` of ``metadata.json``; a record the previous index has stays as it
was. A feed with holes does not fail the build: every hour of every day of the covered
span must be covered by the ``end_of_day`` delta of its day or by its own hourly
delta, and what is not is listed in ``gaps`` of ``metadata.json``. Anything else
that is not as expected (a download that fails after its retries, a file that
cannot be read) fails the build, and nothing is
written: the index of the day before stays the latest one.

The download layer is injectable (``Downloader.fetch(url, dest)``), so the logic is
tested with no network. Python standard library only; the form of a record, the feed
and the files of the index are those of ``_sca_lib.cve_index``, which the early
warning reads the index with, so that the two cannot disagree.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from _sca_lib.cve_index import (
    FEED_URL,
    INDEX_FILES,
    METADATA_FILE,
    RECORDS_FILE,
    SCHEMA_VERSION,
    STATE_REJECTED,
    Downloader,
    Feed,
    FeedClient,
    FormatError,
    IndexBuildError,
    Previous,
    UrllibDownloader,
    apply_deltas,
    gap_ranges,
    gaps_of,
    load_baseline,
    read_previous,
    reconcile,
    write_jsonl_gz,
)
from _sca_lib.gha import append_text, escape_command_data
from _sca_lib.jsonio import dump_json
from _sca_lib.times import format_time, parse_time

DEFAULT_WINDOW_DAYS = 180
MAX_WINDOW_DAYS = 365
# The deltas of this many days before the previous index ended are fetched again:
# an end_of_day delta is published after midnight and a delta can come late
RESCAN_DAYS = 2


@dataclass
class Built:
    records: dict[str, dict[str, Any]]
    metadata: dict[str, Any]


def build(
    downloader: Downloader,
    work_dir: Path,
    now: datetime,
    window_days: int = DEFAULT_WINDOW_DAYS,
    previous: Previous | None = None,
) -> Built:
    now = now.astimezone(UTC).replace(microsecond=0)
    cutoff = now - timedelta(days=window_days)
    client = FeedClient(downloader, FEED_URL, work_dir / "feed")
    feed = Feed()
    records: dict[str, dict[str, Any]] = {}
    baseline: str | None = None
    start = cutoff.date()
    mode = "bootstrap"
    if previous is not None:
        meta = previous.metadata
        prev_to = parse_time((meta.get("covered") or {}).get("to"))
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
    if previous is None or prev_to < cutoff:  # type: ignore[operator]
        # Nothing the deltas connect to: the whole list, then the deltas from its day
        start = load_baseline(client, now.date(), cutoff, records, feed.skipped)
        baseline = str(start)
        mode = "bootstrap"
    apply_deltas(records, client, start, now, cutoff, feed)
    since = datetime(start.year, start.month, start.day, tzinfo=UTC)
    if mode == "bootstrap":
        feed.gaps = {h for h in feed.gaps if h >= since}
    # what the deltas missed, and the gaps that are left over from earlier builds
    since = min([since, *feed.gaps])
    reconciled = reconcile(
        records, downloader, work_dir / "reconcile", since, now, cutoff, feed
    )
    records = {
        cve: r
        for cve, r in records.items()
        if parse_time(r["updated"]) >= cutoff  # type: ignore[operator]
    }
    first_hour = cutoff.replace(minute=0, second=0)
    feed.gaps = {h for h in feed.gaps if h >= first_hour}

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
        "counts": {
            "records": len(records),
            "rejected": sum(r["state"] == STATE_REJECTED for r in records.values()),
            "reconciled": reconciled,
            "skipped": len(feed.skipped),
        },
    }
    return Built(records, metadata)


def write_index(built: Built, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = built.metadata
    records = (built.records[cve] for cve in sorted(built.records))
    write_jsonl_gz(out_dir / RECORDS_FILE, records)
    dump_json(
        out_dir / METADATA_FILE, meta, indent=2, sort_keys=True, ensure_ascii=True
    )


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
        f"- {counts['records']} records ({counts['rejected']} rejected, "
        f"{counts['skipped']} skipped for their shape)",
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
        print(
            f"::error title=CVE index not built::{escape_command_data(err)}",
            file=sys.stderr,
        )
        return 1
    finally:
        shutil.rmtree(args.work_dir, ignore_errors=True)
    summary = summary_markdown(built, args.output_dir, time.monotonic() - started)
    print(summary)
    if args.summary_file:
        append_text(args.summary_file, summary)
    for gap in built.metadata["gaps"]:
        print(
            f"::warning title=CVE feed gap::no delta for {gap['from']} to {gap['to']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
