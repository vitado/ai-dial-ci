#!/usr/bin/env python3
"""Merge the per-target scan results of an SCA scheduled scan into one report.

Inputs:
  * targets.json written by sca_resolve_targets (the list of targets);
  * a parts directory with one subdirectory per scanner (``trivy/``, ``osv/``)
    holding, per scanned target id, ``<id>.json`` (native JSON),
    ``<id>.status.json``, an optional ``<id>.txt`` (table) and, for a Trivy Gradle
    build, ``<id>.gradle-graph/`` (the resolved dependency graph, one JSON file per
    Gradle project, written by the generate_gradle_lockfiles action).

Outputs (in the output directory):
  * ``_report/vulnerabilities.json`` - the findings only: canonical deduplicated
    set, one record per (repo, id x package x installed version), with the
    ``exposure`` of the finding (which shipped artifacts carry it), the
    ``scan_targets`` it was found in, its ``locations`` within them and the
    ``scanners`` that reported it;
  * ``_report/scan_report.json`` - the run manifest and the metrics: one entry
    per target with its status, the scanner that scanned it and its finding
    counts, plus the ``totals`` of the run;
  * ``summary.md`` - the human-readable, decision-first layer;
  * ``_native/<scanner>/<id>.json|txt`` - the unmodified per-target results
    (audit).

A target is identified by its scanner and its id (the id names the scanned
subject, which several scanners share). OSV, queried for the language packages of
every Trivy target, is reported per target (status, package and finding counts,
native result) and its findings are merged into the records: a vulnerability that
Trivy reports too joins its record (``scanners`` becomes ``["osv", "trivy"]``), one
that only OSV knows becomes a record of its own (``scanners: ["osv"]``), with the
package context of the Trivy package of the same purl.

A Gradle lockfile has no dependency graph, so the packages of a trivy ``gradle``
Result carry neither ``Relationship`` nor ``DependsOn``. They are filled in from
the Gradle graph of the project (in memory only, ``_native/`` stays as trivy
wrote it), before the dependency chains are built.

A target is an image, the source of the default branch or - an fs target with a
``tag`` - the source of a release tag. A release source gives the findings of a
release image their dependency chains (the same package version in the lockfile of
the tag; an image has no graph) and, in a run without images, stands for the
release in the exposure and in the headline. With images it never raises a
finding above ``source_only``: see ``classify_exposure``.

Paths that are not shipped (``non_shipped_paths`` of the SCA configuration in
targets.json, and the ``skip-dirs`` / ``skip-files`` of a source target's trivy.yaml
when the configuration says ``trivy_skip_paths: as_non_shipped``) do not count
towards the release or development exposure: a finding seen only in lockfiles under
them is ``source_only`` in every repository, and its locations are marked as not
shipped. The record stays in ``vulnerabilities.json``.

Early warning (``early-warning/`` part of the sca_early_warning action, when the run
has one): CVE records whose CNA data matches a language package of the run but that
no scanner reported. The merge drops the ones whose CVE id or alias is the ``id`` or
an alias of any record (a database maps them now, so a scanner reports them),
classifies the rest by exposure like a record and reports them in
``_report/early_warning.json``, in ``scan_report.json`` (``early_warning``) and in a
section of ``summary.md``. They are not records: not in ``vulnerabilities.json``,
not in the scope table, not in the headline. Every entry carries the ``match`` the
part computed, how it was matched (``package_name``, ``source_repo``, ``product_name``
or ``repo_module``); the merge shows it and neither filters nor tiers by it. The part
says which CVE index it read (``index``: ref, digest, built_at, feed gaps), and the
report repeats it. A broken or missing part is reported as unavailable, never as an
empty result.

A scan that broke is reported as ``failed`` and never looks like a clean
target. The script still exits 0 once the outputs are written: the workflow
decides about failing the run after the artifact has been uploaded.

The script is the orchestration only; the layers are modules of this directory,
each depending on the ones listed before it:

  * ``records``: the record model, keys, exposure (``release_only`` ...), the paths
    that are not shipped, ordering;
  * ``trivy_source``: Trivy results (CVSS selection, Gradle graph, dependency chains,
    base image) into records;
  * ``osv_source``: osv-scanner output into OSV vulnerabilities and records;
  * ``record_merge``: the records of one repository from the Trivy and OSV scans;
  * ``early_warning_merge``: the early warning radar matched with the findings;
  * ``report``: ``vulnerabilities.json`` and ``scan_report.json`` (the contract);
  * ``summary``: ``summary.md`` and its cut to the limit of the step summary.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from _sca_lib.gha import append_text, escape_command_data
from _sca_lib.jsonio import InputError, dump_json, read_json
from _sca_lib.times import format_time
from early_warning_merge import EARLY_WARNING_DIR, build_early_warning
from osv_source import OsvResolutionError, OsvScan, osv_result_problem, resolve_osv_scan
from record_merge import merge_records
from records import (
    KEY_NON_SHIPPED_PATHS,
    KEY_TRIVY_SKIP_PATHS,
    KIND_FS,
    KIND_IMAGE,
    SCANNER_OSV,
    SCANNER_TRIVY,
    SKIP_AS_NON_SHIPPED,
    STATUS_FAILED,
    STATUS_NOT_APPLICABLE,
    STATUS_OK,
    NotShipped,
    Target,
    default_config,
    finalize_records,
)
from report import (
    build_scan_report,
    build_vulnerabilities,
    parse_trivy_db_info,
    trivy_db_stale_days,
)
from summary import (
    SKIP_APPLY,
    SKIP_IGNORE,
    build_summary_md,
    trivy_targets,
    truncate_summary,
)
from trivy_source import apply_gradle_graph

RUN_KINDS = ("full", "partial")
TARGET_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SKIP_MODES = (SKIP_AS_NON_SHIPPED, SKIP_APPLY, SKIP_IGNORE)
TRIVY_CONFIG_SUFFIX = ".trivy-config.json"  # <id>.trivy-config.json of an fs target
TRIVY_CONFIG_SCHEMA_VERSION = 1
GRADLE_GRAPH_SUFFIX = ".gradle-graph"  # <id>.gradle-graph/ next to <id>.json
SCANNERS = (SCANNER_TRIVY, SCANNER_OSV)


def load_targets_file(path: Path) -> dict[str, Any]:
    """Load and validate targets.json."""
    try:
        data = read_json(path)
    except (OSError, ValueError) as e:
        raise InputError(f"cannot read targets file {path}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("targets"), list):
        raise InputError(f"targets file {path} has no 'targets' list")
    seen: set[tuple[str, str]] = set()
    for target in data["targets"]:
        tid = target.get("id") if isinstance(target, dict) else None
        if not isinstance(tid, str) or not TARGET_ID_RE.fullmatch(tid):
            raise InputError(f"targets file {path} has an invalid target id: {tid!r}")
        scanner = target.get("scanner")
        if scanner not in SCANNERS:
            raise InputError(
                f"targets file {path} has an invalid scanner of {tid}: {scanner!r}"
            )
        if (scanner, tid) in seen:
            raise InputError(
                f"targets file {path} has a duplicate {scanner} target id: {tid}"
            )
        seen.add((scanner, tid))
    data["config"] = validate_config(data.get("config"), path)
    if data.get("run_kind") not in RUN_KINDS:
        raise InputError(
            f"targets file {path} has an invalid run_kind: {data.get('run_kind')!r}"
        )
    reasons = data.get("run_kind_reasons")
    if not isinstance(reasons, list) or not all(isinstance(r, str) for r in reasons):
        raise InputError(f"targets file {path} has invalid run_kind_reasons")
    return data


def validate_config(raw: Any, path: Path) -> dict[str, Any]:
    """The SCA configuration of targets.json (the defaults if it has none)."""
    config = default_config()
    if raw is None:
        return config
    where = f"targets file {path}: invalid config"
    if not isinstance(raw, dict):
        raise InputError(f"{where}: not an object")
    patterns = raw.get(KEY_NON_SHIPPED_PATHS, [])
    if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
        raise InputError(f"{where}: {KEY_NON_SHIPPED_PATHS} must be a list of strings")
    mode = raw.get(KEY_TRIVY_SKIP_PATHS, SKIP_AS_NON_SHIPPED)
    if mode not in SKIP_MODES:
        raise InputError(
            f"{where}: {KEY_TRIVY_SKIP_PATHS} {mode!r} is not one of the modes"
        )
    for key in ("source", "overrides"):
        if not isinstance(raw.get(key), str | None):
            raise InputError(f"{where}: {key} must be a string or null")
        config[key] = raw.get(key)
    config.update({KEY_NON_SHIPPED_PATHS: list(patterns), KEY_TRIVY_SKIP_PATHS: mode})
    return config


def load_trivy_config_record(path: Path) -> dict[str, Any]:
    """The ``<id>.trivy-config.json`` of a source target (written by the
    sca_prepare_trivy_config action); raises OSError or ValueError if unusable.
    """
    record = read_json(path)
    if not isinstance(record, dict):
        raise ValueError("not a JSON object")
    if record.get("schema_version") != TRIVY_CONFIG_SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version {record.get('schema_version')!r}")
    if record.get("mode") not in SKIP_MODES:
        raise ValueError(f"invalid mode {record.get('mode')!r}")
    for key in ("skip_dirs", "skip_files"):
        value = record.get(key)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError(f"{key} must be a list of strings")
    if not isinstance(record.get("paths_scanned"), bool):
        raise ValueError("paths_scanned must be a boolean")
    return {
        key: record.get(key)
        for key in ("mode", "paths_scanned", "config_file", "skip_dirs", "skip_files")
    }


def load_target_result(
    target: Mapping[str, Any], scanner_parts_dir: Path
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Determine the final status of one target.

    Returns ``(state, native)``: state carries ``status`` and ``reason``; native
    is the parsed native result of the target's scanner for ``ok`` targets, else
    None. Anything short of a complete, valid result is ``failed`` - a broken scan
    must not look like a clean target.
    """
    tid = target["id"]
    scanner = target["scanner"]
    state: dict[str, Any] = {
        "status": target.get("status"),
        "reason": target.get("reason"),
    }
    if state["status"] in (STATUS_FAILED, STATUS_NOT_APPLICABLE):
        return state, None

    def failed(reason: str) -> tuple[dict[str, Any], None]:
        state.update(status=STATUS_FAILED, reason=reason)
        return state, None

    status_path = scanner_parts_dir / f"{tid}.status.json"
    if not status_path.is_file():
        return failed("scan job produced no result")
    try:
        status = read_json(status_path)
    except (OSError, ValueError) as e:
        return failed(f"unreadable status file: {e}")
    if not isinstance(status, dict):
        return failed("unreadable status file: not a JSON object")

    if status.get("status") == STATUS_FAILED:
        return failed(status.get("reason") or "scan job reported failure")
    if status.get("status") == STATUS_NOT_APPLICABLE:
        # The job found nothing to scan (an OSV target whose Trivy target failed)
        state.update(
            status=STATUS_NOT_APPLICABLE,
            reason=status.get("reason") or "nothing to scan",
        )
        return state, None
    if status.get("status") != STATUS_OK:
        return failed(f"unexpected scan status: {status.get('status')!r}")

    native_path = scanner_parts_dir / f"{tid}.json"
    if not native_path.is_file():
        return failed(f"{scanner} result file is missing")
    try:
        native = read_json(native_path)
    except (OSError, ValueError) as e:
        return failed(f"{scanner} result is not valid JSON: {e}")
    if not isinstance(native, dict):
        return failed(f"{scanner} result is not a JSON object")
    if scanner == SCANNER_OSV and (problem := osv_result_problem(native)):
        return failed(problem)

    state.update(status=STATUS_OK, reason=None)
    if scanner == SCANNER_OSV:
        # What osv-scanner does not say about its own run
        state.update(
            queried_at=status.get("queried_at"),
            scanner_version=status.get("scanner_version"),
            packages_unread=status.get("packages_unread"),
        )
    return state, native


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def copy_native(scanner_parts_dir: Path, target_id: str, native_dir: Path) -> None:
    """Keep the unmodified per-target results of one scanner for audit."""
    for suffix in (".json", ".txt"):
        src = scanner_parts_dir / f"{target_id}{suffix}"
        if src.is_file():
            shutil.copyfile(src, native_dir / src.name)


def resolve_osv_targets(
    results: list[tuple[Target, dict[str, Any], dict[str, Any] | None]],
    trivy_natives: Mapping[str, Mapping[str, Any]],
) -> list[OsvScan]:
    """Join the ``ok`` OSV targets with their Trivy twins (same id).

    An OSV result that does not fit its twin cannot be merged, so its target is
    set to ``failed`` in ``results``: a broken result never looks like a clean one.
    """
    scans = []
    for position, (target, state, native) in enumerate(results):
        if native is None or target["scanner"] != SCANNER_OSV:
            continue
        try:
            scans.append(
                resolve_osv_scan(target["id"], native, trivy_natives.get(target["id"]))
            )
        except OsvResolutionError as e:
            state.update(
                status=STATUS_FAILED, reason=f"osv result does not fit trivy's: {e}"
            )
            results[position] = (target, state, None)
    return scans


def run_merge(
    targets_file: Path,
    parts_dir: Path,
    output_dir: Path,
    generated_utc: str,
    trivy_db: Mapping[str, str | None] | None = None,
    early_warning_enabled: bool = False,
) -> int:
    """Write all outputs; return the number of failed targets.

    ``early_warning_enabled``: the run has an early warning part to report (the
    early-warning job); without it the report has no early warning at all.
    """
    targets_doc = load_targets_file(targets_file)
    report_dir = output_dir / "_report"
    report_dir.mkdir(parents=True, exist_ok=True)
    # The Trivy native directory always exists; other scanners' only if they are used
    (output_dir / "_native" / SCANNER_TRIVY).mkdir(parents=True, exist_ok=True)

    results = []
    trivy_configs: dict[str, dict[str, Any]] = {}
    for target in targets_doc["targets"]:
        scanner = target["scanner"]
        # Parts are namespaced by scanner: <parts-dir>/<scanner>/<id>.*
        native_dir = output_dir / "_native" / scanner
        native_dir.mkdir(parents=True, exist_ok=True)
        scanner_parts_dir = parts_dir / scanner
        state, native = load_target_result(target, scanner_parts_dir)
        if (
            native is not None
            and scanner == SCANNER_TRIVY
            and target.get("kind") == KIND_FS
        ):
            record_path = scanner_parts_dir / f"{target['id']}{TRIVY_CONFIG_SUFFIX}"
            if record_path.is_file():
                try:
                    trivy_configs[target["id"]] = load_trivy_config_record(record_path)
                except (OSError, ValueError) as e:
                    state.update(
                        status=STATUS_FAILED,
                        reason=f"unreadable trivy config record: {e}",
                    )
                    native = None
        if (
            native is not None
            and scanner == SCANNER_TRIVY
            and target.get("kind") == KIND_FS
        ):
            apply_gradle_graph(
                target["id"],
                native,
                scanner_parts_dir / f"{target['id']}{GRADLE_GRAPH_SUFFIX}",
            )
        results.append((target, state, native))
        copy_native(scanner_parts_dir, target["id"], native_dir)

    # Trivy findings create the records, OSV findings join them or add their own
    trivy_only = trivy_targets(targets_doc["targets"])
    ok_scans = [
        (t["id"], SCANNER_TRIVY, native)
        for t, _, native in results
        if native is not None and t["scanner"] == SCANNER_TRIVY
    ]
    osv_scans = resolve_osv_targets(results, {tid: n for tid, _, n in ok_scans})
    repo = targets_doc.get("repo")
    image_ids = {t["id"] for t in trivy_only if t.get("kind") == KIND_IMAGE}
    merged, sightings = merge_records(repo, ok_scans, image_ids, osv_scans)
    not_shipped = NotShipped(
        targets_doc["config"][KEY_NON_SHIPPED_PATHS], trivy_configs
    )
    records = finalize_records(merged, trivy_only, sightings, not_shipped)
    early_warning = None
    if early_warning_enabled:
        early_warning = build_early_warning(
            parts_dir / EARLY_WARNING_DIR,
            repo,
            generated_utc,
            records,
            trivy_only,
            bool(ok_scans),
            not_shipped,
        )
    scan_report = build_scan_report(
        targets_doc,
        results,
        records,
        generated_utc,
        trivy_db,
        trivy_configs,
        early_warning,
    )
    vulns = build_vulnerabilities(repo, generated_utc, records)
    if (stale := trivy_db_stale_days(trivy_db, generated_utc)) is not None:
        print(
            "::warning title=Trivy DB is stale::the vulnerability DB snapshot was "
            f"updated {(trivy_db or {})['vulnerability_db_updated_at']}, {stale} "
            "days before the report; a scan with it may miss recent advisories"
        )

    dump_json(report_dir / "vulnerabilities.json", vulns)
    dump_json(report_dir / "scan_report.json", scan_report)
    if early_warning is not None:
        dump_json(report_dir / "early_warning.json", early_warning.document)
        if early_warning.report["status"] == STATUS_FAILED:
            print(
                "::warning title=Early warning unavailable::"
                + escape_command_data(early_warning.report["reason"])
            )
    write_text(
        output_dir / "summary.md",
        build_summary_md(scan_report, vulns, sightings, early_warning),
    )

    failed = [t for t in scan_report["targets"] if t["status"] == STATUS_FAILED]
    for t in failed:
        name = f"{t['id']} ({t['scanner']})"
        print(
            "::error title=Scan target failed::"
            + escape_command_data(f"{name}: {t['reason']}")
        )
    totals = scan_report["totals"]["findings"]
    print(
        f"canonical set: {totals['total']} records ({totals['fixable']} fixable); "
        f"{len(failed)} failed target(s)"
    )
    return len(failed)


def parse_bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in ("true", "1", "yes"):
        return True
    if lowered in ("false", "0", "no", ""):
        return False
    raise argparse.ArgumentTypeError(f"expected true or false, got {value!r}")


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge per-target scan results of an SCA scheduled scan."
    )
    parser.add_argument(
        "--targets-file",
        required=True,
        type=Path,
        help="targets.json of the targets step",
    )
    parser.add_argument(
        "--parts-dir",
        required=True,
        type=Path,
        help="directory with the scan parts: <scanner>/<id>.json and <id>.status.json",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="directory to write the report to",
    )
    parser.add_argument(
        "--step-summary",
        type=parse_bool,
        default=True,
        help="append summary.md to $GITHUB_STEP_SUMMARY (true/false, default true)",
    )
    parser.add_argument(
        "--trivy-db-info",
        default="",
        help=(
            "JSON object with vulnerability_db_updated_at and java_db_updated_at "
            "of the Trivy DB snapshot used by the run (default: unknown)"
        ),
    )
    parser.add_argument(
        "--early-warning-enabled",
        type=parse_bool,
        default=False,
        help=(
            "the run has an early warning part (early-warning/ in --parts-dir) to "
            "report (true/false, default false)"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    generated_utc = format_time(datetime.now(UTC))
    try:
        failed_count = run_merge(
            args.targets_file,
            args.parts_dir,
            args.output_dir,
            generated_utc,
            parse_trivy_db_info(args.trivy_db_info),
            args.early_warning_enabled,
        )
    except InputError as e:
        print(
            f"::error title=Invalid merge input::{escape_command_data(e)}",
            file=sys.stderr,
        )
        return 1

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.step_summary and step_summary:
        summary = (args.output_dir / "summary.md").read_text(encoding="utf-8")
        server = os.environ.get("GITHUB_SERVER_URL")
        repository = os.environ.get("GITHUB_REPOSITORY")
        run_id = os.environ.get("GITHUB_RUN_ID")
        run_url = (
            f"{server}/{repository}/actions/runs/{run_id}#artifacts"
            if server and repository and run_id
            else None
        )
        append_text(step_summary, truncate_summary(summary, run_url))
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        append_text(github_output, f"failed-count={failed_count}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
