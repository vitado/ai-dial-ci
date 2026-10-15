#!/usr/bin/env python3
"""Merge the per-target scan results of an SCA scheduled scan into one report.

Inputs:
  * targets.json written by sca_resolve_targets (an OSV target is the twin of a Trivy
    target with the same id);
  * a parts directory with one subdirectory per scanner (``trivy/``, ``osv/``)
    holding, per scanned target id, ``<id>.json`` (native JSON),
    ``<id>.status.json``, an optional ``<id>.txt`` (table) and, for a Trivy Gradle
    build, ``<id>.gradle-graph/`` (the resolved dependency graph, one JSON file per
    Gradle project, written by the generate_gradle_lockfiles action).

Outputs (in the output directory):
  * ``report.json`` - the targets with their status and the flat list of findings
    (see ``normalize`` for the rows);
  * ``summary.md`` - the human-readable layer (see ``summary``), also appended to the
    job summary;
  * ``_native/<scanner>/<id>.json|txt`` - the unmodified per-target results (audit).

A scan that broke is reported as ``failed`` and never looks like a clean target. The
script still exits 0 once the outputs are written: the workflow decides about
failing the run after the artifact has been uploaded.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from _sca_lib import append_text, dump_json, escape_command_data, format_time, read_json
from normalize import (
    Findings,
    Inventory,
    apply_gradle_graph,
    borrow_source_chains,
    normalize_osv,
    normalize_trivy,
)
from summary import build_summary, truncate_summary

SCHEMA_VERSION = 2


def load_target_result(
    target: Mapping[str, Any], parts: Path
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
    """The final status of one target: ``(state, native, status file)``.

    ``native`` is the parsed native result of an ``ok`` target, else None. Anything
    short of a complete, valid result is ``failed``: a broken scan must not look like
    a clean target.
    """
    if target["status"] != "pending":  # already resolved as failed or not_applicable
        return {"status": target["status"], "reason": target["reason"]}, None, {}

    def failed(reason: str) -> tuple[dict[str, Any], None, dict[str, Any]]:
        return {"status": "failed", "reason": reason}, None, {}

    scanner, tid = target["scanner"], target["id"]
    try:
        status = read_json(parts / f"{tid}.status.json")
    except FileNotFoundError:
        return failed("scan job produced no result")
    except (OSError, ValueError) as e:
        return failed(f"unreadable status file: {e}")
    if not isinstance(status, dict):
        return failed("unreadable status file: not a JSON object")
    outcome = status.get("status")
    if outcome == "failed":
        return failed(status.get("reason") or "scan job reported failure")
    if outcome == "not_applicable":
        reason = status.get("reason") or "nothing to scan"
        return {"status": "not_applicable", "reason": reason}, None, status
    if outcome != "ok":
        return failed(f"unexpected scan status: {outcome!r}")
    try:
        native = read_json(parts / f"{tid}.json")
    except FileNotFoundError:
        return failed(f"{scanner} result file is missing")
    except (OSError, ValueError) as e:
        return failed(f"{scanner} result is not valid JSON: {e}")
    if not isinstance(native, dict):
        return failed(f"{scanner} result is not a JSON object")
    return {"status": "ok", "reason": None}, native, status


def count_packages(scanner: str, native: Mapping[str, Any]) -> int:
    """Distinct packages (ecosystem, name, version) the scanner looked at; 0 is
    suspicious.
    """
    if scanner == "osv":
        packages = [p["package"] for r in native["results"] for p in r["packages"]]
        return len({(p["ecosystem"], p["name"], p["version"]) for p in packages})
    return len(
        {
            (result.get("Type"), p.get("Name"), p.get("Version"))
            for result in native.get("Results") or []
            for p in result.get("Packages") or []
        }
    )


def run_merge(
    targets_file: Path,
    parts_dir: Path,
    output_dir: Path,
    generated_utc: str,
    trivy_db: Mapping[str, str],
) -> tuple[dict[str, Any], str]:
    """Write all outputs; return the report and the summary."""
    doc = read_json(targets_file)
    entries: list[dict[str, Any]] = []
    natives: dict[tuple[str, str], tuple[Any, dict[str, Any]]] = {}
    for target in doc["targets"]:
        scanner, tid = target["scanner"], target["id"]
        parts = parts_dir / scanner
        native_dir = output_dir / "_native" / scanner
        native_dir.mkdir(parents=True, exist_ok=True)
        for suffix in (".json", ".txt"):
            if (parts / f"{tid}{suffix}").is_file():
                shutil.copyfile(parts / f"{tid}{suffix}", native_dir / f"{tid}{suffix}")
        state, native, status = load_target_result(target, parts)
        if native is not None and scanner == "trivy" and target["kind"] == "fs":
            apply_gradle_graph(tid, native, parts / f"{tid}.gradle-graph")
        entries.append(
            {
                "id": tid,
                "scanner": scanner,
                "kind": target["kind"],
                "ref": target["git_ref"] or target["tag"],
                "commit_sha": target["commit_sha"],
                "image": target["image"],
                "image_digest": None,
                **state,
                "packages_scanned": None,
            }
        )
        if native is not None:
            natives[(scanner, tid)] = (native, status)

    findings: Findings = {}
    inventories: dict[str, Inventory] = {}
    tools: dict[str, Any] = {
        "trivy": None,
        "trivy_db": trivy_db.get("vulnerability_db_updated_at"),
        "trivy_java_db": trivy_db.get("java_db_updated_at"),
        "osv_scanner": None,
        "osv_queried_at": None,
    }
    # Trivy first: the OSV findings read the Trivy inventory of their twin target
    for entry in sorted(entries, key=lambda e: e["scanner"] == "osv"):
        scanner, tid = entry["scanner"], entry["id"]
        if (scanner, tid) not in natives:
            continue
        native, status = natives[(scanner, tid)]
        found: Findings = {}
        inventory: Inventory = {}
        try:
            if scanner == "trivy":
                normalize_trivy(tid, native, found, inventory)
            else:
                normalize_osv(tid, native, found, inventories.get(tid, {}))
            entry["packages_scanned"] = count_packages(scanner, native)
        except (KeyError, TypeError, AttributeError, IndexError) as e:
            reason = f"{scanner} result has an unexpected shape: {e!r}"
            entry.update(status="failed", reason=reason)
            continue
        findings.update(found)
        if entry["packages_scanned"] == 0:
            print(
                "::warning title=No packages in scan result::"
                + escape_command_data(f"{tid} ({scanner}): 0 packages were seen")
            )
        if scanner == "trivy":
            inventories[tid] = inventory
            tools["trivy"] = tools["trivy"] or (native.get("Trivy") or {}).get(
                "Version"
            )
            digests = (native.get("Metadata") or {}).get("RepoDigests") or []
            if digests and entry["kind"] == "image":
                entry["image_digest"] = digests[0]
        else:
            tools["osv_scanner"] = tools["osv_scanner"] or status.get("scanner_version")
            times = [tools["osv_queried_at"], status.get("queried_at")]
            tools["osv_queried_at"] = max(filter(None, times), default=None)
    source_ids = [
        e["id"] for e in entries if e["scanner"] == "trivy" and e["kind"] == "fs"
    ]
    borrow_source_chains(findings, inventories, source_ids)

    report = {
        "schema_version": SCHEMA_VERSION,
        "repo": doc["repo"],
        "commit_sha": doc["commit_sha"],
        "default_branch": doc["default_branch"],
        "run_id": doc["run_id"],
        "run_url": doc["run_url"],
        "generated_utc": generated_utc,
        "tools": tools,
        "targets": entries,
        "findings": list(findings.values()),
    }
    dump_json(output_dir / "report.json", report)
    summary = build_summary(report)
    (output_dir / "summary.md").write_text(summary, encoding="utf-8", newline="\n")
    return report, summary


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge per-target scan results of an SCA scheduled scan."
    )
    parser.add_argument("--targets-file", required=True, type=Path)
    parser.add_argument("--parts-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--trivy-db-info",
        default="",
        help="JSON object with vulnerability_db_updated_at and java_db_updated_at",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    trivy_db = json.loads(args.trivy_db_info) if args.trivy_db_info.strip() else {}
    report, summary = run_merge(
        args.targets_file,
        args.parts_dir,
        args.output_dir,
        format_time(datetime.now(UTC)),
        trivy_db,
    )
    failed = [e for e in report["targets"] if e["status"] == "failed"]
    for entry in failed:
        name = f"{entry['id']} ({entry['scanner']})"
        print(
            "::error title=Scan target failed::"
            + escape_command_data(f"{name}: {entry['reason']}")
        )
    print(f"{len(report['findings'])} findings; {len(failed)} failed target(s)")
    if step_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        append_text(step_summary, truncate_summary(summary, report["run_url"]))
    if github_output := os.environ.get("GITHUB_OUTPUT"):
        append_text(github_output, f"failed-count={len(failed)}\n")


if __name__ == "__main__":
    main()
