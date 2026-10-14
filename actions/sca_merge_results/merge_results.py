#!/usr/bin/env python3
"""Merge the per-target scan results of an SCA scheduled scan into one report.

Inputs:
  * targets.json written by sca_resolve_targets (the list of targets; an OSV target
    is the twin of a Trivy target with the same id);
  * a parts directory with one subdirectory per scanner (``trivy/``, ``osv/``)
    holding, per scanned target id, ``<id>.json`` (native JSON),
    ``<id>.status.json``, an optional ``<id>.txt`` (table) and, for a Trivy Gradle
    build, ``<id>.gradle-graph/`` (the resolved dependency graph, one JSON file per
    Gradle project, written by the generate_gradle_lockfiles action).

Outputs (in the output directory):
  * ``report.json`` - the targets with their status and the flat list of findings
    (see ``normalize`` for the rows);
  * ``summary.md`` - the human-readable layer (see ``summary``);
  * ``_native/<scanner>/<id>.json|txt`` - the unmodified per-target results (audit).

A scan that broke is reported as ``failed`` and never looks like a clean target. The
script still exits 0 once the outputs are written: the workflow decides about
failing the run after the artifact has been uploaded.
"""

from __future__ import annotations

import argparse
import json
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
from normalize import (
    Findings,
    Inventory,
    apply_gradle_graph,
    borrow_source_chains,
    normalize_osv,
    normalize_trivy,
    osv_packages,
)
from summary import build_summary, truncate_summary

RUN_KINDS = ("full", "partial")
SCANNERS = ("trivy", "osv")
STATUS_OK, STATUS_FAILED, STATUS_NOT_APPLICABLE = "ok", "failed", "not_applicable"
TARGET_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SCHEMA_VERSION = 2
DB_KEYS = ("vulnerability_db_updated_at", "java_db_updated_at")


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
        if target.get("scanner") not in SCANNERS:
            raise InputError(f"targets file {path}: invalid scanner of {tid}")
        if (target["scanner"], tid) in seen:
            raise InputError(f"targets file {path}: duplicate target {tid}")
        seen.add((target["scanner"], tid))
    if data.get("run_kind") not in RUN_KINDS:
        raise InputError(f"targets file {path} has an invalid run_kind")
    reasons = data.get("run_kind_reasons")
    if not isinstance(reasons, list) or not all(isinstance(r, str) for r in reasons):
        raise InputError(f"targets file {path} has invalid run_kind_reasons")
    return data


def load_target_result(
    target: Mapping[str, Any], parts: Path
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
    """The final status of one target: ``(state, native, status file)``.

    ``native`` is the parsed native result of an ``ok`` target, else None. Anything
    short of a complete, valid result is ``failed``: a broken scan must not look like
    a clean target.
    """
    state = {"status": target.get("status"), "reason": target.get("reason")}
    if state["status"] in (STATUS_FAILED, STATUS_NOT_APPLICABLE):
        return state, None, {}

    def failed(reason: str) -> tuple[dict[str, Any], None, dict[str, Any]]:
        return {"status": STATUS_FAILED, "reason": reason}, None, {}

    scanner, tid = target["scanner"], target["id"]
    status_path = parts / f"{tid}.status.json"
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
        reason = status.get("reason") or "nothing to scan"
        return {"status": STATUS_NOT_APPLICABLE, "reason": reason}, None, status
    if status.get("status") != STATUS_OK:
        return failed(f"unexpected scan status: {status.get('status')!r}")
    native_path = parts / f"{tid}.json"
    if not native_path.is_file():
        return failed(f"{scanner} result file is missing")
    try:
        native = read_json(native_path)
    except (OSError, ValueError) as e:
        return failed(f"{scanner} result is not valid JSON: {e}")
    if not isinstance(native, dict):
        return failed(f"{scanner} result is not a JSON object")
    return {"status": STATUS_OK, "reason": None}, native, status


def count_packages(scanner: str, native: Mapping[str, Any]) -> int:
    """Distinct packages (name and version) the scanner looked at; 0 is suspicious."""
    if scanner == "osv":
        packages = osv_packages(native)
        return len({(p["package"]["name"], p["package"]["version"]) for p in packages})
    return len(
        {
            (p.get("Name"), p.get("Version"))
            for result in native.get("Results") or []
            for p in result.get("Packages") or []
        }
    )


def parse_trivy_db_info(raw: str) -> dict[str, str | None]:
    """The ``--trivy-db-info`` JSON; empty or malformed means unknown (it only
    decorates the report, so it must not break the merge).
    """
    info: dict[str, str | None] = dict.fromkeys(DB_KEYS)
    try:
        parsed = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as e:
        print("::warning title=Trivy DB info ignored::" + escape_command_data(e))
        return info
    if isinstance(parsed, dict):
        for key in DB_KEYS:
            value = parsed.get(key)
            info[key] = value if isinstance(value, str) and value else None
    return info


def target_entry(target: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": target["id"],
        "scanner": target["scanner"],
        "kind": target.get("kind"),
        "ref": target.get("git_ref") or target.get("tag") or target.get("ref"),
        "commit_sha": target.get("commit_sha"),
        "image": target.get("image"),
        "image_digest": None,
        **state,
        "packages_scanned": None,
    }


def run_merge(
    targets_file: Path,
    parts_dir: Path,
    output_dir: Path,
    generated_utc: str,
    trivy_db: Mapping[str, str | None],
) -> int:
    """Write all outputs; return the number of failed targets."""
    doc = load_targets_file(targets_file)
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
        if native is not None and scanner == "trivy" and target.get("kind") == "fs":
            apply_gradle_graph(tid, native, parts / f"{tid}.gradle-graph")
        entries.append(target_entry(target, state))
        if native is not None:
            natives[(scanner, tid)] = (native, status)

    findings: Findings = {}
    inventories: dict[str, Inventory] = {}
    tools: dict[str, Any] = {
        "trivy": None,
        "trivy_db": trivy_db[DB_KEYS[0]],
        "trivy_java_db": trivy_db[DB_KEYS[1]],
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
            entry.update(status=STATUS_FAILED, reason=reason)
            continue
        findings.update(found)
        if scanner == "trivy":
            inventories[tid] = inventory
        if entry["packages_scanned"] == 0:
            print(
                "::warning title=No packages in scan result::"
                + escape_command_data(f"{tid} ({scanner}): 0 packages were seen")
            )
        if scanner == "trivy":
            tools["trivy"] = tools["trivy"] or (native.get("Trivy") or {}).get(
                "Version"
            )
            digests = (native.get("Metadata") or {}).get("RepoDigests") or []
            entry["image_digest"] = (
                digests[0] if digests and entry["kind"] == "image" else None
            )
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
        "repo": doc.get("repo"),
        "commit_sha": doc.get("commit_sha"),
        "default_branch": doc.get("default_branch"),
        "run_id": doc.get("run_id"),
        "run_url": doc.get("run_url"),
        "generated_utc": generated_utc,
        "run_kind": doc["run_kind"],
        "run_kind_reasons": doc["run_kind_reasons"],
        "tools": tools,
        "targets": entries,
        "findings": list(findings.values()),
    }
    dump_json(output_dir / "report.json", report)
    summary = build_summary(report)
    (output_dir / "summary.md").write_text(summary, encoding="utf-8", newline="\n")

    failed = [e for e in entries if e["status"] == STATUS_FAILED]
    for entry in failed:
        name = f"{entry['id']} ({entry['scanner']})"
        print(
            "::error title=Scan target failed::"
            + escape_command_data(f"{name}: {entry['reason']}")
        )
    print(f"{len(findings)} findings; {len(failed)} failed target(s)")
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
    parser.add_argument("--targets-file", required=True, type=Path)
    parser.add_argument(
        "--parts-dir",
        required=True,
        type=Path,
        help="directory with the scan parts: <scanner>/<id>.json and <id>.status.json",
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--step-summary",
        type=parse_bool,
        default=True,
        help="append summary.md to $GITHUB_STEP_SUMMARY (true/false, default true)",
    )
    parser.add_argument(
        "--trivy-db-info",
        default="",
        help="JSON object with vulnerability_db_updated_at and java_db_updated_at",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        failed_count = run_merge(
            args.targets_file,
            args.parts_dir,
            args.output_dir,
            format_time(datetime.now(UTC)),
            parse_trivy_db_info(args.trivy_db_info),
        )
    except InputError as e:
        message = escape_command_data(e)
        print(f"::error title=Invalid merge input::{message}", file=sys.stderr)
        return 1
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.step_summary and step_summary:
        report = read_json(args.output_dir / "report.json")
        summary = (args.output_dir / "summary.md").read_text(encoding="utf-8")
        append_text(step_summary, truncate_summary(summary, report.get("run_url")))
    if github_output := os.environ.get("GITHUB_OUTPUT"):
        append_text(github_output, f"failed-count={failed_count}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
