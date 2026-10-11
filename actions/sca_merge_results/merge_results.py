#!/usr/bin/env python3
"""Merge the per-target scan results of an SCA scheduled scan into one report.

Inputs:
  * targets.json written by sca_resolve_targets (the list of targets);
  * a parts directory with one subdirectory per scanner (``trivy/``) holding,
    per scanned target id, ``<id>.json`` (native JSON), ``<id>.status.json``
    and an optional ``<id>.txt`` (table).

Outputs (in the output directory):
  * ``_report/vulnerabilities.json`` - canonical deduplicated finding set,
    one record per (repo, CVE x package x installed version), listing the
    ``scan_targets`` it was found in, its ``locations`` within them and the
    ``scanners`` that reported it;
  * ``_report/scan_report.json`` - one entry per target with its status and
    the scanner that scanned it;
  * ``summary.md`` and ``summary.csv`` - the human-readable layer;
  * ``_native/<scanner>/<id>.json|txt`` - the unmodified per-target results
    (audit).

Trivy is the only scanner today; the report schema names the scanner wherever
another one could contribute (``scanners``, ``scanner``, ``_native/<scanner>/``).

A scan that broke is reported as ``failed`` and never looks like a clean
target. The script still exits 0 once the outputs are written: the workflow
decides about failing the run after the artifact has been uploaded.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shutil
import sys
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
UNRANKED = len(SEV_ORDER)
SCHEMA_VERSION = 1
MERGE_KEY = (
    "(repo, CVE x package x installed-version), merged across scan_targets and scanners"
)
TARGET_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_NOT_APPLICABLE = "not_applicable"

SCANNER_TRIVY = "trivy"

Target = dict[str, Any]
Record = dict[str, Any]
FindingKey = tuple[str | None, str | None, str | None]


class InputError(Exception):
    """The inputs are unusable, so no meaningful report can be produced."""


# --------------------------------------------------------------------------
# Reading inputs
# --------------------------------------------------------------------------


def read_json(path: Path) -> Any:
    """Read a JSON file; raises OSError/ValueError with a readable cause."""
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_targets_file(path: Path) -> dict[str, Any]:
    """Load and validate targets.json."""
    try:
        data = read_json(path)
    except (OSError, ValueError) as e:
        raise InputError(f"cannot read targets file {path}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("targets"), list):
        raise InputError(f"targets file {path} has no 'targets' list")
    seen: set[str] = set()
    for target in data["targets"]:
        tid = target.get("id") if isinstance(target, dict) else None
        if not isinstance(tid, str) or not TARGET_ID_RE.fullmatch(tid):
            raise InputError(f"targets file {path} has an invalid target id: {tid!r}")
        if tid in seen:
            raise InputError(f"targets file {path} has a duplicate target id: {tid}")
        seen.add(tid)
    return data


def load_target_result(
    target: Mapping[str, Any], scanner_parts_dir: Path
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Determine the final status of one target.

    Returns ``(state, native)``: state carries ``status``, ``reason`` and
    ``lockfiles``; native is the parsed trivy result for ``ok`` targets, else
    None. Anything short of a complete, valid result is ``failed`` - a broken
    scan must not look like a clean target.
    """
    tid = target["id"]
    state: dict[str, Any] = {
        "status": target.get("status"),
        "reason": target.get("reason"),
        "lockfiles": None,
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

    lockfiles = status.get("lockfiles")
    state["lockfiles"] = lockfiles if isinstance(lockfiles, int) else None
    if status.get("status") == STATUS_FAILED:
        return failed(status.get("reason") or "scan job reported failure")
    if status.get("status") != STATUS_OK:
        return failed(f"unexpected scan status: {status.get('status')!r}")

    native_path = scanner_parts_dir / f"{tid}.json"
    if not native_path.is_file():
        return failed("trivy result file is missing")
    try:
        native = read_json(native_path)
    except (OSError, ValueError) as e:
        return failed(f"trivy result is not valid JSON: {e}")
    if not isinstance(native, dict):
        return failed("trivy result is not a JSON object")

    state.update(status=STATUS_OK, reason=None)
    return state, native


# --------------------------------------------------------------------------
# Analysing trivy results
# --------------------------------------------------------------------------


def iter_vulnerabilities(
    native: Mapping[str, Any],
) -> Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Yield (trivy Result, vulnerability) for every finding."""
    for result in native.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            yield result, vuln


def finding_key(vuln: Mapping[str, Any]) -> FindingKey:
    return (
        vuln.get("VulnerabilityID"),
        vuln.get("PkgName"),
        vuln.get("InstalledVersion"),
    )


def count_findings(native: Mapping[str, Any]) -> dict[str, int]:
    """Raw/unique finding counts of one target (raw = one per finding x lockfile)."""
    raw = 0
    unique: set[FindingKey] = set()
    packages: set[tuple[str | None, str | None]] = set()
    for _, vuln in iter_vulnerabilities(native):
        raw += 1
        unique.add(finding_key(vuln))
        packages.add((vuln.get("PkgName"), vuln.get("InstalledVersion")))
    return {
        "findings_raw": raw,
        "findings_unique": len(unique),
        "vulnerable_package_versions": len(packages),
    }


def image_digest(native: Mapping[str, Any]) -> str | None:
    digests = (native.get("Metadata") or {}).get("RepoDigests") or []
    return digests[0] if digests else None


def package_type(result: Mapping[str, Any]) -> str:
    """'os' for OS packages (base image layer), 'library' for dependencies."""
    return "os" if result.get("Class") == "os-pkgs" else "library"


def new_record(
    repo: str | None,
    key: FindingKey,
    result: Mapping[str, Any],
    vuln: Mapping[str, Any],
) -> Record:
    cve, pkg, version = key
    fixed = vuln.get("FixedVersion") or None
    return {
        "repo": repo,
        "cve": cve,
        "pkg": pkg,
        "version": version,
        "scan_targets": [],
        "locations": [],
        "scanners": [],
        "severity": vuln.get("Severity") or "UNKNOWN",
        # fixed | affected | will_not_fix | fix_deferred ...: tells "never getting
        # a fix" from "no fix yet"
        "status": vuln.get("Status"),
        # os (base image layer) vs library (a dependency): whose fix it is -
        # a base image bump or a dependency bump
        "pkg_type": package_type(result),
        # package manager / OS family (trivy Result Type: npm, gradle, jar, alpine,
        # ...); a list because one finding can surface under several types
        "ecosystem": [],
        "title": (vuln.get("Title") or "").strip() or None,
        "fixed_version": fixed,
        "fix_available": bool(fixed),
        "cwe": vuln.get("CweIDs") or None,
        "published": vuln.get("PublishedDate") or None,
        "primary_url": vuln.get("PrimaryURL") or None,
    }


def record_sort_key(record: Record) -> tuple[Any, ...]:
    return (
        SEV_ORDER.get(record["severity"], UNRANKED),
        not record["fix_available"],
        record["repo"] or "",
        record["cve"] or "",
        record["pkg"] or "",
        record["version"] or "",
    )


def merge_records(
    repo: str | None, scans: Iterable[tuple[str, str, Mapping[str, Any]]]
) -> list[Record]:
    """Deduplicate findings across lockfiles and merge them across targets.

    ``scans`` is ``(target id, scanner, native JSON)`` in targets-file order,
    which is also the order of each record's ``scan_targets``. The first copy
    of a finding wins; a later copy only backfills a missing fixed version.
    """
    by_key: dict[FindingKey, Record] = {}
    for tid, scanner, native in scans:
        for result, vuln in iter_vulnerabilities(native):
            key = finding_key(vuln)
            record = by_key.get(key)
            if record is None:
                record = by_key[key] = new_record(repo, key, result, vuln)
            if tid not in record["scan_targets"]:
                record["scan_targets"].append(tid)
            if scanner not in record["scanners"]:
                record["scanners"].append(scanner)
            ecosystem = result.get("Type")
            if ecosystem and ecosystem not in record["ecosystem"]:
                record["ecosystem"].append(ecosystem)
            location = result.get("Target", "")
            if location not in record["locations"]:
                record["locations"].append(location)
            fixed = vuln.get("FixedVersion")
            if fixed and not record["fix_available"]:
                record["fixed_version"], record["fix_available"] = fixed, True
    for record in by_key.values():
        record["locations"].sort()
        record["scanners"].sort()
        record["ecosystem"].sort()
    return sorted(by_key.values(), key=record_sort_key)


def summarize_records(
    records: Sequence[Record], target_ids: Iterable[str]
) -> tuple[dict[str, Any], dict[str, dict[str, int]]]:
    """Return (counts, per_target) for the canonical record set."""
    counts: dict[str, Any] = {
        "records": len(records),
        "with_fix": sum(r["fix_available"] for r in records),
        "no_fix": sum(not r["fix_available"] for r in records),
    }
    by_severity: dict[str, dict[str, int]] = {}
    for r in records:
        s = by_severity.setdefault(
            r["severity"], {"total": 0, "with_fix": 0, "no_fix": 0}
        )
        s["total"] += 1
        s["with_fix" if r["fix_available"] else "no_fix"] += 1
    counts["by_severity"] = {
        k: by_severity[k]
        for k in sorted(by_severity, key=lambda k: (SEV_ORDER.get(k, UNRANKED), k))
    }

    per_target = {tid: {"records": 0, "only_in_target": 0} for tid in target_ids}
    for r in records:
        for tid in r["scan_targets"]:
            per_target[tid]["records"] += 1
            if len(r["scan_targets"]) == 1:
                per_target[tid]["only_in_target"] += 1
    return counts, per_target


# --------------------------------------------------------------------------
# Building the report
# --------------------------------------------------------------------------


def build_scan_report(
    targets_doc: Mapping[str, Any],
    results: Sequence[tuple[Target, dict[str, Any], Mapping[str, Any] | None]],
    generated_utc: str,
) -> dict[str, Any]:
    trivy_version = None
    targets: list[dict[str, Any]] = []
    for target, state, native in results:
        entry: dict[str, Any] = {
            "id": target["id"],
            "scanner": SCANNER_TRIVY,
            "kind": target.get("kind"),
            "image": target.get("image"),
            "tag": target.get("tag"),
            "ref": target.get("ref"),
            "image_digest": None,
            "status": state["status"],
            "reason": state["reason"],
            "lockfiles": state["lockfiles"],
            "findings_raw": None,
            "findings_unique": None,
            "vulnerable_package_versions": None,
        }
        if native is not None:
            entry.update(count_findings(native))
            if target.get("kind") == "image":
                entry["image_digest"] = image_digest(native)
            trivy_version = trivy_version or (native.get("Trivy") or {}).get("Version")
        targets.append(entry)
    return {
        "schema_version": SCHEMA_VERSION,
        "repo": targets_doc.get("repo"),
        "commit_sha": targets_doc.get("commit_sha"),
        "default_branch": targets_doc.get("default_branch"),
        "run_id": targets_doc.get("run_id"),
        "run_url": targets_doc.get("run_url"),
        "run_started_at": targets_doc.get("run_started_at"),
        "generated_utc": generated_utc,
        "trivy_version": trivy_version,
        "targets": targets,
    }


def md_cell(value: Any) -> str:
    """Render a value as one safe Markdown table cell."""
    if value is None or value == "":
        return "-"
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    return text.replace("\r", " ").replace("\n", " ")


def md_table(
    header: Sequence[str],
    rows: Iterable[Sequence[Any]],
    right: Sequence[int] = (),
) -> list[str]:
    align = ["---:" if i in right else "---" for i in range(len(header))]
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(align) + "|"]
    lines.extend("| " + " | ".join(md_cell(c) for c in row) + " |" for row in rows)
    return lines


def build_summary_md(report: Mapping[str, Any], vulns: Mapping[str, Any]) -> str:
    targets = report["targets"]
    counts, per_target = vulns["counts"], vulns["per_target"]

    lines = ["# SCA scan summary", ""]
    lines.append(
        f"- Repository: `{md_cell(report['repo'])}` "
        f"(default branch `{md_cell(report['default_branch'])}`)"
    )
    lines.append(f"- Commit: `{md_cell(report['commit_sha'])}`")
    run_label = f"run {report['run_id']}" if report["run_id"] else "workflow run"
    if report["run_url"]:
        lines.append(f"- Workflow run: [{run_label}]({report['run_url']})")
    else:
        lines.append(f"- Workflow run: {run_label}")
    lines.append(f"- Generated (UTC): {report['generated_utc']}")
    if report["trivy_version"]:
        lines.append(f"- Trivy: {report['trivy_version']}")
    failed = [t for t in targets if t["status"] == STATUS_FAILED]
    if failed:
        lines += [
            "",
            f"**{len(failed)} target(s) failed - their findings are NOT in this "
            "report.**",
        ]
    lines += [
        "",
        "Counts are UNIQUE findings (CVE x package x version); `raw` counts (one per",
        "finding x lockfile) stay in the native audit layer (`_native/<scanner>/`).",
        "",
        "## Targets",
        "",
    ]
    lines += md_table(
        ["Target", "Kind", "Ref", "Status", "Unique", "Raw", "Vulnerable pkgs", "Note"],
        (
            [
                t["id"],
                t["kind"],
                t["ref"] or "source",
                t["status"],
                t["findings_unique"],
                t["findings_raw"],
                t["vulnerable_package_versions"],
                t["reason"],
            ]
            for t in targets
        ),
        right=(4, 5, 6),
    )

    lines += ["", "## Per-target coverage (unique findings)", ""]
    lines += md_table(
        ["Target", "Findings", "Only in this target", "Shared with other targets"],
        (
            [tid, c["records"], c["only_in_target"], c["records"] - c["only_in_target"]]
            for tid, c in per_target.items()
        ),
        right=(1, 2, 3),
    )
    lines += [
        "",
        f"Canonical set: **{counts['records']} unique findings** - "
        f"{counts['with_fix']} with a fix available, {counts['no_fix']} without. "
        "Detail: `_report/vulnerabilities.json`.",
        "",
        "## By severity and fixability",
        "",
    ]
    lines += md_table(
        ["Severity", "Total", "With fix", "No fix"],
        (
            [sev, s["total"], s["with_fix"], s["no_fix"]]
            for sev, s in counts["by_severity"].items()
        ),
        right=(1, 2, 3),
    )
    lines += ["", "## CRITICAL and HIGH findings (all)", ""]
    lines += md_table(
        [
            "Sev",
            "CVE",
            "Package",
            "Version",
            "Fix available",
            "Fixed in",
            "Type",
            "Targets",
        ],
        (
            [
                r["severity"],
                r["cve"],
                r["pkg"],
                r["version"],
                "yes" if r["fix_available"] else "NO",
                r["fixed_version"] if r["fix_available"] else None,
                r["pkg_type"],
                " + ".join(r["scan_targets"]),
            ]
            for r in vulns["records"]
            if r["severity"] in ("CRITICAL", "HIGH")
        ),
    )
    return "\n".join(lines) + "\n"


def build_summary_csv(report: Mapping[str, Any]) -> str:
    count_fields = (
        "findings_unique",
        "findings_raw",
        "vulnerable_package_versions",
    )
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["target_id", "kind", "ref", "status", *count_fields])
    for t in report["targets"]:
        counts = ["" if t[k] is None else t[k] for k in count_fields]
        writer.writerow([t["id"], t["kind"], t["ref"] or "", t["status"], *counts])
    return buf.getvalue()


# --------------------------------------------------------------------------
# Orchestration and CLI
# --------------------------------------------------------------------------


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def dump_json(path: Path, data: Any) -> None:
    write_text(path, json.dumps(data, indent=1, ensure_ascii=False) + "\n")


def copy_native(scanner_parts_dir: Path, target_id: str, native_dir: Path) -> None:
    """Keep the unmodified per-target results of one scanner for audit."""
    for suffix in (".json", ".txt"):
        src = scanner_parts_dir / f"{target_id}{suffix}"
        if src.is_file():
            shutil.copyfile(src, native_dir / src.name)


def run_merge(
    targets_file: Path, parts_dir: Path, output_dir: Path, generated_utc: str
) -> int:
    """Write all outputs; return the number of failed targets."""
    targets_doc = load_targets_file(targets_file)
    report_dir = output_dir / "_report"
    native_dir = output_dir / "_native" / SCANNER_TRIVY
    # Parts are namespaced by scanner: <parts-dir>/<scanner>/<id>.*
    scanner_parts_dir = parts_dir / SCANNER_TRIVY
    report_dir.mkdir(parents=True, exist_ok=True)
    native_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for target in targets_doc["targets"]:
        state, native = load_target_result(target, scanner_parts_dir)
        results.append((target, state, native))
        copy_native(scanner_parts_dir, target["id"], native_dir)

    scan_report = build_scan_report(targets_doc, results, generated_utc)
    ok_scans = [
        (t["id"], SCANNER_TRIVY, native)
        for t, _, native in results
        if native is not None
    ]
    records = merge_records(targets_doc.get("repo"), ok_scans)
    counts, per_target = summarize_records(records, (tid for tid, _, _ in ok_scans))
    vulns = {
        "schema_version": SCHEMA_VERSION,
        "merge_key": MERGE_KEY,
        "counts": counts,
        "per_target": per_target,
        "records": records,
    }

    dump_json(report_dir / "vulnerabilities.json", vulns)
    dump_json(report_dir / "scan_report.json", scan_report)
    write_text(output_dir / "summary.md", build_summary_md(scan_report, vulns))
    write_text(output_dir / "summary.csv", build_summary_csv(scan_report))

    failed = [t for t in scan_report["targets"] if t["status"] == STATUS_FAILED]
    for t in failed:
        print(f"::error title=Scan target failed::{t['id']}: {t['reason']}")
    print(
        f"canonical set: {counts['records']} records ({counts['with_fix']} with fix, "
        f"{counts['no_fix']} no fix); {len(failed)} failed target(s)"
    )
    return len(failed)


def append_text(path: str, text: str) -> None:
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(text)


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
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    generated_utc = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        failed_count = run_merge(
            args.targets_file, args.parts_dir, args.output_dir, generated_utc
        )
    except InputError as e:
        print(f"::error title=Invalid merge input::{e}", file=sys.stderr)
        return 1

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.step_summary and step_summary:
        summary = (args.output_dir / "summary.md").read_text(encoding="utf-8")
        append_text(step_summary, summary)
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        append_text(
            github_output,
            f"failed-count={failed_count}\nreport-dir={args.output_dir}\n",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
