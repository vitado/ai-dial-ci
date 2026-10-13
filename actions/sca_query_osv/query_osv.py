#!/usr/bin/env python3
"""Check the language packages found by Trivy against OSV with osv-scanner.

Used by the SCA scheduled scan. Every Trivy target that was scanned successfully
gets an OSV twin target (same id, scanner ``osv``). The native Trivy JSON of the
target is converted to a CycloneDX BOM (``trivy convert``), the components that
Trivy covers with its own distribution feeds (OS packages: ``pkg:deb``,
``pkg:apk``, ``pkg:rpm``) and the ones without a package URL are removed, and
``osv-scanner scan source -L <id>.cdx.json --all-packages`` matches the rest
with OSV (online, api.osv.dev).

Inputs:
  * targets.json written by sca_resolve_targets (the OSV targets to process);
  * a parts directory with the ``trivy/`` parts: ``<id>.json`` (native JSON) and
    ``<id>.status.json`` of every Trivy target.

Outputs (in the output directory, ``osv/``), per OSV target id:
  * ``<id>.status.json`` - ``{id, status, reason, packages_queried,
    packages_skipped, queried_at, scanner_version}``; status is ``ok``,
    ``failed`` or ``not_applicable``; ``packages_queried`` counts the packages in
    the osv-scanner output (``--all-packages``, so the clean ones too),
    ``packages_skipped`` the language packages without a package URL;
  * ``<id>.json`` (``ok`` only) - the osv-scanner JSON output, unmodified.

osv-scanner exits 0 (nothing found) or 1 (vulnerabilities found); any other exit
code, or an output that is not a result, is a failure, so a broken run never
looks like a clean one: the target is ``failed`` with a reason (the end of
stderr). A target whose Trivy target was not scanned successfully is
``not_applicable`` and is not queried. The script exits 0 once the outputs are
written (the merge step reports and the workflow decides about failing the run).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCANNER_TRIVY = "trivy"
SCANNER_OSV = "osv"

STATUS_PENDING = "pending"
STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_NOT_APPLICABLE = "not_applicable"

# Components Trivy covers with its distribution feeds
OS_PURL_TYPES = frozenset({"deb", "apk", "rpm"})
# osv-scanner: 0 nothing found, 1 vulnerabilities found
EXIT_CODES_OK = (0, 1)
EXIT_NOT_FOUND = 127
REASON_LIMIT = 400

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


class InputError(Exception):
    """The inputs are unusable, so no meaningful result can be produced."""


def run_command(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run a command; a program that cannot start is exit code 127 (as in a shell)."""
    try:
        return subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
    except OSError as err:
        return subprocess.CompletedProcess(command, EXIT_NOT_FOUND, "", str(err))


def tail(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= REASON_LIMIT else "..." + text[-REASON_LIMIT:]


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def load_targets_file(path: Path) -> list[dict[str, Any]]:
    try:
        data = read_json(path)
    except (OSError, ValueError) as err:
        raise InputError(f"cannot read targets file {path}: {err}") from err
    targets = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(targets, list) or not all(isinstance(t, dict) for t in targets):
        raise InputError(f"targets file {path} has no 'targets' list")
    return targets


def trivy_status(trivy_dir: Path, target_id: str) -> str:
    """The status of a Trivy target; anything short of a complete result is failed."""
    try:
        status = read_json(trivy_dir / f"{target_id}.status.json")
    except (OSError, ValueError):
        return STATUS_FAILED
    if not isinstance(status, dict):
        return STATUS_FAILED
    if (
        status.get("status") == STATUS_OK
        and not (trivy_dir / f"{target_id}.json").is_file()
    ):
        return STATUS_FAILED
    return str(status.get("status") or STATUS_FAILED)


def purl_type(purl: str) -> str:
    return purl.removeprefix("pkg:").split("/", 1)[0].lower()


def with_full_name(component: dict[str, Any], kind: str) -> dict[str, Any]:
    group = component.get("group")
    if not group:
        return component
    separator = ":" if kind == "maven" else "/"
    full = {**component, "name": f"{group}{separator}{component.get('name')}"}
    del full["group"]
    return full


def filter_bom(bom: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """``(BOM of the language packages, library components without a purl)``.

    Only the components stay: osv-scanner has no use for the dependency graph and
    the Trivy findings of the BOM. Trivy keeps the namespace of a package in
    ``group`` (a Maven group, an npm scope), but osv-scanner names the package it
    reports after ``name`` alone, so the group is folded into the name as OSV
    writes it (``group:artifact``, ``@scope/name``), or the result could not be
    told from another package of the same name.
    """
    kept: list[dict[str, Any]] = []
    skipped = 0
    for component in bom.get("components") or []:
        purl = component.get("purl")
        if isinstance(purl, str) and purl.startswith("pkg:"):
            if purl_type(purl) not in OS_PURL_TYPES:
                kept.append(with_full_name(component, purl_type(purl)))
        elif component.get("type") == "library":
            skipped += 1
    return {
        **bom,
        "components": kept,
        "dependencies": [],
        "vulnerabilities": [],
    }, skipped


@dataclass
class Outcome:
    status: str
    reason: str | None = None
    packages_queried: int | None = None
    packages_skipped: int | None = None


def scan_target(
    native: Path, bom_path: Path, output: Path, trivy: str, scanner: str, run: Runner
) -> Outcome:
    """Convert, filter and scan one target; the osv-scanner output is ``output``."""
    convert = [trivy, "convert", "--format", "cyclonedx", "--output", str(bom_path)]
    converted = run([*convert, str(native)])
    if converted.returncode:
        code = converted.returncode
        reason = f"trivy convert failed (exit {code}): {tail(converted.stderr)}"
        return Outcome(STATUS_FAILED, reason)
    try:
        bom, skipped = filter_bom(read_json(bom_path))
    except (OSError, ValueError, AttributeError) as err:
        return Outcome(STATUS_FAILED, f"trivy convert wrote no valid BOM: {err}")
    write_json(bom_path, bom)
    queried = len(bom["components"])
    output.unlink(missing_ok=True)  # no stale result can pass for this run's
    if queried:
        scan = ["scan", "source", "-L", str(bom_path), "--all-packages"]
        scan += ["--format", "json", "--output-file", str(output)]
        scanned = run([scanner, *scan])
        if scanned.returncode not in EXIT_CODES_OK:
            code = scanned.returncode
            reason = f"osv-scanner failed (exit {code}): {tail(scanned.stderr)}"
            return Outcome(STATUS_FAILED, reason, queried, skipped)
    else:
        write_json(output, {"results": []})
    try:
        packages = {
            (p["package"]["ecosystem"], p["package"]["name"], p["package"]["version"])
            for result in read_json(output)["results"]
            for p in result["packages"]
        }
    except (OSError, ValueError, KeyError, TypeError) as err:
        reason = f"osv-scanner wrote no valid result: {err!r}"
        return Outcome(STATUS_FAILED, reason, queried, skipped)
    return Outcome(STATUS_OK, None, len(packages), skipped)


def run_all(args: argparse.Namespace, run: Runner, now: datetime) -> int:
    """Write all outputs; return the number of failed OSV targets."""
    queried_at = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    # "osv-scanner version: 2.6.0"
    first = (run([args.osv_scanner, "--version"]).stdout.strip().splitlines() or [""])[
        0
    ]
    version = first.rpartition(":")[2].strip() or None
    out_dir = args.output_dir / SCANNER_OSV
    out_dir.mkdir(parents=True, exist_ok=True)
    failed = 0
    with tempfile.TemporaryDirectory() as work:
        for target in load_targets_file(args.targets_file):
            if target.get("scanner") != SCANNER_OSV:
                continue
            if target.get("status") != STATUS_PENDING:
                continue
            tid = target["id"]
            output = out_dir / f"{tid}.json"
            status = trivy_status(args.parts_dir / SCANNER_TRIVY, tid)
            if status != STATUS_OK:
                outcome = Outcome(STATUS_NOT_APPLICABLE, f"trivy target {status}")
            else:
                native = args.parts_dir / SCANNER_TRIVY / f"{tid}.json"
                # osv-scanner takes a CycloneDX file by its name
                bom_path = Path(work) / f"{tid}.cdx.json"
                outcome = scan_target(
                    native, bom_path, output, args.trivy, args.osv_scanner, run
                )
            if outcome.status != STATUS_OK:
                output.unlink(missing_ok=True)
            applicable = outcome.status != STATUS_NOT_APPLICABLE
            write_json(
                out_dir / f"{tid}.status.json",
                {
                    "id": tid,
                    "status": outcome.status,
                    "reason": outcome.reason,
                    "packages_queried": outcome.packages_queried,
                    "packages_skipped": outcome.packages_skipped,
                    "queried_at": queried_at if applicable else None,
                    "scanner_version": version if applicable else None,
                },
            )
            failed += outcome.status == STATUS_FAILED
            reason = f" ({outcome.reason})" if outcome.reason else ""
            print(f"{tid}: {outcome.status}{reason}")
            if outcome.packages_skipped:
                print(
                    f"::notice title=OSV skipped packages::{tid}: "
                    f"{outcome.packages_skipped} package(s) without a package URL"
                )
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
        "--trivy", default="trivy", help="trivy binary (default: %(default)s)"
    )
    parser.add_argument(
        "--osv-scanner",
        default="osv-scanner",
        help="osv-scanner binary (default: %(default)s)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        run_all(args, run_command, datetime.now(UTC))
    except InputError as err:
        print(f"::error title=Invalid OSV query input::{err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
