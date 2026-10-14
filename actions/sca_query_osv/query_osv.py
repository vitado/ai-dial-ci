#!/usr/bin/env python3
"""Check the language packages found by Trivy against OSV with osv-scanner.

Used by the SCA scheduled scan. Every pending OSV target is the twin of a scanned
Trivy target (same id). The native Trivy JSON of the target is converted to a
CycloneDX BOM (``trivy convert``); OS packages (Trivy has its own feeds for them) and
components without a package URL or a version (a local workspace package, which OSV
cannot be asked about) are removed; ``osv-scanner scan source -L <id>.cdx.json
--all-packages`` matches the rest with OSV (online, api.osv.dev).

Reads targets.json and ``trivy/<id>.status.json`` of the parts directory. Writes, per
OSV target, ``osv/<id>.status.json`` (``{status, reason, queried_at,
scanner_version}``) and, if ``ok``, ``osv/<id>.json``, the osv-scanner output as is.

osv-scanner exits 0 (nothing found) or 1 (vulnerabilities found); any other exit code
is a failure, so a broken run never looks like a clean one. A target whose Trivy
target was not scanned is ``not_applicable``. The merge fails an output that is not a
valid result. The script exits 0: the workflow decides about failing the run.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from _sca_lib import dump_json, format_time, read_json

# Components Trivy covers with its distribution feeds
OS_PURL_TYPES = frozenset({"deb", "apk", "rpm"})
# osv-scanner: 0 nothing found, 1 vulnerabilities found
EXIT_CODES_OK = (0, 1)
REASON_LIMIT = 400

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


def run_command(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run a command; a program that cannot start is exit code 127 (as in a shell)."""
    try:
        return subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
    except OSError as err:
        return subprocess.CompletedProcess(command, 127, "", str(err))


def tail(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= REASON_LIMIT else "..." + text[-REASON_LIMIT:]


def filter_bom(bom: dict[str, Any]) -> dict[str, Any]:
    """The BOM of the language packages with a version, for osv-scanner.

    Only the components stay: osv-scanner has no use for the dependency graph and the
    Trivy findings. Trivy keeps the namespace of a package in ``group`` (a Maven
    group, an npm scope), but osv-scanner names the package it reports after ``name``
    alone, so the group is folded into the name as OSV writes it
    (``group:artifact``, ``@scope/name``).
    """
    kept = []
    for component in bom.get("components") or []:
        purl = component.get("purl") or ""
        ecosystem = purl.removeprefix("pkg:").split("/", 1)[0].lower()
        if (
            not purl.startswith("pkg:")
            or ecosystem in OS_PURL_TYPES
            or not component.get("version")
            or "@" not in re.split(r"[?#]", purl)[0]
        ):
            continue
        if group := component.get("group"):
            separator = ":" if ecosystem == "maven" else "/"
            component = {
                **{k: v for k, v in component.items() if k != "group"},
                "name": f"{group}{separator}{component.get('name')}",
            }
        kept.append(component)
    return {**bom, "components": kept, "dependencies": [], "vulnerabilities": []}


def scan_target(
    native: Path, bom_path: Path, output: Path, run: Runner
) -> tuple[str, str | None]:
    """Convert, filter and scan one target: ``(status, reason)``; the osv-scanner
    output is written to ``output``.
    """
    convert = ["trivy", "convert", "--format", "cyclonedx", "--output", str(bom_path)]
    converted = run([*convert, str(native)])
    if converted.returncode:
        code = converted.returncode
        return "failed", f"trivy convert failed (exit {code}): {tail(converted.stderr)}"
    try:
        bom = filter_bom(read_json(bom_path))
    except (OSError, ValueError, AttributeError) as err:
        return "failed", f"trivy convert wrote no valid BOM: {err}"
    dump_json(bom_path, bom)
    if bom["components"]:
        scan = ["scan", "source", "-L", str(bom_path), "--all-packages"]
        scan += ["--format", "json", "--output-file", str(output)]
        scanned = run(["osv-scanner", *scan])
        if scanned.returncode not in EXIT_CODES_OK:
            code = scanned.returncode
            return "failed", f"osv-scanner failed (exit {code}): {tail(scanned.stderr)}"
    else:
        dump_json(output, {"results": []})
    return "ok", None


def trivy_status(trivy_dir: Path, target_id: str) -> str:
    try:
        return str(read_json(trivy_dir / f"{target_id}.status.json")["status"])
    except (OSError, ValueError, KeyError, TypeError):
        return "failed"


def run_all(args: argparse.Namespace, run: Runner, now: datetime) -> None:
    # "osv-scanner version: 2.6.0"
    lines = run(["osv-scanner", "--version"]).stdout.strip().splitlines()
    version = lines[0].rpartition(":")[2].strip() if lines else None
    out_dir = args.output_dir / "osv"
    out_dir.mkdir(parents=True, exist_ok=True)
    trivy_dir = args.parts_dir / "trivy"
    with tempfile.TemporaryDirectory() as work:
        for target in read_json(args.targets_file)["targets"]:
            if target["scanner"] != "osv" or target["status"] != "pending":
                continue
            tid = target["id"]
            if (trivy := trivy_status(trivy_dir, tid)) != "ok":
                status, reason = "not_applicable", f"trivy target {trivy}"
            else:
                status, reason = scan_target(
                    trivy_dir / f"{tid}.json",
                    # osv-scanner takes the format of a BOM from its file name
                    Path(work) / f"{tid}.cdx.json",
                    out_dir / f"{tid}.json",
                    run,
                )
            dump_json(
                out_dir / f"{tid}.status.json",
                {
                    "status": status,
                    "reason": reason,
                    "queried_at": format_time(now),
                    "scanner_version": version or None,
                },
            )
            print(f"{tid}: {status}" + (f" ({reason})" if reason else ""))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--targets-file", required=True, type=Path)
    parser.add_argument("--parts-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args(argv)


if __name__ == "__main__":
    run_all(parse_args(), run_command, datetime.now(UTC))
