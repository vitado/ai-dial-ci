"""summary.md of the SCA merge: results by target, libraries, base image packages."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from normalize import SEVERITIES, norm

SEPARATOR = "&emsp;"
# GitHub rejects a step summary over 1 MiB; the rest of the limit is left for the
# parts of the job summary that are not this one
STEP_SUMMARY_LIMIT_BYTES = 1024 * 1024 - 16 * 1024

Finding = Mapping[str, Any]


def cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def short_time(value: str | None) -> str:
    return f"{value[:16]}Z" if value else "n/a"


def target_label(target: Mapping[str, Any], repo: str) -> str:
    """``src·dev``, ``img·0.43.0``, ``img·bff·dev`` (an image of another name);
    ``img·?`` for an image without a tag (its resolution failed).
    """
    ref = {"development": "dev", None: "?"}.get(target["ref"], target["ref"])
    if target["kind"] == "fs":
        return f"src·{ref}"
    image = target["image"].split("/")[-1]
    if image == repo:
        return f"img·{ref}"
    short = image.removeprefix(f"{repo}-") if image.startswith(f"{repo}-") else image
    return f"img·{short}·{ref}"


def vulnerability_keys(
    findings: Sequence[Finding], cls: str, tid: str | None = None
) -> dict[tuple[str, str, str], str]:
    """(id, package, version) -> severity of the unique vulnerabilities of a class,
    of one target or of all; Trivy's severity wins over OSV's.
    """
    keys: dict[tuple[str, str, str], str] = {}
    for f in sorted(findings, key=lambda f: f["scanner"] != "trivy"):
        if f["class"] == cls and tid in (None, f["target"]):
            keys.setdefault((f["id"], norm(f["pkg"]), f["version"]), f["severity"])
    return keys


def severity_counts(keys: Mapping[Any, str]) -> str:
    counts = [
        f"{s[0]}–{n}"
        for s in SEVERITIES
        if (n := sum(1 for sev in keys.values() if sev == s))
    ]
    return SEPARATOR.join(counts) or "—"


def package_rows(
    findings: Sequence[Finding], source_ids: set[str]
) -> list[dict[str, Any]]:
    """One row per (class, normalized package name, version) with its unique
    vulnerabilities merged over targets and scanners (Trivy's severity wins), worst
    severity first.
    """
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f["class"], norm(f["pkg"]), f["version"]), []).append(f)
    rows = []
    for (cls, _, version), fs in groups.items():
        # the name as written in a source target (lockfile), else the first seen
        pkg = next((f for f in fs if f["target"] in source_ids), fs[0])["pkg"]
        # findings of one vulnerability under different ids merge by shared aliases
        vulns: list[dict[str, Any]] = []
        for f in sorted(fs, key=lambda f: f["scanner"] != "trivy"):
            names = {f["id"], *f.get("aliases", [])}
            v = next((v for v in vulns if v["names"] & names), None)
            if v is None:
                v = {
                    "id": f["id"],
                    "names": set(),
                    "severity": f["severity"],
                    "url": f["url"],
                    "fixed": [],
                    "scanners": set(),
                }
                vulns.append(v)
            v["names"] |= names
            if f["id"].startswith("CVE-") and not v["id"].startswith("CVE-"):
                v["id"], v["url"] = f["id"], f["url"]
            v["fixed"] += [
                x.strip() for x in f["fixed_version"].split(",") if x.strip()
            ]
            v["scanners"].add(f["scanner"])
        ordered = sorted(
            vulns, key=lambda v: (SEVERITIES.index(v["severity"]), v["id"])
        )
        with_chain = next((f for f in fs if f["chain"]), None)
        in_source = [
            loc for f in fs if f["target"] in source_ids for loc in f["locations"]
        ]
        scanners = "+".join(
            s[0].upper()
            for s in ("trivy", "osv")
            if any(s in v["scanners"] for v in ordered)
        )
        rows.append(
            {
                "class": cls,
                "pkg": pkg,
                "version": version,
                "vulns": ordered,
                "severity": ordered[0]["severity"],
                "fixed": ", ".join(
                    dict.fromkeys(x for v in ordered for x in v["fixed"])
                ),
                "chain": with_chain["chain"] if with_chain else [],
                "relationship": next(
                    (f["relationship"] for f in fs if f["relationship"]), None
                ),
                "dev": all(f["dev"] for f in fs),
                "where": in_source or [loc for f in fs for loc in f["locations"]],
                "targets": {f["target"] for f in fs},
                "scanners": scanners,
            }
        )
    return sorted(
        rows, key=lambda r: (SEVERITIES.index(r["severity"]), r["pkg"], r["version"])
    )


def where_cell(locations: Sequence[str]) -> str:
    parts = list(dict.fromkeys("/".join(loc.split("/")[-2:]) for loc in locations))
    return cell(
        ", ".join(parts[:2]) + (f" +{len(parts) - 2}" if len(parts) > 2 else "")
    )


def chain_cell(row: Mapping[str, Any]) -> str:
    chain = row["chain"]
    direct = "direct" if chain or row["relationship"] == "direct" else ""
    text = " → ".join(chain) if len(chain) > 1 else direct
    return cell(" · ".join(x for x in (text, "dev" if row["dev"] else "") if x))


def vulnerabilities_cell(row: Mapping[str, Any]) -> str:
    mixed = len({v["severity"] for v in row["vulns"]}) > 1
    return ", ".join(
        (v["severity"][0] + " " if mixed else "")
        + (f"[{cell(v['id'])}]({v['url']})" if v["url"] else cell(v["id"]))
        for v in row["vulns"]
    )


def package_table(
    rows: Sequence[Mapping[str, Any]],
    columns: Sequence[tuple[str, str]],
    libraries: bool,
) -> list[str]:
    head = ["Package@version", "Vulnerabilities", "Fixed"]
    head += ["Chain", "Where"] if libraries else []
    head += ["Targets", "Scanner"]
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    for r in rows:
        cells = [
            cell(f"{r['pkg']}@{r['version']}"),
            vulnerabilities_cell(r),
            cell(r["fixed"]),
        ]
        if libraries:
            cells += [chain_cell(r), where_cell(r["where"])]
        cells += [
            ", ".join(label for label, tid in columns if tid in r["targets"]),
            r["scanners"],
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def totals(rows: Sequence[Mapping[str, Any]]) -> str:
    vulns = [v for r in rows for v in r["vulns"]]
    fixable = sum(1 for v in vulns if v["fixed"])
    return f"{len(rows)} packages, {len(vulns)} vulnerabilities, {fixable} fixable"


def scan_status(trivy: Mapping[str, Any], osv: Mapping[str, Any] | None) -> str:
    text = trivy["status"] + (f" ({trivy['reason']})" if trivy["reason"] else "")
    if trivy["status"] == "ok" and osv and osv["status"] != "ok":
        detail = (
            f"failed: {osv['reason']}" if osv["status"] == "failed" else osv["status"]
        )
        text += f" · OSV {detail}"
    return text


def header(report: Mapping[str, Any]) -> list[str]:
    tools = report["tools"]
    parts = [
        f"commit `{(report['commit_sha'] or '')[:7]}`",
        f"default branch `{report['default_branch']}`",
        f"Trivy {tools['trivy']} (DB {short_time(tools['trivy_db'])}, "
        f"Java DB {short_time(tools['trivy_java_db'])})",
        f"osv-scanner {tools['osv_scanner']} (queried {tools['osv_queried_at'] or 'n/a'})",
    ]
    if report["run_url"]:
        parts.append(f"[run {report['run_id']}]({report['run_url']})")
    return [f"# SCA · {report['repo']}", "", " · ".join(parts), ""]


def results_by_target(report: Mapping[str, Any]) -> list[str]:
    findings = report["findings"]
    by_id: dict[str, list[Mapping[str, Any]]] = {}
    for t in report["targets"]:
        by_id.setdefault(t["id"], []).append(t)
    lines = [
        "## Results by target",
        "",
        "| Target | Type | Version | Scan | Packages scanned | "
        "Vulnerabilities in libraries | Vulnerabilities in OS packages |",
        "|---|---|---|---|---:|---|---|",
    ]
    for tid, ts in by_id.items():
        trivy = next((t for t in ts if t["scanner"] == "trivy"), ts[0])
        osv = next((t for t in ts if t["scanner"] == "osv"), None)
        ref = trivy["ref"] or "—"
        if trivy["kind"] == "fs" and trivy["commit_sha"]:
            ref = f"{ref}@{trivy['commit_sha'][:7]}"
        packages = (
            "–" if trivy["packages_scanned"] is None else trivy["packages_scanned"]
        )
        ok = trivy["status"] == "ok"
        lang, os_ = (
            severity_counts(vulnerability_keys(findings, c, tid)) if ok else ""
            for c in ("lang", "os")
        )
        kind = "source" if trivy["kind"] == "fs" else "image"
        lines.append(
            f"| {cell(tid)} | {kind} | {cell(ref)} | {cell(scan_status(trivy, osv))} | "
            f"{packages} | {lang} | {os_} |"
        )
    lang, os_ = (
        severity_counts(vulnerability_keys(findings, c)) for c in ("lang", "os")
    )
    lines.append(f"| **All targets** | | | | | {lang} | {os_} |")
    legend = SEPARATOR.join(f"{s[0]} {s.lower()}" for s in SEVERITIES)
    return [*lines, "", f"{legend} — unique vulnerabilities (id + package + version)"]


def build_summary(report: Mapping[str, Any]) -> str:
    short = report["repo"].split("/")[-1]
    columns, seen = [], set()
    for t in report["targets"]:
        if t["id"] not in seen:
            seen.add(t["id"])
            columns.append((target_label(t, short), t["id"]))
    source_ids = {t["id"] for t in report["targets"] if t["kind"] == "fs"}
    rows = package_rows(report["findings"], source_ids)
    libraries = [r for r in rows if r["class"] == "lang"]
    lines = header(report) + results_by_target(report)
    lines += ["", f"## Libraries — {totals(libraries)}", ""]
    for severity in SEVERITIES:
        if part := [r for r in libraries if r["severity"] == severity]:
            opened = " open" if severity == "CRITICAL" else ""
            lines += [
                f"<details{opened}><summary><b>{severity} — {totals(part)}</b></summary>",
                "",
            ]
            lines += [*package_table(part, columns, True), "", "</details>", ""]
    if os_rows := [r for r in rows if r["class"] == "os"]:
        lines += [f"## Base image (OS packages) — {totals(os_rows)}", ""]
        lines += ["<details><summary>Show packages</summary>", ""]
        lines += [*package_table(os_rows, columns, False), "", "</details>", ""]
    lines += [
        "---",
        "Artifact `sca-report`: `report.json` plus native reports in "
        "`_native/trivy/` and `_native/osv/`.",
    ]
    return "\n".join(lines) + "\n"


def truncate_summary(text: str, run_url: str | None) -> str:
    """The summary as the job summary can take it: whole if it fits, else cut at a
    line, with the ``<details>`` the cut leaves open closed and a note on where the
    whole of it is.
    """
    data = text.encode("utf-8")
    if len(data) <= STEP_SUMMARY_LIMIT_BYTES:
        return text
    where = "the `sca-report` artifact of this run"
    if run_url:
        where = f"the `sca-report` artifact of [this run]({run_url})"
    note = (
        f"\n> The summary is cut: it is {len(data)} bytes and a job summary takes "
        f"1 MiB. The whole `summary.md` is in {where}.\n"
    )
    close = "</details>\n"
    room = STEP_SUMMARY_LIMIT_BYTES - len(note.encode("utf-8"))
    while True:
        kept = data[:room].decode("utf-8", errors="ignore")
        kept = kept[: kept.rfind("\n") + 1]
        closing = close * max(kept.count("<details") - kept.count("</details>"), 0)
        if len((kept + closing + note).encode("utf-8")) <= STEP_SUMMARY_LIMIT_BYTES:
            return kept + closing + note
        room -= len(close)
