"""The ``summary.md`` of the SCA merge: facts, tables, early warning, footer.

The whole Markdown rendering lives here (also the cut of the text to the limit of
the GitHub step summary). It depends on the record model and the report; they do
not depend on it.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from functools import cmp_to_key
from typing import Any

from _sca_lib.versions import compare_tokens
from early_warning_merge import (
    ADP_SOURCE_PREFIX,
    CVE_RECORD_URL,
    EARLY_WARNING_COLLAPSE_ABOVE,
    EARLY_WARNING_GAPS_LISTED,
    HEADLINE_SEVERITIES,
    EarlyWarning,
    early_warning_groups,
)
from osv_source import OSV_FOOTER
from records import (
    CLASS_DEVELOPMENT,
    CLASS_SOURCE,
    DEVELOPMENT_TAG,
    EXPOSURE_DEVELOPMENT_ONLY,
    EXPOSURE_ORDER,
    EXPOSURE_RELEASE_AND_DEVELOPMENT,
    EXPOSURE_RELEASE_ONLY,
    EXPOSURE_SOURCE_ONLY,
    EXPOSURES,
    KEY_NON_SHIPPED_PATHS,
    KEY_TRIVY_SKIP_PATHS,
    KIND_FS,
    KIND_IMAGE,
    SCANNER_OSV,
    SCANNER_TRIVY,
    SEV_ORDER,
    SEVERITIES,
    SKIP_AS_NON_SHIPPED,
    STATUS_FAILED,
    STATUS_OK,
    UNKNOWN_SEVERITY,
    NotShipped,
    Record,
    Sightings,
    append_unique,
    default_config,
    record_identity,
    release_class,
    target_class,
    target_name,
)
from report import count_by_severity, trivy_db_stale_days
from trivy_source import ECOSYSTEM_FAMILIES

SHORT_SHA_LENGTH = 7
DIGEST_SHORT_LENGTH = 12


# GitHub rejects a step summary over 1 MiB; the rest of the limit is left for the
# parts of the summary that are not this one
STEP_SUMMARY_LIMIT_BYTES = 1024 * 1024 - 16 * 1024


SKIP_APPLY = "apply"
SKIP_IGNORE = "ignore"


# A finding that is certainly not in production, and why: marked the same way in
# every table of summary.md
NOT_IN_PRODUCTION = "not in production"


REASON_DEV_DEPENDENCY = "dev dependency"
REASON_NOT_SHIPPED_PATH = "not shipped path"
NOT_SHIPPED_MARK = f"({NOT_IN_PRODUCTION} · {REASON_NOT_SHIPPED_PATH})"
MAX_LISTED_SKIPS = 5
PATH_SEPARATOR = " › "
RELEASE_LINE_RE = re.compile(r"^v?(\d+)\.(\d+)")
TITLE_MAX_LENGTH = 80
MAX_LISTED_LOCATIONS = 3


class Markup(str):
    """Markdown that the report itself wrote (a link): ``md_cell`` keeps it."""


def md_escape(text: Any) -> str:
    """A text of any source as plain text in a Markdown table cell: no link, image,
    code span or HTML out of an outside text (an advisory title).
    """
    escaped = str(text).replace("\\", "\\\\")
    for char in "|[]()!`":
        escaped = escaped.replace(char, "\\" + char)
    escaped = escaped.replace("<", "&lt;").replace(">", "&gt;")
    return escaped.replace("\r", " ").replace("\n", " ")


def md_link(text: Any, url: str) -> Markup:
    """A link whose text is plain text and whose URL cannot end early."""
    target = url.replace("(", "%28").replace(")", "%29").replace(" ", "%20")
    return Markup(f"[{md_escape(text)}]({target})")


def md_join(separator: str, parts: Iterable[Any]) -> Markup:
    """Parts (``Markup`` as it is, the rest as plain text) joined by a separator."""
    return Markup(
        separator.join(p if isinstance(p, Markup) else md_escape(p) for p in parts)
    )


def md_cell(value: Any) -> str:
    """Render a value as one safe Markdown table cell."""
    if value is None or value == "":
        return "-"
    if isinstance(value, Markup):
        return value.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return md_escape(value)


def md_table(
    header: Sequence[str],
    rows: Iterable[Sequence[Any]],
    right: Sequence[int] = (),
) -> list[str]:
    align = ["---:" if i in right else "---" for i in range(len(header))]
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(align) + "|"]
    lines.extend("| " + " | ".join(md_cell(c) for c in row) + " |" for row in rows)
    return lines


def md_details(summary: str, body: Sequence[str], is_open: bool = False) -> list[str]:
    """A collapsible block; the blank lines make GitHub render the Markdown inside."""
    tag = "<details open>" if is_open else "<details>"
    return [tag, f"<summary>{summary}</summary>", "", *body, "", "</details>"]


def strip_package_prefix(title: str | None, pkg: str | None) -> str | None:
    """Drop the leading ``<package>: `` repeats of advisory titles, as in
    ``urllib3: urllib3: Denial of Service``.
    """
    if not title or not pkg:
        return title
    prefix = re.compile(rf"{re.escape(pkg)}:\s+", re.IGNORECASE)
    while (match := prefix.match(title)) and len(title) > match.end():
        title = title[match.end() :]
    return title


def short_title(record: Mapping[str, Any]) -> str | None:
    return truncate(strip_package_prefix(record["title"], record["pkg"]))


def truncate(text: str | None, limit: int = TITLE_MAX_LENGTH) -> str | None:
    if text is None or len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


_TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})")


def format_timestamp(value: str | None, with_date: bool = True) -> str | None:
    """``2026-10-12T01:14:57Z`` -> ``2026-10-12 01:14Z`` (``01:14Z`` if no date)."""
    match = _TIMESTAMP_RE.match(value or "")
    if not match:
        return None
    date, time = match.groups()
    return f"{date} {time}Z" if with_date else f"{time}Z"


def format_severity_counts(counts: Mapping[str, int], separator: str = " · ") -> str:
    """``2 HIGH · 4 MEDIUM``; empty string when there is nothing."""
    return separator.join(f"{counts[s]} {s}" for s in SEVERITIES if counts.get(s))


def image_short_name(target: Mapping[str, Any]) -> str:
    return (target.get("image") or "image").rsplit("/", 1)[-1]


def has_several_images(targets: Iterable[Mapping[str, Any]]) -> bool:
    return len({t.get("image") for t in targets if t.get("kind") == KIND_IMAGE}) > 1


def trivy_targets(targets: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The targets whose findings are in the records."""
    return [t for t in targets if t["scanner"] == SCANNER_TRIVY]


def target_label(target: Mapping[str, Any], several_images: bool) -> str:
    """Short name: ``source @ development 3d0c8a3``, ``source @ 1.0 3d0c8a3``,
    ``image :1.0``, ``app :1.0``.
    """
    if target.get("kind") == KIND_FS:
        parts = ["source @", target.get("git_ref") or "?"]
        if target.get("commit_sha"):
            parts.append(target["commit_sha"][:SHORT_SHA_LENGTH])
        return " ".join(parts)
    name = image_short_name(target) if several_images else "image"
    return f"{name} :{target.get('tag')}"


def records_in(records: Iterable[Record], target_ids: Collection[str]) -> list[Record]:
    return [r for r in records if not target_ids.isdisjoint(r["scan_targets"])]


def release_subjects(targets: Iterable[Mapping[str, Any]]) -> dict[str, set[str]]:
    """The scanned targets that stand for a release, by tag in targets order: the
    images of the tag or, in a run without images, its source (``source-<tag>``).
    """
    targets = list(targets)
    kind = release_class(any(t.get("kind") == KIND_IMAGE for t in targets))
    subjects: dict[str, set[str]] = {}
    for target in trivy_targets(targets):
        if target["status"] == STATUS_OK and target_class(target) == kind:
            subjects.setdefault(target["tag"], set()).add(target["id"])
    return subjects


def development_scanned(targets: Iterable[Mapping[str, Any]]) -> bool:
    """Whether the development images or the default branch source were scanned."""
    return any(
        t["status"] == STATUS_OK
        and target_class(t) in (CLASS_DEVELOPMENT, CLASS_SOURCE)
        for t in trivy_targets(targets)
    )


def report_not_shipped(report: Mapping[str, Any]) -> NotShipped:
    """The not shipped locations of a run, from its scan_report.json."""
    config = report.get("config") or default_config()
    configs = {
        t["id"]: t["trivy_skip_paths"]
        for t in report["targets"]
        if t.get("trivy_skip_paths")
    }
    return NotShipped(config[KEY_NON_SHIPPED_PATHS], configs)


def join_names(names: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    if len(names) < 2:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


def facts_text(
    report: Mapping[str, Any],
    records: Sequence[Record],
    early_warning: EarlyWarning | None = None,
) -> str:
    """The facts of the run in one line: the (unique) findings by severity, where
    they are (a finding in a release and in development counts in both), how many
    have a fix in the databases and the early warnings; or that there are none.
    """
    warning = early_warning_headline(early_warning)
    if not records:
        targets = report["targets"]
        names = [*release_subjects(targets)]
        if development_scanned(targets):
            names.append(DEVELOPMENT_TAG)
        where = join_names(names) or "the scanned targets"
        text = f"No known vulnerabilities in {where}"
        return f"{text} · {warning}" if warning else text
    counts = count_by_severity(r["severity"] for r in records)
    severities = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
    total = len(records)
    parts = [f"{total} finding{'s' if total > 1 else ''}: {severities}"]
    exposures = [r["exposure"] for r in records]
    in_release = (EXPOSURE_RELEASE_AND_DEVELOPMENT, EXPOSURE_RELEASE_ONLY)
    in_development = (EXPOSURE_RELEASE_AND_DEVELOPMENT, EXPOSURE_DEVELOPMENT_ONLY)
    where_counts = [
        (sum(e in in_release for e in exposures), "in release"),
        (sum(e in in_development for e in exposures), "in development"),
        (sum(e == EXPOSURE_SOURCE_ONLY for e in exposures), "only in source"),
    ]
    parts.append(", ".join(f"{n} {label}" for n, label in where_counts if n))
    if fixable := sum(r["fix_available"] for r in records):
        parts.append(f"{fixable} with a fix in the database")
    if warning:
        parts.append(warning)
    return " · ".join(p for p in parts if p)


def scope_row(
    label: str,
    records: Sequence[Record],
    severities: Sequence[str],
    base_column: bool = True,
) -> list[Any]:
    """Unique records by severity, those with a fix, and those of the base image."""
    counts = count_by_severity(r["severity"] for r in records)
    return [
        label,
        *(counts[s] for s in severities),
        sum(r["fix_available"] for r in records),
        sum(is_base_image(r) for r in records) if base_column else "—",
    ]


def scope_table(report: Mapping[str, Any], records: Sequence[Record]) -> list[str]:
    """The findings by scope: each release, development and what is only in sources.

    A record is counted once per row: in a release if it is in the release's images
    (its source in a run without images), in development if it is in development
    (see ``classify_exposure``), and in the last row only if it is in no shipped
    artifact. Rows without records are left out.
    """
    targets = report["targets"]
    scopes: list[tuple[str, list[Record], bool]] = []
    in_release = (EXPOSURE_RELEASE_AND_DEVELOPMENT, EXPOSURE_RELEASE_ONLY)
    for tag, ids in release_subjects(targets).items():
        found = [r for r in records_in(records, ids) if r["exposure"] in in_release]
        scopes.append((f"{tag} (released)", found, True))
    if development_scanned(targets):
        in_development = (EXPOSURE_RELEASE_AND_DEVELOPMENT, EXPOSURE_DEVELOPMENT_ONLY)
        found = [r for r in records if r["exposure"] in in_development]
        scopes.append((DEVELOPMENT_TAG, found, True))
    found = [r for r in records if r["exposure"] == EXPOSURE_SOURCE_ONLY]
    label = (
        "build / test / not shipped" if report_not_shipped(report) else "build / test"
    )
    scopes.append((f"Source only ({label})", found, False))
    scopes = [scope for scope in scopes if scope[1]]
    if not scopes:
        return []
    # UNKNOWN has a column only if some record has no usable severity
    has_unknown = any(
        r["severity"] == UNKNOWN_SEVERITY for _, group, _ in scopes for r in group
    )
    severities = SEVERITIES if has_unknown else SEVERITIES[:-1]
    header = ["Scope", *severities, "Fixable", "Base image"]
    rows = [scope_row(label, group, severities, base) for label, group, base in scopes]
    return md_table(header, rows, right=range(1, len(header)))


def totals_line(
    report: Mapping[str, Any],
    osv_only: int = 0,
    packages: int | None = None,
) -> str:
    """Coverage of the run: ``8/8 targets scanned · 10 found only by OSV``."""
    counts = report["totals"]["targets"]
    applicable = counts["total"] - counts["not_applicable"]
    line = f"{counts['ok']}/{applicable} targets scanned"
    if packages is not None:
        line += f" · {packages} packages"
    if osv_only:
        line += f" · {osv_only} found only by OSV"
    if counts["not_applicable"]:
        line += f" · {counts['not_applicable']} not applicable"
    return line


def headline_blocks(
    report: Mapping[str, Any],
    records: Sequence[Record],
    early_warning: EarlyWarning | None = None,
) -> list[list[str]]:
    """The paragraphs of the headline: failures, the facts, the scope table, the
    coverage of the run.
    """
    targets = report["targets"]
    blocks: list[list[str]] = []
    failed = [target_name(t) for t in targets if t["status"] == STATUS_FAILED]
    if failed:
        blocks.append(
            [
                f"**Incomplete: {len(failed)} target(s) failed** — {', '.join(failed)} "
                "(their findings are missing)"
            ]
        )
    ok = [t for t in trivy_targets(targets) if t["status"] == STATUS_OK]
    if not ok:
        scanned = any(t["status"] == STATUS_OK for t in targets)
        text = "No Trivy target was scanned" if scanned else "No target was scanned"
        return [*blocks, [text]]

    osv_only = sum(is_osv_only(r) for r in records)
    blocks.append([f"**{facts_text(report, records, early_warning)}**"])
    if records:
        if table := scope_table(report, records):
            blocks.append(table)
        blocks.append([totals_line(report, osv_only)])
    else:
        packages = sum(t["packages_scanned"] or 0 for t in ok)
        blocks.append([totals_line(report, osv_only, packages)])
    if report["run_kind"] != "full":
        reasons = "; ".join(report["run_kind_reasons"])
        blocks.append([f"Partial run ({reasons}): not a full scan of the repository"])
    return blocks


def render_headline(blocks: Sequence[Sequence[str]]) -> list[str]:
    """A blockquote with one paragraph per block (a plain newline would merge them)."""
    quoted: list[str] = []
    for block in blocks:
        if quoted:
            quoted.append(">")
        quoted.extend(f"> {line}" for line in block)
    return quoted


def max_cvss_score(records: Iterable[Record]) -> float | None:
    scores = [r["cvss"]["score"] for r in records if r["cvss"]]
    scores = [score for score in scores if score is not None]
    return max(scores) if scores else None


def is_base_image(record: Mapping[str, Any]) -> bool:
    """Whether the package is an OS package, so the fix is a new base image."""
    return record["pkg_type"] == "os"


def urgency_key(group: Sequence[Record], name: str, version: str) -> tuple[Any, ...]:
    """Order of a group of records of one exposure: urgency, worst severity, highest
    CVSS score (none last), then its name.
    """
    score = max_cvss_score(group)
    return (
        EXPOSURE_ORDER.get(group[0]["exposure"], len(EXPOSURES)),
        min(SEV_ORDER.get(r["severity"], len(SEV_ORDER)) for r in group),
        score is None,
        -(score or 0),
        name,
        version,
    )


def group_fixes(records: Iterable[Record]) -> list[list[Record]]:
    """One group per (exposure, package, installed version), most urgent first."""
    groups: dict[tuple[Any, Any, Any], list[Record]] = {}
    for record in records:
        key = (record["exposure"], record["pkg"], record["version"])
        groups.setdefault(key, []).append(record)
    return sorted(
        groups.values(),
        key=lambda group: urgency_key(
            group, group[0]["pkg"] or "", group[0]["version"] or ""
        ),
    )


def package_families(group: Iterable[Record]) -> str:
    return "/".join(
        sorted({ECOSYSTEM_FAMILIES.get(e, e) for r in group for e in r["ecosystem"]})
    )


def group_relationship(group: Iterable[Record]) -> str | None:
    """``direct`` if any record says so, ``indirect`` if all that know are indirect."""
    relationships = {rel for r in group for rel in r["relationship"]}
    if "direct" in relationships:
        return "direct"
    return "indirect" if "indirect" in relationships else None


def group_dev(group: Iterable[Record]) -> bool | None:
    flags = [r["dev"] for r in group if r["dev"] is not None]
    return all(flags) if flags else None


def group_paths(group: Iterable[Record]) -> tuple[list[list[str]], int, bool]:
    """Chains of a package version (the same on all its records) as stored."""
    paths: list[list[str]] = []
    total, truncated = 0, False
    for r in group:
        for path in r["dependency_paths"]:
            if path not in paths:
                paths.append(path)
        total = max(total, r["dependency_paths_total"])
        truncated = truncated or r["dependency_paths_truncated"]
    paths.sort(key=lambda path: (len(path), path))
    return paths, total, truncated


def shortest_path_text(group: Iterable[Record]) -> str:
    """``jest › micromatch › braces (+3 more paths)``; empty without a chain."""
    paths, total, truncated = group_paths(group)
    if not paths:
        return ""
    text = PATH_SEPARATOR.join(paths[0])
    more = total - 1
    if more > 0:
        plus = f"{more}+" if truncated else str(more)
        text += f" (+{plus} more {'path' if more == 1 and not truncated else 'paths'})"
    return text


FIXED_VERSIONS_SHOWN = 3


def fixed_versions_text(versions: Iterable[str], installed: str | None = None) -> str:
    """``1.2, 1.3, 2.0 +4 more``: the fixed versions above the installed one (all of
    them if it is unknown or they cannot be compared), lowest first.
    """

    def order(a: str, b: str) -> int:
        return compare_tokens(a, b) or 0

    # versions that cannot be compared keep their alphabetical order
    candidates = sorted(sorted(set(versions)), key=cmp_to_key(order))
    if installed:
        above = [v for v in candidates if compare_tokens(v, installed) != -1]
        candidates = above or candidates
    text = ", ".join(candidates[:FIXED_VERSIONS_SHOWN])
    hidden = len(candidates) - FIXED_VERSIONS_SHOWN
    return f"{text} +{hidden} more" if hidden > 0 else text


def release_tags_of(
    group: Iterable[Record], targets: Sequence[Mapping[str, Any]]
) -> list[str]:
    """Release tags (in targets order) of the images a group was found in, or of
    the release sources if the run has no images.
    """
    found = {tid for r in group for tid in r["scan_targets"]}
    kind = release_class(any(t.get("kind") == KIND_IMAGE for t in targets))
    tags: list[str] = []
    for target in targets:
        if target["id"] in found and target_class(target) == kind:
            append_unique(tags, target["tag"])
    return tags


def exposure_label(
    exposure: str,
    reasons: Sequence[str],
    tags: Sequence[str],
    has_images: bool,
) -> str:
    """Where the finding lives (a state, not an action). ``reasons`` are why it is
    certainly not in production (see ``not_in_production_reasons``), if it is not:
    ``not in production · dev dependency``.
    """
    released = ", ".join(tags)
    mark = " · ".join([NOT_IN_PRODUCTION, *reasons]) if reasons else ""
    if exposure == EXPOSURE_SOURCE_ONLY:
        if mark:
            return mark
        return "Source only · not in images" if has_images else "Source only"
    if exposure == EXPOSURE_RELEASE_AND_DEVELOPMENT:
        text = f"Released {released} + development"
    elif exposure == EXPOSURE_RELEASE_ONLY:
        text = f"Released {released} only"
    else:
        text = "development only" if has_images else "development (source)"
    return f"{text} · {mark}" if mark else text


def in_not_shipped_paths(
    record: Record,
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
    not_shipped: NotShipped | None,
) -> bool:
    """Whether every location the record was seen in is a not shipped one (in sources
    only: a sighting in an image is never one).
    """
    if not not_shipped:
        return False
    kinds = {t["id"]: t.get("kind") for t in targets}
    seen = sightings.get(record_identity(record), {})
    return bool(seen) and all(
        kinds.get(tid) == KIND_FS
        and bool(locations)
        and all(not_shipped.matches(tid, loc) for loc in locations)
        for tid, locations in seen.items()
    )


def not_in_production_reasons(
    group: Sequence[Record],
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
    not_shipped: NotShipped | None,
) -> list[str]:
    """Why a group is certainly not in production: it is a dev dependency
    (``dev``), and / or every location of it is in ``non_shipped_paths``. Empty if
    neither is known (``Source only`` alone is not one: for a library the source is
    the product).
    """
    reasons = []
    if group_dev(group):
        reasons.append(REASON_DEV_DEPENDENCY)
    if all(in_not_shipped_paths(r, sightings, targets, not_shipped) for r in group):
        reasons.append(REASON_NOT_SHIPPED_PATH)
    return reasons


def where_cell(
    group: Sequence[Record],
    sightings: Sightings,
    targets: Sequence[Mapping[str, Any]],
    not_shipped: NotShipped | None = None,
) -> str:
    """Where a group was found: tags per image, then the lockfiles of the source
    of the default branch and of each release tag; a lockfile in a not shipped
    location is marked ``(not shipped)``.

    ``statgpt-chat :development, :0.17.7 · statgpt-admin :development · source
    poetry.lock · source @ 0.17.7 poetry.lock``; a run with one image calls it
    ``image``.
    """
    several = has_several_images(targets)
    tags: dict[str, list[str]] = {}
    sources: dict[str, list[str]] = {}  # "source" / "source @ <tag>" -> lockfiles
    for target in targets:
        for record in group:
            seen = sightings.get(record_identity(record), {})
            if target["id"] not in seen:
                continue
            if target.get("kind") == KIND_FS:
                name = f"source @ {target['tag']}" if target.get("tag") else "source"
                sources.setdefault(name, []).extend(
                    f"{loc} {NOT_SHIPPED_MARK}"
                    if not_shipped and not_shipped.matches(target["id"], loc)
                    else loc
                    for loc in seen[target["id"]]
                )
            else:
                name = image_short_name(target) if several else "image"
                append_unique(tags.setdefault(name, []), f":{target.get('tag')}")
    parts = [f"{name} {', '.join(names)}" for name, names in tags.items()]
    for name, locations in sources.items():
        shown = sorted(set(locations))
        text = f"{name} " + ", ".join(shown[:MAX_LISTED_LOCATIONS])
        if len(shown) > MAX_LISTED_LOCATIONS:
            text += f" +{len(shown) - MAX_LISTED_LOCATIONS} more"
        parts.append(text)
    return " · ".join(parts)


def group_exposure_label(
    group: Sequence[Record],
    targets: Sequence[Mapping[str, Any]],
    sightings: Sightings,
    not_shipped: NotShipped | None,
) -> str:
    has_images = any(t.get("kind") == KIND_IMAGE for t in targets)
    return exposure_label(
        group[0]["exposure"],
        not_in_production_reasons(group, sightings, targets, not_shipped),
        release_tags_of(group, targets),
        has_images,
    )


def render_dependency_paths(records: Sequence[Record]) -> list[str]:
    """One collapsible block with the stored chains of every package that has them."""
    items: list[str] = []
    seen: set[tuple[Any, Any]] = set()
    for group in group_fixes(records):
        key = (group[0]["pkg"], group[0]["version"])
        paths, total, truncated = group_paths(group)
        if key in seen or not paths or group_relationship(group) != "indirect":
            continue
        seen.add(key)
        count = f"{total}+" if truncated else str(total)
        shown = f", showing {len(paths)}" if len(paths) < total else ""
        noun = "path" if total == 1 and not truncated else "paths"
        label = f"{group[0]['pkg']} {group[0]['version']}"
        items.append(f"- **{label}** ({count} {noun}{shown})")
        items += [f"  - {PATH_SEPARATOR.join(path)}" for path in paths]
    if not items:
        return []
    return ["", *md_details(f"Dependency paths ({len(seen)})", items)]


def scope_cell(group: Sequence[Record]) -> str:
    dev = group_dev(group)
    scope = "-" if dev is None else ("dev" if dev else "runtime")
    relationship = group_relationship(group)
    return f"{scope}, {relationship}" if relationship else scope


def render_unfixed(
    records: Sequence[Record],
    targets: Sequence[Mapping[str, Any]],
    sightings: Sightings,
    not_shipped: NotShipped | None = None,
) -> list[str]:
    """Findings without a fix in the databases.

    The dependencies are open if anything CRITICAL is in them, else
    collapsed; the OS packages of the base image are always collapsed.
    """
    unfixed = [r for r in records if not r["fix_available"]]
    dependencies = [r for r in unfixed if not is_base_image(r)]
    os_records = [r for r in unfixed if is_base_image(r)]
    lines: list[str] = []
    if dependencies:
        lines += render_unfixed_dependencies(
            dependencies, targets, sightings, not_shipped
        )
    if os_records:
        lines += [
            "",
            *render_unfixed_base_image(os_records, targets, sightings, not_shipped),
        ]
    return lines


def render_unfixed_dependencies(
    unfixed: Sequence[Record],
    targets: Sequence[Mapping[str, Any]],
    sightings: Sightings,
    not_shipped: NotShipped | None,
) -> list[str]:
    rows = []
    for group in group_fixes(unfixed):
        counts = count_by_severity(r["severity"] for r in group)
        family = package_families(group)
        rows.append(
            [
                f"{group[0]['pkg']} {group[0]['version']}"
                + (f" · {family}" if family else ""),
                format_severity_counts(counts, ", "),
                scope_cell(group),
                shortest_path_text(group),
                group_exposure_label(group, targets, sightings, not_shipped),
            ]
        )
    header = [
        "Package",
        "Severity",
        "Scope",
        "Introduced via",
        "Exposure",
    ]
    table = md_table(["#", *header], ([i, *row] for i, row in enumerate(rows, 1)))
    title = "No fix available"
    if any(r["severity"] == "CRITICAL" for r in unfixed):
        return ["", f"## {title}", "", *table]
    return ["", *md_details(f"{title} ({len(unfixed)})", table)]


def render_unfixed_base_image(
    unfixed: Sequence[Record],
    targets: Sequence[Mapping[str, Any]],
    sightings: Sightings,
    not_shipped: NotShipped | None,
) -> list[str]:
    """OS packages without a fix in the databases."""
    rows = []
    for group in group_fixes(unfixed):
        counts = count_by_severity(r["severity"] for r in group)
        rows.append(
            [
                f"{group[0]['pkg']} {group[0]['version']}",
                format_severity_counts(counts, ", "),
                group_exposure_label(group, targets, sightings, not_shipped),
            ]
        )
    header = ["#", "Package", "Severity", "Exposure"]
    table = md_table(header, ([i, *row] for i, row in enumerate(rows, 1)))
    title = f"No fix available — base image (OS packages) ({len(unfixed)})"
    return md_details(title, table)


def is_osv_only(record: Mapping[str, Any]) -> bool:
    """Whether only OSV, not Trivy, reports the vulnerability."""
    return record["scanners"] == [SCANNER_OSV]


def id_cell(record: Record) -> Markup:
    vuln_id = record["id"]
    text = (
        md_link(vuln_id, record["primary_url"])
        if record["primary_url"]
        else md_escape(vuln_id)
    )
    return Markup(f"{text} · OSV only" if is_osv_only(record) else text)


def cvss_cell(record: Record) -> str | None:
    cvss = record["cvss"]
    if not cvss:
        return None
    # A CVSS 4.0 vector from OSV has no computed score
    score = cvss["score"] if cvss["score"] is not None else f"v{cvss['version']}"
    return f"{score} ({cvss['source']})"


def render_severity_section(
    severity: str,
    records: Sequence[Record],
    targets: Sequence[Mapping[str, Any]],
    sightings: Sightings,
    not_shipped: NotShipped | None,
) -> list[str]:
    rows = (
        [
            id_cell(r),
            r["pkg"],
            r["version"],
            fixed_versions_text(r["fixed_versions"], r["version"]),
            cvss_cell(r),
            (r["published"] or "")[:10],
            group_exposure_label([r], targets, sightings, not_shipped),
            short_title(r),
        ]
        for r in records
    )
    header = [
        "ID",
        "Package",
        "Installed",
        "Fixed in",
        "CVSS",
        "Published",
        "Exposure",
        "Title",
    ]
    body = md_table(header, rows)
    summary = f"{severity} ({len(records)})"
    return md_details(summary, body, is_open=severity == "CRITICAL")


def render_severity_sections(
    records: Sequence[Record],
    targets: Sequence[Mapping[str, Any]],
    sightings: Sightings,
    not_shipped: NotShipped | None = None,
) -> list[str]:
    """The findings by severity: the dependencies, then the OS packages of the base
    image in one collapsed block (a base image is hundreds of lines of noise).
    """

    def sections(group: Sequence[Record]) -> list[list[str]]:
        return [
            render_severity_section(severity, selected, targets, sightings, not_shipped)
            for severity in SEVERITIES
            if (selected := [r for r in group if r["severity"] == severity])
        ]

    lines: list[str] = []
    for section in sections([r for r in records if not is_base_image(r)]):
        lines += ["", *section]
    os_records = [r for r in records if is_base_image(r)]
    if os_records:
        body: list[str] = []
        for section in sections(os_records):
            body += ["", *section] if body else section
        summary = f"Base image (OS packages) ({len(os_records)})"
        lines += ["", *md_details(summary, body)]
    return lines


def scan_cell(
    target: Mapping[str, Any] | None, describe: Callable[[Mapping[str, Any]], str]
) -> str:
    """``ok · 556 pkgs · <findings>`` of a scanned target, else its status and
    reason, ``—`` without a target.
    """
    if target is None:
        return "—"
    if target["status"] != STATUS_OK:
        reason = f" · {target['reason']}" if target["reason"] else ""
        return f"{target['status']}{reason}"
    return f"ok · {target['packages_scanned']} pkgs · {describe(target['findings'])}"


def trivy_findings_text(findings: Mapping[str, Any]) -> str:
    """``5/31/190/55``: CRITICAL/HIGH/MEDIUM/LOW, plus the unknown ones if any."""
    by_severity = findings["by_severity"]
    text = "/".join(str(by_severity[s]) for s in SEVERITIES[:4])
    unknown = by_severity[UNKNOWN_SEVERITY]
    return f"{text} · {unknown} UNKNOWN" if unknown else text


def skip_paths_note(target: Mapping[str, Any] | None) -> str | None:
    """What was done with the skip-dirs / skip-files of the trivy.yaml of a source
    target, None if it lists none.
    """
    skip = (target or {}).get("trivy_skip_paths")
    paths = [*skip["skip_dirs"], *skip["skip_files"]] if skip else []
    if not paths:
        return None
    shown = ", ".join(paths[:MAX_LISTED_SKIPS])
    if len(paths) > MAX_LISTED_SKIPS:
        shown += f" +{len(paths) - MAX_LISTED_SKIPS} more"
    return {
        SKIP_APPLY: f"trivy.yaml skip paths skipped by Trivy: {shown}",
        SKIP_AS_NON_SHIPPED: f"trivy.yaml skip paths scanned, not shipped: {shown}",
        SKIP_IGNORE: f"trivy.yaml skip paths scanned: {shown}",
    }[skip["mode"]]


def unread_note(osv: Mapping[str, Any] | None) -> str | None:
    """The packages of the BOM that osv-scanner did not read, so OSV did not check."""
    unread = (osv or {}).get("packages_unread")
    if not unread or osv["status"] != STATUS_OK:  # type: ignore[index]
        return None
    return f"OSV did not read {unread} package(s)"


def render_coverage(targets: Sequence[Mapping[str, Any]]) -> list[str]:
    """One row per scanned subject (the id Trivy and OSV share), a cell per scanner."""
    several = has_several_images(targets)
    subjects: dict[str, dict[str, Mapping[str, Any]]] = {}
    for target in targets:
        subjects.setdefault(target["id"], {})[target["scanner"]] = target
    # Only a run with OSV targets needs the column: Trivy-only reports stay as is
    with_osv = any(t["scanner"] == SCANNER_OSV for t in targets)
    rows = []
    for scanners in subjects.values():
        trivy = scanners.get(SCANNER_TRIVY)
        osv = scanners.get(SCANNER_OSV)
        scanned = [t for t in (trivy, osv) if t and t["status"] == STATUS_OK]
        empty = any(t["packages_scanned"] == 0 for t in scanned)
        rows.append(
            [
                target_label(trivy or osv, several),  # type: ignore[arg-type]
                scan_cell(trivy, trivy_findings_text),
                *([scan_cell(osv, lambda f: str(f["total"]))] if with_osv else []),
                "; ".join(
                    note
                    for note in (
                        "no packages seen" if empty else None,
                        unread_note(osv),
                        skip_paths_note(trivy),
                    )
                    if note
                )
                or None,
            ]
        )
    header = ["Target", "Trivy", *(["OSV"] if with_osv else []), "Note"]
    legend = "Trivy: status · packages · CRITICAL/HIGH/MEDIUM/LOW findings"
    if with_osv:
        legend += (
            "; OSV: status · language packages only (not the OS packages of an image)"
            " · findings"
        )
    body = [f"<sub>{legend}</sub>", "", *md_table(header, rows)]
    return ["", *md_details("Scan coverage", body)]


def config_text(config: Mapping[str, Any] | None) -> str | None:
    """Where the SCA configuration of the run came from and what it sets; None if
    the run has none.
    """
    if not config or not config.get("source"):
        return None

    def short(ref: str) -> str:
        path, _, sha = ref.partition("@")
        return f"{path}@{sha[:SHORT_SHA_LENGTH]}" if sha else ref

    if config["source"] == "input":
        text = "Configuration: workflow input"
        if config.get("overrides"):
            text += f" (replaces {short(config['overrides'])})"
    else:
        text = f"Configuration: {short(config['source'])}"
    if config[KEY_NON_SHIPPED_PATHS]:
        text += f" · not shipped: {', '.join(config[KEY_NON_SHIPPED_PATHS])}"
    if config[KEY_TRIVY_SKIP_PATHS] != SKIP_AS_NON_SHIPPED:
        text += f" · trivy_skip_paths: {config[KEY_TRIVY_SKIP_PATHS]}"
    return text


EARLY_WARNING_TITLE = "Early warning — not yet in vulnerability databases"


EARLY_WARNING_EXPLANATION = (
    "CVE records of their CNAs match these packages, but no vulnerability database "
    "maps them to a package yet."
)


EARLY_WARNING_HEADER = [
    "Package",
    "Severity",
    "CVE",
    "CNA",
    "Published",
    "Affected",
    "Match",
    "Exposure",
    "Where",
]


def early_warning_headline(early_warning: EarlyWarning | None) -> str | None:
    """The early warning part of the coverage line: ``2 early warnings (1 CRITICAL)``
    (packages, and how many of them have CRITICAL or HIGH ones), or a note that it
    is unavailable, so that its absence is not read as "nothing".
    """
    if early_warning is None:
        return None
    status = early_warning.report["status"]
    if status == STATUS_FAILED:
        return "early warning unavailable"
    if status != STATUS_OK or not early_warning.entries:
        return None
    groups = early_warning_groups(early_warning.entries)
    worst = count_by_severity(
        min((e["severity"] for e in g), key=lambda s: SEV_ORDER.get(s, len(SEV_ORDER)))
        for g in groups
    )
    text = f"{len(groups)} early warning{'s' if len(groups) != 1 else ''}"
    urgent = format_severity_counts({s: worst[s] for s in HEADLINE_SEVERITIES})
    return f"{text} ({urgent})" if urgent else text


def early_warning_severity_text(entry: Record) -> str:
    """``HIGH 7.5``; ``(ADP)`` when the score is not the CNA's, and what is known
    about exploitation.
    """
    text = entry["severity"]
    score = (entry["cvss"] or {}).get("score")
    if score is not None:
        text += f" {score:.1f}"
    if (entry["severity_source"] or "").startswith(ADP_SOURCE_PREFIX):
        text += " (ADP)"
    exploitation = entry["exploitation"] or {}
    if exploitation.get("kev"):
        text += " · KEV"
    elif exploitation.get("ssvc") == "active":
        text += " · exploited (SSVC)"
    return text


def early_warning_row(
    group: Sequence[Record],
    early_warning: EarlyWarning,
    targets: Sequence[Mapping[str, Any]],
    not_shipped: NotShipped | None,
) -> list[Any]:
    """One package version: the worst severity of its CVEs, and the CVEs (with their
    own severity if there are several) with the distinct CNAs, publication dates,
    affected ranges and matches.
    """
    links = []
    for entry in group:
        link = md_link(entry["cve"], f"{CVE_RECORD_URL}{entry['cve']}")
        if len(group) > 1:
            severity = md_escape(early_warning_severity_text(entry))
            link = Markup(f"{link} ({severity})")
        links.append(link)
    cnas: list[str] = []
    dates: list[str] = []
    ranges: list[str] = []
    matches: list[str] = []
    for entry in group:
        append_unique(cnas, entry["cna"])
        append_unique(dates, (entry["published"] or "?")[:10])
        append_unique(ranges, entry["affected_range"] or "?")
        append_unique(matches, entry["match"].replace("_", " "))
    return [
        f"{group[0]['pkg']} {group[0]['version']}",
        early_warning_severity_text(group[0]),
        md_join(", ", links),
        ", ".join(cnas),
        ", ".join(dates),
        " · ".join(ranges),
        ", ".join(matches),
        group_exposure_label(group, targets, early_warning.sightings, not_shipped),
        where_cell(group, early_warning.sightings, targets, not_shipped),
    ]


def render_early_warning(
    early_warning: EarlyWarning | None,
    targets: Sequence[Mapping[str, Any]],
    not_shipped: NotShipped | None = None,
) -> list[str]:
    """The early warning section: the packages, worst first, collapsed above
    ``EARLY_WARNING_COLLAPSE_ABOVE``; or the reason it is unavailable. Nothing when
    it was skipped or has nothing to report.
    """
    if early_warning is None:
        return []
    report = early_warning.report
    if report["status"] == STATUS_FAILED:
        reason = report["reason"] or "unknown reason"
        return [
            "",
            "## Early warning — unavailable",
            "",
            f"Early warning unavailable: {md_cell(reason)}",
        ]
    groups = early_warning_groups(early_warning.entries)
    if report["status"] != STATUS_OK or not groups:
        return []
    table = md_table(
        EARLY_WARNING_HEADER,
        (early_warning_row(g, early_warning, targets, not_shipped) for g in groups),
    )
    if len(groups) > EARLY_WARNING_COLLAPSE_ABOVE:
        table = md_details(f"Show the {len(groups)} packages", table)
    return [
        "",
        f"## {EARLY_WARNING_TITLE} ({len(groups)})",
        "",
        EARLY_WARNING_EXPLANATION,
        "",
        *table,
    ]


def short_digest(digest: str | None) -> str | None:
    """``sha256:0123456789ab`` of an OCI digest."""
    if not digest:
        return None
    algorithm, _, value = digest.rpartition(":")
    return f"{algorithm}:{value[:DIGEST_SHORT_LENGTH]}" if algorithm else digest


def early_warning_footer(early_warning: EarlyWarning | None) -> str | None:
    """Where the early warning looked: the CVE index (its date and digest), the
    window, and the gaps of the feed in it.
    """
    if early_warning is None or early_warning.report["status"] != STATUS_OK:
        return None
    report = early_warning.report
    index = report["index"]
    built = format_timestamp(index["built_at"]) or index["built_at"]
    digest = short_digest(index["digest"])
    window = (early_warning.document.get("generated_from") or {}).get("from")
    start = format_timestamp(window)
    text = f"Early warning: CVE index of {built}"
    if digest:
        text += f" ({digest})"
    text += f", records published or updated in the last {report['window_days']} days"
    if start:
        text += f" (since {start})"
    if report["records_scanned"] is not None:
        text += f", {report['records_scanned']} checked"
    if index.get("stale"):
        text += " · the index is more than 2 days old, its daily build is late"
    if early_warning.gaps:
        listed = early_warning.gaps[:EARLY_WARNING_GAPS_LISTED]
        more = len(early_warning.gaps) - len(listed)
        text += f" · feed gaps: {', '.join(listed)}"
        if more:
            text += f" and {more} more"
    return text


def render_footer(
    report: Mapping[str, Any], early_warning: EarlyWarning | None = None
) -> list[str]:
    parts = []
    if report["commit_sha"]:
        parts.append(f"commit {report['commit_sha'][:SHORT_SHA_LENGTH]}")
    if report["run_url"]:
        run_label = f"run {report['run_id']}" if report["run_id"] else "run"
        parts.append(f"[{run_label}]({report['run_url']})")
    if report["trivy_version"]:
        parts.append(f"Trivy {report['trivy_version']}")
    db = report["trivy_db"]
    vuln_db = format_timestamp(db["vulnerability_db_updated_at"])
    if vuln_db:
        text = f"DB vuln {vuln_db}"
        java_raw = db["java_db_updated_at"]
        same_day = (java_raw or "")[:10] == (db["vulnerability_db_updated_at"] or "")[
            :10
        ]
        java_db = format_timestamp(java_raw, with_date=not same_day)
        parts.append(f"{text} (java {java_db})" if java_db else text)
        stale = trivy_db_stale_days(db, report["generated_utc"])
        if stale is not None:
            parts.append(f"DB is {stale} days old")
    generated = format_timestamp(report["generated_utc"])
    if generated:
        parts.append(f"generated {generated}")
    lines = ["", f"<sub>{' · '.join(parts)}</sub>"]
    if text := config_text(report.get("config")):
        lines += ["", f"<sub>{text}</sub>"]
    if report.get("osv"):
        queried = [t["queried_at"] for t in report["targets"] if t["queried_at"]]
        queried_at = format_timestamp(max(queried)) if queried else None
        text = f"{OSV_FOOTER} · queried {queried_at}" if queried_at else OSV_FOOTER
        lines += ["", f"<sub>{text}</sub>"]
    if text := early_warning_footer(early_warning):
        lines += ["", f"<sub>{text}</sub>"]
    return lines


def build_summary_md(
    report: Mapping[str, Any],
    vulns: Mapping[str, Any],
    sightings: Sightings,
    early_warning: EarlyWarning | None = None,
) -> str:
    """``early_warning`` is the early warning of the run, if it has one."""
    records = vulns["records"]
    targets = report["targets"]
    # The findings sections are about the records, so about the Trivy targets only
    record_targets = trivy_targets(targets)
    not_shipped = report_not_shipped(report)
    lines = [f"# SCA · {md_cell(report['repo'])}", ""]
    lines += render_headline(headline_blocks(report, records, early_warning))
    if records:
        lines += render_unfixed(records, record_targets, sightings, not_shipped)
    lines += render_early_warning(early_warning, record_targets, not_shipped)
    if records:
        lines += render_severity_sections(
            records, record_targets, sightings, not_shipped
        )
        lines += render_dependency_paths(records)
    lines += render_coverage(targets)
    lines += render_footer(report, early_warning)
    return "\n".join(lines) + "\n"


def truncate_summary(text: str, run_url: str | None) -> str:
    """The summary as the job summary can take it: whole if it fits, else cut at a
    line, with the ``<details>`` it left open closed and a note on where the whole
    of it is.
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
    close = "</details>" + "\n"
    # room to close the blocks that the cut leaves open (they do not nest deeper)
    room = STEP_SUMMARY_LIMIT_BYTES - len(note.encode("utf-8")) - 2 * len(close)
    kept = data[:room].decode("utf-8", errors="ignore")
    kept = kept[: kept.rfind("\n") + 1]
    open_blocks = kept.count("<details") - kept.count("</details>")
    return kept + close * max(open_blocks, 0) + note
