"""What changed since the baseline run: the whole diff of an SCA report.

The merge (merge_results.py) compares the records and the early warnings of a run with
those of a baseline run, the latest full run of the same workflow on the default
branch. All the code of that comparison is here, so that the diff can be taken out of
the merge, or put back, by removing or adding this module and the few places where the
merge calls it (``sca_diff.`` in merge_results.py). The module does not import the
merge: the helpers it needs come as ``Tools``.

The first part does not depend on the report format of the records: the state of the
targets of a run, the classification of keyed items, and the differences in the
conditions under which two runs were made. The rest builds ``diff.json``,
``scan_report.json: diff`` and the ``diff`` of the records, and renders the diff in
``summary.md``.

An item is identified by a key; each item says in which targets (scan target ids) it
was seen. Per target, a run either scanned it successfully (``ok``) or did not (failed,
not applicable, or it was not part of the run at all). Whether an item appeared or
disappeared is only known where both runs scanned the targets involved:

* ``new``: not in the baseline, and every target it is seen in now was ``ok`` there;
* ``resolved``: in the baseline, not now, and every target it was seen in there is
  ``ok`` now;
* ``not_comparable``: it appeared or disappeared, but a target involved was not
  scanned successfully in one of the two runs (a failed scan, or a target that is not
  in both runs, e.g. a new release tag), so it may as well have been there all along;
* ``unchanged``: in both.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:  # the merge imports this module, so it is not imported at run time
    from merge_results import EarlyWarning

Record = dict[str, Any]

STATUS_OK = "ok"
SCANNER_OSV = "osv"

NEW = "new"
RESOLVED = "resolved"
NOT_COMPARABLE = "not_comparable"
UNCHANGED = "unchanged"
# A record of a run that has no baseline: nothing to say whether it is new
BASELINE = "baseline"

APPEARED = "appeared"
DISAPPEARED = "disappeared"

# The SCA configuration of a run that has none (what a report without ``config``, of an
# older version, stands for)
DEFAULT_CONFIG: dict[str, Any] = {
    "source": None,
    "non_shipped_paths": [],
    "trivy_skip_paths": "as_non_shipped",
}


def target_states(targets: Iterable[Mapping[str, Any]]) -> dict[str, bool]:
    """Target id -> whether the target was scanned successfully by every scanner that
    has it (a Trivy target and its OSV twin share the id).
    """
    states: dict[str, bool] = {}
    for target in targets:
        states[target["id"]] = states.get(target["id"], True) and (
            target.get("status") == STATUS_OK
        )
    return states


@dataclass
class NotComparable:
    key: Hashable
    direction: str  # APPEARED (in the current run only) or DISAPPEARED
    targets: list[str]  # the targets that make it not comparable


@dataclass
class Classification:
    new: list[Hashable] = field(default_factory=list)
    resolved: list[Hashable] = field(default_factory=list)
    not_comparable: list[NotComparable] = field(default_factory=list)
    unchanged: list[Hashable] = field(default_factory=list)
    # the state (NEW, NOT_COMPARABLE or UNCHANGED) of every item of the current run
    states: dict[Hashable, str] = field(default_factory=dict)


def classify(
    current: Mapping[Hashable, Sequence[str]],
    baseline: Mapping[Hashable, Sequence[str]],
    current_ok: Mapping[str, bool],
    baseline_ok: Mapping[str, bool],
) -> Classification:
    """Classify keyed items; the mappings give the targets each item is seen in.

    The order is that of ``current`` for the items of the current run and that of
    ``baseline`` for the items that are gone.
    """
    result = Classification()
    for key, seen in current.items():
        if key in baseline:
            result.unchanged.append(key)
            result.states[key] = UNCHANGED
            continue
        unsure = [t for t in seen if not baseline_ok.get(t, False)]
        if unsure:
            result.not_comparable.append(NotComparable(key, APPEARED, unsure))
            result.states[key] = NOT_COMPARABLE
        else:
            result.new.append(key)
            result.states[key] = NEW
    for key, seen in baseline.items():
        if key in current:
            continue
        unsure = [t for t in seen if not current_ok.get(t, False)]
        if unsure:
            result.not_comparable.append(NotComparable(key, DISAPPEARED, unsure))
        else:
            result.resolved.append(key)
    return result


def _config_source_kind(config: Mapping[str, Any]) -> str | None:
    """Where the configuration came from, without the commit of the file."""
    source = config.get("source")
    return source.partition("@")[0] if isinstance(source, str) else None


def _onoff(value: bool) -> str:
    return "on" if value else "off"


def _is_release_source(target: Mapping[str, Any]) -> bool:
    """A source target of a release: it has a tag, or is the placeholder of a release
    that could not be resolved (``git_ref`` is empty, which the default branch's is
    not).
    """
    return target.get("kind") == "fs" and (
        bool(target.get("tag")) or not target.get("git_ref")
    )


def baseline_differences(
    current: Mapping[str, Any], baseline: Mapping[str, Any]
) -> list[str]:
    """How the conditions of the two runs differ, so that a reader can judge the
    comparison: ``schema_version``, the SCA configuration (where it came from and what
    it says), the scanners, ``osv-enabled``, ``scan-release-source`` and whether the
    early warning ran. Everything is read from the two ``scan_report.json`` files, so a
    report of an older version works as a baseline.
    """
    reasons: list[str] = []
    if current.get("schema_version") != baseline.get("schema_version"):
        reasons.append(
            f"schema_version: {baseline.get('schema_version')} → "
            f"{current.get('schema_version')}"
        )
    now_config = {**DEFAULT_CONFIG, **(current.get("config") or {})}
    was_config = {**DEFAULT_CONFIG, **(baseline.get("config") or {})}
    if _config_source_kind(now_config) != _config_source_kind(was_config):
        reasons.append(
            f"config source: {_config_source_kind(was_config) or 'defaults'} → "
            f"{_config_source_kind(now_config) or 'defaults'}"
        )
    for key in ("non_shipped_paths", "trivy_skip_paths"):
        if now_config.get(key) != was_config.get(key):
            reasons.append(
                f"config {key}: {was_config.get(key)} → {now_config.get(key)}"
            )

    def scanners(report: Mapping[str, Any]) -> set[str]:
        return {t["scanner"] for t in report.get("targets") or []}

    now_scanners, was_scanners = scanners(current), scanners(baseline)
    if (now_scanners - {SCANNER_OSV}) != (was_scanners - {SCANNER_OSV}):
        reasons.append(
            f"scanners: {', '.join(sorted(was_scanners - {SCANNER_OSV}))} → "
            f"{', '.join(sorted(now_scanners - {SCANNER_OSV}))}"
        )
    if (SCANNER_OSV in now_scanners) != (SCANNER_OSV in was_scanners):
        reasons.append(
            f"osv-enabled: {_onoff(SCANNER_OSV in was_scanners)} → "
            f"{_onoff(SCANNER_OSV in now_scanners)}"
        )

    def release_sources(report: Mapping[str, Any]) -> bool:
        return any(_is_release_source(t) for t in report.get("targets") or [])

    if release_sources(current) != release_sources(baseline):
        reasons.append(
            f"scan-release-source: {_onoff(release_sources(baseline))} → "
            f"{_onoff(release_sources(current))}"
        )
    now_ew = current.get("early_warning") is not None
    was_ew = baseline.get("early_warning") is not None
    if now_ew != was_ew:
        reasons.append(f"early-warning-enabled: {_onoff(was_ew)} → {_onoff(now_ew)}")
    return reasons


# --------------------------------------------------------------------------
# What changed since the baseline run
# --------------------------------------------------------------------------

DIFF_SCHEMA_VERSION = 1
REPORT_FILE = "_report/scan_report.json"
VULNERABILITIES_FILE = "_report/vulnerabilities.json"
EARLY_WARNING_FILE = "_report/early_warning.json"
# The fields of a record or an early warning in the lists of diff.json
DIFF_RECORD_KEYS = (
    "repo",
    "cve",
    "pkg",
    "version",
    "severity",
    "fix_available",
    "upgrade_to",
    "exposure",
    "scan_targets",
)
DIFF_EARLY_WARNING_KEYS = ("cve", "package", "severity", "exposure", "scan_targets")
MAX_LISTED_RESOLVED = 20
EW_UNAVAILABLE = "unavailable"


class BaselineError(Exception):
    """The baseline cannot be used; the report is made without a diff."""


class Tools(NamedTuple):
    """What the diff takes from the merge (merge_results.py), which imports this
    module and so cannot be imported by it. ``merge_results.diff_tools()`` makes them.
    """

    canonical_package_name: Callable[[str | None, str | None], str | None]
    ecosystem_families: Mapping[str, str]
    python_family: str
    record_ids: Callable[[Mapping[str, Any]], set[str]]
    record_sort_key: Callable[[Record], Any]
    read_json: Callable[[Path], Any]
    dump_json: Callable[[Path, Any], None]
    md_cell: Callable[[Any], str]
    md_table: Callable[..., list[str]]
    md_details: Callable[..., list[str]]


@dataclass
class Baseline:
    """The ``sca-report`` of the baseline run."""

    report: dict[str, Any]
    records: list[Record]
    early_warning: dict[str, Any] | None


@dataclass
class EarlyWarningDiff:
    """The early warnings of a run against those of the baseline.

    ``status`` is ``ok`` or ``unavailable`` (``reason`` says why); the rest is only
    set when it is ``ok``.
    """

    status: str
    reason: str | None = None
    classification: Classification = field(default_factory=Classification)
    baseline_items: dict[tuple[Any, ...], Record] = field(default_factory=dict)
    # baseline early warnings whose CVE a database maps now, with those records
    confirmed: list[tuple[Record, list[Record]]] = field(default_factory=list)


@dataclass
class Diff:
    """What changed since the baseline run, or why that is not known."""

    tools: Tools
    repo: str | None
    baseline: Baseline | None
    reason: str | None = None
    differs: list[str] = field(default_factory=list)
    classification: Classification = field(default_factory=Classification)
    baseline_records: dict[tuple[Any, ...], Record] = field(default_factory=dict)
    early_warning: EarlyWarningDiff | None = None

    @property
    def resolved(self) -> list[Record]:
        return [self.baseline_records[k] for k in self.classification.resolved]

    def baseline_value(self, key: str) -> Any:
        return self.baseline.report.get(key) if self.baseline else None

    @property
    def counts(self) -> dict[str, Any] | None:
        if self.baseline is None:
            return None
        ew = self.early_warning
        return {
            **diff_counts(self.classification),
            "early_warning": {
                **diff_counts(ew.classification),
                "confirmed": len(ew.confirmed),
            }
            if ew and ew.status == STATUS_OK
            else None,
        }


def diff_counts(classification: Classification) -> dict[str, int]:
    return {
        "new": len(classification.new),
        "resolved": len(classification.resolved),
        "not_comparable": len(classification.not_comparable),
        "unchanged": len(classification.unchanged),
    }


def record_key(tools: Tools, record: Mapping[str, Any]) -> tuple[Any, ...]:
    """What identifies a record across runs: repository, CVE, package (compared the
    way merging does, so ``Mako`` and ``mako`` are one) and version.
    """
    python = any(
        tools.ecosystem_families.get(e) == tools.python_family
        for e in record.get("ecosystem") or []
    )
    return (
        record.get("repo"),
        record.get("cve"),
        tools.canonical_package_name(record.get("pkg"), "poetry" if python else None),
        record.get("version"),
    )


def early_warning_key(repo: str | None, entry: Mapping[str, Any]) -> tuple[Any, ...]:
    package = entry.get("package") or {}
    return (repo, entry.get("cve"), package.get("name"), package.get("version"))


def load_baseline(tools: Tools, baseline_dir: Path | None) -> Baseline:
    """Read the ``sca-report`` of the baseline run; raises BaselineError."""
    if baseline_dir is None or not (baseline_dir / REPORT_FILE).is_file():
        raise BaselineError("no baseline report was provided")
    early_warning_path = baseline_dir / EARLY_WARNING_FILE
    try:
        report = tools.read_json(baseline_dir / REPORT_FILE)
        vulnerabilities = tools.read_json(baseline_dir / VULNERABILITIES_FILE)
        early_warning = (
            tools.read_json(early_warning_path)
            if early_warning_path.is_file()
            else None
        )
    except (OSError, ValueError) as e:
        raise BaselineError(f"the baseline report is unreadable: {e}") from e
    records = (
        vulnerabilities.get("records") if isinstance(vulnerabilities, dict) else None
    )
    targets = report.get("targets") if isinstance(report, dict) else None
    if (
        not isinstance(targets, list)
        or not isinstance(records, list)
        or not all(isinstance(r, dict) for r in records)
        or not all(isinstance(t, dict) and "id" in t for t in targets)
        or (early_warning is not None and not isinstance(early_warning, dict))
    ):
        raise BaselineError("the baseline report is not valid")
    return Baseline(report, records, early_warning)


def early_warning_diff(
    tools: Tools,
    repo: str | None,
    baseline: Baseline,
    early_warning: EarlyWarning | None,
    records: Sequence[Record],
    current_ok: Mapping[str, bool],
    baseline_ok: Mapping[str, bool],
) -> EarlyWarningDiff | None:
    """The early warnings against those of the baseline; None if this run has none.

    ``confirmed``: a baseline early warning whose CVE (or alias) is a record now, so a
    database maps it. It is a live measure of how good the early warning is, and it is
    not also ``resolved``.
    """
    if early_warning is None:
        return None
    if early_warning.report["status"] != STATUS_OK:
        return EarlyWarningDiff(EW_UNAVAILABLE, "the early warning of this run failed")
    if (baseline.early_warning or {}).get("status") != STATUS_OK:
        return EarlyWarningDiff(EW_UNAVAILABLE, "the baseline has no early warning")
    known: dict[str, list[Record]] = {}
    for record in records:
        for ident in tools.record_ids(record):
            if ident:
                known.setdefault(ident.upper(), []).append(record)
    result = EarlyWarningDiff(STATUS_OK)
    for entry in (baseline.early_warning or {}).get("entries") or []:
        mapped: dict[int, Record] = {}
        for ident in (entry.get("cve"), *(entry.get("aliases") or [])):
            for record in known.get((ident or "").upper(), []):
                mapped[id(record)] = record
        if mapped:
            result.confirmed.append((entry, list(mapped.values())))
        else:
            result.baseline_items[early_warning_key(repo, entry)] = entry
    result.classification = classify(
        {early_warning_key(repo, e): e["scan_targets"] for e in early_warning.entries},
        {k: e.get("scan_targets") or [] for k, e in result.baseline_items.items()},
        current_ok,
        baseline_ok,
    )
    return result


def build_diff(
    tools: Tools,
    repo: str | None,
    baseline_dir: Path | None,
    baseline_reason: str,
    targets: Sequence[Mapping[str, Any]],
    report: Mapping[str, Any],
    records: Sequence[Record],
    early_warning: EarlyWarning | None,
) -> Diff:
    """Compare the records and the early warnings of this run with the baseline.

    ``targets`` are the targets of this run with their final status, ``report`` is its
    ``scan_report.json`` without ``diff``. A baseline that is missing, unreadable or of
    another repository leaves the run without a diff but with the reason (the
    ``baseline_reason`` of the step that looked for it, if it provided none); it never
    fails the merge.
    """
    try:
        baseline = load_baseline(tools, baseline_dir)
        if baseline.report.get("repo") != repo:
            raise BaselineError(
                f"the baseline is a report of {baseline.report.get('repo')}, not {repo}"
            )
        if baseline.report.get("run_id") == report.get("run_id"):
            raise BaselineError("the baseline is this very run")
    except BaselineError as e:
        reason = baseline_reason.strip() or str(e)
        return Diff(tools, repo, None, reason)
    current_ok = target_states(targets)
    baseline_ok = target_states(baseline.report["targets"])
    was = {record_key(tools, r): r for r in baseline.records}
    classification = classify(
        {record_key(tools, r): r["scan_targets"] for r in records},
        {k: r.get("scan_targets") or [] for k, r in was.items()},
        current_ok,
        baseline_ok,
    )
    return Diff(
        tools,
        repo,
        baseline,
        None,
        baseline_differences(report, baseline.report),
        classification,
        was,
        early_warning_diff(
            tools, repo, baseline, early_warning, records, current_ok, baseline_ok
        ),
    )


def annotate_diff(
    diff: Diff, records: Sequence[Record], early_warning: EarlyWarning | None
) -> None:
    """Set ``diff`` on every record and early warning: ``new``, ``unchanged`` or
    ``not_comparable``; ``baseline`` where there is nothing to compare with (no
    baseline, or no early warning diff), so that nothing is called new.
    """
    states = diff.classification.states
    for record in records:
        record["diff"] = states.get(record_key(diff.tools, record), BASELINE)
    if early_warning is None:
        return
    ew = diff.early_warning
    ew_states = ew.classification.states if ew and ew.status == STATUS_OK else {}
    for entry in early_warning.entries:
        entry["diff"] = ew_states.get(early_warning_key(diff.repo, entry), BASELINE)
    for item, entry in zip(
        early_warning.document["entries"], early_warning.entries, strict=True
    ):
        item["diff"] = entry["diff"]


def attach_diff(
    tools: Tools,
    repo: str | None,
    baseline_dir: Path | None,
    baseline_reason: str,
    scan_report: dict[str, Any],
    records: Sequence[Record],
    early_warning: EarlyWarning | None,
) -> Diff:
    """Compare the run with the baseline and put the result where the reports have
    it: ``scan_report.json: diff`` and ``diff`` on every record and early warning.
    ``scan_report`` is the report of the run without ``diff``.
    """
    diff = build_diff(
        tools,
        repo,
        baseline_dir,
        baseline_reason,
        scan_report["targets"],
        scan_report,
        records,
        early_warning,
    )
    scan_report["diff"] = build_diff_summary(diff)
    annotate_diff(diff, records, early_warning)
    return diff


def write_diff(
    report_dir: Path,
    diff: Diff,
    records: Sequence[Record],
    early_warning: EarlyWarning | None,
    generated_utc: str,
) -> None:
    """Write ``_report/diff.json``; say if there is no baseline to compare with."""
    diff.tools.dump_json(
        report_dir / "diff.json",
        build_diff_document(diff, records, early_warning, generated_utc),
    )
    if diff.baseline is None:
        print(f"::notice title=No baseline::{diff.reason}")


def diff_record_item(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record.get(key) for key in DIFF_RECORD_KEYS}


def diff_early_warning_item(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {key: entry.get(key) for key in DIFF_EARLY_WARNING_KEYS}


def not_comparable_items(
    classification: Classification,
    current: Mapping[tuple[Any, ...], Mapping[str, Any]],
    baseline: Mapping[tuple[Any, ...], Mapping[str, Any]],
    item: Callable[[Mapping[str, Any]], dict[str, Any]],
) -> list[dict[str, Any]]:
    """The items that may or may not have changed, with the targets that tell."""
    return [
        {
            **item(current[n.key] if n.direction == APPEARED else baseline[n.key]),
            "direction": n.direction,
            "targets": n.targets,
        }
        for n in classification.not_comparable
    ]


def build_diff_document(
    diff: Diff,
    records: Sequence[Record],
    early_warning: EarlyWarning | None,
    generated_utc: str,
) -> dict[str, Any]:
    """``_report/diff.json``: what changed since the baseline run.

    Without a baseline ``baseline`` is null, ``reason`` says why and the lists are
    empty: a consumer must not take the records of such a run for new ones.
    """
    document: dict[str, Any] = {
        "schema_version": DIFF_SCHEMA_VERSION,
        "repo": diff.repo,
        "generated_utc": generated_utc,
        "baseline": None,
        "reason": diff.reason,
        "baseline_differs": diff.differs,
        "new": [],
        "resolved": [],
        "not_comparable": [],
        "unchanged": None,
        "early_warning": None,
    }
    if diff.baseline is None:
        return document
    report = diff.baseline.report
    current = {record_key(diff.tools, r): r for r in records}
    classification = diff.classification
    document.update(
        baseline={
            "run_id": report.get("run_id"),
            "run_url": report.get("run_url"),
            "run_started_at": report.get("run_started_at"),
            "commit_sha": report.get("commit_sha"),
        },
        new=[diff_record_item(current[k]) for k in classification.new],
        resolved=[diff_record_item(r) for r in diff.resolved],
        not_comparable=not_comparable_items(
            classification, current, diff.baseline_records, diff_record_item
        ),
        unchanged=len(classification.unchanged),
    )
    ew = diff.early_warning
    if ew is None or early_warning is None:
        return document
    if ew.status != STATUS_OK:
        document["early_warning"] = {"status": ew.status, "reason": ew.reason}
        return document
    now = {early_warning_key(diff.repo, e): e for e in early_warning.entries}
    document["early_warning"] = {
        "status": STATUS_OK,
        "reason": None,
        "new": [diff_early_warning_item(now[k]) for k in ew.classification.new],
        "resolved": [
            diff_early_warning_item(ew.baseline_items[k])
            for k in ew.classification.resolved
        ],
        "not_comparable": not_comparable_items(
            ew.classification, now, ew.baseline_items, diff_early_warning_item
        ),
        "unchanged": len(ew.classification.unchanged),
        "confirmed": [
            {
                **diff_early_warning_item(entry),
                "records": [
                    {k: r.get(k) for k in ("cve", "pkg", "version", "severity")}
                    for r in mapped
                ],
            }
            for entry, mapped in ew.confirmed
        ],
    }
    return document


def build_diff_summary(diff: Diff) -> dict[str, Any]:
    """``scan_report.json: diff``."""
    return {
        "baseline_run_id": diff.baseline_value("run_id"),
        "baseline_started_at": diff.baseline_value("run_started_at"),
        "counts": diff.counts,
        "baseline_differs": diff.differs,
        "reason": diff.reason,
    }


# --------------------------------------------------------------------------
# summary.md: what changed since the baseline
# --------------------------------------------------------------------------


def new_suffix(items: Sequence[Mapping[str, Any]]) -> str:
    """` · new` for records (or early warnings) that appeared since the baseline,
    ` · 2 new` if only some of a group did; nothing without a baseline.
    """
    new = sum(item.get("diff") == NEW for item in items)
    if not new:
        return ""
    return " · new" if new == len(items) else f" · {new} new"


def early_warning_diff_text(ew: EarlyWarningDiff | None) -> str | None:
    """The early warning part of the diff line, nothing if it did not change."""
    if ew is None or ew.status != STATUS_OK:
        return None
    parts = [
        f"{count} {name}"
        for count, name in (
            (len(ew.classification.new), "new"),
            (len(ew.classification.resolved), "resolved"),
            (len(ew.confirmed), "confirmed"),
        )
        if count
    ]
    return f"early warnings: {', '.join(parts)}" if parts else None


def diff_line(diff: Diff) -> str:
    """`Since 2026-10-05 (run 20): +2 new · −1 resolved · 3 not comparable`, or why
    there is nothing to compare with.
    """
    if diff.baseline is None:
        return f"No baseline to compare with: {diff.tools.md_cell(diff.reason)}"
    counts = diff_counts(diff.classification)
    started = (diff.baseline_value("run_started_at") or "")[:10]
    run_id, run_url = diff.baseline_value("run_id"), diff.baseline_value("run_url")
    label = f"run {run_id}" if run_id else "run"
    run = f"[{label}]({run_url})" if run_url else label
    since = f"Since {started}" if started else "Since the baseline"
    text = f"{since} ({run}): +{counts['new']} new · −{counts['resolved']} resolved"
    if counts["not_comparable"]:
        text += f" · {counts['not_comparable']} not comparable"
    if warning := early_warning_diff_text(diff.early_warning):
        text += f" · {warning}"
    if diff.differs:
        text += f" · baseline made under other conditions: {'; '.join(diff.differs)}"
    return text


def early_warning_text(entry: Mapping[str, Any]) -> str:
    package = entry.get("package") or {}
    return f"{entry.get('cve')} ({package.get('name')} {package.get('version')})"


def render_resolved(diff: Diff | None) -> list[str]:
    """A short collapsed list of what is gone since the baseline: records, early
    warnings that are gone, and early warnings that a database confirmed. Nothing if
    nothing is.
    """
    if diff is None or diff.baseline is None:
        return []
    resolved = sorted(diff.resolved, key=diff.tools.record_sort_key)
    ew = diff.early_warning
    if ew is not None and ew.status != STATUS_OK:
        ew = None
    gone = [ew.baseline_items[k] for k in ew.classification.resolved] if ew else []
    confirmed = [entry for entry, _ in ew.confirmed] if ew else []
    if not (resolved or gone or confirmed):
        return []
    started = (diff.baseline_value("run_started_at") or "")[:10] or "the baseline"
    body: list[str] = []
    if resolved:
        rows = [
            [
                r.get("cve"),
                f"{r.get('pkg')} {r.get('version')}",
                r.get("severity"),
                str(r.get("exposure") or "").replace("_", " "),
                ", ".join(r.get("scan_targets") or []),
            ]
            for r in resolved[:MAX_LISTED_RESOLVED]
        ]
        body += diff.tools.md_table(
            ["CVE", "Package", "Severity", "Was", "Where"], rows
        )
        if len(resolved) > MAX_LISTED_RESOLVED:
            more = len(resolved) - MAX_LISTED_RESOLVED
            body += ["", f"+{more} more, see `_report/diff.json`"]
    for title, entries in (
        ("Early warnings that a database reports now", confirmed),
        ("Early warnings that are gone", gone),
    ):
        if entries:
            shown = ", ".join(early_warning_text(e) for e in entries)
            body += [*([""] if body else []), f"{title}: {diff.tools.md_cell(shown)}"]
    summary = (
        f"Resolved since {started} ({len(resolved)})"
        if resolved
        else f"Early warnings resolved since {started}"
    )
    return ["", *diff.tools.md_details(summary, body)]
