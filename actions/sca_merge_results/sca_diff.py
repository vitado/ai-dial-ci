"""What changed since the baseline run: the pure part of the diff of an SCA report.

The merge (merge_results.py) compares the records and the early warnings of a run with
those of a baseline run, the latest full run of the same workflow on the default
branch. This module holds what does not depend on the report format of the records:
the state of the targets of a run, the classification of keyed items, and the
differences in the conditions under which two runs were made.

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

from collections.abc import Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

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
