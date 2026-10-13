"""The records of one repository: Trivy and OSV scans merged into them."""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import Any, NamedTuple

from osv_source import (
    OsvScan,
    OsvVulnerability,
    PackageSighting,
    new_osv_record,
    osv_primary_id,
)
from records import (
    SCANNER_OSV,
    FindingKey,
    Record,
    Sightings,
    absorb_sighting,
    append_unique,
    cve_of,
    record_ids,
)
from trivy_source import (
    DependencyInfo,
    PackageIndex,
    absorb_finding,
    canonical_package_name,
    combine_dependency_info,
    finding_key,
    fixed_in_place,
    iter_findings,
    new_record,
    package_dev_flag,
    package_relationships,
)


class MergeResult(NamedTuple):
    """What the merge knows: the records, where each was seen and which are fixed in
    place (see ``fixed_in_place``); the last two are keyed by ``(id, pkg, version)``.
    """

    records: list[Record]
    sightings: Sightings
    fixed_in_place: frozenset[tuple[Any, Any, Any]]


class RecordSet:
    """The records of one repository while the scans are merged into them.

    Trivy findings are added first, as they create the records; OSV findings then
    join them (``add_osv``) or, where Trivy does not know the vulnerability, create
    records of their own. ``finish`` completes and returns the records.
    """

    def __init__(self, repo: str | None, image_ids: Collection[str] = ()) -> None:
        self.repo = repo
        self.image_ids = image_ids
        self.by_key: dict[FindingKey, Record] = {}
        self.sightings: dict[FindingKey, dict[str, list[str]]] = {}
        # (canonical package name, version) -> keys of the records of the package
        self.by_package: dict[tuple[str | None, str | None], list[FindingKey]] = {}
        self._target_order: dict[str, int] = {}
        self._named_by_image: set[FindingKey] = set()
        self._dev_packages: dict[FindingKey, list[Mapping[str, Any]]] = {}
        self._chains: dict[FindingKey, dict[tuple[Any, Any], DependencyInfo]] = {}
        # key -> whether every sighting found the fix in the package's own file
        self._in_place: dict[FindingKey, bool] = {}

    def _add_record(self, key: FindingKey, record: Record) -> None:
        self.by_key[key] = record
        self.by_package.setdefault((key[1], key[2]), []).append(key)

    def _note_packages(
        self,
        key: FindingKey,
        tid: str,
        pkg_name: str | None,
        result: Mapping[str, Any],
        packages: Sequence[Mapping[str, Any]],
        index: PackageIndex,
    ) -> None:
        """Remember the packages of a sighting: display name, dev flag, chains and
        where the record was seen.
        """
        if tid in self.image_ids and key not in self._named_by_image:
            self._named_by_image.add(key)
            self.by_key[key]["pkg"] = pkg_name
        self._in_place[key] = self._in_place.get(key, True) and fixed_in_place(
            packages, self.by_key[key]["fixed_versions"], index
        )
        self._dev_packages.setdefault(key, []).extend(packages)
        for package in packages:
            # one chain set per package of a lockfile, however many targets saw it
            sighting = (result.get("Target"), package.get("ID") or package.get("Name"))
            self._chains.setdefault(key, {})[sighting] = index.dependency_info(package)
        append_unique(
            self.sightings.setdefault(key, {}).setdefault(tid, []),
            result.get("Target", ""),
        )

    def _position(self, tid: str) -> int:
        """The place of a target in the targets file (the order it was added in)."""
        return self._target_order.setdefault(tid, len(self._target_order))

    def add_trivy(self, tid: str, scanner: str, native: Mapping[str, Any]) -> None:
        self._position(tid)
        for result, vuln, packages, index in iter_findings(native):
            key = finding_key(result, vuln)
            record = self.by_key.get(key)
            if record is None:
                record = new_record(self.repo, key, result, vuln)
                self._add_record(key, record)
            absorb_finding(
                record, tid, scanner, result, vuln, package_relationships(packages)
            )
            self._note_packages(key, tid, vuln.get("PkgName"), result, packages, index)

    def add_osv(self, scan: OsvScan) -> None:
        """Merge the findings of one OSV target into the records.

        Per package, the ids osv-scanner grouped by their aliases are one
        vulnerability (``OsvVulnerability``). It joins every record of the same
        package version that it shares an id with (the record's ``id`` or an
        alias): the record gains the ``osv`` scanner, the ids and where OSV saw
        it, and keeps everything Trivy said. A vulnerability no record has
        becomes a record of its own, whose package context comes from the Trivy
        package OSV looked at.
        """
        self._position(scan.tid)
        for package in sorted(scan.packages, key=lambda p: p.key):
            for vulnerability in package.vulnerabilities:
                for found in scan.sightings[package.key]:
                    self._add_osv_finding(
                        scan.tid, package.identity, vulnerability, found
                    )

    def _add_osv_finding(
        self,
        tid: str,
        identity: tuple[str, str],
        vulnerability: OsvVulnerability,
        found: PackageSighting,
    ) -> None:
        result, package, index = found
        name = canonical_package_name(package.get("Name"), result.get("Type"))
        version = package.get("Version")
        matched = [
            key
            for key in self.by_package.get((name, version), [])
            if vulnerability.names & record_ids(self.by_key[key])
        ]
        if not matched:
            key = (osv_primary_id(vulnerability), name, version)
            self._add_record(
                key, new_osv_record(self.repo, key, identity, vulnerability, found)
            )
            matched = [key]
        # Ids of the vulnerability that are the id of one of the matched records
        # stay out of the aliases of the others
        ids = {self.by_key[key]["id"] for key in matched}
        packages = [package]
        for key in matched:
            record = self.by_key[key]
            for alias in sorted(vulnerability.names - ids):
                append_unique(record["aliases"], alias)
            absorb_sighting(
                record, tid, SCANNER_OSV, result, package_relationships(packages)
            )
            self._note_packages(key, tid, package.get("Name"), result, packages, index)

    def finish(self) -> MergeResult:
        """The records, completed, and what is known of them (see ``merge_records``)."""
        for key, record in self.by_key.items():
            for name in (
                "locations",
                "scanners",
                "ecosystem",
                "relationship",
                "aliases",
            ):
                record[name].sort()
            record["pkg_paths"].sort()
            record["cve"] = cve_of(record)
            # OSV may have added targets after the Trivy ones: back to targets order
            record["scan_targets"].sort(key=self._target_order.__getitem__)
            record["dev"] = package_dev_flag(self._dev_packages.get(key, []))
            (
                record["dependency_paths"],
                record["dependency_paths_total"],
                record["dependency_paths_truncated"],
                record["introduced_via"],
            ) = combine_dependency_info(self._chains.get(key, {}).values())
        by_record = {
            (r["id"], r["pkg"], r["version"]): self.sightings[key]
            for key, r in self.by_key.items()
        }
        in_place = frozenset(
            (r["id"], r["pkg"], r["version"])
            for key, r in self.by_key.items()
            if self._in_place.get(key)
        )
        return MergeResult(list(self.by_key.values()), by_record, in_place)


def merge_records(
    repo: str | None,
    scans: Iterable[tuple[str, str, Mapping[str, Any]]],
    image_ids: Collection[str] = (),
    osv_scans: Iterable[OsvScan] = (),
) -> MergeResult:
    """Deduplicate findings across lockfiles and merge them across targets.

    ``scans`` is ``(target id, scanner, native JSON)`` of the Trivy targets in
    targets-file order, which is also the order of each record's ``scan_targets``;
    ``osv_scans`` are the OSV targets, merged into the Trivy records. Returns the
    records (unordered, not enriched yet), where each finding was seen and which
    findings are fixed in place, keyed by ``(id, pkg, version)`` of the record. A
    package seen under several spellings (see ``canonical_package_name``) is shown
    under the spelling of its first image record, else of its first record.
    """
    record_set = RecordSet(repo, image_ids)
    for tid, scanner, native in scans:
        record_set.add_trivy(tid, scanner, native)
    for osv_scan in osv_scans:
        record_set.add_osv(osv_scan)
    return record_set.finish()
