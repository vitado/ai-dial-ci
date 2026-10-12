"""Tests for actions/sca_early_warning/early_warning.py (synthetic data, fake HTTP)."""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import zipfile
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2030, 1, 10, 12, 30, 0, tzinfo=UTC)
FEED = "https://feed.example/releases/download"
DEPSDEV = "https://deps.example"


def _load_early_warning():
    path = ROOT / "actions" / "sca_early_warning" / "early_warning.py"
    spec = importlib.util.spec_from_file_location("early_warning", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


ew = _load_early_warning()


# --- builders -------------------------------------------------------------------


def pkg(ecosystem: str, name: str, version: str) -> Any:
    return ew.Package(ecosystem, name, version)


def inventory(*packages: Any, target: str = "source-development") -> Any:
    inv = ew.Inventory()
    for package in packages:
        inv.sightings[package] = {target: {"package-lock.json"}}
    inv.targets_read = 1
    return inv


def index_of(inv: Any, repos: Mapping[tuple[str, str], tuple[str, ...]] = ()) -> Any:
    return ew.build_index(inv, dict(repos))


def cna(**fields: Any) -> dict[str, Any]:
    return fields


def affected(
    *versions: dict[str, Any], default: str = "unaffected", **entry: Any
) -> dict[str, Any]:
    return {"defaultStatus": default, "versions": list(versions), **entry}


def below(limit: str, start: str = "0", version_type: str = "semver") -> dict[str, Any]:
    return {
        "version": start,
        "lessThan": limit,
        "status": "affected",
        "versionType": version_type,
    }


def record(
    cve: str = "CVE-2030-0001",
    entries: list[dict[str, Any]] | None = None,
    refs: tuple[str, ...] = (),
    title: str = "A title",
    description: str = "A description",
    metrics: dict[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "cve": cve,
        "state": "PUBLISHED",
        "published": "2030-01-05T10:00:00.000Z",
        "updated": "2030-01-06T10:00:00.000Z",
        "assigner": "ExampleCNA",
        "title": title,
        "description": description,
        "affected": entries or [],
        "references": list(refs),
        "metrics": metrics or {"cvss": [], "exploitation": None},
        **extra,
    }


def match(
    records: list[dict[str, Any]],
    inv: Any,
    repos: Mapping[Any, Any] = (),
    cnas: Mapping[str, Mapping[str, int]] | None = None,
) -> Any:
    return ew.match_records(records, index_of(inv, repos), inv, cnas or {})


def found(result: Any) -> set[tuple[str, str, str, str]]:
    return {
        (c["cve"], c["package"]["name"], c["package"]["version"], c["rule"])
        for c in result.candidates
    }


# --- versions -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.2.3", "1.2.3", 0),
        ("1.2.3", "1.10.0", -1),
        ("v2.0.0", "2.0", 0),
        ("1.0.0-alpha", "1.0.0", -1),
        ("1.0.0-alpha.2", "1.0.0-alpha.10", -1),
        ("1.0.0-alpha.1", "1.0.0-alpha", 1),
        ("1.0.0-alpha", "1.0.0-beta", -1),
        ("1.0.0-1", "1.0.0-alpha", -1),
        ("1.0.0+build.5", "1.0.0", 0),
        ("1.2.3.4", "1.2.3", None),
        ("latest", "1.0.0", None),
    ],
)
def test_semver_comparison(a: str, b: str, expected: int | None) -> None:
    assert ew.compare_versions("npm", a, b) == expected
    assert ew.compare_versions("cargo", a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0.0", 0),
        ("1.0rc1", "1.0", -1),
        ("1.0a1", "1.0b1", -1),
        ("1.0b2", "1.0rc1", -1),
        ("1.0.dev1", "1.0a1", -1),
        ("1.0", "1.0.post1", -1),
        ("1.0.post1", "1.1", -1),
        ("1.0-1", "1.0.post1", 0),
        ("1!0.5", "2.0", 1),
        ("1.0+local.1", "1.0", 0),
        ("1.0.rc.1", "1.0c1", 0),
        ("2.10", "2.9", 1),
        ("1.0.post1.dev1", "1.0.post1", -1),
        ("not a version", "1.0", None),
    ],
)
def test_pep440_comparison(a: str, b: str, expected: int | None) -> None:
    assert ew.compare_versions("pypi", a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0.0", 0),
        ("1", "1.0.0.0", 0),
        ("33.4.8-jre", "33.7.2", -1),
        ("33.7.2-jre", "33.7.2", 1),
        ("33.7.2-android", "33.7.2-jre", -1),
        ("1.0-alpha-1", "1.0-beta-1", -1),
        ("1.0-beta-1", "1.0-rc-1", -1),
        ("1.0-rc1", "1.0-SNAPSHOT", -1),
        ("1.0-SNAPSHOT", "1.0", -1),
        ("1.0", "1.0-sp1", -1),
        ("1.0-ga", "1.0", 0),
        ("1.0.Final", "1.0", 0),
        ("1.0-cr1", "1.0-rc1", 0),
        ("1.0a1", "1.0-alpha-1", 0),
        ("1.10", "1.9", 1),
        ("1.0.1", "1.0-1", 1),
        ("2.9.10.8", "2.9.10", 1),
        ("1.85", "1.86", -1),
        ("1.0-milestone-2", "1.0-m2", 0),
        ("no-digits", "1.0", None),
    ],
)
def test_maven_comparison(a: str, b: str, expected: int | None) -> None:
    assert ew.compare_versions("maven", a, b) == expected
    if expected is not None:
        assert ew.compare_versions("maven", b, a) == -expected


def test_other_ecosystems_are_not_compared() -> None:
    assert ew.compare_versions("golang", "1.0.0", "1.0.1") is None


# --- affected versions ----------------------------------------------------------


@pytest.mark.parametrize(
    ("ecosystem", "version", "entry", "expected"),
    [
        ("maven", "33.4.8-jre", affected(below("33.7.2", "4.0")), "affected"),
        ("maven", "33.7.2", affected(below("33.7.2", "4.0")), "not_affected"),
        ("maven", "1.0.2", affected(below("33.7.2", "4.0")), "not_affected"),
        ("npm", "1.0.0", affected(below("1.0.1")), "affected"),
        (
            "npm",
            "1.0.1",
            affected(
                {
                    "version": "1.0.0",
                    "lessThanOrEqual": "1.0.1",
                    "status": "affected",
                    "versionType": "semver",
                }
            ),
            "affected",
        ),
        (
            "npm",
            "2.0.0",
            affected({"version": "1.0.0", "status": "affected"}),
            "not_affected",
        ),
        (
            "npm",
            "1.0.0",
            affected({"version": "1.0.0", "status": "affected"}),
            "affected",
        ),
        # an unbounded upper end
        (
            "npm",
            "9.0.0",
            affected(
                {"version": "1.0.0", "lessThan": "*", "status": "affected"},
            ),
            "affected",
        ),
        # nothing listed: the default status speaks for every version
        ("npm", "1.0.0", affected(default="affected"), "affected_all"),
        ("npm", "1.0.0", affected(default="unaffected"), "unknown"),
        # defaultStatus affected, a range that is unaffected
        (
            "npm",
            "2.0.0",
            affected(
                {"version": "2.0.0", "status": "unaffected", "versionType": "semver"},
                default="affected",
            ),
            "not_affected",
        ),
        (
            "npm",
            "1.0.0",
            affected(
                {"version": "2.0.0", "status": "unaffected", "versionType": "semver"},
                default="affected",
            ),
            "affected",
        ),
        # git ranges and commit hashes cannot be compared
        ("npm", "1.0.0", affected(below("2.0.0", version_type="git")), "unknown"),
        ("npm", "1.0.0", affected(below("a" * 40)), "unknown"),
        # a version the scheme cannot parse
        ("npm", "1.0.0", affected(below("next")), "unknown"),
        # the changes of an item
        (
            "npm",
            "1.5.0",
            affected(
                {
                    "version": "1.0.0",
                    "status": "affected",
                    "changes": [{"at": "1.4.0", "status": "unaffected"}],
                }
            ),
            "not_affected",
        ),
        (
            "npm",
            "1.3.0",
            affected(
                {
                    "version": "1.0.0",
                    "status": "affected",
                    "changes": [{"at": "1.4.0", "status": "unaffected"}],
                }
            ),
            "affected",
        ),
        # free text (GitHub CNA style)
        (
            "npm",
            "2.13.0",
            affected({"version": "< 2.14.0", "status": "affected"}),
            "affected",
        ),
        (
            "npm",
            "2.14.0",
            affected({"version": "< 2.14.0", "status": "affected"}),
            "not_affected",
        ),
        (
            "npm",
            "6.30.0",
            affected({"version": "7.0.0 < 7.24.0; < 6.24.0", "status": "affected"}),
            "not_affected",
        ),
        (
            "npm",
            "7.1.0",
            affected({"version": "7.0.0 < 7.24.0; < 6.24.0", "status": "affected"}),
            "affected",
        ),
        (
            "npm",
            "1.2.0",
            affected({"version": ">= 1.0, < 1.5", "status": "affected"}),
            "affected",
        ),
        (
            "npm",
            "1.2.0",
            affected({"version": "<< what", "status": "affected"}),
            "unknown",
        ),
    ],
)
def test_entry_status(
    ecosystem: str, version: str, entry: dict[str, Any], expected: str
) -> None:
    assert ew.entry_status(ecosystem, version, entry) == expected


def test_range_is_described_as_the_cna_gave_it() -> None:
    assert ew.describe_range(affected(below("33.7.2", "4.0"))) == ">= 4.0, < 33.7.2"
    assert ew.describe_range(affected(below("1.86"))) == "< 1.86"
    assert (
        ew.describe_range(
            affected({"version": "1.0.0", "status": "affected"}),
        )
        == "= 1.0.0"
    )
    assert ew.describe_range(
        affected({"version": "< 2.14.0", "status": "affected"})
    ) == ("< 2.14.0")
    assert ew.describe_range(affected(default="affected")) == "all versions"
    assert (
        ew.describe_range(
            affected(
                {
                    "version": "1.0.0",
                    "status": "affected",
                    "changes": [{"at": "1.4.0", "status": "unaffected"}],
                }
            )
        )
        == "= 1.0.0 (fixed in 1.4.0)"
    )


# --- names and repositories -----------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/Google/Guava", "github.com/google/guava"),
        ("https://www.github.com/google/guava.git", "github.com/google/guava"),
        ("git+https://github.com/google/guava.git", "github.com/google/guava"),
        ("git@github.com:google/guava.git", "github.com/google/guava"),
        ("ssh://git@github.com/google/guava", "github.com/google/guava"),
        (
            "https://github.com/google/guava/tree/master/guava",
            "github.com/google/guava",
        ),
        ("https://github.com/google/guava/", "github.com/google/guava"),
        ("github.com/google/guava#readme", "github.com/google/guava"),
        (
            "github.com:open-telemetry/opentelemetry-java",
            "github.com/open-telemetry/opentelemetry-java",
        ),
        ("", None),
        (None, None),
    ],
)
def test_normalize_repo(url: Any, expected: str | None) -> None:
    assert ew.normalize_repo(url) == expected


def test_normalize_name() -> None:
    assert ew.normalize_name("pypi", "Foo_Bar.baz") == "foo-bar-baz"
    assert ew.normalize_name("cargo", "Foo_Bar") == "foo-bar"
    assert ew.normalize_name("maven", "Org.X/Art") == "org.x:art"
    assert ew.normalize_name("npm", "@Scope/Name") == "@scope/name"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://registry.npmjs.org/", "npm"),
        ("https://www.npmjs.com/package/x", "npm"),
        ("https://pypi.org/project/x", "pypi"),
        ("https://repo.maven.apache.org/maven2/", "maven"),
        ("https://crates.io/crates/x", "cargo"),
        ("https://github.com/apache/maven", None),
        ("https://gitlab.com/x/y", None),
        ("https://access.redhat.com/x", "other"),
        ("https://wordpress.org/plugins/x", "other"),
        ("https://pkg.go.dev/github.com/x/y", "other"),
        ("https://unknown.example/x", None),
        (None, None),
    ],
)
def test_registry_ecosystem(url: str | None, expected: str | None) -> None:
    assert ew.registry_ecosystem(url) == expected


def test_url_points_at_repo_by_whole_path_segments() -> None:
    repo = "github.com/google/guava"
    assert ew.url_points_at_repo("https://github.com/google/guava", repo)
    assert ew.url_points_at_repo("https://github.com/Google/guava/", repo)
    assert ew.url_points_at_repo(
        "https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94", repo
    )
    assert not ew.url_points_at_repo("https://github.com/google/guava-testlib", repo)
    assert not ew.url_points_at_repo("https://github.com/google", repo)
    assert not ew.url_points_at_repo(
        "https://example.com/github.com/google/guava", repo
    )


def test_purl_of_supported_ecosystems() -> None:
    assert ew.parse_purl("pkg:maven/com.google.guava/guava@33.4.8-jre") == pkg(
        "maven", "com.google.guava:guava", "33.4.8-jre"
    )
    assert ew.parse_purl("pkg:npm/%40nestjs/common@10.0.0") == pkg(
        "npm", "@nestjs/common", "10.0.0"
    )
    assert ew.parse_purl("pkg:pypi/requests@2.0.0?arch=x") == pkg(
        "pypi", "requests", "2.0.0"
    )
    assert ew.parse_purl("pkg:cargo/serde@1.0.0") == pkg("cargo", "serde", "1.0.0")
    assert ew.parse_purl("pkg:golang/github.com/x/y@v1.0.0") is None
    assert ew.parse_purl("pkg:deb/debian/zlib@1.2?distro=x") is None
    assert ew.parse_purl("pkg:npm/lodash") is None


# --- the matcher ----------------------------------------------------------------

GUAVA = pkg("maven", "com.google.guava:guava", "33.4.8-jre")
FAILUREACCESS = pkg("maven", "com.google.guava:failureaccess", "1.0.3")
LISTENABLE = pkg("maven", "com.google.guava:listenablefuture", "9999.0-empty")
GUAVA_REPO = "github.com/google/guava"
GUAVA_REPOS = {
    ("maven", p.name): (GUAVA_REPO,) for p in (GUAVA, FAILUREACCESS, LISTENABLE)
}


def test_t2_repo_with_the_artifact_named_by_product() -> None:
    entry = cna(
        vendor="Google",
        product="Guava",
        repo="https://github.com/google/guava",
        **affected(below("33.7.2", "4.0")),
    )
    result = match(
        [record(entries=[entry])],
        inventory(GUAVA, FAILUREACCESS, LISTENABLE),
        GUAVA_REPOS,
    )
    assert found(result) == {("CVE-2030-0001", GUAVA.name, GUAVA.version, "T2")}
    # the other artifacts of the repository are out: the product is the repository
    # and the text does not name them
    assert result.outcomes["module_unknown"] == 2
    assert result.candidates[0]["affected_range"] == ">= 4.0, < 33.7.2"


def test_t2_without_the_product_check_the_repository_would_match_every_artifact() -> (
    None
):
    entry = cna(
        vendor="Google",
        repo="https://github.com/google/guava",
        **affected(below("99")),
    )
    result = match(
        [record(entries=[entry])], inventory(GUAVA, FAILUREACCESS), GUAVA_REPOS
    )
    assert result.candidates == []


def test_t2_bouncy_castle_family_name_and_other_modules_of_the_repo() -> None:
    bcprov = pkg("maven", "org.bouncycastle:bcprov-jdk18on", "1.85")
    bcpkix = pkg("maven", "org.bouncycastle:bcpkix-jdk18on", "1.85")
    repos = {
        ("maven", bcprov.name): ("github.com/bcgit/bc-java",),
        ("maven", bcpkix.name): ("github.com/bcgit/bc-java",),
    }

    def entry(name: str) -> dict[str, Any]:
        return cna(
            product="BC-JAVA",
            packageName=name,
            repo="https://github.com/bcgit/bc-java",
            **affected(below("1.86")),
        )

    result = match(
        [
            record("CVE-2030-0001", [entry("bcprov")]),
            record("CVE-2030-0002", [entry("bcpg")]),
            record("CVE-2030-0003", [entry("bcpkix")]),
        ],
        inventory(bcprov, bcpkix),
        repos,
    )
    assert found(result) == {
        ("CVE-2030-0001", bcprov.name, "1.85", "T2"),
        ("CVE-2030-0003", bcpkix.name, "1.85", "T2"),
    }
    # bcprov-for-bcpkix, bcpg for both, bcpkix-for-bcprov
    assert result.outcomes["wrong_artifact"] == 4


def test_jackson_smile_cve_does_not_match_the_cbor_module() -> None:
    cbor = pkg(
        "maven", "com.fasterxml.jackson.dataformat:jackson-dataformat-cbor", "2.21.0"
    )
    repos = {("maven", cbor.name): ("github.com/fasterxml/jackson-dataformats-binary",)}
    entry = cna(
        vendor="FasterXML",
        product="jackson-dataformats-binary",
        packageName="jackson-dataformat-smile",
        repo="https://github.com/FasterXML/jackson-dataformats-binary",
        **affected(below("2.22.0")),
    )
    result = match([record(entries=[entry])], inventory(cbor), repos)
    assert result.candidates == []
    entry["packageName"] = "com.fasterxml.jackson.dataformat:jackson-dataformat-cbor"
    result = match([record(entries=[entry])], inventory(cbor), repos)
    assert found(result) == {("CVE-2030-0001", cbor.name, "2.21.0", "T1")}


def test_t1_by_package_name_in_the_ecosystem_of_the_collection() -> None:
    inv = inventory(pkg("npm", "zod", "3.0.0"), pkg("pypi", "zod", "3.0.0"))
    entry = cna(
        packageName="zod",
        collectionURL="https://registry.npmjs.org",
        **affected(below("3.5.0")),
    )
    result = match([record(entries=[entry])], inv)
    assert found(result) == {("CVE-2030-0001", "zod", "3.0.0", "T1")}
    assert result.candidates[0]["package"]["ecosystem"] == "npm"
    assert result.outcomes["rejected_registry"] == 1


def test_t1_name_collision_with_a_foreign_registry_is_rejected() -> None:
    inv = inventory(pkg("maven", "io.netty:netty-codec-http", "4.1.0"))
    entry = cna(
        packageName="io.netty:netty-codec-http",
        collectionURL="https://access.redhat.com/security/data",
        **affected(below("5.0.0", version_type="maven")),
    )
    result = match([record(entries=[entry])], inv)
    assert result.candidates == []
    assert result.outcomes["rejected_registry"] == 1


def test_t1_repository_of_the_entry_that_differs_from_the_package_is_rejected() -> None:
    package = pkg("cargo", "console", "0.15.0")
    repos = {("cargo", "console"): ("github.com/console-rs/console",)}
    entry = cna(
        packageName="console",
        repo="https://github.com/streamshub/console",
        **affected(below("1.0.0")),
    )
    result = match([record(entries=[entry])], inventory(package), repos)
    assert result.candidates == []
    assert result.outcomes["rejected_repo_conflict"] == 1
    # without a repository known for the package nothing contradicts the name
    result = match([record(entries=[entry])], inventory(package), {})
    assert len(result.candidates) == 1


def test_t1_name_is_compared_the_way_of_the_ecosystem() -> None:
    result = match(
        [record(entries=[cna(packageName="Ruamel_Yaml", **affected(below("1.0")))])],
        inventory(pkg("pypi", "ruamel.yaml", "0.5")),
    )
    assert found(result) == {("CVE-2030-0001", "ruamel.yaml", "0.5", "T1")}


def test_the_strongest_rule_of_several_entries_is_kept() -> None:
    package = pkg("npm", "left-pad", "1.0.0")
    repos = {("npm", "left-pad"): ("github.com/stevemao/left-pad",)}
    by_repo = cna(
        product="left-pad",
        repo="https://github.com/stevemao/left-pad",
        **affected(below("2.0.0")),
    )
    by_name = cna(packageName="left-pad", **affected(below("1.5.0")))
    result = match([record(entries=[by_repo, by_name])], inventory(package), repos)
    (candidate,) = result.candidates
    assert candidate["rule"] == "T1"
    assert candidate["affected_range"] == "< 1.5.0"


def test_a_package_version_is_reported_once_per_cve() -> None:
    inv = inventory(
        pkg("npm", "x", "1.0.0"), pkg("npm", "x", "1.1.0"), pkg("npm", "x", "2.0.0")
    )
    result = match(
        [record(entries=[cna(packageName="x", **affected(below("2.0.0")))])], inv
    )
    assert {c["package"]["version"] for c in result.candidates} == {"1.0.0", "1.1.0"}
    assert result.outcomes["version_outside_range"] == 1


def test_unparseable_versions_are_not_reported_and_are_counted() -> None:
    inv = inventory(pkg("npm", "x", "1.0.0"))
    git = cna(packageName="x", **affected(below("2.0.0", version_type="git")))
    result = match([record(entries=[git])], inv)
    assert result.candidates == []
    assert result.outcomes["version_unknown"] == 1
    # an installed version that is not a version
    inv = inventory(pkg("npm", "x", "latest"))
    result = match(
        [record(entries=[cna(packageName="x", **affected(below("2.0.0")))])], inv
    )
    assert result.candidates == []
    assert result.outcomes["version_unknown"] == 1


ZOD = pkg("npm", "zod", "3.0.0")
ZOD_REPOS = {("npm", "zod"): ("github.com/colinhacks/zod",)}


def t3_entry(**fields: Any) -> dict[str, Any]:
    return {
        "vendor": "colinhacks",
        "product": "zod",
        **affected(below("3.5.0")),
        **fields,
    }


def test_t3_needs_the_artifact_the_owner_and_a_reference_to_the_repository() -> None:
    refs = (
        "https://github.com/colinhacks/zod/security/advisories/GHSA-xxxx-xxxx-xxxx",
    )
    result = match([record(entries=[t3_entry()], refs=refs)], inventory(ZOD), ZOD_REPOS)
    assert found(result) == {("CVE-2030-0001", "zod", "3.0.0", "T3")}


def test_t3_the_elastic_shape_is_not_reported() -> None:
    """A CVE about the Elasticsearch server must not hit the Python client."""
    client = pkg("pypi", "elasticsearch", "8.0.0")
    repos = {("pypi", "elasticsearch"): ("github.com/elastic/elasticsearch-py",)}
    entry = cna(vendor="Elastic", product="Elasticsearch", **affected(below("9.0.0")))
    refs = ("https://discuss.elastic.co/t/elastic-security-announcement/1",)
    result = match([record(entries=[entry], refs=refs)], inventory(client), repos)
    assert result.candidates == []
    assert result.outcomes["uncorroborated"] == 1


def test_t3_vendor_must_be_the_owner_or_the_artifact() -> None:
    refs = ("https://github.com/colinhacks/zod",)
    result = match(
        [record(entries=[t3_entry(vendor="someone-else")], refs=refs)],
        inventory(ZOD),
        ZOD_REPOS,
    )
    assert result.candidates == []
    assert result.outcomes["wrong_vendor"] == 1
    result = match(
        [record(entries=[t3_entry(vendor="Zod")], refs=refs)], inventory(ZOD), ZOD_REPOS
    )
    assert len(result.candidates) == 1


def test_t3_a_scoped_npm_package_needs_the_vendor_scope() -> None:
    types = pkg("npm", "@types/multer", "1.0.0")
    repos = {("npm", "@types/multer"): ("github.com/definitelytyped/definitelytyped",)}
    entry = cna(vendor="expressjs", product="multer", **affected(below("2.0.0")))
    refs = ("https://github.com/definitelytyped/definitelytyped/pull/1",)
    result = match([record(entries=[entry], refs=refs)], inventory(types), repos)
    assert result.candidates == []
    assert result.outcomes == {"wrong_vendor": 1}
    # the vendor owns the repository, but the scope is somebody else's
    entry["vendor"] = "DefinitelyTyped"
    result = match([record(entries=[entry], refs=refs)], inventory(types), repos)
    assert result.candidates == []
    assert result.outcomes == {"wrong_scope": 1}
    # the scope is the vendor: fine
    nest = pkg("npm", "@nestjs/axios", "1.0.0")
    nest_repos = {("npm", "@nestjs/axios"): ("github.com/nestjs/axios",)}
    entry = cna(vendor="nestjs", product="axios", **affected(below("2.0.0")))
    refs = ("https://github.com/nestjs/axios/security/advisories/GHSA-1",)
    result = match([record(entries=[entry], refs=refs)], inventory(nest), nest_repos)
    assert len(result.candidates) == 1


def test_t3_needs_a_repository_of_the_package() -> None:
    entry = t3_entry()
    refs = ("https://github.com/colinhacks/zod",)
    result = match([record(entries=[entry], refs=refs)], inventory(ZOD), {})
    assert result.candidates == []


NETTY_HTTP = pkg("maven", "io.netty:netty-codec-http", "4.1.0")
NETTY_COMMON = pkg("maven", "io.netty:netty-common", "4.1.0")
NETTY_REPOS = {
    ("maven", NETTY_HTTP.name): ("github.com/netty/netty",),
    ("maven", NETTY_COMMON.name): ("github.com/netty/netty",),
}


def repo_level_entry() -> dict[str, Any]:
    return cna(
        vendor="netty",
        product="netty",
        **affected(below("4.2.0", version_type="maven")),
    )


def test_repo_level_needs_the_module_to_be_named_in_the_text() -> None:
    named = record(
        description="A flaw in netty-codec-http allows request smuggling.",
        entries=[repo_level_entry()],
    )
    result = match([named], inventory(NETTY_HTTP, NETTY_COMMON), NETTY_REPOS)
    assert found(result) == {("CVE-2030-0001", NETTY_HTTP.name, "4.1.0", "repo-level")}
    assert result.outcomes["module_unknown"] == 1
    unnamed = record(description="Netty has a flaw.", entries=[repo_level_entry()])
    result = match([unnamed], inventory(NETTY_HTTP, NETTY_COMMON), NETTY_REPOS)
    assert result.candidates == []
    assert result.outcomes["module_unknown"] == 2


def test_repo_level_with_a_repo_field_and_a_product_that_is_the_repository() -> None:
    entry = cna(
        vendor="netty",
        product="netty",
        repo="https://github.com/netty/netty",
        **affected(below("4.2.0", version_type="maven")),
    )
    text = record(description="netty-common is affected", entries=[entry])
    result = match([text], inventory(NETTY_HTTP, NETTY_COMMON), NETTY_REPOS)
    assert found(result) == {
        ("CVE-2030-0001", NETTY_COMMON.name, "4.1.0", "repo-level")
    }


def test_a_module_is_not_named_by_a_longer_name_that_contains_it() -> None:
    longer = record(
        description="netty-codec-http3 is affected", entries=[repo_level_entry()]
    )
    result = match([longer], inventory(NETTY_HTTP), NETTY_REPOS)
    assert result.candidates == []


def test_repo_level_a_scoped_npm_package_is_named_by_its_full_name_only() -> None:
    common = pkg("npm", "@nestjs/common", "10.0.0")
    repos = {("npm", "@nestjs/common"): ("github.com/nestjs/nest",)}
    entry = cna(vendor="nestjs", product="nest", **affected(below("11.0.0")))
    by_artifact = record(description="The common module is affected", entries=[entry])
    assert match([by_artifact], inventory(common), repos).candidates == []
    by_name = record(description="@nestjs/common is affected", entries=[entry])
    assert len(match([by_name], inventory(common), repos).candidates) == 1


def test_ghsa_aliases_come_from_the_references() -> None:
    refs = (
        "https://github.com/google/guava/security/advisories/GHSA-XXPH-C9ww-hj94",
        "https://github.com/advisories/GHSA-xxph-c9ww-hj94",
        "https://example.com/other",
    )
    assert ew.ghsa_aliases(record(refs=refs)) == ["GHSA-xxph-c9ww-hj94"]


def test_candidate_document_has_the_cna_data_and_where_the_package_was_seen() -> None:
    inv = ew.Inventory()
    inv.sightings[GUAVA] = {
        "source-development": {"gradle.lockfile", "core/gradle.lockfile"},
        "app-development": {"Java"},
    }
    entry = cna(
        product="Guava",
        repo="https://github.com/google/guava",
        **affected(below("33.7.2", "4.0")),
    )
    rec = record(
        entries=[entry], refs=("https://github.com/advisories/GHSA-xxph-c9ww-hj94",)
    )
    (candidate,) = match([rec], inv, GUAVA_REPOS).candidates
    assert candidate == {
        "cve": "CVE-2030-0001",
        "aliases": ["GHSA-xxph-c9ww-hj94"],
        "cna": "ExampleCNA",
        "published": "2030-01-05T10:00:00.000Z",
        "updated": "2030-01-06T10:00:00.000Z",
        "title": "A title",
        "package": {
            "ecosystem": "maven",
            "name": "com.google.guava:guava",
            "version": "33.4.8-jre",
        },
        "affected_range": ">= 4.0, < 33.7.2",
        "rule": "T2",
        "confidence": {
            "basis": "cna_history",
            "cna": "ExampleCNA",
            "confirmed": 0,
            "errors": 0,
            "pending": 0,
            "ratio": None,
        },
        "severity": "UNKNOWN",
        "severity_source": None,
        "cvss": None,
        "cvss_v4": None,
        "exploitation": None,
        "sightings": {
            "app-development": ["Java"],
            "source-development": ["core/gradle.lockfile", "gradle.lockfile"],
        },
    }


# --- severity -------------------------------------------------------------------


def cvss(
    key: str, score: float, severity: str | None, vector: str = "V"
) -> dict[str, Any]:
    body: dict[str, Any] = {"baseScore": score, "vectorString": vector}
    if severity:
        body["baseSeverity"] = severity
    return {key: body}


def containers(
    cna_metrics: list[Any] | None = None, **adp: list[Any]
) -> dict[str, Any]:
    return {
        "cna": {"metrics": cna_metrics or []},
        "adp": [
            {"providerMetadata": {"shortName": name}, "metrics": metrics}
            for name, metrics in adp.items()
        ],
    }


def severity_of(**kwargs: Any) -> dict[str, Any]:
    return ew.select_severity(ew.extract_metrics(containers(**kwargs)))


def test_severity_from_the_cna_cvss_31() -> None:
    result = severity_of(
        cna_metrics=[cvss("cvssV3_1", 9.8, "CRITICAL", "CVSS:3.1/AV:N")]
    )
    assert result == {
        "severity": "CRITICAL",
        "severity_source": "cna",
        "cvss": {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N",
            "version": "3.1",
            "source": "cna",
        },
        "cvss_v4": None,
    }


def test_severity_prefers_cvss_31_for_ranking_and_keeps_v4() -> None:
    result = severity_of(
        cna_metrics=[
            cvss("cvssV4_0", 9.3, "CRITICAL", "CVSS:4.0/AV:N"),
            cvss("cvssV3_0", 5.0, "MEDIUM"),
            cvss("cvssV3_1", 7.5, "HIGH", "CVSS:3.1/AV:N"),
        ]
    )
    assert result["severity"] == "HIGH"
    assert result["cvss"]["version"] == "3.1"
    assert result["cvss"]["score"] == 7.5
    assert result["cvss_v4"] == {
        "score": 9.3,
        "vector": "CVSS:4.0/AV:N",
        "version": "4.0",
        "source": "cna",
    }


def test_severity_with_cvss_v4_only() -> None:
    result = severity_of(cna_metrics=[cvss("cvssV4_0", 8.7, "HIGH", "CVSS:4.0/AV:N")])
    assert result["severity"] == "HIGH"
    assert result["cvss"]["version"] == "4.0"
    assert result["cvss_v4"] is None  # it is the ranking score already


def test_severity_falls_back_to_adp_when_the_cna_gives_none() -> None:
    result = severity_of(
        cna_metrics=[
            {
                "other": {
                    "type": "Red Hat severity rating",
                    "content": {"value": "Moderate"},
                }
            },
            cvss("cvssV2_0", 7.5, None),
        ],
        **{"CISA-ADP": [cvss("cvssV3_1", 3.7, "LOW")]},
    )
    assert result["severity"] == "LOW"
    assert result["severity_source"] == "adp:CISA-ADP"
    assert result["cvss"]["source"] == "adp:CISA-ADP"


def test_the_cna_wins_over_adp() -> None:
    result = severity_of(
        cna_metrics=[cvss("cvssV3_1", 5.0, "MEDIUM")],
        **{"CISA-ADP": [cvss("cvssV3_1", 9.8, "CRITICAL")]},
    )
    assert (result["severity"], result["severity_source"]) == ("MEDIUM", "cna")


def test_the_first_adp_by_name_is_used() -> None:
    result = severity_of(
        **{
            "redhat-SADP": [cvss("cvssV3_1", 9.0, "CRITICAL")],
            "CISA-ADP": [cvss("cvssV3_1", 4.0, "MEDIUM")],
        }
    )
    assert result["severity_source"] == "adp:CISA-ADP"


def test_no_severity_is_unknown() -> None:
    assert severity_of() == {
        "severity": "UNKNOWN",
        "severity_source": None,
        "cvss": None,
        "cvss_v4": None,
    }
    # CVSS 2 and free text do not count
    result = severity_of(
        cna_metrics=[
            cvss("cvssV2_0", 9.0, None),
            {
                "other": {
                    "type": "Textual description of severity",
                    "content": {"text": "high"},
                }
            },
        ]
    )
    assert result["severity"] == "UNKNOWN"
    assert result["cvss"] is None


@pytest.mark.parametrize(
    ("score", "expected"),
    [(10.0, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"),
     (6.9, "MEDIUM"),
     (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW"), (0.0, "UNKNOWN")],
)  # fmt: skip
def test_severity_is_derived_from_the_score_when_the_record_gives_none(
    score: float, expected: str
) -> None:
    result = severity_of(cna_metrics=[cvss("cvssV3_1", score, None)])
    assert result["severity"] == expected
    # and a rating that is not a rating
    result = severity_of(cna_metrics=[cvss("cvssV3_1", 9.8, "NONE")])
    assert result["severity"] == "CRITICAL"


def test_exploitation_from_adp_kev_and_ssvc() -> None:
    kev = {"other": {"type": "kev", "content": {"dateAdded": "2022-05-25"}}}
    ssvc = {
        "other": {
            "type": "ssvc",
            "content": {"options": [{"Exploitation": "active"}, {"Automatable": "no"}]},
        }
    }
    metrics = ew.extract_metrics(containers(**{"CISA-ADP": [ssvc, kev]}))
    assert metrics["exploitation"] == {
        "kev": True,
        "kev_date_added": "2022-05-25",
        "ssvc": "active",
        "source": "adp:CISA-ADP",
    }
    only_ssvc = ew.extract_metrics(containers(**{"CISA-ADP": [ssvc]}))
    assert only_ssvc["exploitation"]["kev"] is False
    assert only_ssvc["exploitation"]["ssvc"] == "active"
    assert ew.extract_metrics(containers())["exploitation"] is None


def test_candidates_are_ordered_by_severity_score_and_date() -> None:
    inv = inventory(*(pkg("npm", f"p{i}", "1.0.0") for i in range(5)))

    def rec(i: int, score: float | None, published: str) -> dict[str, Any]:
        metrics = {"cvss": [], "exploitation": None}
        if score is not None:
            key = "cvssV3_1"
            metrics = ew.extract_metrics(
                containers(cna_metrics=[cvss(key, score, None)])
            )
        return record(
            f"CVE-2030-000{i}",
            [cna(packageName=f"p{i}", **affected(below("2")))],
            metrics=metrics,
            published=published,
        )

    result = match(
        [
            rec(0, None, "2030-01-09T00:00:00Z"),
            rec(1, 7.5, "2030-01-01T00:00:00Z"),
            rec(2, 9.8, "2030-01-02T00:00:00Z"),
            rec(3, 7.5, "2030-01-08T00:00:00Z"),
            rec(4, 7.9, "2030-01-03T00:00:00Z"),
        ],
        inv,
    )
    assert [c["cve"] for c in result.candidates] == [
        "CVE-2030-0002",  # CRITICAL
        "CVE-2030-0004",  # HIGH 7.9
        "CVE-2030-0003",  # HIGH 7.5, newer
        "CVE-2030-0001",  # HIGH 7.5
        "CVE-2030-0000",  # UNKNOWN
    ]


# --- CVE records and the feed assets --------------------------------------------


def cve_json(
    cve: str,
    published: str = "2030-01-09T10:00:00.000Z",
    updated: str | None = None,
    state: str = "PUBLISHED",
    affected_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "dataType": "CVE_RECORD",
        "cveMetadata": {
            "cveId": cve,
            "state": state,
            "datePublished": published,
            "dateUpdated": updated or published,
            "assignerShortName": "ExampleCNA",
        },
        "containers": {
            "cna": {
                "title": f"Title of {cve}",
                "descriptions": [
                    {"lang": "es", "value": "otro"},
                    {"lang": "en", "value": f"Description of {cve}"},
                ],
                "affected": affected_entries or [],
                "references": [{"url": "https://example.com/" + cve}],
                "metrics": [cvss("cvssV3_1", 7.5, "HIGH")],
            },
            "adp": [],
        },
    }


def delta_zip(
    *documents: dict[str, Any], extra: dict[str, bytes] | None = None
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for document in documents:
            name = f"deltaCves/{document['cveMetadata']['cveId']}.json"
            archive.writestr(name, json.dumps(document))
        for name, body in (extra or {}).items():
            archive.writestr(name, body)
    return buffer.getvalue()


def with_repo(*repos: str) -> dict[str, Any]:
    return {
        "relatedProjects": [
            {"projectKey": {"id": r}, "relationType": "SOURCE_REPO"} for r in repos
        ]
    }


def day_asset(day: str) -> str:
    return f"cve_{day}_at_end_of_day/{day}_delta_CVEs_at_end_of_day.zip"


def hour_asset(day: str, hour: int) -> str:
    return f"cve_{day}_{hour:02d}00Z/{day}_delta_CVEs_at_{hour:02d}00Z.zip"


def test_asset_names_follow_the_release_naming() -> None:
    from datetime import date

    assert ew.end_of_day_asset(date(2026, 10, 11)) == (
        "cve_2026-10-11_at_end_of_day/2026-10-11_delta_CVEs_at_end_of_day.zip"
    )
    assert ew.hourly_asset(date(2026, 10, 12), 5) == (
        "cve_2026-10-12_0500Z/2026-10-12_delta_CVEs_at_0500Z.zip"
    )


# --- confidence -----------------------------------------------------------------


def test_confidence_of_t1_and_t2_is_the_history_of_the_cna() -> None:
    cnas = {"VulnCheck": {"confirmed": 119, "errors": 4, "pending": 1483}}
    for rule in ("T1", "T2"):
        assert ew.confidence_of(rule, "VulnCheck", cnas) == {
            "basis": "cna_history",
            "cna": "VulnCheck",
            "confirmed": 119,
            "errors": 4,
            "pending": 1483,
            "ratio": 0.9675,
        }


def test_a_cna_without_resolved_claims_has_no_ratio() -> None:
    cnas = {"Google": {"confirmed": 0, "errors": 0, "pending": 6}}
    expected = {
        "basis": "cna_history",
        "cna": "Google",
        "confirmed": 0,
        "errors": 0,
        "pending": 6,
        "ratio": None,
    }
    assert ew.confidence_of("T2", "Google", cnas) == expected
    # a CNA that the index does not know has no history either
    unknown = ew.confidence_of("T1", "Nobody", cnas)
    assert unknown == {**expected, "cna": "Nobody", "pending": 0}
    assert ew.confidence_of("T1", None, cnas)["cna"] is None


def test_a_match_by_names_has_no_cna_history() -> None:
    cnas = {"ExampleCNA": {"confirmed": 50, "errors": 0, "pending": 0}}
    for rule in ("T3", "repo-level"):
        assert ew.confidence_of(rule, "ExampleCNA", cnas) == {"basis": "name_match"}


def test_candidates_carry_the_confidence_of_their_rule() -> None:
    package = pkg("npm", "lodash", "4.17.0")
    inv = inventory(package)
    by_name = record(
        entries=[cna(packageName="lodash", **affected(below("4.17.21")))],
        refs=("https://github.com/lodash/lodash/issues/1",),
    )
    by_names = record(
        "CVE-2030-0002",
        entries=[cna(vendor="lodash", product="lodash", **affected(below("5.0.0")))],
        refs=("https://github.com/lodash/lodash/issues/1",),
    )
    cnas = {"ExampleCNA": {"confirmed": 3, "errors": 1, "pending": 0}}
    result = match(
        [by_name, by_names],
        inv,
        {("npm", "lodash"): ("github.com/lodash/lodash",)},
        cnas,
    )
    confidence = {c["rule"]: c["confidence"] for c in result.candidates}
    assert confidence == {
        "T1": {
            "basis": "cna_history",
            "cna": "ExampleCNA",
            "confirmed": 3,
            "errors": 1,
            "pending": 0,
            "ratio": 0.75,
        },
        "T3": {"basis": "name_match"},
    }


# --- the CVE index --------------------------------------------------------------

BUILT = "2030-01-10T03:21:00Z"
WINDOW = 5  # days: the window at NOW starts 2030-01-05T12:30Z
DIGEST = "sha256:" + "ab12" * 16
IMAGE = "ghcr.io/example/ai-dial-sca-cve-index"
GUAVA_ENTRY = cna(
    vendor="Google",
    product="Guava",
    repo="https://github.com/google/guava",
    **affected(below("33.7.2", "4.0")),
)


def slim(cve: str, **fields: Any) -> dict[str, Any]:
    """A record as the index keeps it."""
    return record(cve, **fields)


def write_index(
    directory: Path,
    records: list[dict[str, Any]],
    cnas: Mapping[str, Mapping[str, int]] | None = None,
    **metadata: Any,
) -> Path:
    bci = ew.builder()
    directory.mkdir(parents=True, exist_ok=True)
    bci.write_jsonl_gz(directory / "cves.jsonl.gz", records)
    bci.write_json(
        directory / "reputation.json",
        {"schema_version": 1, "cnas": dict(cnas or {})},
    )
    bci.write_json(
        directory / "metadata.json",
        {
            "schema_version": 1,
            "built_at": BUILT,
            "window_days": WINDOW,
            "covered": {"from": "2030-01-05T03:21:00Z", "to": "2030-01-10T03:00:00Z"},
            "gaps": [],
            **metadata,
        },
    )
    return directory


class FakeDownloader:
    """The download layer of the deltas: a dict of files, 404 for the rest."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.fail: set[str] = set()
        self.requested: list[str] = []
        # an old entry sets how far back the delta log goes: it covers the span
        self.files[ew.builder().DELTA_LOG_URL] = json.dumps(
            [{"fetchTime": "2029-12-01T00:00:00Z", "new": [], "updated": []}]
        ).encode()

    def fetch(self, url: str, dest: Path) -> dict[str, str] | None:
        self.requested.append(url)
        if url in self.fail:
            raise ew.builder().DownloadError(f"GET {url}: HTTP 500")
        if url not in self.files:
            return None
        dest.write_bytes(self.files[url])
        return {}

    def hour(self, day: str, hour: int, *documents: dict[str, Any]) -> None:
        asset = hour_asset(day, hour)
        self.files[f"{FEED}/{asset}"] = delta_zip(*documents)

    def day(self, day: str, *documents: dict[str, Any]) -> None:
        self.files[f"{FEED}/{day_asset(day)}"] = delta_zip(*documents)

    def hours_of_today(self, *, skip: tuple[int, ...] = ()) -> None:
        """The hourly deltas of 2030-01-10 before the current hour (12)."""
        for hour in range(12):
            if hour not in skip:
                self.hour("2030-01-10", hour)

    def log(self, fetched: str, *documents: dict[str, Any]) -> None:
        changes = [
            {
                "cveId": d["cveMetadata"]["cveId"],
                "dateUpdated": d["cveMetadata"]["dateUpdated"],
            }
            for d in documents
        ]
        log = json.loads(self.files[ew.builder().DELTA_LOG_URL])
        log.insert(0, {"fetchTime": fetched, "new": [], "updated": changes})
        self.files[ew.builder().DELTA_LOG_URL] = json.dumps(log).encode()
        for document in documents:
            self.files[
                ew.builder().record_url(
                    ew.builder().RECORDS_URL, document["cveMetadata"]["cveId"]
                )
            ] = json.dumps(document).encode()


def loaded(directory: Path, ref: str = IMAGE + ":1") -> Any:
    return ew.read_index(directory, ref, DIGEST)


def caught_up(index: Any, net: FakeDownloader, tmp_path: Path) -> Any:
    ew.catch_up(index, net, FEED, tmp_path / "work", NOW)
    return index


def test_an_index_is_read_with_its_reputation(tmp_path: Path) -> None:
    cnas = {"Google": {"confirmed": 1, "errors": 0, "pending": 2}}
    directory = write_index(tmp_path / "index", [slim("CVE-2030-0001")], cnas)
    index = loaded(directory)
    assert set(index.records) == {"CVE-2030-0001"}
    assert index.cnas == cnas
    assert (index.ref, index.digest) == (IMAGE + ":1", DIGEST)
    assert ew.index_document(index) == {
        "ref": IMAGE + ":1",
        "digest": DIGEST,
        "built_at": BUILT,
        "gaps": [],
    }


@pytest.mark.parametrize(
    "damage",
    [
        lambda d: (d / "metadata.json").unlink(),
        lambda d: (d / "cves.jsonl.gz").write_bytes(b"not gzip"),
        lambda d: (d / "metadata.json").write_text('{"schema_version": 2}'),
        lambda d: (d / "metadata.json").write_text(
            '{"schema_version": 1, "gaps": [{"from": "x", "to": "y"}]}'
        ),
        lambda d: (d / "reputation.json").unlink(),
        lambda d: (d / "reputation.json").write_text("{"),
        lambda d: (d / "reputation.json").write_text('{"schema_version": 1}'),
        lambda d: (d / "reputation.json").write_text(
            '{"schema_version": 2, "cnas": {}}'
        ),
        lambda d: (d / "reputation.json").write_text(
            '{"schema_version": 1, "cnas": {"A": {"confirmed": 1}}}'
        ),
        lambda d: (d / "reputation.json").write_text(
            '{"schema_version": 1, "cnas": {"A": {"confirmed": 1, "errors": true, '
            '"pending": 0}}}'
        ),
    ],
)
def test_an_index_that_cannot_be_read_is_unavailable(
    tmp_path: Path, damage: Any
) -> None:
    directory = write_index(tmp_path / "index", [slim("CVE-2030-0001")])
    damage(directory)
    with pytest.raises(ew.IndexUnavailable, match="index"):
        loaded(directory)


class FakeOras:
    """``subprocess.run`` for the ``oras`` command: what it was asked, what it says."""

    def __init__(self, resolve: tuple[int, str, str] | Exception, pull_rc: int = 0):
        self.resolve = resolve
        self.pull_rc = pull_rc
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> Any:
        self.calls.append(command)
        assert kwargs["timeout"] == ew.ORAS_TIMEOUT_SECONDS
        if command[1] == "resolve":
            if isinstance(self.resolve, Exception):
                raise self.resolve
            code, out, err = self.resolve
            return subprocess.CompletedProcess(command, code, out, err)
        stderr = "Error: pull failed\nthe registry said no" if self.pull_rc else ""
        return subprocess.CompletedProcess(command, self.pull_rc, "", stderr)


def test_the_index_is_resolved_to_a_digest_and_pulled_by_it(tmp_path: Path) -> None:
    oras = FakeOras((0, DIGEST + "\n", ""))
    assert ew.pull_index(IMAGE + ":1", tmp_path / "dest", oras) == DIGEST
    assert oras.calls == [
        ["oras", "resolve", IMAGE + ":1"],
        ["oras", "pull", f"{IMAGE}@{DIGEST}", "--output", str(tmp_path / "dest")],
    ]


def test_a_registry_with_a_port_and_a_digest_reference_are_pulled_the_same_way(
    tmp_path: Path,
) -> None:
    for ref in (
        "localhost:5000/x/y:1",
        "localhost:5000/x/y",
        f"localhost:5000/x/y@{DIGEST}",
    ):
        oras = FakeOras((0, DIGEST, ""))
        ew.pull_index(ref, tmp_path / "dest", oras)
        assert oras.calls[1][2] == f"localhost:5000/x/y@{DIGEST}"


@pytest.mark.parametrize(
    ("oras", "message"),
    [
        (
            FakeOras((1, "", "Error: unauthorized\nGET denied")),
            "oras resolve failed: GET denied",
        ),
        (FakeOras((1, "", "")), "oras resolve failed: exit code 1"),
        (FakeOras((0, "<html>", "")), "no digest"),
        (FakeOras((0, "", "")), "no digest"),
        (FakeOras(FileNotFoundError("oras")), "oras"),
        (FakeOras(subprocess.TimeoutExpired("oras", 300)), "timed out"),
        (
            FakeOras((0, DIGEST, ""), pull_rc=1),
            "oras pull failed: the registry said no",
        ),
    ],
)
def test_oras_or_the_registry_failing_is_unavailable(
    tmp_path: Path, oras: FakeOras, message: str
) -> None:
    with pytest.raises(ew.IndexUnavailable, match=f"cannot pull {IMAGE}:1.*{message}"):
        ew.pull_index(IMAGE + ":1", tmp_path / "dest", oras)


def test_only_the_deltas_since_the_index_was_built_are_applied(tmp_path: Path) -> None:
    old = slim("CVE-2030-0001", updated="2030-01-09T10:00:00.000Z")
    index = loaded(write_index(tmp_path / "index", [old]))
    net = FakeDownloader()
    net.hours_of_today(skip=(9,))
    net.hour(
        "2030-01-10",
        9,
        # a record that is new, and the one of the index, rejected now
        cve_json("CVE-2030-0002", published="2030-01-10T09:30:00Z"),
        cve_json("CVE-2030-0001", updated="2030-01-10T09:40:00Z", state="REJECTED"),
    )
    caught_up(index, net, tmp_path)
    assert set(index.records) == {"CVE-2030-0002"}
    assert index.gaps == []
    # nothing before the day of the index, nothing of the hours to come
    assert not any("2030-01-09" in url or "01-08" in url for url in net.requested)
    assert not any("1300Z" in url for url in net.requested)
    assert f"{FEED}/{hour_asset('2030-01-10', 9)}" in net.requested


def test_a_past_day_is_its_end_of_day_delta(tmp_path: Path) -> None:
    index = loaded(write_index(tmp_path / "index", [], built_at="2030-01-08T03:21:00Z"))
    net = FakeDownloader()
    net.day("2030-01-08", cve_json("CVE-2030-0001", updated="2030-01-08T23:00:00Z"))
    net.day("2030-01-09", cve_json("CVE-2030-0002", updated="2030-01-09T12:00:00Z"))
    net.hours_of_today()
    caught_up(index, net, tmp_path)
    assert set(index.records) == {"CVE-2030-0001", "CVE-2030-0002"}
    assert f"{FEED}/{hour_asset('2030-01-09', 10)}" not in net.requested


def test_a_record_the_deltas_lack_is_fetched_from_the_delta_log(tmp_path: Path) -> None:
    index = loaded(write_index(tmp_path / "index", []))
    net = FakeDownloader()
    net.hours_of_today()
    lost = cve_json("CVE-2030-0003", published="2030-01-10T08:00:30Z")
    net.log("2030-01-10T08:05:00Z", lost)
    caught_up(index, net, tmp_path)
    assert set(index.records) == {"CVE-2030-0003"}


def test_stale_records_and_rejected_ones_are_not_kept(tmp_path: Path) -> None:
    records = [
        slim("CVE-2030-0001", updated="2030-01-04T00:00:00.000Z"),  # before the window
        slim("CVE-2030-0002", updated="2030-01-06T00:00:00.000Z"),
        slim("CVE-2030-0003", updated="2030-01-06T00:00:00.000Z", state="REJECTED"),
    ]
    index = loaded(write_index(tmp_path / "index", records))
    net = FakeDownloader()
    net.hours_of_today()
    caught_up(index, net, tmp_path)
    assert set(index.records) == {"CVE-2030-0002"}


def test_gaps_of_the_index_and_of_the_deltas_are_both_reported(tmp_path: Path) -> None:
    before = {"from": "2030-01-07T04:00:00Z", "to": "2030-01-07T08:00:00Z"}
    outside = {"from": "2030-01-01T04:00:00Z", "to": "2030-01-01T06:00:00Z"}
    healed = {"from": "2030-01-10T01:00:00Z", "to": "2030-01-10T02:00:00Z"}
    index = loaded(write_index(tmp_path / "index", [], gaps=[outside, before, healed]))
    net = FakeDownloader()
    net.hours_of_today(skip=(4, 5, 11))
    # the log covers every hour since its horizon: the missing deltas are made up
    # by it, and the gaps that it cannot clear are those before its horizon
    net.files[ew.builder().DELTA_LOG_URL] = json.dumps(
        [{"fetchTime": "2030-01-09T00:00:00Z", "new": [], "updated": []}]
    ).encode()
    caught_up(index, net, tmp_path)
    assert index.gaps == [before]  # the one before the day of the index, in the window
    assert ew.index_document(index)["gaps"] == [before]


def test_missing_deltas_that_the_log_cannot_cover_are_gaps(tmp_path: Path) -> None:
    index = loaded(write_index(tmp_path / "index", []))
    net = FakeDownloader()
    net.hours_of_today(skip=(4, 5, 11))
    net.files[ew.builder().DELTA_LOG_URL] = json.dumps(
        [{"fetchTime": "2030-01-10T10:00:00Z", "new": [], "updated": []}]
    ).encode()
    caught_up(index, net, tmp_path)
    # hour 11 is after the horizon of the log, which lists what changed in it
    assert index.gaps == [
        {"from": "2030-01-10T04:00:00Z", "to": "2030-01-10T06:00:00Z"}
    ]


def test_an_unreadable_delta_log_is_a_gap_of_the_whole_span(tmp_path: Path) -> None:
    index = loaded(write_index(tmp_path / "index", []))
    net = FakeDownloader()
    net.hours_of_today()
    del net.files[ew.builder().DELTA_LOG_URL]
    caught_up(index, net, tmp_path)
    assert index.gaps == [
        {"from": "2030-01-10T00:00:00Z", "to": "2030-01-10T13:00:00Z"}
    ]


def test_a_delta_that_cannot_be_downloaded_or_read_is_unavailable(
    tmp_path: Path,
) -> None:
    net = FakeDownloader()
    net.hours_of_today()
    net.fail.add(f"{FEED}/{hour_asset('2030-01-10', 3)}")
    index = loaded(write_index(tmp_path / "one", []))
    with pytest.raises(ew.IndexUnavailable, match="HTTP 500"):
        caught_up(index, net, tmp_path)
    net.fail.clear()
    net.files[f"{FEED}/{hour_asset('2030-01-10', 3)}"] = b"<html>rate limited</html>"
    index = loaded(write_index(tmp_path / "two", []))
    with pytest.raises(ew.IndexUnavailable, match="not a valid zip"):
        caught_up(index, net, tmp_path)


def test_an_index_older_than_its_window_is_unavailable(tmp_path: Path) -> None:
    index = loaded(write_index(tmp_path / "index", [], built_at="2030-01-02T03:21:00Z"))
    net = FakeDownloader()
    with pytest.raises(ew.IndexUnavailable, match="before its window of 5 days"):
        caught_up(index, net, tmp_path)
    assert net.requested == []


@pytest.mark.parametrize("metadata", [{"built_at": "soon"}, {"window_days": 0}])
def test_an_index_without_a_usable_date_or_window_is_unavailable(
    tmp_path: Path, metadata: dict[str, Any]
) -> None:
    index = loaded(write_index(tmp_path / "index", [], **metadata))
    with pytest.raises(ew.IndexUnavailable, match="no built_at or window"):
        caught_up(index, FakeDownloader(), tmp_path)


# --- deps.dev -------------------------------------------------------------------


class FakeNetwork:
    """A fake of deps.dev behind the Transport interface.

    ``depsdev``: ``<system>/<name>/<version>`` -> deps.dev answer, a missing one 404.
    ``script``: responses (or exceptions) consumed first, for failure injection.
    """

    def __init__(self, depsdev: Mapping[str, Any] | None = None) -> None:
        self.depsdev = dict(depsdev or {})
        self.script: list[Any] = []
        self.requests: list[str] = []
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> Any:
        self.requests.append(url)
        if self.script:
            step = self.script.pop(0)
            if isinstance(step, Exception):
                raise step
            return step
        if url.startswith(DEPSDEV + "/v3/systems/"):
            from urllib.parse import unquote

            parts = unquote(url.removeprefix(DEPSDEV + "/v3/systems/")).split("/")
            key = f"{parts[0]}/{parts[2]}/{parts[4]}"
            answer = self.depsdev.get(key)
            if answer is None:
                return ew.Response(404)
            return ew.Response(200, {}, json.dumps(answer).encode())
        raise AssertionError(f"unexpected request {url}")


def depsdev_client(network: FakeNetwork) -> Any:
    return ew.DepsDevClient(ew.HttpClient(network, network.sleep), DEPSDEV)


def test_source_repos_from_related_projects_and_links() -> None:
    network = FakeNetwork(
        {
            "maven/com.google.guava:guava/33.4.8-jre": {
                "relatedProjects": [
                    {
                        "projectKey": {"id": "github.com/google/guava"},
                        "relationType": "SOURCE_REPO",
                    },
                    {
                        "projectKey": {"id": "github.com/google/guava"},
                        "relationType": "ISSUE_TRACKER",
                    },
                    {
                        "projectKey": {"id": "github.com/other/thing"},
                        "relationType": "ISSUE_TRACKER",
                    },
                ],
                "links": [
                    {
                        "label": "SOURCE_REPO",
                        "url": "https://github.com/Google/Guava.git",
                    },
                    {"label": "HOMEPAGE", "url": "https://elsewhere.example"},
                ],
            }
        },
    )
    assert depsdev_client(network).source_repos(GUAVA) == ("github.com/google/guava",)
    assert depsdev_client(network).source_repos(pkg("npm", "x", "1")) is None


def test_repos_are_asked_per_name_newest_version_first_and_the_next_if_unknown() -> (
    None
):
    inv = inventory(
        pkg("npm", "a", "1.0.0"),
        pkg("npm", "a", "2.0.0"),
        pkg("npm", "b", "1.0.0"),
        pkg("maven", "g:c", "1.0"),
    )
    network = FakeNetwork(
        {
            "npm/a/1.0.0": with_repo("github.com/o/a"),
            "npm/b/1.0.0": {},
        }
    )
    lookup = ew.resolve_repos(depsdev_client(network), inv)
    assert lookup.repos == {
        ("npm", "a"): ("github.com/o/a",),
        ("npm", "b"): (),
        ("maven", "g:c"): (),
    }
    assert lookup.without_repo == 2
    assert lookup.errors == 0
    asked = [u.removeprefix(DEPSDEV + "/v3/systems/") for u in network.requests]
    assert asked.index("npm/packages/a/versions/2.0.0") < asked.index(
        "npm/packages/a/versions/1.0.0"
    )
    assert "npm/packages/b/versions/1.0.0" in asked
    assert lookup.requests == len(asked) == 4


def test_a_failing_request_leaves_the_name_without_repos_and_is_counted() -> None:
    inv = inventory(pkg("npm", "a", "1.0.0"), pkg("npm", "b", "1.0.0"))
    network = FakeNetwork({"npm/b/1.0.0": with_repo("github.com/o/b")})
    network.script = [ew.Response(500)] * ew.MAX_ATTEMPTS
    lookup = ew.resolve_repos(depsdev_client(network), inv, workers=1)
    assert lookup.repos[("npm", "a")] == ()
    assert lookup.repos[("npm", "b")] == ("github.com/o/b",)
    assert lookup.errors == 1


def test_persistent_failures_make_deps_dev_unavailable() -> None:
    inv = inventory(*(pkg("npm", f"p{i}", "1.0.0") for i in range(30)))
    network = FakeNetwork()
    network.script = [ew.Response(503)] * 1000
    with pytest.raises(ew.DepsDevUnavailable, match="HTTP 503"):
        ew.resolve_repos(depsdev_client(network), inv, workers=1, breaker=3)


# --- the run --------------------------------------------------------------------


def trivy_native(*purls: str) -> dict[str, Any]:
    return {
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Packages": [{"Name": "n", "Identifier": {"PURL": p}} for p in purls],
            },
            {
                "Target": "app (debian 12)",
                "Class": "os-pkgs",
                "Packages": [
                    {"Name": "zlib", "Identifier": {"PURL": "pkg:deb/zlib@1"}}
                ],
            },
        ]
    }


class Workspace:
    def __init__(self, tmp_path: Path) -> None:
        self.targets_file = tmp_path / "targets.json"
        self.parts = tmp_path / "parts"
        self.trivy = self.parts / "trivy"
        self.trivy.mkdir(parents=True)
        self.out = tmp_path / "out"
        self.targets: list[dict[str, Any]] = []

    def add_target(
        self, tid: str, native: dict[str, Any] | None, status: str = "ok"
    ) -> None:
        self.targets.append({"id": tid, "scanner": "trivy", "status": "pending"})
        (self.trivy / f"{tid}.status.json").write_text(
            json.dumps({"id": tid, "status": status}), encoding="utf-8"
        )
        if native is not None:
            (self.trivy / f"{tid}.json").write_text(
                json.dumps(native), encoding="utf-8"
            )

    def args(self, **overrides: Any) -> argparse.Namespace:
        self.targets_file.write_text(
            json.dumps({"targets": self.targets}), encoding="utf-8"
        )
        values = {
            "targets_file": self.targets_file,
            "parts_dir": self.parts,
            "output_dir": self.out,
            "cve_index": IMAGE + ":1",
            "index_dir": None,
            "feed_url": FEED,
            "depsdev_url": DEPSDEV,
        }
        return argparse.Namespace(**{**values, **overrides})

    def json(self, name: str) -> Any:
        return json.loads(
            (self.out / "early-warning" / name).read_text(encoding="utf-8")
        )


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    return Workspace(tmp_path)


def guava_network() -> FakeNetwork:
    return FakeNetwork(
        {
            "maven/com.google.guava:guava/33.4.8-jre": with_repo(
                "github.com/google/guava"
            ),
            "maven/com.google.guava:failureaccess/1.0.3": with_repo(
                "github.com/google/guava"
            ),
        }
    )


def guava_index(tmp_path: Path, **metadata: Any) -> Path:
    """An index with a Guava CVE of a CNA with a history, and one of an unknown CNA."""
    return write_index(
        tmp_path / "cve-index",
        [
            slim(
                "CVE-2030-0001",
                entries=[GUAVA_ENTRY],
                assigner="Google",
                updated="2030-01-09T18:00:00Z",
            ),
        ],
        {"Google": {"confirmed": 9, "errors": 1, "pending": 2}},
        **metadata,
    )


def todays_deltas() -> FakeDownloader:
    net = FakeDownloader()
    net.hours_of_today()
    return net


GUAVA_PURLS = (
    "pkg:maven/com.google.guava/guava@33.4.8-jre",
    "pkg:maven/com.google.guava/failureaccess@1.0.3",
    "pkg:golang/example.com/x@v1.0.0",
)


def run_early_warning(
    ws: Workspace,
    network: FakeNetwork,
    net: FakeDownloader | None = None,
    environ: Mapping[str, str] | None = None,
    runner: Any = None,
    **overrides: Any,
) -> str:
    return ew.run(
        ws.args(**overrides),
        network,
        environ or {},
        NOW,
        network.sleep,
        net or todays_deltas(),
        runner or FakeOras((0, DIGEST, "")),
    )


def test_run_writes_the_part(ws: Workspace, tmp_path: Path) -> None:
    ws.add_target("source-development", trivy_native(*GUAVA_PURLS))
    ws.add_target(
        "app-development", trivy_native("pkg:maven/com.google.guava/guava@33.4.8-jre")
    )
    network = guava_network()
    status = run_early_warning(
        ws, network, index_dir=guava_index(tmp_path), cve_index=None
    )
    assert status == "ok"
    document = ws.json("status.json")
    assert document["status"] == "ok"
    assert document["reason"] is None
    assert (
        document["window_days"],
        document["records_scanned"],
        document["candidates"],
    ) == (5, 1, 1)
    # a directory has no digest; its path stands for the reference
    assert document["index"] == {
        "ref": str(tmp_path / "cve-index"),
        "digest": None,
        "built_at": BUILT,
        "gaps": [],
    }
    diagnostics = document["diagnostics"]
    assert diagnostics["packages"] == 2
    assert diagnostics["packages_unsupported"] == 1
    assert diagnostics["index_records"] == 1
    assert diagnostics["outcomes"] == {"module_unknown": 1}
    assert diagnostics["depsdev_requests"] == 2
    candidates = ws.json("candidates.json")
    assert candidates["schema_version"] == 1
    assert candidates["generated_from"] == {
        "days": 5,
        "from": "2030-01-05T12:30:00Z",
        "to": "2030-01-10T12:30:00Z",
    }
    (candidate,) = candidates["candidates"]
    assert candidate["cve"] == "CVE-2030-0001"
    assert candidate["package"]["name"] == "com.google.guava:guava"
    assert set(candidate["sightings"]) == {"source-development", "app-development"}
    assert candidate["rule"] == "T2"
    assert candidate["confidence"] == {
        "basis": "cna_history",
        "cna": "Google",
        "confirmed": 9,
        "errors": 1,
        "pending": 2,
        "ratio": 0.9,
    }


def test_run_pulls_the_index_and_reports_its_digest(
    ws: Workspace, tmp_path: Path
) -> None:
    ws.add_target("source-development", trivy_native(*GUAVA_PURLS))
    source = guava_index(tmp_path)

    def oras(command: list[str], **kwargs: Any) -> Any:
        if command[1] == "pull":  # what ORAS pulls is the files of the index
            shutil.copytree(source, command[-1])
        return FakeOras((0, DIGEST, ""))(command, **kwargs)

    assert (
        run_early_warning(
            ws, guava_network(), runner=oras, index_dir=None, cve_index=IMAGE + ":1"
        )
        == "ok"
    )
    index = ws.json("status.json")["index"]
    assert (index["ref"], index["digest"]) == (IMAGE + ":1", DIGEST)
    assert len(ws.json("candidates.json")["candidates"]) == 1


def test_deltas_since_the_index_are_part_of_the_result(
    ws: Workspace, tmp_path: Path
) -> None:
    ws.add_target("source-development", trivy_native(*GUAVA_PURLS))
    net = todays_deltas()
    # published after the index was built, by a CNA that the index does not know
    net.hour(
        "2030-01-10",
        9,
        cve_json(
            "CVE-2030-0002",
            published="2030-01-10T09:30:00Z",
            affected_entries=[
                cna(
                    packageName="com.google.guava:guava",
                    collectionURL="https://repo.maven.apache.org/maven2",
                    **affected(below("33.7.2", "4.0")),
                )
            ],
        ),
    )
    run_early_warning(
        ws, guava_network(), net, index_dir=guava_index(tmp_path), cve_index=None
    )
    candidates = {c["cve"]: c for c in ws.json("candidates.json")["candidates"]}
    assert set(candidates) == {"CVE-2030-0001", "CVE-2030-0002"}
    assert candidates["CVE-2030-0002"]["rule"] == "T1"
    assert candidates["CVE-2030-0002"]["confidence"]["ratio"] is None


def test_run_reports_the_gaps_of_the_feed(
    ws: Workspace, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws.add_target("source-development", trivy_native(*GUAVA_PURLS))
    gap = {"from": "2030-01-07T04:00:00Z", "to": "2030-01-07T08:00:00Z"}
    run_early_warning(
        ws,
        guava_network(),
        index_dir=guava_index(tmp_path, gaps=[gap]),
        cve_index=None,
    )
    assert ws.json("status.json")["index"]["gaps"] == [gap]
    assert (
        "::warning title=Early warning feed gaps::no CVE feed delta for "
        "2030-01-07T04:00:00Z to 2030-01-07T08:00:00Z" in capsys.readouterr().out
    )


def test_run_skips_without_a_scanned_trivy_target(ws: Workspace) -> None:
    ws.add_target("source-development", None, status="failed")
    network = FakeNetwork()
    oras = FakeOras((0, DIGEST, ""))
    assert run_early_warning(ws, network, runner=oras) == "skipped"
    assert ws.json("status.json")["reason"] == "no Trivy target was scanned"
    assert ws.json("status.json")["index"] is None
    assert not (ws.out / "early-warning" / "candidates.json").exists()
    assert network.requests == [] and oras.calls == []


@pytest.mark.parametrize(
    "oras",
    [
        FakeOras((1, "", "Error: unauthorized")),
        FakeOras((0, DIGEST, ""), pull_rc=1),
    ],
)
def test_run_reports_an_index_that_cannot_be_pulled_and_does_not_fail(
    ws: Workspace, oras: FakeOras, capsys: pytest.CaptureFixture[str]
) -> None:
    ws.add_target("source-development", trivy_native("pkg:npm/x@1.0.0"))
    network = FakeNetwork()
    result = run_early_warning(
        ws, network, runner=oras, index_dir=None, cve_index=IMAGE + ":1"
    )
    assert result == "failed"
    document = ws.json("status.json")
    assert document["status"] == "failed"
    assert document["reason"].startswith(f"cannot pull {IMAGE}:1")
    assert document["index"] is None
    assert not (ws.out / "early-warning" / "candidates.json").exists()
    assert "::warning title=Early warning unavailable::cannot pull" in (
        capsys.readouterr().out
    )
    assert network.requests == []  # deps.dev is not asked without the CVE records


def test_run_reports_a_delta_failure_with_the_index_and_does_not_fail(
    ws: Workspace, tmp_path: Path
) -> None:
    ws.add_target("source-development", trivy_native("pkg:npm/x@1.0.0"))
    net = todays_deltas()
    net.fail.add(f"{FEED}/{hour_asset('2030-01-10', 5)}")
    result = run_early_warning(
        ws, FakeNetwork(), net, index_dir=guava_index(tmp_path), cve_index=None
    )
    assert result == "failed"
    document = ws.json("status.json")
    assert "HTTP 500" in document["reason"]
    # the index was read: the report can say which one it was
    assert document["index"]["built_at"] == BUILT
    assert document["window_days"] == 5


def test_run_reports_deps_dev_being_down_and_does_not_fail(
    ws: Workspace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws.add_target(
        "source-development", trivy_native(*(f"pkg:npm/p{i}@1.0.0" for i in range(20)))
    )
    network = guava_network()
    network.depsdev.clear()
    original = ew.resolve_repos
    network_requests = network.requests

    def failing(client: Any, inv: Any) -> Any:
        network.script = [ew.Response(500)] * 10_000
        return original(client, inv, workers=1)

    monkeypatch.setattr(ew, "resolve_repos", failing)
    result = run_early_warning(
        ws, network, index_dir=guava_index(tmp_path), cve_index=None
    )
    assert result == "failed"
    assert "deps.dev" in ws.json("status.json")["reason"]
    assert ws.json("status.json")["index"]["built_at"] == BUILT
    assert network_requests


def test_run_writes_the_github_output(ws: Workspace, tmp_path: Path) -> None:
    ws.add_target("source-development", None, status="failed")
    output = tmp_path / "github_output"
    run_early_warning(ws, FakeNetwork(), environ={"GITHUB_OUTPUT": str(output)})
    text = output.read_text(encoding="utf-8")
    assert text.startswith("status<<ghadelimiter_")
    assert "\nskipped\n" in text


@pytest.mark.parametrize(
    "overrides",
    [
        {"feed_url": "http://feed.example"},
        {"depsdev_url": "ftp://deps.example"},
        {"cve_index": None, "index_dir": None},
        {"cve_index": IMAGE + ":1", "index_dir": Path("somewhere")},
    ],
)
def test_run_rejects_unusable_inputs(ws: Workspace, overrides: dict[str, Any]) -> None:
    ws.add_target("source-development", trivy_native("pkg:npm/x@1.0.0"))
    with pytest.raises(ew.InputError):
        run_early_warning(ws, FakeNetwork(), **overrides)


def test_run_fails_on_a_broken_targets_file(ws: Workspace) -> None:
    args = ws.args()
    ws.targets_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ew.InputError):
        ew.run(args, FakeNetwork(), {}, NOW)


def test_main_exits_one_on_unusable_input(tmp_path: Path) -> None:
    code = ew.main(
        [
            "--targets-file",
            str(tmp_path / "missing.json"),
            "--parts-dir",
            str(tmp_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--cve-index",
            IMAGE + ":1",
        ]
    )
    assert code == 1


def test_one_source_of_the_index_is_required(tmp_path: Path) -> None:
    base = ["--targets-file", "t", "--parts-dir", "p", "--output-dir", "o"]
    with pytest.raises(SystemExit):
        ew.parse_args(base)
    with pytest.raises(SystemExit):
        ew.parse_args([*base, "--cve-index", IMAGE, "--index-dir", str(tmp_path)])
    assert ew.parse_args([*base, "--index-dir", str(tmp_path)]).cve_index is None


def test_inventory_records_where_each_package_was_seen(ws: Workspace) -> None:
    ws.add_target("source-development", trivy_native("pkg:npm/x@1.0.0"))
    ws.add_target(
        "app-1.0.0",
        trivy_native("pkg:npm/x@1.0.0", "pkg:npm/y@2.0.0", "pkg:gem/z@1.0.0"),
    )
    ws.add_target("broken", None, status="failed")
    ws.args()
    targets = ew.load_targets_file(ws.targets_file)
    inv = ew.load_inventory(targets, ws.trivy)
    assert inv.targets_read == 2
    assert inv.sightings[pkg("npm", "x", "1.0.0")] == {
        "source-development": {"package-lock.json"},
        "app-1.0.0": {"package-lock.json"},
    }
    # a Ruby package; the OS packages are not part of the inventory at all
    assert inv.unsupported == 1
    assert Counter(p.ecosystem for p in inv.sightings) == {"npm": 2}
