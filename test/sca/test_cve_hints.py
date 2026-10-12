"""Tests for the curated hints of actions/sca_early_warning/early_warning.py: the
schema (``parse_hints``) and the matching (``match_records`` with hints), on synthetic
records and packages. The index and the report are tested with the early warning and
the builder.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load_early_warning():
    path = ROOT / "actions" / "sca_early_warning" / "early_warning.py"
    spec = importlib.util.spec_from_file_location("early_warning", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


ew = _load_early_warning()


# --- builders -------------------------------------------------------------------


def maven(name: str, version: str) -> Any:
    return ew.Package("maven", name, version)


def inventory(*packages: Any) -> Any:
    inv = ew.Inventory()
    for package in packages:
        inv.sightings[package] = {"source-development": {"pom.xml"}}
    inv.targets_read = 1
    return inv


def affected(*versions: dict[str, Any], **entry: Any) -> dict[str, Any]:
    return {"defaultStatus": "unaffected", "versions": list(versions), **entry}


def below(limit: str, start: str = "0") -> dict[str, Any]:
    return {
        "version": start,
        "lessThan": limit,
        "status": "affected",
        "versionType": "custom",
    }


def record(
    cve: str = "CVE-2030-0001",
    entries: list[dict[str, Any]] | None = None,
    assigner: str = "apache",
    title: str = "A title",
    description: str = "A description",
    refs: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "cve": cve,
        "state": "PUBLISHED",
        "published": "2030-01-05T10:00:00.000Z",
        "updated": "2030-01-06T10:00:00.000Z",
        "assigner": assigner,
        "title": title,
        "description": description,
        "affected": entries or [],
        "references": list(refs),
        "metrics": {"cvss": [], "exploitation": None},
    }


def hint_doc(**fields: Any) -> dict[str, Any]:
    """A valid product hint of Tomcat, with the fields changed."""
    hint = {
        "id": "apache-tomcat",
        "kind": "product",
        "reason": "The CNA names the product and no artifact",
        "source": "https://tomcat.apache.org/security.html",
        "added": "2030-01-01",
        "ecosystem": "maven",
        "packages": ["org.apache.tomcat.embed:tomcat-embed-core"],
        "product": "Apache Tomcat",
        "versions_are_artifact_versions": True,
    }
    return {k: v for k, v in {**hint, **fields}.items() if v is not None}


def cve_hint_doc(**fields: Any) -> dict[str, Any]:
    hint = {
        "id": "guava-33-7-2",
        "kind": "cve",
        "reason": "The CNA has no package",
        "source": "https://github.com/google/guava/security/advisories",
        "added": "2030-01-01",
        "ecosystem": "maven",
        "packages": ["com.google.guava:guava"],
        "cve": "CVE-2030-0001",
    }
    return {k: v for k, v in {**hint, **fields}.items() if v is not None}


def hints_of(*docs: dict[str, Any]) -> tuple[Any, ...]:
    return ew.parse_hints({"schema_version": 1, "hints": list(docs)})


def match(records: list[dict[str, Any]], inv: Any, hints: Any, repos: Any = ()) -> Any:
    index = ew.build_index(inv, dict(repos))
    return ew.match_records(records, index, inv, {}, hints)


def found(result: Any) -> set[tuple[str, str, str, str]]:
    return {
        (c["cve"], c["package"]["name"], c["package"]["version"], c["rule"])
        for c in result.candidates
    }


TOMCAT_ENTRY = {
    "vendor": "Apache Software Foundation",
    "product": "Apache Tomcat",
    **affected(below("11.0.25", "11.0.0-M1"), below("10.1.58", "10.1.0-M1")),
}
CORE = "org.apache.tomcat.embed:tomcat-embed-core"


# --- the schema -----------------------------------------------------------------


def test_the_hints_round_trip_through_their_json() -> None:
    hints = hints_of(
        hint_doc(
            packages=["org.apache.tomcat.embed:tomcat-embed-*", "org.apache.tomcat:*"],
            exclude=["org.apache.tomcat.embed:tomcat-embed-el"],
            vendor="Apache Software Foundation",
            assigner="apache",
            module_from_text=True,
            added="2030-01-01",
        ),
        cve_hint_doc(ranges=[{"before": "33.7.2", "from": "4.0"}, {"through": "3.9"}]),
    )
    document = ew.hints_document(hints)
    assert ew.parse_hints(document) == hints
    assert ew.hints_document(ew.parse_hints(document)) == document
    product, by_cve = document["hints"]
    assert product["exclude"] == ["org.apache.tomcat.embed:tomcat-embed-el"]
    assert by_cve["ranges"] == [
        {"before": "33.7.2", "from": "4.0"},
        {"from": "0", "through": "3.9"},
    ]
    assert "vendor" not in document["hints"][0] or document["hints"][0]["vendor"]


def test_a_date_of_yaml_and_the_names_are_normalized() -> None:
    import datetime

    (hint,) = hints_of(
        hint_doc(added=datetime.date(2030, 1, 1), packages=["Org.Apache:Tomcat-*"])
    )
    assert hint.added == "2030-01-01"
    assert hint.packages == ("org.apache:tomcat-*",)


def test_no_hints_is_valid() -> None:
    assert ew.parse_hints({"schema_version": 1, "hints": []}) == ()


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (None, "mapping"),
        ({"schema_version": 1}, "mapping"),
        ({"schema_version": 2, "hints": []}, "schema_version"),
        ({"schema_version": True, "hints": []}, "schema_version"),
        ({"schema_version": 1, "hints": {}}, "list"),
        ({"schema_version": 1, "hints": [1]}, "mapping"),
        ({"schema_version": 1, "hints": [], "extra": 1}, "mapping"),
    ],
)
def test_a_document_of_another_shape_is_refused(document: Any, message: str) -> None:
    with pytest.raises(ew.HintsError, match=message):
        ew.parse_hints(document)


@pytest.mark.parametrize(
    ("hint", "message"),
    [
        (hint_doc(kind="other"), "kind"),
        (hint_doc(kind=None), "kind"),
        (hint_doc(extra="x"), "unknown key"),
        (hint_doc(cve="CVE-2030-0001"), "unknown key"),  # a key of the other kind
        (cve_hint_doc(product="x"), "unknown key"),
        (hint_doc(reason=None), "missing reason"),
        (hint_doc(source=None), "missing source"),
        (hint_doc(added=None), "missing added"),
        (hint_doc(product=None), "missing product"),
        (hint_doc(versions_are_artifact_versions=None), "missing"),
        (hint_doc(versions_are_artifact_versions=False), "must be true"),
        (hint_doc(id="Bad Id"), "id"),
        (hint_doc(id=1), "id"),
        (hint_doc(reason=" padded"), "one line"),
        (hint_doc(reason="two\nlines"), "one line"),
        (hint_doc(reason="x" * 501), "one line"),
        (hint_doc(reason=""), "non-empty"),
        (hint_doc(source="http://tomcat.apache.org"), "https"),
        (hint_doc(added="2030-13-01"), "date"),
        (hint_doc(added="2030-1-1"), "date"),
        (hint_doc(added=20300101), "date"),
        (hint_doc(ecosystem="golang"), "ecosystem"),
        (hint_doc(packages=[]), "non-empty list"),
        (hint_doc(packages="org.a:b"), "non-empty list"),
        (hint_doc(packages=["*"]), "matches everything"),
        (hint_doc(packages=["org.a:b", "ORG.a:b"]), "twice"),
        (hint_doc(packages=["org.*:b"]), "literal group"),
        (hint_doc(packages=["tomcat"]), "group:artifact"),
        (hint_doc(packages=["org.a:"]), "group:artifact"),
        (hint_doc(packages=["org a:b"]), "not a package name"),
        (hint_doc(exclude=[]), "non-empty list"),
        (hint_doc(module_from_text="yes"), "true or false"),
        (hint_doc(module_from_text=True), "needs a pattern"),
        (cve_hint_doc(cve="CVE-30-1"), "CVE id"),
        (cve_hint_doc(cve=None), "missing cve"),
        (cve_hint_doc(packages=["com.google.guava:*"]), "exact names"),
        (cve_hint_doc(ranges=[]), "non-empty list"),
        (cve_hint_doc(ranges=[{"from": "1"}]), "exactly one of"),
        (cve_hint_doc(ranges=[{"before": "1", "through": "1"}]), "exactly one of"),
        (cve_hint_doc(ranges=[{"before": "1", "to": "2"}]), "mapping of"),
        (cve_hint_doc(ranges=[{"before": "latest"}]), "not a maven version"),
        (cve_hint_doc(ranges=[{"before": "*"}]), "not a maven version"),
        (cve_hint_doc(ranges=["< 1"]), "mapping of"),
    ],
)
def test_a_hint_that_is_not_valid_is_refused(
    hint: dict[str, Any], message: str
) -> None:
    with pytest.raises(ew.HintsError, match=message):
        hints_of(hint)


def test_a_pattern_is_for_a_product_hint_with_a_literal_group_in_maven_only() -> None:
    hints_of(hint_doc(ecosystem="pypi", packages=["huggingface-*"], product="x"))
    hints_of(hint_doc(ecosystem="npm", packages=["@scope/*"], product="x"))


def test_a_duplicate_id_or_cve_is_refused() -> None:
    with pytest.raises(ew.HintsError, match="duplicate id apache-tomcat"):
        hints_of(hint_doc(), hint_doc(product="Other"))
    with pytest.raises(ew.HintsError, match="duplicate cve CVE-2030-0001"):
        hints_of(cve_hint_doc(), cve_hint_doc(id="second"))


# --- product hints --------------------------------------------------------------


def test_a_product_hint_matches_a_product_the_cna_does_not_map_to_a_package() -> None:
    inv = inventory(maven(CORE, "11.0.22"), maven(CORE, "11.0.30"))
    result = match([record(entries=[TOMCAT_ENTRY])], inv, hints_of(hint_doc()))
    # 11.0.30 is above the range of the CNA: the CNA's own ranges apply
    assert found(result) == {("CVE-2030-0001", CORE, "11.0.22", "hint")}
    (candidate,) = result.candidates
    assert candidate["confidence"] == {"basis": "hint", "hint_id": "apache-tomcat"}
    assert (
        candidate["affected_range"]
        == ">= 11.0.0-M1, < 11.0.25; >= 10.1.0-M1, < 10.1.58"
    )
    assert result.outcomes["version_outside_range"] == 1


def test_without_hints_the_product_is_not_matched() -> None:
    inv = inventory(maven(CORE, "11.0.22"))
    assert not match([record(entries=[TOMCAT_ENTRY])], inv, ()).candidates


def test_the_product_is_compared_the_way_names_are() -> None:
    inv = inventory(maven(CORE, "11.0.22"))
    entry = {**TOMCAT_ENTRY, "product": "apache-tomcat"}
    assert found(match([record(entries=[entry])], inv, hints_of(hint_doc()))) == {
        ("CVE-2030-0001", CORE, "11.0.22", "hint")
    }
    other = {**TOMCAT_ENTRY, "product": "Apache Tomcat Native"}
    assert not match([record(entries=[other])], inv, hints_of(hint_doc())).candidates


def test_the_assigner_and_the_vendor_restrict_the_hint_when_it_names_them() -> None:
    inv = inventory(maven(CORE, "11.0.22"))
    hints = hints_of(
        hint_doc(assigner="apache", vendor="Apache Software Foundation"),
    )
    assert match([record(entries=[TOMCAT_ENTRY])], inv, hints).candidates
    # case does not matter for the CNA short name
    assert match(
        [record(entries=[TOMCAT_ENTRY], assigner="Apache")], inv, hints
    ).candidates
    wrong_cna = record(entries=[TOMCAT_ENTRY], assigner="VulnCheck")
    assert not match([wrong_cna], inv, hints).candidates
    wrong_vendor = {**TOMCAT_ENTRY, "vendor": "Somebody"}
    assert not match([record(entries=[wrong_vendor])], inv, hints).candidates
    # a hint that names neither takes the product of any CNA
    anyone = hints_of(hint_doc())
    assert match([wrong_cna], inv, anyone).candidates


def test_only_the_packages_of_the_hint_are_candidates() -> None:
    inv = inventory(
        maven(CORE, "11.0.22"),
        maven("org.apache.tomcat.embed:tomcat-embed-el", "11.0.22"),
        maven("org.apache.tomcat.embed:tomcat-embed-core", "9.0.1"),
        ew.Package("npm", "tomcat-embed-core", "11.0.22"),
    )
    result = match([record(entries=[TOMCAT_ENTRY])], inv, hints_of(hint_doc()))
    assert found(result) == {("CVE-2030-0001", CORE, "11.0.22", "hint")}


def test_a_pattern_stands_for_any_characters_and_exclude_takes_names_out() -> None:
    names = [
        "org.springframework:spring-core",
        "org.springframework:spring-webmvc",
        "org.springframework:spring-boot",  # an exclusion
        "org.springframework.boot:spring-boot",  # another group
        "org.springframework:springloaded",  # the pattern needs the dash
    ]
    inv = inventory(*(maven(n, "6.2.1") for n in names))
    entry = {
        "vendor": "Spring",
        "product": "Spring Framework",
        **affected(below("6.2.5", "6.2.0")),
    }
    hint = hint_doc(
        id="spring",
        product="Spring Framework",
        packages=["org.springframework:spring-*"],
        exclude=["org.springframework:spring-boot"],
    )
    result = match([record(entries=[entry])], inv, hints_of(hint))
    assert {name for _, name, _, _ in found(result)} == {
        "org.springframework:spring-core",
        "org.springframework:spring-webmvc",
    }


def test_the_module_of_the_text_keeps_the_artifacts_the_text_names() -> None:
    names = [
        "io.netty:netty-codec-http",
        "io.netty:netty-codec-http2",
        "io.netty:netty-codec-socks",
        "io.netty:netty-handler",
        "io.netty:netty-common",
        "io.netty:netty-all",
    ]
    inv = inventory(*(maven(n, "4.1.100.Final") for n in names))
    entry = {"vendor": "netty", "product": "netty", **affected(below("4.1.137.Final"))}
    hint = hint_doc(
        id="netty",
        product="netty",
        packages=["io.netty:netty-*", "io.netty:netty-all"],
        module_from_text=True,
    )
    text = (
        "Prior to 4.1.137.Final, io.netty.handler.codec.http.cors.CorsHandler is wrong"
    )
    result = match([record(entries=[entry], description=text)], inv, hints_of(hint))
    # codec-http (its words are in the package name), and the exact name needs no text;
    # codec-http2 is not codec-http, and handler/common/socks are not in the text...
    assert {n for _, n, _, _ in found(result)} == {
        "io.netty:netty-codec-http",
        "io.netty:netty-handler",  # ... but "handler" is: the limit of the module
        "io.netty:netty-all",
    }
    assert result.outcomes["hint_module_not_in_text"] == 3


def test_the_module_may_be_named_in_the_title_with_any_separator() -> None:
    inv = inventory(maven("io.netty:netty-codec-http", "4.1.100.Final"))
    entry = {"vendor": "netty", "product": "netty", **affected(below("4.1.137.Final"))}
    hint = hint_doc(id="netty", product="netty", packages=["io.netty:netty-*"])
    hint["module_from_text"] = True
    for title in ("netty-codec-http: x", "io.netty.codec.http", "codec_http leaks"):
        result = match([record(entries=[entry], title=title)], inv, hints_of(hint))
        assert result.candidates, title
    result = match(
        [record(entries=[entry], title="netty-codec-http2")], inv, hints_of(hint)
    )
    assert not result.candidates


def test_the_versions_of_the_entry_decide_and_an_unknown_one_matches_nothing() -> None:
    inv = inventory(maven(CORE, "11.0.22"), maven(CORE, "not-a-version"))
    result = match([record(entries=[TOMCAT_ENTRY])], inv, hints_of(hint_doc()))
    assert found(result) == {("CVE-2030-0001", CORE, "11.0.22", "hint")}
    no_versions = {
        "vendor": "x",
        "product": "Apache Tomcat",
        "defaultStatus": "unknown",
    }
    assert not match(
        [record(entries=[no_versions])], inv, hints_of(hint_doc())
    ).candidates


# --- cve hints ------------------------------------------------------------------

GUAVA = "com.google.guava:guava"
GUAVA_ENTRY = {
    "vendor": "Google",
    "product": "Guava",
    **affected(below("33.7.2", "4.0")),
}


def test_a_cve_hint_names_the_package_of_one_cve_and_takes_the_ranges_of_the_cna() -> (
    None
):
    inv = inventory(maven(GUAVA, "33.4.8-jre"), maven(GUAVA, "33.7.2"))
    records = [
        record(entries=[GUAVA_ENTRY]),
        record("CVE-2030-0002", entries=[GUAVA_ENTRY]),  # no hint: nothing found
    ]
    result = match(records, inv, hints_of(cve_hint_doc()))
    assert found(result) == {("CVE-2030-0001", GUAVA, "33.4.8-jre", "hint")}
    (candidate,) = result.candidates
    assert candidate["confidence"] == {"basis": "hint", "hint_id": "guava-33-7-2"}


def test_the_ranges_of_a_cve_hint_replace_those_of_the_cna() -> None:
    inv = inventory(
        maven(GUAVA, "30.0"), maven(GUAVA, "33.4.8-jre"), maven(GUAVA, "40.0")
    )
    wrong = {"vendor": "Google", "product": "Guava", **affected(below("2.0"))}
    hint = cve_hint_doc(
        ranges=[{"from": "4.0", "before": "33.7.2"}, {"through": "1.0"}]
    )
    result = match([record(entries=[wrong])], inv, hints_of(hint))
    assert {v for _, _, v, _ in found(result)} == {"30.0", "33.4.8-jre"}
    assert {c["affected_range"] for c in result.candidates} == {
        ">= 4.0, < 33.7.2; <= 1.0"
    }
    # also where the CNA has no entry at all
    assert match([record(entries=[])], inv, hints_of(hint)).candidates


def test_a_cve_hint_without_ranges_needs_the_entries_of_the_cna() -> None:
    inv = inventory(maven(GUAVA, "33.4.8-jre"))
    assert not match([record(entries=[])], inv, hints_of(cve_hint_doc())).candidates


# --- priority -------------------------------------------------------------------


def test_a_package_that_t1_matched_is_not_matched_by_a_hint() -> None:
    inv = inventory(maven(CORE, "11.0.22"), maven(CORE, "11.0.30"))
    entry = {"packageName": CORE, **affected(below("11.0.25", "11.0.0-M1"))}
    entries = [entry, TOMCAT_ENTRY]
    result = match([record(entries=entries)], inv, hints_of(hint_doc()))
    # 11.0.22 is T1's; 11.0.30 is outside T1's range and the hint must not take it
    # up by the range of the other entry
    assert found(result) == {("CVE-2030-0001", CORE, "11.0.22", "T1")}
    assert result.candidates[0]["confidence"]["basis"] == "cna_history", (
        "T1 keeps its own confidence"
    )
    wide = {"packageName": CORE, **affected(below("11.0.0"))}
    result = match([record(entries=[wide, TOMCAT_ENTRY])], inv, hints_of(hint_doc()))
    assert not result.candidates, (
        "T1 says not affected, and a hint does not overrule it"
    )


def test_a_hint_ranks_before_t3_and_repo_level_and_after_t2() -> None:
    assert [ew.RULE_PRIORITY[r] for r in ("T1", "T2", "hint", "T3", "repo-level")] == [
        0,
        1,
        2,
        3,
        4,
    ]
    package = ew.Package("npm", "lodash", "4.17.0")
    inv = inventory(package)
    entry = {"vendor": "lodash", "product": "lodash", **affected(below("4.17.21"))}
    refs = ("https://github.com/lodash/lodash/issues/1",)
    repos = {("npm", "lodash"): ("github.com/lodash/lodash",)}
    plain = match([record(entries=[entry], refs=refs)], inv, (), repos)
    assert {c["rule"] for c in plain.candidates} == {"T3"}
    hint = hint_doc(id="lodash", ecosystem="npm", product="lodash", packages=["lodash"])
    hinted = match([record(entries=[entry], refs=refs)], inv, hints_of(hint), repos)
    assert {c["rule"] for c in hinted.candidates} == {"hint"}
    t2 = {"repo": "https://github.com/lodash/lodash", "product": "lodash", **entry}
    result = match([record(entries=[t2], refs=refs)], inv, hints_of(hint), repos)
    assert {c["rule"] for c in result.candidates} == {"T2"}


def test_a_hint_changes_neither_the_other_candidates_nor_their_order() -> None:
    inv = inventory(maven(CORE, "11.0.22"), maven(GUAVA, "33.4.8-jre"))
    entry = {"packageName": GUAVA, **affected(below("33.7.2", "4.0"))}
    records = [
        record("CVE-2030-0002", entries=[entry]),
        record("CVE-2030-0001", entries=[TOMCAT_ENTRY]),
    ]
    plain = match(records, inv, ())
    hinted = match(records, inv, hints_of(hint_doc()))
    assert [c for c in hinted.candidates if c["rule"] != "hint"] == plain.candidates
    # the order is that of every candidate (here by package name), not a hint's first
    assert [c["cve"] for c in hinted.candidates] == ["CVE-2030-0002", "CVE-2030-0001"]


def test_the_hints_in_a_run_are_the_given_ones() -> None:
    hints = hints_of(hint_doc())
    inv = inventory(maven(CORE, "11.0.22"))
    index = ew.build_index(inv, {})
    records = [record(entries=[TOMCAT_ENTRY])]
    assert ew.match_records(records, index, inv, {}, hints).candidates
    assert not ew.match_records(records, index, inv, {}).candidates
    assert copy.deepcopy(hints) == hints  # frozen values, nothing shared by accident


def test_the_confidence_of_a_hint_names_it() -> None:
    cnas: Mapping[str, Mapping[str, int]] = {
        "apache": {"confirmed": 5, "errors": 0, "pending": 0}
    }
    assert ew.confidence_of("hint", "apache", cnas, "apache-tomcat") == {
        "basis": "hint",
        "hint_id": "apache-tomcat",
    }
