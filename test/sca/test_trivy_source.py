"""Tests of actions/sca_merge_results/trivy_source.py (synthetic fixtures only)."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_merge_results import (
    PACKAGES_NATIVE,
    gradle_result,
    graph_file,
    info_for,
    ladder,
    pkg,
)
from trivy_source import (
    MAX_DEPENDENCY_PATHS,
    PATH_COUNT_LIMIT,
    DependencyInfo,
    PackageIndex,
    ProjectGraph,
    canonical_package_name,
    combine_dependency_info,
    count_packages,
    enrich_gradle_results,
    load_gradle_graphs,
    lockfile_project_dir,
    normalize_project_dir,
    package_relationships,
    parse_project_graph,
    select_cvss,
    split_fixed_versions,
)


def test_count_packages_distinct_name_and_version() -> None:
    assert count_packages(PACKAGES_NATIVE) == {
        "packages_scanned": 3,
        "locations_scanned": 3,
    }
    assert count_packages({"Results": None}) == {
        "packages_scanned": 0,
        "locations_scanned": 0,
    }
    assert count_packages({}) == {"packages_scanned": 0, "locations_scanned": 0}


def test_split_fixed_versions() -> None:
    assert split_fixed_versions("15.5.27, 16.3.8") == ["15.5.27", "16.3.8"]
    assert split_fixed_versions(" 1.0 ,, ") == ["1.0"]
    assert split_fixed_versions(None) == []
    assert split_fixed_versions("") == []


def test_select_cvss_prefers_severity_source() -> None:
    v = {
        "SeveritySource": "ghsa",
        "CVSS": {
            "nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N"},
            "ghsa": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:L"},
        },
    }
    assert select_cvss(v) == {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:L",
        "version": "3.1",
        "source": "ghsa",
    }


def test_select_cvss_falls_back_to_nvd_then_ghsa_then_alphabetical() -> None:
    entry = {"V3Score": 5.0, "V3Vector": "CVSS:3.0/AV:N"}
    both = {"CVSS": {"ghsa": entry, "nvd": entry, "redhat": entry}}
    assert select_cvss(both)["source"] == "nvd"
    no_nvd = {"SeveritySource": "debian", "CVSS": {"redhat": entry, "ghsa": entry}}
    assert select_cvss(no_nvd)["source"] == "ghsa"
    others = {"CVSS": {"redhat": entry, "bitnami": entry}}
    assert select_cvss(others)["source"] == "bitnami"
    assert select_cvss(others)["version"] == "3.0"


def test_select_cvss_prefers_v4_of_the_chosen_source() -> None:
    v = {
        "CVSS": {
            "nvd": {
                "V3Score": 7.0,
                "V3Vector": "CVSS:3.1/AV:N",
                "V40Score": 8.7,
                "V40Vector": "CVSS:4.0/AV:N",
            }
        }
    }
    cvss = select_cvss(v)
    assert (cvss["score"], cvss["version"]) == (8.7, "4.0")


def test_select_cvss_skips_sources_without_a_score() -> None:
    v = {
        "SeveritySource": "redhat",
        "CVSS": {"redhat": {"V2Score": 5.0}, "ghsa": {"V3Score": 4.0}},
    }
    assert select_cvss(v)["source"] == "ghsa"


def test_relationship_unknown_is_left_out() -> None:
    packages = [{"Name": "a", "Version": "1", "Relationship": "unknown"}]
    assert package_relationships(packages) == set()


@pytest.mark.parametrize(
    ("name", "result_type", "expected"),
    [
        ("Mako", "python-pkg", "mako"),
        ("mako", "poetry", "mako"),
        ("Typing_Extensions", "pip", "typing-extensions"),
        ("zope.interface", "uv", "zope-interface"),
        ("a-_.b", "conda-pkg", "a-b"),
        ("Lodash", "npm", "Lodash"),
        ("Org.Example:Lib", "gradle", "Org.Example:Lib"),
        ("Zlib", "alpine", "Zlib"),
        ("Mako", None, "Mako"),
        (None, "poetry", None),
    ],
)
def test_canonical_package_name(
    name: str | None, result_type: str | None, expected: str | None
) -> None:
    assert canonical_package_name(name, result_type) == expected


def test_dependency_chain_deeper_than_three_levels() -> None:
    packages = [
        pkg("jest", "direct", ("@jest/core",)),
        pkg("@jest/core", deps=("micromatch",)),
        pkg("micromatch", deps=("braces",)),
        pkg("braces"),
    ]
    info = info_for(packages, "braces")
    assert info.paths == [("jest", "@jest/core", "micromatch", "braces")]
    assert (info.total, info.truncated) == (1, False)
    assert info.roots == {"jest"}


def test_dependency_paths_of_a_diamond_shortest_then_alphabetical() -> None:
    packages = [
        pkg("a", "direct", ("c", "b", "long")),
        pkg("e", "direct", ("d",)),
        pkg("b", deps=("d",)),
        pkg("c", deps=("d",)),
        pkg("long", deps=("longer",)),
        pkg("longer", deps=("d",)),
        pkg("d"),
    ]
    info = info_for(packages, "d")
    assert info.paths == [
        ("e", "d"),
        ("a", "b", "d"),
        ("a", "c", "d"),
        ("a", "long", "longer", "d"),
    ]
    assert info.total == 4
    assert info.roots == {"a", "e"}


def test_dependency_paths_stop_at_the_nearest_direct_package() -> None:
    packages = [
        pkg("outer", "direct", ("inner",)),
        pkg("inner", "direct", ("leaf",)),
        pkg("leaf"),
    ]
    info = info_for(packages, "leaf")
    assert info.paths == [("inner", "leaf")]
    assert info.roots == {"inner"}


def test_dependency_paths_survive_a_cycle() -> None:
    packages = [
        pkg("a", "direct", ("b",)),
        pkg("b", deps=("c",)),
        pkg("c", deps=("b", "t")),
        pkg("t"),
    ]
    info = info_for(packages, "t")
    assert info.paths == [("a", "b", "c", "t")]
    assert info.total == 1


def test_dependency_paths_are_capped_but_counted_exactly() -> None:
    info = info_for(ladder(4), "t")
    assert info.total == 16
    assert info.truncated is False
    assert len(info.paths) == MAX_DEPENDENCY_PATHS
    assert info.paths[0] == ("root", "x1", "x2", "x3", "x4", "t")
    assert list(info.paths) == sorted(info.paths, key=lambda p: (len(p), p))


def test_dependency_path_count_is_bounded_and_marked_truncated() -> None:
    info = info_for(ladder(14), "t")  # 16384 paths
    assert info.total == PATH_COUNT_LIMIT
    assert info.truncated is True
    assert len(info.paths) == MAX_DEPENDENCY_PATHS


def test_introduced_via_lists_all_roots_not_just_the_stored_paths() -> None:
    names = [f"r{n}" for n in range(7)]
    packages = [pkg(n, "direct", ("t",)) for n in names] + [pkg("t")]
    info = info_for(packages, "t")
    assert info.total == 7
    assert len(info.paths) == 5
    assert info.roots == set(names)
    paths, total, truncated, via = combine_dependency_info([info])
    assert (total, truncated) == (7, False)
    assert via == names[:5]
    assert len(paths) == 5


def test_direct_and_graphless_packages() -> None:
    direct = info_for([pkg("lodash", "direct")], "lodash")
    assert (list(direct.paths), direct.total, set(direct.roots)) == (
        [("lodash",)],
        1,
        set(),
    )
    lonely = info_for([pkg("x")], "x")  # indirect, nothing depends on it
    assert (list(lonely.paths), lonely.total, set(lonely.roots)) == ([], 0, set())
    unknown = info_for([pkg("x", "unknown")], "x")
    assert (list(unknown.paths), unknown.total) == ([], 0)


def test_combine_dependency_info_dedupes_paths_and_sums_totals() -> None:
    one = DependencyInfo([("a", "t")], 1, False, frozenset({"a"}))
    two = DependencyInfo([("a", "t"), ("b", "t")], 2, False, frozenset({"a", "b"}))
    paths, total, truncated, via = combine_dependency_info([one, two])
    assert paths == [["a", "t"], ["b", "t"]]
    assert (total, truncated, via) == (3, False, ["a", "b"])
    assert combine_dependency_info([]) == ([], 0, False, [])


def test_package_index_matches_by_uid_then_id_then_name() -> None:
    packages = [
        {"ID": "mako@1", "Name": "mako", "Version": "1", "Identifier": {"UID": "u"}},
    ]
    index = PackageIndex(packages, "poetry")
    assert index.match({"PkgIdentifier": {"UID": "u"}}) == packages
    assert index.match({"PkgID": "mako@1"}) == packages
    assert index.match({"PkgName": "Mako", "InstalledVersion": "1"}) == packages
    assert index.match({"PkgName": "Mako", "InstalledVersion": "2"}) == []


def test_enrich_gradle_results_marks_direct_and_drops_foreign_edges() -> None:
    native = {
        "Results": [
            gradle_result("gradle.lockfile", "g:a", "g:b"),
            {"Target": "package-lock.json", "Type": "npm", "Packages": [pkg("x")]},
        ]
    }
    graphs, problems = load_gradle_graphs(Path("does-not-exist"))
    assert (graphs, problems) == ({}, [])
    graph = ProjectGraph(
        direct={"g:a:1.0"},
        edges={"g:a:1.0": {"g:b:1.0", "g:gone:1.0"}, "g:b:1.0": {"g:a:1.0"}},
    )
    assert enrich_gradle_results(native, {".": graph}) == []
    by_name = {p["Name"]: p for p in native["Results"][0]["Packages"]}
    assert by_name["g:a"]["Relationship"] == "direct"
    assert by_name["g:a"]["DependsOn"] == ["g:b:1.0"]
    assert by_name["g:b"]["Relationship"] == "indirect"
    assert by_name["g:b"]["DependsOn"] == ["g:a:1.0"]
    # not a gradle Result: untouched
    assert "Relationship" in native["Results"][1]["Packages"][0]
    assert native["Results"][1]["Packages"][0]["DependsOn"] == []


def test_enrich_gradle_results_leaves_packages_unknown_to_the_graph() -> None:
    native = {"Results": [gradle_result("server/gradle.lockfile", "g:a", "g:b")]}
    graph = ProjectGraph(direct={"g:a:1.0"}, edges={"g:a:1.0": set()})
    assert enrich_gradle_results(native, {"server": graph}) == []
    unknown = native["Results"][0]["Packages"][1]
    assert "Relationship" not in unknown and "DependsOn" not in unknown


def test_lockfile_project_dir_and_graph_project_dir_are_comparable() -> None:
    assert lockfile_project_dir("gradle.lockfile") == "."
    assert lockfile_project_dir("nested/util/gradle.lockfile") == "nested/util"
    assert normalize_project_dir("") == "."
    assert normalize_project_dir("./app") == "app"
    data = graph_file(":", ".", {"g:a:1.0": []}, ["g:a:1.0"])
    assert parse_project_graph(data)[0] == "."
