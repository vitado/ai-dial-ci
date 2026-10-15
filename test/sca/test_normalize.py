"""Normalizers of the SCA merge: Trivy and OSV results into findings."""

import json

from normalize import (
    apply_gradle_graph,
    borrow_source_chains,
    normalize_osv,
    normalize_trivy,
    pick_id,
    severity_of_score,
)


def package(name, version="1.0", depends_on=(), rel=None, dev=False, **extra):
    pkg = {"ID": f"{name}@{version}", "Name": name, "Version": version, **extra}
    pkg["DependsOn"] = [f"{d}@1.0" for d in depends_on]
    if rel:
        pkg["Relationship"] = rel
    if dev:
        pkg["Dev"] = True
    return pkg


def vuln(name, vid="CVE-2026-1", version="1.0", **extra):
    return {
        "VulnerabilityID": vid,
        "PkgName": name,
        "InstalledVersion": version,
        "Severity": "HIGH",
        "FixedVersion": "2.0",
        "PrimaryURL": f"https://example.test/{vid}",
        **extra,
    }


def result(
    packages, vulns=(), target="package-lock.json", rtype="npm", cls="lang-pkgs"
):
    return {
        "Target": target,
        "Type": rtype,
        "Class": cls,
        "Packages": packages,
        "Vulnerabilities": list(vulns),
    }


def trivy(*results, tid="source-development"):
    findings, inventory = {}, {}
    normalize_trivy(tid, {"Results": list(results)}, findings, inventory)
    return list(findings.values()), inventory


def test_id_is_the_cve_of_the_id_or_the_aliases():
    assert pick_id(["GHSA-aaaa", "CVE-2026-2", "CVE-2026-1"]) == "CVE-2026-1"
    assert pick_id(["GHSA-aaaa", "PYSEC-1"]) == "GHSA-aaaa"
    rows, _ = trivy(
        result([package("a")], [vuln("a", "GHSA-aaaa", VendorIDs=["CVE-2026-7"])])
    )
    assert (rows[0]["id"], rows[0]["aliases"]) == ("CVE-2026-7", ["GHSA-aaaa"])


def test_copies_in_several_lockfiles_become_one_row_with_locations():
    pkgs = [package("a")]
    rows, _ = trivy(
        result(
            pkgs,
            [vuln("a", PkgPath="x/package-lock.json")],
            target="x/package-lock.json",
        ),
        result(pkgs, [vuln("A")], target="y/package-lock.json"),
    )
    assert len(rows) == 1
    assert rows[0]["locations"] == ["x/package-lock.json", "y/package-lock.json"]
    assert rows[0]["severity"] == "HIGH" and rows[0]["fixed_version"] == "2.0"


def test_chain_is_the_shortest_path_from_the_nearest_direct_dependency():
    pkgs = [
        package("top", depends_on=["mid", "x"], rel="direct"),
        package("mid", depends_on=["leaf"], rel="indirect"),
        package("x", depends_on=["y"], rel="indirect"),
        package("y", depends_on=["leaf"], rel="indirect"),
        package("leaf", rel="indirect", dev=True),
        package("own", rel="direct"),
    ]
    rows, _ = trivy(result(pkgs, [vuln("leaf"), vuln("own", "CVE-2026-2")]))
    leaf, own = rows
    assert leaf["chain"] == ["top", "mid", "leaf"]
    assert (leaf["relationship"], leaf["dev"]) == ("indirect", True)
    assert own["chain"] == ["own"] and own["relationship"] == "direct"


def test_a_dependency_cycle_ends_and_gives_no_chain():
    pkgs = [
        package("a", depends_on=["b"], rel="indirect"),
        package("b", depends_on=["a"], rel="indirect"),
    ]
    rows, _ = trivy(result(pkgs, [vuln("b")]))
    assert rows[0]["chain"] == []


def test_no_graph_information_is_an_empty_chain_not_an_error():
    rows, _ = trivy(result([package("a")], [vuln("a")]))
    assert rows[0]["chain"] == [] and rows[0]["relationship"] is None


def test_os_findings_have_no_locations_and_no_chain():
    pkgs = [package("zlib", "1.3")]
    rows, inventory = trivy(
        result(pkgs, [vuln("zlib", version="1.3")], "alpine", "alpine", "os-pkgs")
    )
    assert (rows[0]["class"], rows[0]["locations"], rows[0]["chain"]) == ("os", [], [])
    assert inventory == {}


def write_graph(directory, project_dir, direct, modules):
    directory.mkdir(exist_ok=True)
    data = {
        "schema_version": 1,
        "project": ":" + project_dir,
        "project_dir": project_dir,
        "configurations": {"runtimeClasspath": {"direct": direct, "modules": modules}},
    }
    (directory / f"graph-{project_dir}.json").write_text(json.dumps(data))


def gradle_native(target="server/gradle.lockfile"):
    ids = ["g:app:1", "g:lib:1", "g:leaf:1"]
    pkgs = [{"ID": i, "Name": i.rsplit(":", 1)[0], "Version": "1"} for i in ids]
    vulns = [vuln("g:leaf", version="1", PkgID="g:leaf:1")]
    return {"Results": [result(pkgs, vulns, target, "gradle")]}


def test_gradle_chain_comes_from_the_graph_of_the_project(tmp_path):
    graph_dir = tmp_path / "graph"
    write_graph(
        graph_dir,
        "server",
        ["g:app:1"],
        {"g:app:1": ["g:lib:1"], "g:lib:1": ["g:leaf:1", "other:x:1"], "g:leaf:1": []},
    )
    native = gradle_native()
    apply_gradle_graph("source-development", native, graph_dir)
    findings = {}
    normalize_trivy("source-development", native, findings, {})
    row = next(iter(findings.values()))
    assert row["chain"] == ["g:app", "g:lib", "g:leaf"]
    assert row["relationship"] == "indirect"


def test_gradle_without_a_graph_for_the_project_has_no_chain(tmp_path, capsys):
    write_graph(tmp_path / "graph", "other", ["g:app:1"], {"g:app:1": []})
    native = gradle_native()
    apply_gradle_graph("source-development", native, tmp_path / "graph")
    findings = {}
    normalize_trivy("source-development", native, findings, {})
    assert next(iter(findings.values()))["chain"] == []
    assert "No Gradle dependency graph" in capsys.readouterr().out


def test_an_unreadable_graph_file_is_skipped_with_a_warning(tmp_path, capsys):
    (tmp_path / "graph").mkdir()
    (tmp_path / "graph" / "graph-x.json").write_text("{not json")
    apply_gradle_graph("source-development", gradle_native(), tmp_path / "graph")
    assert "Gradle dependency graph ignored" in capsys.readouterr().out


def test_an_image_package_borrows_the_chain_of_the_source_not_its_dev_flag():
    src_pkgs = [
        package("top", depends_on=["jar"], rel="direct"),
        package("jar", rel="indirect", dev=True),
    ]
    _, src_inventory = trivy(result(src_pkgs))
    image = result([package("Jar")], [vuln("Jar")], target="app/jar", rtype="jar")
    rows, _ = trivy(image, tid="app-development")
    findings = dict(enumerate(rows))
    borrow_source_chains(
        findings, {"source-development": src_inventory}, ["source-development"]
    )
    assert rows[0]["chain"] == ["top", "jar"] and rows[0]["relationship"] == "indirect"
    assert rows[0]["dev"] is False


def test_an_image_package_the_source_does_not_have_stays_without_a_chain():
    rows, _ = trivy(result([package("a")], [vuln("a")]), tid="app-development")
    borrow_source_chains(
        dict(enumerate(rows)), {"source-development": {}}, ["source-development"]
    )
    assert rows[0]["chain"] == []


def osv_native(
    group_ids=("GHSA-aaaa",), aliases=("CVE-2026-9",), severity=None, score="7.5"
):
    record = {
        "id": group_ids[0],
        "summary": "A flaw",
        "database_specific": {"severity": severity} if severity else {},
        "affected": [
            {
                "package": {"name": "a"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.5"}],
                    }
                ],
            }
        ],
    }
    group = {"ids": list(group_ids), "aliases": list(aliases), "max_severity": score}
    package_entry = {
        "package": {"name": "a", "version": "1.0", "ecosystem": "npm"},
        "vulnerabilities": [record],
        "groups": [group],
    }
    return {"results": [{"packages": [package_entry]}]}


def test_osv_finding_takes_chain_dev_and_locations_from_the_trivy_inventory():
    pkgs = [
        package("top", depends_on=["a"], rel="direct"),
        package("a", rel="indirect", dev=True),
    ]
    _, inventory = trivy(result(pkgs))
    findings = {}
    normalize_osv(
        "source-development", osv_native(severity="MODERATE"), findings, inventory
    )
    (row,) = findings.values()
    assert (row["id"], row["aliases"], row["scanner"]) == (
        "CVE-2026-9",
        ["GHSA-aaaa"],
        "osv",
    )
    assert (row["severity"], row["fixed_version"]) == ("MEDIUM", "1.5")
    assert row["chain"] == ["top", "a"] and row["dev"] is True
    assert row["locations"] == ["package-lock.json"]
    assert row["url"] == "https://osv.dev/vulnerability/GHSA-aaaa"


def test_osv_severity_falls_back_to_the_score_and_a_missing_inventory_is_fine():
    findings = {}
    normalize_osv("t", osv_native(score="9.8"), findings, {})
    (row,) = findings.values()
    assert (
        row["severity"] == "CRITICAL" and row["chain"] == [] and row["locations"] == []
    )
    assert [severity_of_score(s) for s in ("4.0", "0.1", "0", "", None)] == [
        "MEDIUM",
        "LOW",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
    ]


def test_trivy_and_osv_rows_of_one_vulnerability_share_the_key_fields():
    pkgs = [package("a")]
    trivy_rows, inventory = trivy(
        result(pkgs, [vuln("a", "CVE-2026-9", VendorIDs=["GHSA-aaaa"])])
    )
    findings = {}
    normalize_osv("source-development", osv_native(), findings, inventory)
    (osv_row,) = findings.values()
    key = ("id", "pkg", "version")
    assert [trivy_rows[0][k] for k in key] == [osv_row[k] for k in key]


def osv_fixed(*ranges):
    native = osv_native()
    affected = native["results"][0]["packages"][0]["vulnerabilities"][0]["affected"]
    affected[0]["ranges"] = [
        {"type": t, "events": [{"fixed": f} for f in fixed]} for t, *fixed in ranges
    ]
    findings = {}
    normalize_osv("t", native, findings, {})
    return next(iter(findings.values()))["fixed_version"]


def test_osv_fixed_version_skips_git_ranges():
    assert osv_fixed(("GIT", "0123abc"), ("SEMVER", "1.5")) == "1.5"
    assert osv_fixed(("GIT", "0123abc")) == ""


def test_osv_fixed_version_lists_every_branch_once():
    assert osv_fixed(("ECOSYSTEM", "1.5"), ("SEMVER", "2.1", "1.5")) == "1.5, 2.1"
