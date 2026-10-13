"""Tests for actions/sca_query_osv/query_osv.py (synthetic data, fake commands)."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)


def _load_query_osv():
    path = ROOT / "actions" / "sca_query_osv" / "query_osv.py"
    spec = importlib.util.spec_from_file_location("query_osv", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


qo = _load_query_osv()


# --- fakes and builders -------------------------------------------------------


def component(purl: str | None, kind: str = "library") -> dict[str, Any]:
    last = (purl or "lockfile").split("/")[-1]
    name, _, version = last.partition("@")
    return {
        "type": kind,
        "name": name,
        **({"version": version.split("?")[0]} if version else {}),
        **({"purl": purl} if purl else {}),
    }


BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"component": {"type": "container", "name": "image"}},
    "components": [
        component("pkg:npm/lodash@4.17.0"),
        component("pkg:pypi/requests@2.0.0"),
        component("pkg:deb/debian/zlib@1.2?distro=debian-12"),
        component("pkg:apk/alpine/musl@1.2.4-r0"),
        component("pkg:rpm/redhat/glibc@2.34"),
        component(None),
        component(None, kind="application"),
        component("pkg:oci/image@sha256:0", kind="container"),
    ],
    "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
    "vulnerabilities": [{"id": "CVE-2030-1"}],
}


def osv_output(*packages: tuple[str, str, str], vulnerable: bool = False) -> dict:
    """An osv-scanner result (``--format json --all-packages``) of one BOM."""
    entries = []
    for ecosystem, name, version in packages:
        entry: dict[str, Any] = {
            "package": {"ecosystem": ecosystem, "name": name, "version": version}
        }
        if vulnerable:
            entry["vulnerabilities"] = [{"id": "GHSA-aaaa-aaaa-aaaa"}]
            entry["groups"] = [{"ids": ["GHSA-aaaa-aaaa-aaaa"], "max_severity": "7.5"}]
        entries.append(entry)
    source = {"path": "x.cdx.json", "type": "sbom"}
    return {"results": [{"source": source, "packages": entries}] if entries else []}


PACKAGES = (("npm", "lodash", "4.17.0"), ("PyPI", "requests", "2.0.0"))


class FakeCommands:
    """Stands in for ``trivy`` and ``osv-scanner``; records every command.

    ``scanner_exit``/``scanner_output``: what osv-scanner does (an output of
    False writes nothing; a string is written as is).
    """

    def __init__(
        self,
        bom: Any = BOM,
        convert_exit: int = 0,
        scanner_exit: int = 1,
        scanner_output: Any = None,
        scanner_stderr: str = "",
    ) -> None:
        self.bom = bom
        self.convert_exit = convert_exit
        self.scanner_exit = scanner_exit
        self.scanner_output = (
            osv_output(*PACKAGES, vulnerable=True)
            if scanner_output is None
            else scanner_output
        )
        self.scanner_stderr = scanner_stderr
        self.calls: list[list[str]] = []
        self.scanned_boms: list[dict[str, Any]] = []

    def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command = list(command)
        self.calls.append(command)
        if command[1] == "--version":
            out = "osv-scanner version: 2.6.0\nosv-scalibr version: 0.4.8\n"
            return subprocess.CompletedProcess(command, 0, out, "")
        if command[1] == "convert":
            if self.convert_exit:
                return subprocess.CompletedProcess(
                    command, self.convert_exit, "", "boom"
                )
            Path(command[command.index("--output") + 1]).write_text(
                json.dumps(self.bom), encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, 0, "", "")
        bom_path = Path(command[command.index("-L") + 1])
        self.scanned_boms.append(json.loads(bom_path.read_text(encoding="utf-8")))
        output = Path(command[command.index("--output-file") + 1])
        if self.scanner_output is not False:
            text = (
                self.scanner_output
                if isinstance(self.scanner_output, str)
                else json.dumps(self.scanner_output)
            )
            output.write_text(text, encoding="utf-8")
        return subprocess.CompletedProcess(
            command, self.scanner_exit, "", self.scanner_stderr
        )

    def scans(self) -> list[list[str]]:
        return [c for c in self.calls if c[1:3] == ["scan", "source"]]


class Workspace:
    """targets.json (one Trivy target and its OSV twin) and the Trivy parts."""

    def __init__(self, tmp_path: Path, trivy_status: str | None = "ok") -> None:
        self.targets_file = tmp_path / "targets.json"
        self.parts_dir = tmp_path / "parts"
        self.output_dir = tmp_path / "out"
        trivy = self.parts_dir / "trivy"
        trivy.mkdir(parents=True)
        target = {"id": "source-development", "status": "pending"}
        self.targets_file.write_text(
            json.dumps(
                {
                    "targets": [
                        {**target, "scanner": "trivy"},
                        {**target, "scanner": "osv"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        if trivy_status is not None:
            (trivy / "source-development.status.json").write_text(
                json.dumps({"id": "source-development", "status": trivy_status}),
                encoding="utf-8",
            )
        if trivy_status == "ok":
            (trivy / "source-development.json").write_text(
                json.dumps({"Results": []}), encoding="utf-8"
            )

    def run(self, commands: FakeCommands) -> int:
        args = argparse.Namespace(
            targets_file=self.targets_file,
            parts_dir=self.parts_dir,
            output_dir=self.output_dir,
            trivy="trivy",
            osv_scanner="osv-scanner",
        )
        return qo.run_all(args, commands, NOW)

    @property
    def osv_dir(self) -> Path:
        return self.output_dir / "osv"

    def status(self) -> dict[str, Any]:
        path = self.osv_dir / "source-development.status.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def result(self) -> Path:
        return self.osv_dir / "source-development.json"


# --- the BOM ------------------------------------------------------------------


def test_filter_bom_keeps_language_packages_and_counts_the_unusable() -> None:
    bom, skipped = qo.filter_bom(BOM)
    assert [c["purl"] for c in bom["components"]] == [
        "pkg:npm/lodash@4.17.0",
        "pkg:pypi/requests@2.0.0",
        "pkg:oci/image@sha256:0",
    ]
    # a library without a purl; the lockfile (application) is not a package
    assert skipped == 1
    # the graph and the Trivy findings are of no use to osv-scanner
    assert (bom["dependencies"], bom["vulnerabilities"]) == ([], [])
    assert bom["bomFormat"] == "CycloneDX"


@pytest.mark.parametrize("purl_type", ["deb", "apk", "rpm", "DEB"])
def test_filter_bom_removes_os_packages(purl_type: str) -> None:
    bom, skipped = qo.filter_bom(
        {"components": [component(f"pkg:{purl_type}/distro/pkg@1")]}
    )
    assert (bom["components"], skipped) == ([], 0)


def test_filter_bom_folds_the_group_into_the_name_as_osv_writes_it() -> None:
    maven = {**component("pkg:maven/org.example/lib@1.0"), "group": "org.example"}
    scoped = {**component("pkg:npm/%40scope/pkg@1.0"), "group": "@scope"}
    plain = component("pkg:npm/plain@1.0")
    bom, _ = qo.filter_bom({"components": [maven, scoped, plain]})
    assert [(c["name"], "group" in c) for c in bom["components"]] == [
        ("org.example:lib", False),
        ("@scope/pkg", False),
        ("plain", False),
    ]
    assert "group" in maven  # the input is not modified


def test_filter_bom_without_components() -> None:
    assert qo.filter_bom({})[0]["components"] == []


# --- a target -------------------------------------------------------------------


def test_osv_scanner_is_run_on_the_filtered_bom_with_the_documented_flags(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path)
    commands = FakeCommands()
    assert ws.run(commands) == 0
    convert = commands.calls[1]
    assert convert[:5] == ["trivy", "convert", "--format", "cyclonedx", "--output"]
    assert convert[-1] == str(ws.parts_dir / "trivy" / "source-development.json")
    (scan,) = commands.scans()
    assert scan[:3] == ["osv-scanner", "scan", "source"]
    # osv-scanner takes the format of a BOM from its file name
    assert scan[scan.index("-L") + 1].endswith(".cdx.json")
    assert "--all-packages" in scan
    assert scan[scan.index("--format") + 1] == "json"
    assert scan[scan.index("--output-file") + 1] == str(ws.result())
    assert len(commands.scanned_boms[0]["components"]) == 3


@pytest.mark.parametrize(("exit_code", "vulnerable"), [(0, False), (1, True)])
def test_exit_0_and_1_are_ok_and_the_output_is_kept_as_is(
    tmp_path: Path, exit_code: int, vulnerable: bool
) -> None:
    ws = Workspace(tmp_path)
    output = osv_output(*PACKAGES, vulnerable=vulnerable)
    assert ws.run(FakeCommands(scanner_exit=exit_code, scanner_output=output)) == 0
    assert json.loads(ws.result().read_text(encoding="utf-8")) == output
    assert ws.status() == {
        "id": "source-development",
        "status": "ok",
        "reason": None,
        # the packages of the output (--all-packages), not the findings
        "packages_queried": 2,
        "packages_skipped": 1,
        "packages_unread": 0,
        "queried_at": "2030-01-01T12:00:00Z",
        "scanner_version": "2.6.0",
    }


def test_packages_queried_counts_distinct_packages_of_all_results(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path)
    output = osv_output(*PACKAGES, ("npm", "lodash", "4.17.0"))
    ws.run(FakeCommands(scanner_exit=0, scanner_output=output))
    assert ws.status()["packages_queried"] == 2


@pytest.mark.parametrize("exit_code", [2, 127, 128, 130])
def test_any_other_exit_code_is_a_failure_even_with_an_empty_json(
    tmp_path: Path, exit_code: int
) -> None:
    ws = Workspace(tmp_path)
    # a clean-looking output next to a failure must not count as clean
    commands = FakeCommands(
        scanner_exit=exit_code,
        scanner_output=osv_output(),
        scanner_stderr="Error during extraction:\nmax retries exceeded",
    )
    assert ws.run(commands) == 1
    status = ws.status()
    assert status["status"] == "failed"
    assert status["reason"] == (
        f"osv-scanner failed (exit {exit_code}): "
        "Error during extraction: max retries exceeded"
    )
    assert status["packages_queried"] == 3
    assert not ws.result().exists()


def test_a_missing_osv_scanner_is_exit_127(tmp_path: Path) -> None:
    result = qo.run_command([str(tmp_path / "no-such-binary"), "--version"])
    assert result.returncode == 127
    assert result.stderr


@pytest.mark.parametrize(
    "output",
    [
        False,  # nothing written
        "",
        "{",
        "[]",
        {"results": None},
        {"results": [{"packages": None}]},
        {"results": [{"packages": [{"package": {"name": "a"}}]}]},
    ],
)
def test_an_output_that_is_not_a_result_is_a_failure_even_on_exit_0(
    tmp_path: Path, output: Any
) -> None:
    ws = Workspace(tmp_path)
    assert ws.run(FakeCommands(scanner_exit=0, scanner_output=output)) == 1
    assert ws.status()["status"] == "failed"
    assert ws.status()["reason"].startswith("osv-scanner wrote no valid result")
    assert not ws.result().exists()


def test_a_stale_output_does_not_pass_for_the_result_of_the_run(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path)
    ws.osv_dir.mkdir(parents=True)
    ws.result().write_text(json.dumps(osv_output(*PACKAGES)), encoding="utf-8")
    assert ws.run(FakeCommands(scanner_exit=0, scanner_output=False)) == 1
    assert ws.status()["status"] == "failed"


def test_the_reason_is_the_end_of_stderr_and_is_cut(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    ws.run(FakeCommands(scanner_exit=2, scanner_stderr="x" * 5000 + " the end"))
    reason = ws.status()["reason"]
    assert reason.endswith("the end")
    assert len(reason) < 500


def test_trivy_convert_failure_is_a_failed_target(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    commands = FakeCommands(convert_exit=1)
    assert ws.run(commands) == 1
    assert ws.status()["reason"] == "trivy convert failed (exit 1): boom"
    assert commands.scans() == []


def test_an_unreadable_bom_is_a_failed_target(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    assert ws.run(FakeCommands(bom=["not", "a", "bom"])) == 1
    assert ws.status()["reason"].startswith("trivy convert wrote no valid BOM")


def test_a_target_without_language_packages_is_ok_without_running_osv_scanner(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path)
    commands = FakeCommands(bom={"components": [component("pkg:deb/debian/a@1")]})
    assert ws.run(commands) == 0
    assert commands.scans() == []
    assert json.loads(ws.result().read_text(encoding="utf-8")) == {"results": []}
    assert ws.status()["status"] == "ok"
    assert ws.status()["packages_queried"] == 0


def test_skipped_packages_are_noticed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    Workspace(tmp_path).run(FakeCommands())
    out = capsys.readouterr().out
    assert "source-development: ok" in out
    assert (
        "::notice title=OSV skipped packages::source-development: 1 package(s)" in out
    )


def test_packages_of_the_bom_that_osv_scanner_did_not_read_are_counted_and_warned(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = Workspace(tmp_path)
    output = osv_output(("npm", "lodash", "4.17.0"))
    assert ws.run(FakeCommands(scanner_exit=0, scanner_output=output)) == 0
    assert ws.status()["status"] == "ok"
    assert ws.status()["packages_unread"] == 1
    out = capsys.readouterr().out
    assert "::warning title=OSV did not read packages::source-development:" in out
    assert "requests@2.0.0" in out


def test_all_packages_read_gives_no_unread_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    Workspace(tmp_path).run(FakeCommands())
    assert "did not read" not in capsys.readouterr().out


def test_package_names_are_compared_loosely() -> None:
    bom = {"components": [{"name": "Typing_Extensions", "version": "4.0"}]}
    output = osv_output(("PyPI", "typing-extensions", "4.0"))
    assert qo.unread_packages(bom, output) == []


@pytest.mark.parametrize("trivy_status", ["failed", "not_applicable", None, "ok-ish"])
def test_a_target_whose_trivy_target_was_not_scanned_is_not_applicable(
    tmp_path: Path, trivy_status: str | None
) -> None:
    ws = Workspace(tmp_path, trivy_status)
    commands = FakeCommands()
    assert ws.run(commands) == 0
    status = ws.status()
    assert status["status"] == "not_applicable"
    assert status["reason"] == f"trivy target {trivy_status or 'failed'}"
    assert (status["packages_queried"], status["queried_at"]) == (None, None)
    assert not ws.result().exists()
    assert commands.scans() == []


def test_a_trivy_part_without_its_native_result_is_failed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    (ws.parts_dir / "trivy" / "source-development.json").unlink()
    ws.run(FakeCommands())
    assert ws.status()["reason"] == "trivy target failed"


def test_only_pending_osv_targets_are_processed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    doc = json.loads(ws.targets_file.read_text(encoding="utf-8"))
    doc["targets"][1]["status"] = "failed"
    ws.targets_file.write_text(json.dumps(doc), encoding="utf-8")
    commands = FakeCommands()
    assert ws.run(commands) == 0
    assert commands.scans() == []
    assert not (ws.osv_dir / "source-development.status.json").exists()


@pytest.mark.parametrize("content", ["{", "[]", '{"targets": 1}', '{"targets": [1]}'])
def test_an_unusable_targets_file_is_an_input_error(
    tmp_path: Path, content: str
) -> None:
    ws = Workspace(tmp_path)
    ws.targets_file.write_text(content, encoding="utf-8")
    with pytest.raises(qo.InputError):
        ws.run(FakeCommands())


def test_main_reports_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = Workspace(tmp_path)
    ws.targets_file.write_text("{", encoding="utf-8")
    argv = [
        "--targets-file",
        str(ws.targets_file),
        "--parts-dir",
        str(ws.parts_dir),
        "--output-dir",
        str(ws.output_dir),
    ]
    assert qo.main(argv) == 1
    assert "::error title=Invalid OSV query input::" in capsys.readouterr().err
