"""Tests for actions/sca_prepare_trivy_config/prepare_trivy_config.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "actions"
    / "sca_prepare_trivy_config"
    / "prepare_trivy_config.py"
)
_spec = importlib.util.spec_from_file_location("prepare_trivy_config", SCRIPT)
assert _spec is not None
assert _spec.loader is not None
ptc = importlib.util.module_from_spec(_spec)
sys.modules["prepare_trivy_config"] = ptc
_spec.loader.exec_module(ptc)

TRIVY_YAML = """\
# mirrors of the DB
db:
  repository: mirror.example/trivy-db:2
scan:
  skip-dirs:
    - examples
    - "**/docs"
  skip-files:
    - "**/*.lock"
  scanners:
    - vuln
timeout: 7m
"""


class Dirs:
    def __init__(self, tmp_path: Path) -> None:
        self.config = tmp_path / "trivy.yaml"
        self.out = tmp_path / "out"
        self.generated = tmp_path / "generated"

    def prepare(self, mode: str, tid: str = "source-development") -> Path | None:
        return ptc.prepare(mode, self.config, tid, self.out, self.generated)

    def record(self, tid: str = "source-development") -> dict[str, Any]:
        return json.loads((self.out / f"{tid}.trivy-config.json").read_text())


@pytest.fixture
def dirs(tmp_path: Path) -> Dirs:
    return Dirs(tmp_path)


@pytest.mark.parametrize("mode", ["as_non_shipped", "ignore"])
def test_modes_that_scan_the_skip_paths_replace_the_config(
    dirs: Dirs, mode: str
) -> None:
    dirs.config.write_text(TRIVY_YAML)
    replacement = dirs.prepare(mode)
    assert replacement == dirs.generated / "source-development.trivy.yaml"
    generated = yaml.safe_load(replacement.read_text())  # type: ignore[union-attr]
    # the same document without the two keys, so nothing else of it is lost
    assert generated == {
        "db": {"repository": "mirror.example/trivy-db:2"},
        "scan": {"scanners": ["vuln"]},
        "timeout": "7m",
    }
    assert dirs.record() == {
        "schema_version": 1,
        "id": "source-development",
        "mode": mode,
        "config_file": str(dirs.config),
        "skip_dirs": ["examples", "**/docs"],
        "skip_files": ["**/*.lock"],
        "paths_scanned": True,
    }


def test_apply_keeps_the_config_and_records_the_skip_paths(dirs: Dirs) -> None:
    dirs.config.write_text(TRIVY_YAML)
    assert dirs.prepare("apply") is None
    assert not dirs.generated.exists()
    record = dirs.record()
    assert record["skip_dirs"] == ["examples", "**/docs"]
    assert record["paths_scanned"] is False


def test_the_original_config_is_not_modified(dirs: Dirs) -> None:
    dirs.config.write_text(TRIVY_YAML)
    dirs.prepare("ignore")
    assert dirs.config.read_text() == TRIVY_YAML


def test_scan_section_is_dropped_when_only_skips_were_in_it(dirs: Dirs) -> None:
    dirs.config.write_text("scan:\n  skip-dirs: [a]\ntimeout: 5m\n")
    replacement = dirs.prepare("ignore")
    assert yaml.safe_load(replacement.read_text()) == {"timeout": "5m"}  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "content",
    [
        "timeout: 5m\n",
        "scan:\n  scanners: [vuln]\n",
        "scan:\n  skip-dirs: []\n  skip-files: []\n",
        "scan: {}\n",
        "scan:\n",
        "",
    ],
)
@pytest.mark.parametrize("mode", ["as_non_shipped", "apply", "ignore"])
def test_config_without_skip_paths_is_left_alone(
    dirs: Dirs, mode: str, content: str
) -> None:
    dirs.config.write_text(content)
    assert dirs.prepare(mode) is None
    record = dirs.record()
    assert record["skip_dirs"] == []
    assert record["skip_files"] == []
    assert record["config_file"] == str(dirs.config)


@pytest.mark.parametrize("mode", ["as_non_shipped", "apply", "ignore"])
def test_repository_without_trivy_yaml(dirs: Dirs, mode: str) -> None:
    assert dirs.prepare(mode) is None
    record = dirs.record()
    assert record["config_file"] is None
    assert record["skip_dirs"] == record["skip_files"] == []


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("scan:\n  skip-dirs: examples\n", "scan.skip-dirs must be a list of strings"),
        ("scan:\n  skip-files: [1]\n", "scan.skip-files must be a list of strings"),
        ("scan: [a]\n", "'scan' must be a mapping"),
        ("- a\n", "must be a mapping"),
        ("scan: [\n", "cannot read"),
    ],
)
def test_unusable_trivy_yaml_is_an_error(
    dirs: Dirs, content: str, message: str
) -> None:
    dirs.config.write_text(content)
    with pytest.raises(ptc.ConfigError, match=message):
        dirs.prepare("as_non_shipped")


def test_main_writes_the_output_and_reports_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "trivy.yaml"
    config.write_text(TRIVY_YAML)
    output = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    argv = [
        "--mode",
        "ignore",
        "--target-id",
        "source-1.0.0",
        "--output-dir",
        str(tmp_path / "out"),
        "--generated-dir",
        str(tmp_path / "gen"),
        "--config-path",
        str(config),
    ]
    assert ptc.main(argv) == 0
    assert (
        output.read_text()
        == f"config-file={tmp_path / 'gen' / 'source-1.0.0.trivy.yaml'}\n"
    )
    assert (tmp_path / "out" / "source-1.0.0.trivy-config.json").is_file()

    config.write_text("scan:\n  skip-dirs: a\n")
    assert ptc.main(argv) == 1
    assert "::error title=Invalid Trivy configuration::" in capsys.readouterr().out


def test_main_output_is_empty_when_trivy_keeps_its_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    argv = [
        "--mode",
        "apply",
        "--target-id",
        "source-development",
        "--output-dir",
        str(tmp_path / "out"),
        "--generated-dir",
        str(tmp_path / "gen"),
        "--config-path",
        str(tmp_path / "missing.yaml"),
    ]
    assert ptc.main(argv) == 0
    assert output.read_text() == "config-file=\n"


def test_record_is_what_the_merge_reads(dirs: Dirs) -> None:
    """The merge validates the record the action writes (same schema, one version)."""
    merge_path = (
        Path(__file__).resolve().parents[2]
        / "actions"
        / "sca_merge_results"
        / "merge_results.py"
    )
    spec = importlib.util.spec_from_file_location("merge_for_record", merge_path)
    assert spec is not None
    assert spec.loader is not None
    merge = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = merge
    spec.loader.exec_module(merge)
    dirs.config.write_text(TRIVY_YAML)
    for mode in ("as_non_shipped", "apply", "ignore"):
        dirs.prepare(mode)
        loaded = merge.load_trivy_config_record(
            dirs.out / "source-development.trivy-config.json"
        )
        assert loaded["mode"] == mode
        assert loaded["skip_dirs"] == ["examples", "**/docs"]
