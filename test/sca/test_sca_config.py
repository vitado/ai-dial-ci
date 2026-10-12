"""Tests of actions/sca_resolve_targets/sca_config.py (the .github/sca.yml schema)."""

from __future__ import annotations

from pathlib import Path

import pytest
import sca_config

ORIGIN = ".github/sca.yml@abc"
FULL = """\
schema_version: 1
non_shipped_paths:
  - examples/
  - website/package-lock.json
trivy_skip_paths: apply
"""


def settings(text: str) -> dict:
    return sca_config.parse_settings(text, ORIGIN)


def error_of(text: str) -> str:
    with pytest.raises(sca_config.ConfigError) as err:
        settings(text)
    return str(err.value)


# ----------------------------------------------------------------- parsing


def test_full_document() -> None:
    assert settings(FULL) == {
        "non_shipped_paths": ["examples/", "website/package-lock.json"],
        "trivy_skip_paths": "apply",
    }


def test_defaults_are_filled_in() -> None:
    assert settings("schema_version: 1\n") == {
        "non_shipped_paths": [],
        "trivy_skip_paths": "as_non_shipped",
    }


def test_empty_list_and_comments() -> None:
    text = "# policy\nschema_version: 1\nnon_shipped_paths: []  # none\n"
    assert settings(text)["non_shipped_paths"] == []


@pytest.mark.parametrize("mode", ["as_non_shipped", "apply", "ignore"])
def test_trivy_skip_paths_modes(mode: str) -> None:
    assert (
        settings(f"schema_version: 1\ntrivy_skip_paths: {mode}\n")["trivy_skip_paths"]
        == mode
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "must be a mapping"),
        ("- a\n- b\n", "must be a mapping"),
        ("just text\n", "must be a mapping"),
        ("non_shipped_paths: [a/]\n", "schema_version is required"),
        ("schema_version: 2\n", "unsupported schema_version 2"),
        ("schema_version: '1'\n", "unsupported schema_version '1'"),
        ("schema_version: true\n", "unsupported schema_version True"),
        (
            "schema_version: 1\nnon_shiped_paths: [a/]\n",
            "unknown key 'non_shiped_paths'",
        ),
        ("schema_version: 1\nfoo: 1\nbar: 2\n", "unknown key 'foo', 'bar'"),
        ("schema_version: 1\nnon_shipped_paths: examples/\n", "must be a list"),
        ("schema_version: 1\nnon_shipped_paths:\n", "must be a list"),
        ("schema_version: 1\nnon_shipped_paths: {a: b}\n", "must be a list"),
        ("schema_version: 1\nnon_shipped_paths: [1]\n", "[1] must be a string"),
        ("schema_version: 1\nnon_shipped_paths: [yes]\n", "must be a string, got True"),
        (
            "schema_version: 1\nnon_shipped_paths: [a/, '']\n",
            "[2] '': must not be empty",
        ),
        ("schema_version: 1\ntrivy_skip_paths: sometimes\n", "must be one of"),
        ("schema_version: 1\ntrivy_skip_paths: [apply]\n", "must be one of"),
        ("schema_version: 1\nschema_version: 1\n", "duplicate key 'schema_version'"),
        (
            "schema_version: 1\nnon_shipped_paths: [a/]\nnon_shipped_paths: [b/]\n",
            "duplicate key 'non_shipped_paths'",
        ),
        ("schema_version: 1\nx: &a [1]\ny: *a\n", "aliases are not supported"),
        ("schema_version: [1\n", "invalid YAML"),
        ("a: 1\n---\nb: 2\n", "invalid YAML"),
    ],
)
def test_invalid_documents_are_rejected_with_a_clear_error(
    text: str, message: str
) -> None:
    error = error_of(text)
    assert error.startswith(f"{ORIGIN}: ")
    assert message in error
    assert "\n" not in error  # the error ends up in a workflow command


def test_oversized_document_is_rejected() -> None:
    text = "schema_version: 1\n# " + "x" * sca_config.MAX_CONFIG_BYTES + "\n"
    assert "larger than 64 KiB" in error_of(text)


# ---------------------------------------------------------------- patterns


@pytest.mark.parametrize(
    "pattern",
    [
        "examples/",
        "website/package-lock.json",
        "**/examples/",
        "a/**/b/",
        "a/**",
        "*/package-lock.json",
        "requirements-*.txt",
        "a b/c d/",
        "a#b/",
        "..foo/",
        ".github/",
    ],
)
def test_valid_patterns(pattern: str) -> None:
    assert sca_config.validate_pattern(pattern) == pattern


@pytest.mark.parametrize(
    ("pattern", "message"),
    [
        ("", "must not be empty"),
        (" examples/", "whitespace"),
        ("examples/ ", "whitespace"),
        ("/examples/", "not start with '/'"),
        ("!examples/", "negation"),
        ("a\\b/", "must not contain"),
        ("a?b/", "must not contain"),
        ("a[b]/", "must not contain"),
        ("a{b,c}/", "must not contain"),
        ("a//b/", "empty path segments"),
        ("a/./b/", "'.' segment"),
        ("../a/", "'..' segment"),
        ("a/..", "'..' segment"),
        ("a**/", "whole path segment"),
        ("**a/", "whole path segment"),
        ("a/***/", "whole path segment"),
        ("**", "whole repository"),
        ("**/", "whole repository"),
        ("**/**", "whole repository"),
    ],
)
def test_invalid_patterns(pattern: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        sca_config.validate_pattern(pattern)


def test_pattern_error_names_the_item_and_the_pattern() -> None:
    error = error_of("schema_version: 1\nnon_shipped_paths: [a/, '/b/']\n")
    assert error == (
        f"{ORIGIN}: non_shipped_paths[2] '/b/': "
        "must be relative to the repository root, not start with '/'"
    )


# ------------------------------------------------------------ build_config


def test_no_file_no_input_is_the_defaults() -> None:
    assert sca_config.build_config(None, None, "") == {
        "source": None,
        "overrides": None,
        "non_shipped_paths": [],
        "trivy_skip_paths": "as_non_shipped",
    }


def test_file_is_used_and_named() -> None:
    config = sca_config.build_config(FULL, ".github/sca.yml@" + "a" * 40, "")
    assert config["source"] == ".github/sca.yml@" + "a" * 40
    assert config["overrides"] is None
    assert config["non_shipped_paths"] == ["examples/", "website/package-lock.json"]
    assert config["trivy_skip_paths"] == "apply"


def test_input_wins_over_the_file_and_the_report_says_so() -> None:
    ref = ".github/sca.yml@" + "a" * 40
    config = sca_config.build_config(
        FULL, ref, "schema_version: 1\nnon_shipped_paths: [docs/]\n"
    )
    assert config["source"] == "input"
    assert config["overrides"] == ref
    assert config["non_shipped_paths"] == ["docs/"]
    # not the value of the file: the input does not inherit from it
    assert config["trivy_skip_paths"] == "as_non_shipped"


def test_input_without_a_file_overrides_nothing() -> None:
    config = sca_config.build_config(None, None, "schema_version: 1\n")
    assert config["source"] == "input"
    assert config["overrides"] is None


def test_replaced_file_is_not_parsed() -> None:
    config = sca_config.build_config(
        "this: is: not yaml: [", ".github/sca.yml@x", "schema_version: 1\n"
    )
    assert config["source"] == "input"


def test_whitespace_input_counts_as_empty() -> None:
    config = sca_config.build_config(FULL, ".github/sca.yml@x", " \n\t\n")
    assert config["source"] == ".github/sca.yml@x"


def test_invalid_input_is_named_as_the_input() -> None:
    with pytest.raises(sca_config.ConfigError, match="workflow input 'config': "):
        sca_config.build_config(None, None, "schema_version: 3\n")


def test_invalid_file_is_named_with_its_commit() -> None:
    with pytest.raises(sca_config.ConfigError) as err:
        sca_config.build_config("schema_version: 3\n", ".github/sca.yml@abc123", "")
    assert str(err.value).startswith(".github/sca.yml@abc123: ")


def test_empty_file_is_invalid_not_defaults() -> None:
    with pytest.raises(sca_config.ConfigError, match="must be a mapping"):
        sca_config.build_config("", ".github/sca.yml@x", "")


# ----------------------------------------------------- dependency handling


def test_the_actions_pin_the_same_requirements() -> None:
    actions = Path(__file__).resolve().parents[2] / "actions"
    resolve = (actions / "sca_resolve_targets" / "requirements.txt").read_bytes()
    for other in ("sca_prepare_trivy_config", "sca_build_cve_index"):
        assert (actions / other / "requirements.txt").read_bytes() == resolve


def test_requirements_pin_every_package_with_hashes() -> None:
    path = Path(__file__).resolve().parents[2]
    text = (path / "actions" / "sca_resolve_targets" / "requirements.txt").read_text()
    lines = [x for x in text.splitlines() if x.strip() and not x.startswith("#")]
    assert lines[0].startswith("pyyaml==")
    assert all("--hash=sha256:" in x for x in lines[1:])
    assert len(lines) > 1
