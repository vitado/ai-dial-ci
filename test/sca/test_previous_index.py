"""Tests for actions/sca_build_cve_index/previous_index.sh (fake gh and oras)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "actions" / "sca_build_cve_index" / "previous_index.sh"
BASH = shutil.which("bash")
IMAGE = "ghcr.io/epam/ai-dial-sca-cve-index"

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is needed")

FAKE_GH = """#!/usr/bin/env bash
echo "gh $*" >> "$CALLS"
case "$*" in
  "api repos/"*) echo "$OWNER_TYPE" ;;
  "api -i "*)
    printf '%s\\n' "$PACKAGE_RESPONSE"
    [[ "$PACKAGE_RESPONSE" == HTTP/*" 200 "* ]] || exit 1
    ;;
  *) exit 99 ;;
esac
"""

FAKE_ORAS = """#!/usr/bin/env bash
echo "oras $*" >> "$CALLS"
[[ "$ORAS_RC" == 0 ]] && mkdir -p "${@: -1}" && touch "${@: -1}/metadata.json"
exit "$ORAS_RC"
"""


def run(
    tmp_path: Path,
    package_response: str,
    owner_type: str = "Organization",
    oras_rc: int = 0,
    bootstrap: str = "",
) -> tuple[subprocess.CompletedProcess[str], list[str], str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, text in (("gh", FAKE_GH), ("oras", FAKE_ORAS)):
        path = bin_dir / name
        path.write_text(text, encoding="utf-8", newline="\n")
        path.chmod(0o755)
    calls, output = tmp_path / "calls", tmp_path / "output"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "CALLS": str(calls),
        "GITHUB_OUTPUT": str(output),
        "OWNER_TYPE": owner_type,
        "PACKAGE_RESPONSE": package_response,
        "ORAS_RC": str(oras_rc),
        "REPOSITORY": "Epam/ai-dial-ci",
        "IMAGE": IMAGE,
        "DEST": str(tmp_path / "previous"),
        "BOOTSTRAP": bootstrap,
    }
    result = subprocess.run(
        [BASH, str(SCRIPT)], env=env, capture_output=True, text=True, check=False
    )
    made = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    written = output.read_text(encoding="utf-8") if output.exists() else ""
    return result, made, written


def test_a_package_that_exists_is_pulled(tmp_path: Path) -> None:
    result, calls, output = run(tmp_path, "HTTP/2.0 200 OK")
    assert result.returncode == 0, result.stderr
    assert output == f"dir={tmp_path / 'previous'}\n"
    assert calls[1] == "gh api -i orgs/Epam/packages/container/ai-dial-sca-cve-index"
    assert calls[2] == f"oras pull {IMAGE}:1 --output {tmp_path / 'previous'}"


def test_a_user_owns_the_package_with_the_users_api(tmp_path: Path) -> None:
    result, calls, _ = run(tmp_path, "HTTP/2.0 200 OK", owner_type="User")
    assert result.returncode == 0
    assert calls[1].startswith("gh api -i users/Epam/packages/container/")


def test_a_package_that_does_not_exist_is_a_bootstrap(tmp_path: Path) -> None:
    result, calls, output = run(tmp_path, "HTTP/2.0 404 Not Found")
    assert result.returncode == 0
    assert output == ""  # no previous index
    assert "::notice::No previous index" in result.stdout
    assert not any(call.startswith("oras") for call in calls)


@pytest.mark.parametrize(
    "response", ["HTTP/2.0 403 Forbidden", "HTTP/2.0 502 Bad Gateway", ""]
)
def test_any_other_answer_fails_and_does_not_bootstrap(
    tmp_path: Path, response: str
) -> None:
    result, calls, output = run(tmp_path, response)
    assert result.returncode == 1
    assert "::error::Cannot tell whether" in result.stdout
    assert output == ""
    assert not any(call.startswith("oras") for call in calls)


def test_a_failing_pull_of_an_existing_package_fails(tmp_path: Path) -> None:
    result, _, output = run(tmp_path, "HTTP/2.0 200 OK", oras_rc=1)
    assert result.returncode == 1
    assert "Cannot pull" in result.stdout
    assert output == ""


def test_an_unknown_owner_type_fails(tmp_path: Path) -> None:
    result, _, _ = run(tmp_path, "HTTP/2.0 200 OK", owner_type="Bot")
    assert result.returncode == 1
    assert "Unknown owner type" in result.stdout


def test_bootstrap_does_not_look_at_all(tmp_path: Path) -> None:
    result, calls, output = run(tmp_path, "HTTP/2.0 200 OK", bootstrap="true")
    assert result.returncode == 0
    assert calls == []
    assert output == ""
