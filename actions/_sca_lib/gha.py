"""GitHub Actions: workflow commands, step outputs and the step summary."""

from __future__ import annotations

import secrets
from pathlib import Path


def escape_command_data(text: object) -> str:
    """Escape a text for the message of a workflow command (``::warning::``).

    The text may come from outside (scanner output, a repository, a feed), and
    ``%``, CR and LF would end or forge the command.
    """
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def format_output(name: str, value: str) -> str:
    """One $GITHUB_OUTPUT entry in the delimiter format, safe for multiline values."""
    delimiter = f"ghadelimiter_{secrets.token_hex(16)}"
    return f"{name}<<{delimiter}\n{value}\n{delimiter}\n"


def append_text(path: str | Path, text: str) -> None:
    """Append to a file of the step ($GITHUB_OUTPUT, $GITHUB_STEP_SUMMARY)."""
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(text)
