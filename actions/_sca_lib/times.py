"""Time as the SCA files write and read it: UTC, ``2026-10-12T01:14:57Z``."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def format_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(TIME_FORMAT)


def parse_time(value: Any) -> datetime | None:
    """An ISO 8601 text as a time (UTC if it has no zone); None if it is not one."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
