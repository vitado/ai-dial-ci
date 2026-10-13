"""Package URLs (purl) as the scanners print them."""

from __future__ import annotations

import urllib.parse
from typing import NamedTuple


class Purl(NamedTuple):
    type: str  # lower case
    namespace: str  # percent-decoded, "" if there is none
    name: str  # percent-decoded
    version: str | None  # percent-decoded, None if there is none


def parse_purl(purl: str) -> Purl | None:
    """The parts of a purl; None if it is malformed (no name, an empty segment)."""
    if not purl.startswith("pkg:"):
        return None
    rest = purl[len("pkg:") :].split("#", 1)[0].split("?", 1)[0]
    body, at, version = rest.partition("@")
    parts = body.split("/")
    if len(parts) < 2 or not all(parts):
        return None
    namespace = "/".join(urllib.parse.unquote(part) for part in parts[1:-1])
    return Purl(
        parts[0].lower(),
        namespace,
        urllib.parse.unquote(parts[-1]),
        urllib.parse.unquote(version) if at and version else None,
    )
