"""Version comparison.

``compare_versions`` orders two versions by the scheme of an ecosystem (SemVer for
npm and cargo, PEP 440 for PyPI, Maven ``ComparableVersion``); a version that is not
valid in it is not comparable. ``compare_tokens`` is the tolerant comparison of a
scheme-less version (OS packages: ``1.3.2-r1``): numeric tokens as integers, words
as text. Both return -1, 0 or 1, and None where the versions cannot be compared.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

_SEMVER_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)


def _semver_key(version: str) -> tuple[tuple[int, int, int], list[str] | None] | None:
    match = _SEMVER_RE.match(version.strip().lstrip("="))
    if not match:
        return None
    numbers = tuple(int(part) if part else 0 for part in match.groups()[:3])
    pre = match.group(4)
    return numbers, (pre.split(".") if pre else None)  # type: ignore[return-value]


def _cmp_prerelease(a: list[str] | None, b: list[str] | None) -> int:
    """SemVer 2.0 precedence of pre-release parts (no pre-release is the highest)."""
    if a is None or b is None:
        return (a is None) - (b is None)
    for x, y in zip(a, b, strict=False):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return -1 if int(x) < int(y) else 1
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1
        return -1 if x < y else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def compare_semver(a: str, b: str) -> int | None:
    ka, kb = _semver_key(a), _semver_key(b)
    if ka is None or kb is None:
        return None
    if ka[0] != kb[0]:
        return -1 if ka[0] < kb[0] else 1
    return _cmp_prerelease(ka[1], kb[1])


# PEP 440, Appendix B
_PEP440_RE = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.IGNORECASE | re.VERBOSE,
)
_PEP440_PRE = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "c": 2,
    "rc": 2,
    "pre": 2,
    "preview": 2,
}
_NEG_INF = (-1,)
_POS_INF = (1 << 62,)


def _pep440_key(version: str) -> tuple[Any, ...] | None:
    """Ordering key as of ``packaging``; the local version label is ignored (the
    affected ranges of a CVE are about public versions).
    """
    match = _PEP440_RE.match(version)
    if not match:
        return None
    release = [int(part) for part in match.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = post = dev = None
    if match.group("pre_l"):
        pre = (
            _PEP440_PRE[match.group("pre_l").lower()],
            int(match.group("pre_n") or 0),
        )
    if match.group("post"):
        post = int(match.group("post_n1") or match.group("post_n2") or 0)
    if match.group("dev_l"):
        dev = int(match.group("dev_n") or 0)
    if pre is None and post is None and dev is not None:
        pre_key: tuple[Any, ...] = _NEG_INF
    elif pre is None:
        pre_key = _POS_INF
    else:
        pre_key = pre
    return (
        int(match.group("epoch") or 0),
        tuple(release),
        pre_key,
        _NEG_INF if post is None else (post,),
        _POS_INF if dev is None else (dev,),
    )


def compare_pep440(a: str, b: str) -> int | None:
    ka, kb = _pep440_key(a), _pep440_key(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


# Maven ComparableVersion (Maven 3.x): items are int, str (a qualifier) or list.
_MAVEN_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
_MAVEN_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
_MAVEN_SHORT = {"a": "alpha", "b": "beta", "m": "milestone"}
_MAVEN_RELEASE_KEY = str(_MAVEN_QUALIFIERS.index(""))
_MavenItem = int | str | list


def _maven_qualifier_key(qualifier: str) -> str:
    if qualifier in _MAVEN_QUALIFIERS:
        return str(_MAVEN_QUALIFIERS.index(qualifier))
    return f"{len(_MAVEN_QUALIFIERS)}-{qualifier}"


def _maven_string_item(text: str, followed_by_digit: bool) -> str:
    if followed_by_digit and len(text) == 1:
        text = _MAVEN_SHORT.get(text, text)
    return _MAVEN_ALIASES.get(text, text)


def _maven_is_null(item: _MavenItem) -> bool:
    if isinstance(item, int):
        return item == 0
    if isinstance(item, str):
        return _maven_qualifier_key(item) == _MAVEN_RELEASE_KEY
    return not item


def _maven_normalize(items: list[_MavenItem]) -> None:
    for index in range(len(items) - 1, -1, -1):
        item = items[index]
        if _maven_is_null(item):
            del items[index]
        elif not isinstance(item, list):
            break


def _maven_parse(version: str) -> list[_MavenItem]:
    version = version.strip().lower()
    root: list[_MavenItem] = []
    current = root
    stack = [root]
    is_digit = False
    start = 0

    def item(digit: bool, text: str) -> _MavenItem:
        return int(text) if digit else _maven_string_item(text, False)

    def descend() -> list[_MavenItem]:
        child: list[_MavenItem] = []
        current.append(child)
        stack.append(child)
        return child

    for index, char in enumerate(version):
        if char == ".":
            current.append(
                0 if index == start else item(is_digit, version[start:index])
            )
            start = index + 1
        elif char == "-":
            current.append(
                0 if index == start else item(is_digit, version[start:index])
            )
            start = index + 1
            current = descend()
        elif char.isdigit():
            if not is_digit and index > start:
                current.append(_maven_string_item(version[start:index], True))
                start = index
                current = descend()
            is_digit = True
        else:
            if is_digit and index > start:
                current.append(int(version[start:index]))
                start = index
                current = descend()
            is_digit = False
    if len(version) > start:
        current.append(item(is_digit, version[start:]))
    while stack:
        _maven_normalize(stack.pop())
    return root


def _maven_cmp_item(a: _MavenItem | None, b: _MavenItem | None) -> int:
    """``ComparableVersion.*Item.compareTo``; None is the missing item."""
    if a is None:
        return 0 if b is None else -_maven_cmp_item(b, None)
    if isinstance(a, int):
        if b is None:
            return 0 if a == 0 else 1
        if isinstance(b, int):
            return (a > b) - (a < b)
        return 1
    if isinstance(a, str):
        if b is None:
            ka, kb = _maven_qualifier_key(a), _MAVEN_RELEASE_KEY
        elif isinstance(b, str):
            ka, kb = _maven_qualifier_key(a), _maven_qualifier_key(b)
        else:
            return -1
        return (ka > kb) - (ka < kb)
    if b is None:
        return 0 if not a else _maven_cmp_item(a[0], None)
    if isinstance(b, int):
        return -1
    if isinstance(b, str):
        return 1
    for index in range(max(len(a), len(b))):
        left = a[index] if index < len(a) else None
        right = b[index] if index < len(b) else None
        result = _maven_cmp_item(left, right)
        if result:
            return result
    return 0


def compare_maven(a: str, b: str) -> int | None:
    if not (re.search(r"\d", a) and re.search(r"\d", b)):
        return None
    return _maven_cmp_item(_maven_parse(a), _maven_parse(b))


def compare_versions(ecosystem: str, a: str, b: str) -> int | None:
    """-1, 0 or 1 by the version scheme of the ecosystem; None if either version is
    not valid in it.
    """
    if ecosystem in ("npm", "cargo"):
        return compare_semver(a, b)
    if ecosystem == "pypi":
        return compare_pep440(a, b)
    if ecosystem == "maven":
        return compare_maven(a, b)
    return None


# Versions of no known scheme

PRERELEASE_TOKENS = frozenset(
    {"a", "alpha", "b", "beta", "c", "rc", "pre", "preview", "dev", "snapshot", "m"}
)
_VERSION_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


def version_tokens(version: str) -> list[int | str]:
    """Split a version into numeric (int) and alphabetic (lowercase str) tokens."""
    return [
        int(token) if token.isdigit() else token.lower()
        for token in _VERSION_TOKEN_RE.findall(version)
    ]


def _tail_order(tail: Sequence[int | str]) -> int:
    """Order of a version that has ``tail`` more tokens than the one it is compared to.

    Trailing zeros change nothing (1.0 == 1.0.0), a pre-release word makes the
    longer version older (1.0rc1 < 1.0), anything else makes it newer (1.0.1, 1.0-r1).
    """
    if all(token == 0 for token in tail):
        return 0
    return -1 if tail[0] in PRERELEASE_TOKENS else 1


def compare_tokens(a: str, b: str) -> int | None:
    """Tolerant version comparison: -1, 0 or 1; None if the versions are not comparable.

    Works for semver-like, Alpine (``1.3.2-r1``) and similar schemes by comparing
    numeric tokens as integers and alphabetic ones as text. Versions without any
    number, or whose first difference is a number against a word, are not comparable.
    """
    tokens_a, tokens_b = version_tokens(a), version_tokens(b)
    if not any(isinstance(t, int) for t in tokens_a) or not any(
        isinstance(t, int) for t in tokens_b
    ):
        return None
    for x, y in zip(tokens_a, tokens_b, strict=False):
        if x == y:
            continue
        if isinstance(x, int) != isinstance(y, int):
            return None
        return -1 if x < y else 1  # type: ignore[operator]
    common = min(len(tokens_a), len(tokens_b))
    if len(tokens_a) > common:
        return _tail_order(tokens_a[common:])
    if len(tokens_b) > common:
        return -_tail_order(tokens_b[common:])
    return 0
