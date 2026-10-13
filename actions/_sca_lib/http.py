"""HTTPS requests with bounded retries: one client for the SCA actions.

The transport (``(method, url, headers, body) -> Response``) is injectable, so the
code that uses it is tested with no network. ``backoff_delay`` is the retry policy
(429/5xx and network errors, exponential backoff, ``Retry-After``) of
``HttpClient``.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

REQUEST_TIMEOUT_SECONDS = 60.0
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 60.0
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
# an answer larger than this is not what was asked for
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024


class TransportError(Exception):
    """A network-level failure (DNS, connection, timeout)."""


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "headers", {k.lower(): v for k, v in self.headers.items()}
        )

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


Transport = Callable[[str, str, Mapping[str, str], bytes | None], Response]


def backoff_delay(
    attempt: int,
    retry_after: str | None = None,
    base: float = BACKOFF_BASE_SECONDS,
) -> float:
    """Seconds to wait after the ``attempt``-th failed attempt (counted from 1):
    ``Retry-After`` of the server (seconds, at most a minute) if it sent one, else
    the exponential backoff.
    """
    if retry_after is not None and retry_after.strip().isdigit():
        return min(float(retry_after), MAX_RETRY_AFTER_SECONDS) or base * 2 ** (
            attempt - 1
        )
    return base * 2 ** (attempt - 1)


class UrllibTransport:
    """Production transport: an HTTPS request through urllib with a timeout."""

    def __init__(
        self,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
        max_bytes: int = MAX_DOWNLOAD_BYTES,
    ) -> None:
        self._timeout = timeout
        self._max_bytes = max_bytes

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> Response:
        if urllib.parse.urlsplit(url).scheme != "https":
            raise TransportError(f"refusing non-HTTPS URL: {url}")
        request = urllib.request.Request(
            url, data=body, headers=dict(headers), method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                data = resp.read(self._max_bytes + 1)
                if len(data) > self._max_bytes:
                    raise TransportError(f"{url}: answer is larger than the limit")
                return Response(resp.status, dict(resp.headers), data)
        except urllib.error.HTTPError as err:
            return Response(err.code, dict(err.headers), err.read(4096))
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            raise TransportError(f"{url}: {err}") from err


class HttpClient:
    """Adds bounded retries with backoff (429/5xx, network errors) to a Transport."""

    def __init__(
        self,
        transport: Transport,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = MAX_ATTEMPTS,
        backoff_base: float = BACKOFF_BASE_SECONDS,
    ) -> None:
        self._transport = transport
        self._sleep = sleep
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base

    def request(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> Response:
        for attempt in range(1, self._max_attempts + 1):
            delay = backoff_delay(attempt, base=self._backoff_base)
            try:
                response = self._transport(method, url, headers, body)
            except TransportError:
                if attempt == self._max_attempts:
                    raise
            else:
                if (
                    response.status not in RETRY_STATUSES
                    or attempt == self._max_attempts
                ):
                    return response
                delay = backoff_delay(
                    attempt, response.header("Retry-After"), self._backoff_base
                )
            self._sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover
