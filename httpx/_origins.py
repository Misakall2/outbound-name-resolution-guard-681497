from __future__ import annotations

import typing

from ._exceptions import InvalidURL
from ._urls import URL

__all__ = ["Origin", "OriginDecision", "OriginRestriction"]

#: The request extension key used to attach a caller-provided origin restriction.
#:
#: The value is expected to be an `httpx.OriginRestriction` instance. The
#: extension travels with the request, including across redirects.
ORIGIN_RESTRICTION_EXTENSION = "origin_restriction"

#: The response extension key used to expose the origin decisions taken while
#: handling a request. The value is a tuple of `httpx.OriginDecision` records.
ORIGIN_DECISIONS_EXTENSION = "origin_decisions"

_DEFAULT_PORTS: dict[str, int] = {
    "ftp": 21,
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}


class Origin(typing.NamedTuple):
    """
    The origin of a URL, as `(scheme, host, port)`.

    Only the information required to compare origins is kept, so an origin
    never carries a path, a query string, a fragment, or user credentials.

    The port is the *effective* port: URLs using the default port for their
    scheme, and URLs that omit the port, both give the default port. For
    example:

    ```python
    >>> httpx.Origin.from_url("https://example.org/path?query=1")
    Origin(scheme='https', host='example.org', port=443)
    ```
    """

    scheme: str
    host: str
    port: int | None

    @classmethod
    def from_url(cls, url: URL | str) -> Origin:
        """
        Return the origin of the given URL.
        """
        parsed = URL(url)
        port = parsed.port
        if port is None:
            port = _DEFAULT_PORTS.get(parsed.scheme)
        return cls(scheme=parsed.scheme, host=parsed.host, port=port)

    def __str__(self) -> str:
        if not self.scheme or not self.host:
            return "<unknown-origin>"
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port is None or self.port == _DEFAULT_PORTS.get(self.scheme):
            return f"{self.scheme}://{host}"
        return f"{self.scheme}://{host}:{self.port}"


class OriginDecision(typing.NamedTuple):
    """
    A diagnostic record for a single origin comparison.

    `entry_origin` is the origin of the request in force, `target_origin` is
    the origin of the address the client resolved (for a redirect, this is the
    `Location` header resolved against the current request), and `allowed`
    records whether the target was listed in the restriction.
    """

    entry_origin: Origin
    target_origin: Origin
    allowed: bool

    def __str__(self) -> str:
        verdict = "allowed" if self.allowed else "rejected"
        return f"{self.entry_origin} -> {self.target_origin}: {verdict}"


class OriginRestriction:
    """
    A caller-provided list of origins that a request may contact.

    The restriction is passed per request, using the `"origin_restriction"`
    request extension, and applies to the initial request and to each redirect
    the client would follow. Only scheme, host and port take part in the
    comparison.

    ```python
    restriction = httpx.OriginRestriction(["https://example.org"])
    response = client.get(
        "https://example.org/start",
        follow_redirects=True,
        extensions={"origin_restriction": restriction},
    )
    ```

    Each request should be given its own restriction; the client keeps no
    origin cache and no restriction decisions between requests. The decisions
    taken while handling a request are available on the response, or on the
    raised `httpx.OriginNotAllowed`, as `httpx.OriginDecision` records.
    """

    def __init__(
        self, origins: typing.Iterable[Origin | URL | str] | Origin | URL | str
    ) -> None:
        if isinstance(origins, (Origin, URL, str)):
            entries: typing.Iterable[Origin | URL | str] = [origins]
        else:
            try:
                entries = list(origins)
            except TypeError:
                raise TypeError(
                    "OriginRestriction() expects an origin, a URL, a string, "
                    "or an iterable of them."
                ) from None

        allowed = frozenset(_coerce_origin(entry) for entry in entries)
        if not allowed:
            raise ValueError("At least one allowed origin is required.")
        self._allowed_origins = allowed

    @property
    def allowed_origins(self) -> frozenset[Origin]:
        """
        The normalised origins that requests may contact.
        """
        return self._allowed_origins

    def allows(self, url: URL | str) -> bool:
        """
        Return `True` if the given URL's origin is listed in the restriction.
        """
        return Origin.from_url(url) in self._allowed_origins

    def decide(self, entry_url: URL | str, target_url: URL | str) -> OriginDecision:
        """
        Return the decision for moving from `entry_url` to `target_url`.

        The returned record contains only origin information: paths, query
        strings, fragments and user credentials are never retained.
        """
        entry_origin = Origin.from_url(entry_url)
        target_origin = Origin.from_url(target_url)
        return OriginDecision(
            entry_origin=entry_origin,
            target_origin=target_origin,
            allowed=target_origin in self._allowed_origins,
        )

    def __repr__(self) -> str:
        origins = ", ".join(sorted(str(origin) for origin in self._allowed_origins))
        return f"OriginRestriction([{origins}])"


def _coerce_origin(value: Origin | URL | str) -> Origin:
    if isinstance(value, Origin):
        return value

    try:
        url = URL(value)
    except (InvalidURL, TypeError):
        # Deliberately avoid echoing the caller's value, which may carry
        # credentials, in the error message.
        raise ValueError(
            "Allowed origins must be absolute URLs with a scheme and host."
        ) from None

    if not url.scheme or not url.host:
        raise ValueError(
            "Allowed origins must be absolute URLs with a scheme and host."
        )
    return Origin.from_url(url)
