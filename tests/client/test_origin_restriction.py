from __future__ import annotations

import typing

import pytest

import httpx

SECRET_QUERY = "token=top-secret-value"
SECRET_USERINFO = "user:hunter2"


def make_transport(calls: list[httpx.URL]) -> httpx.MockTransport:
    """
    Return a mock transport that records each dispatched URL.

    The handler answers `/start` with a same-origin relative redirect,
    `/jump` with a cross-origin redirect, and anything else with 200.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url)
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": f"/next?{SECRET_QUERY}"})
        if request.url.path == "/jump":
            return httpx.Response(
                302,
                headers={
                    "location": f"https://disallowed.example.org/x?{SECRET_QUERY}"
                },
            )
        return httpx.Response(200, text="ok")

    return httpx.MockTransport(handler)


def make_async_transport(calls: list[httpx.URL]) -> httpx.MockTransport:
    transport = make_transport(calls)
    return transport


def test_same_origin_relative_redirect_is_followed() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=make_transport(calls)) as client:
        response = client.get(
            f"https://example.org/start?{SECRET_QUERY}",
            follow_redirects=True,
            extensions={"origin_restriction": restriction},
        )

    assert response.status_code == 200
    assert response.url == f"https://example.org/next?{SECRET_QUERY}"
    # The initial request and the one redirect each reached the transport.
    assert [str(url) for url in calls] == [
        f"https://example.org/start?{SECRET_QUERY}",
        f"https://example.org/next?{SECRET_QUERY}",
    ]

    decisions = response.extensions["origin_decisions"]
    assert [decision.allowed for decision in decisions] == [True, True]
    assert decisions[0].entry_origin == httpx.Origin("https", "example.org", 443)
    assert decisions[1].target_origin == httpx.Origin("https", "example.org", 443)


def test_cross_origin_redirect_is_rejected_before_dispatch() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=make_transport(calls)) as client:
        with pytest.raises(httpx.OriginNotAllowed) as exc_info:
            client.get(
                f"https://example.org/jump?{SECRET_QUERY}",
                follow_redirects=True,
                extensions={"origin_restriction": restriction},
            )

    exc = exc_info.value
    assert exc.origin == httpx.Origin("https", "disallowed.example.org", 443)
    # Only the first request was handed to the transport, so the rejection
    # happened while preparing the next hop.
    assert [str(url) for url in calls] == [f"https://example.org/jump?{SECRET_QUERY}"]

    decisions = exc.decisions
    assert [(d.target_origin.host, d.allowed) for d in decisions] == [
        ("example.org", True),
        ("disallowed.example.org", False),
    ]
    # The entry origin is the origin of the request that produced the redirect.
    assert decisions[1].entry_origin == httpx.Origin("https", "example.org", 443)


def test_rejection_does_not_leak_query_or_credentials() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=make_transport(calls)) as client:
        with pytest.raises(httpx.OriginNotAllowed) as exc_info:
            client.get(
                f"https://{SECRET_USERINFO}@example.org/jump?{SECRET_QUERY}",
                follow_redirects=True,
                extensions={"origin_restriction": restriction},
            )

    exc = exc_info.value
    rendered = " ".join(
        [str(exc), *(str(decision) for decision in exc.decisions), repr(exc.decisions)]
    )
    assert SECRET_QUERY not in rendered
    assert "top-secret-value" not in rendered
    assert "hunter2" not in rendered
    assert "/jump" not in rendered
    assert "disallowed.example.org" in rendered


def test_response_diagnostics_do_not_leak_query_or_credentials() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=make_transport(calls)) as client:
        response = client.get(
            f"https://{SECRET_USERINFO}@example.org/start?{SECRET_QUERY}",
            follow_redirects=True,
            extensions={"origin_restriction": restriction},
        )

    decisions = response.extensions["origin_decisions"]
    rendered = " ".join([*(str(decision) for decision in decisions), repr(decisions)])
    assert SECRET_QUERY not in rendered
    assert "top-secret-value" not in rendered
    assert "hunter2" not in rendered
    assert "/start" not in rendered
    assert "/next" not in rendered


def test_initial_request_outside_restriction_never_reaches_transport() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=make_transport(calls)) as client:
        with pytest.raises(httpx.OriginNotAllowed):
            client.get(
                "https://other.example.org/start",
                follow_redirects=True,
                extensions={"origin_restriction": restriction},
            )

    assert calls == []


def test_client_switches_restrictions_between_requests() -> None:
    calls: list[httpx.URL] = []
    first = httpx.OriginRestriction(["https://example.org"])
    second = httpx.OriginRestriction(["https://disallowed.example.org"])

    with httpx.Client(transport=make_transport(calls)) as client:
        response = client.get(
            "https://example.org/start",
            follow_redirects=True,
            extensions={"origin_restriction": first},
        )
        assert response.status_code == 200
        assert len(calls) == 2

        calls.clear()
        with pytest.raises(httpx.OriginNotAllowed):
            client.get(
                "https://example.org/jump",
                follow_redirects=True,
                extensions={"origin_restriction": second},
            )
        # Had the second request reused the first restriction, its initial
        # request would have been dispatched. It was rejected at the initial
        # origin instead, so no request reached the transport.
        assert calls == []

        calls.clear()
        response = client.get(
            "https://disallowed.example.org/start",
            follow_redirects=True,
            extensions={"origin_restriction": second},
        )
        assert response.status_code == 200
        assert [str(url) for url in calls] == [
            "https://disallowed.example.org/start",
            "https://disallowed.example.org/next?token=top-secret-value",
        ]


def test_unrestricted_requests_keep_previous_behaviour() -> None:
    calls: list[httpx.URL] = []
    with httpx.Client(transport=make_transport(calls)) as client:
        response = client.get("https://example.org/jump", follow_redirects=True)

    assert response.status_code == 200
    assert len(calls) == 2
    assert "origin_decisions" not in response.extensions
    assert "origin_decisions" not in response.history[0].extensions


def test_unfollowed_redirect_is_still_checked() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=make_transport(calls)) as client:
        with pytest.raises(httpx.OriginNotAllowed):
            client.get(
                "https://example.org/jump",
                follow_redirects=False,
                extensions={"origin_restriction": restriction},
            )
    assert len(calls) == 1


def test_next_request_is_returned_for_allowed_same_origin_redirect() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=make_transport(calls)) as client:
        response = client.get(
            "https://example.org/start",
            follow_redirects=False,
            extensions={"origin_restriction": restriction},
        )

    assert response.status_code == 302
    assert response.next_request is not None
    assert (
        str(response.next_request.url)
        == "https://example.org/next?token=top-secret-value"
    )
    decisions = response.extensions["origin_decisions"]
    assert [decision.allowed for decision in decisions] == [True, True]


def test_decision_compares_scheme_host_and_port() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org:8443"])
    with httpx.Client(transport=make_transport(calls)) as client:
        with pytest.raises(httpx.OriginNotAllowed):
            client.get(
                "https://example.org/start",
                follow_redirects=True,
                extensions={"origin_restriction": restriction},
            )
    assert calls == []

    calls.clear()
    with httpx.Client(transport=make_transport(calls)) as client:
        with pytest.raises(httpx.OriginNotAllowed):
            client.get(
                "http://example.org:8443/start",
                follow_redirects=True,
                extensions={"origin_restriction": restriction},
            )
    assert calls == []


def test_default_ports_are_normalised() -> None:
    assert httpx.Origin.from_url("https://example.org") == httpx.Origin(
        "https", "example.org", 443
    )
    assert httpx.Origin.from_url("https://example.org:443") == httpx.Origin(
        "https", "example.org", 443
    )
    assert httpx.Origin.from_url("http://example.org:80") == httpx.Origin(
        "http", "example.org", 80
    )
    assert (
        str(httpx.Origin.from_url("https://example.org:443")) == "https://example.org"
    )
    assert str(httpx.Origin.from_url("https://example.org:8443")) == (
        "https://example.org:8443"
    )
    assert str(httpx.Origin.from_url("http://[::1]:8080")) == "http://[::1]:8080"


def test_restriction_matches_methods_and_allows_origin_objects() -> None:
    restriction = httpx.OriginRestriction(
        [httpx.Origin("https", "example.org", 443), "http://other.example.org"]
    )
    assert restriction.allows("https://example.org/anything?x=1")
    assert restriction.allows("http://other.example.org:80/path")
    assert not restriction.allows("https://example.org:8443/")
    assert not restriction.allows("http://example.org/")
    assert restriction.allowed_origins == frozenset(
        {
            httpx.Origin("https", "example.org", 443),
            httpx.Origin("http", "other.example.org", 80),
        }
    )


@pytest.mark.parametrize(
    "value",
    ["example.org", "/relative", "https://", [""]],
)
def test_restriction_rejects_incomplete_origins(value: typing.Any) -> None:
    with pytest.raises(ValueError):
        httpx.OriginRestriction(value)


def test_restriction_requires_at_least_one_origin() -> None:
    with pytest.raises(ValueError):
        httpx.OriginRestriction([])


def test_restriction_does_not_mutate_the_input() -> None:
    origins = ["https://example.org"]
    httpx.OriginRestriction(origins)
    assert origins == ["https://example.org"]


def test_restriction_accepts_a_single_origin_value() -> None:
    assert httpx.OriginRestriction("https://example.org").allowed_origins == {
        httpx.Origin("https", "example.org", 443)
    }
    assert httpx.OriginRestriction(httpx.Origin("https", "example.org", 443)).allows(
        "https://example.org/"
    )
    assert httpx.OriginRestriction(httpx.URL("https://example.org/")).allows(
        "https://example.org/"
    )


def test_restriction_rejects_non_iterable_input() -> None:
    with pytest.raises(TypeError):
        httpx.OriginRestriction(1)  # type: ignore[arg-type]


def test_restriction_repr_lists_origins_without_paths() -> None:
    restriction = httpx.OriginRestriction(
        ["https://b.example/some/path?query=1", "http://a.example"]
    )
    assert (
        repr(restriction) == "OriginRestriction([http://a.example, https://b.example])"
    )


def test_origin_repr_and_str_hide_unknown_origins() -> None:
    assert str(httpx.Origin("", "", None)) == "<unknown-origin>"
    assert repr(httpx.Origin("https", "example.org", 443)) == (
        "Origin(scheme='https', host='example.org', port=443)"
    )


def test_decision_record_rendering_names_verdict() -> None:
    decision = httpx.OriginDecision(
        entry_origin=httpx.Origin("https", "example.org", 443),
        target_origin=httpx.Origin("https", "other.example.org", 443),
        allowed=False,
    )
    assert str(decision) == "https://example.org -> https://other.example.org: rejected"
    allowed_decision = decision._replace(allowed=True)
    assert str(allowed_decision) == (
        "https://example.org -> https://other.example.org: allowed"
    )


def test_invalid_extension_value_is_rejected() -> None:
    calls: list[httpx.URL] = []
    with httpx.Client(transport=make_transport(calls)) as client:
        with pytest.raises(TypeError):
            client.get(
                "https://example.org/start",
                extensions={"origin_restriction": "https://example.org"},
            )
    assert calls == []


@pytest.mark.parametrize("value", ["https://\N{SMILING FACE WITH HALO}/"])
def test_restriction_does_not_echo_invalid_locations(value: str) -> None:
    with pytest.raises(ValueError) as exc_info:
        httpx.OriginRestriction(value)
    assert "\N{SMILING FACE WITH HALO}" not in str(exc_info.value)


def test_restriction_travels_on_a_built_request() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=make_transport(calls)) as client:
        request = client.build_request(
            "GET",
            "https://example.org/start",
            extensions={"origin_restriction": restriction},
        )
        response = client.send(request, follow_redirects=True)

    assert len(calls) == 2
    assert [d.allowed for d in response.extensions["origin_decisions"]] == [True, True]


@pytest.mark.anyio
async def test_restriction_travels_on_a_built_async_request() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    async with httpx.AsyncClient(transport=make_async_transport(calls)) as client:
        request = client.build_request(
            "GET",
            "https://example.org/start",
            extensions={"origin_restriction": restriction},
        )
        response = await client.send(request, follow_redirects=True)

    assert len(calls) == 2
    assert [d.allowed for d in response.extensions["origin_decisions"]] == [True, True]


def test_restricted_streaming_response_is_rejected_before_dispatch() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=make_transport(calls)) as client:
        with pytest.raises(httpx.OriginNotAllowed):
            with client.stream(
                "GET",
                "https://example.org/jump",
                follow_redirects=True,
                extensions={"origin_restriction": restriction},
            ):
                pass  # pragma: no cover
    assert len(calls) == 1


@pytest.mark.anyio
async def test_async_same_origin_relative_redirect_is_followed() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    async with httpx.AsyncClient(transport=make_async_transport(calls)) as client:
        response = await client.get(
            "https://example.org/start",
            follow_redirects=True,
            extensions={"origin_restriction": restriction},
        )

    assert response.status_code == 200
    assert len(calls) == 2
    assert [d.allowed for d in response.extensions["origin_decisions"]] == [True, True]


@pytest.mark.anyio
async def test_async_cross_origin_redirect_is_rejected_before_dispatch() -> None:
    calls: list[httpx.URL] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    async with httpx.AsyncClient(transport=make_async_transport(calls)) as client:
        with pytest.raises(httpx.OriginNotAllowed) as exc_info:
            await client.get(
                "https://example.org/jump",
                follow_redirects=True,
                extensions={"origin_restriction": restriction},
            )

    assert len(calls) == 1
    assert exc_info.value.origin == httpx.Origin("https", "disallowed.example.org", 443)


@pytest.mark.anyio
async def test_async_client_switches_restrictions_between_requests() -> None:
    calls: list[httpx.URL] = []
    first = httpx.OriginRestriction(["https://example.org"])
    second = httpx.OriginRestriction(["https://disallowed.example.org"])

    async with httpx.AsyncClient(transport=make_async_transport(calls)) as client:
        response = await client.get(
            "https://example.org/start",
            follow_redirects=True,
            extensions={"origin_restriction": first},
        )
        assert response.status_code == 200
        assert len(calls) == 2

        calls.clear()
        with pytest.raises(httpx.OriginNotAllowed):
            await client.get(
                "https://example.org/jump",
                follow_redirects=True,
                extensions={"origin_restriction": second},
            )
        assert calls == []


def test_relative_location_is_resolved_against_current_request() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/a/start":
            return httpx.Response(302, headers={"location": "next"})
        return httpx.Response(200)

    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        response = client.get(
            "https://example.org/a/start",
            follow_redirects=True,
            extensions={"origin_restriction": restriction},
        )

    assert seen == ["/a/start", "/a/next"]
    decision = response.extensions["origin_decisions"][1]
    assert decision.entry_origin == httpx.Origin("https", "example.org", 443)
    assert decision.target_origin == httpx.Origin("https", "example.org", 443)
    assert response.url == "https://example.org/a/next"
