#!/usr/bin/env python
"""
Acceptance harness for the per-request origin restriction on redirects.

Run it with:

    python examples/origin_restriction/origin_restriction_check.py

The harness uses the repository's existing ``httpx.MockTransport`` so no
name resolution, sockets, or external services are involved. It records the
order in which the mock transport was called, and prints the origin decisions
for each scenario.

The scenarios are:

1. ``same-origin`` — a same-origin relative redirect is followed; the mock
   transport is called twice.
2. ``disallowed-origin`` — a redirect to an origin outside the restriction is
   rejected before the second request is dispatched; the mock transport is
   called once.
3. ``restriction-switch`` — the same client is used with two different
   restrictions; the second request is judged only by its own restriction.
4. ``no-restriction`` — a request without a restriction keeps the previous
   redirect handling.

The output deliberately contains only scheme/host/port information, so the
query strings and credentials in the test URLs never appear in the records.
"""

from __future__ import annotations

import sys
import typing
from pathlib import Path

# Make sure the checkout's `httpx` package is used, rather than any copy that
# happens to be installed in the environment.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402

# Query strings and credentials are present in the requests below so that the
# harness can confirm they never appear in the diagnostics.
ENTRY_QUERY = "session=entry-secret&step=1"
REDIRECT_QUERY = "ticket=redirect-secret&step=2"
ENTRY_USERINFO = "svc:entry-password"


def build_transport(calls: list[str]) -> httpx.MockTransport:
    """
    Return a mock transport that records each dispatched URL and answers:

    * ``/start`` with a same-origin relative redirect,
    * ``/jump`` with a redirect to a disallowed origin.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": f"/next?{REDIRECT_QUERY}"})
        if request.url.path == "/jump":
            return httpx.Response(
                302,
                headers={
                    "location": f"https://disallowed.example.org/target?{REDIRECT_QUERY}"
                },
            )
        return httpx.Response(200, text="ok")

    return httpx.MockTransport(handler)


def format_decisions(decisions: typing.Iterable[httpx.OriginDecision]) -> list[str]:
    return [str(decision) for decision in decisions]


def run_same_origin_scenario() -> dict[str, typing.Any]:
    calls: list[str] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    with httpx.Client(transport=build_transport(calls)) as client:
        response = client.get(
            f"https://{ENTRY_USERINFO}@example.org/start?{ENTRY_QUERY}",
            follow_redirects=True,
            extensions={"origin_restriction": restriction},
        )
    decisions = response.extensions["origin_decisions"]
    return {
        "name": "same-origin",
        "transport_calls": calls,
        "final_origin": str(httpx.Origin.from_url(response.url)),
        "decisions": format_decisions(decisions),
        "rejected": False,
    }


def run_disallowed_origin_scenario() -> dict[str, typing.Any]:
    calls: list[str] = []
    restriction = httpx.OriginRestriction(["https://example.org"])
    rejected = False
    decisions: typing.Iterable[httpx.OriginDecision] = ()
    error = ""
    with httpx.Client(transport=build_transport(calls)) as client:
        try:
            client.get(
                f"https://example.org/jump?{ENTRY_QUERY}",
                follow_redirects=True,
                extensions={"origin_restriction": restriction},
            )
        except httpx.OriginNotAllowed as exc:
            rejected = True
            decisions = exc.decisions
            error = str(exc)
    return {
        "name": "disallowed-origin",
        "transport_calls": calls,
        "decisions": format_decisions(decisions),
        "rejected": rejected,
        "error": error,
    }


def run_restriction_switch_scenario() -> dict[str, typing.Any]:
    calls: list[str] = []
    first = httpx.OriginRestriction(["https://example.org"])
    second = httpx.OriginRestriction(["https://disallowed.example.org"])
    results: list[dict[str, typing.Any]] = []

    with httpx.Client(transport=build_transport(calls)) as client:
        calls.clear()
        first_response = client.get(
            "https://example.org/start",
            follow_redirects=True,
            extensions={"origin_restriction": first},
        )
        results.append(
            {
                "restriction": repr(first),
                "transport_calls": list(calls),
                "decisions": format_decisions(
                    first_response.extensions["origin_decisions"]
                ),
                "rejected": False,
            }
        )

        calls.clear()
        try:
            client.get(
                "https://example.org/jump",
                follow_redirects=True,
                extensions={"origin_restriction": second},
            )
        except httpx.OriginNotAllowed as exc:
            results.append(
                {
                    "restriction": repr(second),
                    "transport_calls": list(calls),
                    "decisions": format_decisions(exc.decisions),
                    "rejected": True,
                }
            )

        calls.clear()
        third_response = client.get(
            "https://disallowed.example.org/start",
            follow_redirects=True,
            extensions={"origin_restriction": second},
        )
        results.append(
            {
                "restriction": repr(second),
                "transport_calls": list(calls),
                "decisions": format_decisions(
                    third_response.extensions["origin_decisions"]
                ),
                "rejected": False,
            }
        )

    return {"name": "restriction-switch", "requests": results}


def run_unrestricted_scenario() -> dict[str, typing.Any]:
    calls: list[str] = []
    with httpx.Client(transport=build_transport(calls)) as client:
        response = client.get("https://example.org/jump", follow_redirects=True)
    return {
        "name": "no-restriction",
        "transport_calls": calls,
        "final_origin": str(httpx.Origin.from_url(response.url)),
        "has_decisions": "origin_decisions" in response.extensions,
    }


def diagnostic_text(scenarios: list[dict[str, typing.Any]]) -> str:
    """
    Collect only the diagnostic output (decisions, rejection reasons and
    restriction descriptions), excluding the transport call log which
    intentionally shows the dispatched URLs.
    """
    parts: list[str] = []
    for scenario in scenarios:
        if "requests" in scenario:
            for request in scenario["requests"]:
                parts.append(request["restriction"])
                parts.extend(request["decisions"])
        else:
            parts.append(scenario.get("restriction", ""))
            parts.extend(scenario.get("decisions", []))
            parts.append(scenario.get("error", ""))
    return "\n".join(parts)


def redaction_check(scenarios: list[dict[str, typing.Any]]) -> dict[str, bool]:
    """
    Confirm that neither queries nor credentials appear in the diagnostics.
    """
    rendered = diagnostic_text(scenarios)
    return {
        "entry_query_hidden": "entry-secret" not in rendered,
        "redirect_query_hidden": "redirect-secret" not in rendered,
        "entry_password_hidden": "entry-password" not in rendered,
        "paths_hidden": "/start" not in rendered and "/next" not in rendered,
    }


def render(report: dict[str, typing.Any]) -> str:
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("Origin restriction acceptance report")
    lines.append("=" * 72)
    for scenario in report["scenarios"]:
        lines.append("")
        lines.append(f"[{scenario['name']}]")
        if "requests" in scenario:
            for index, result in enumerate(scenario["requests"], start=1):
                lines.append(f"  request {index}: {result['restriction']}")
                lines.append(f"    transport calls ({len(result['transport_calls'])}):")
                for call in result["transport_calls"]:
                    lines.append(f"      - {call}")
                for decision in result["decisions"]:
                    lines.append(f"    decision: {decision}")
                lines.append(f"    rejected: {result['rejected']}")
            continue
        lines.append(f"  transport calls ({len(scenario['transport_calls'])}):")
        for call in scenario["transport_calls"]:
            lines.append(f"    - {call}")
        for decision in scenario.get("decisions", []):
            lines.append(f"  decision: {decision}")
        if scenario.get("rejected"):
            lines.append(f"  rejected before dispatch: {scenario['error']}")
        if "final_origin" in scenario:
            lines.append(f"  final origin: {scenario['final_origin']}")
        if "has_decisions" in scenario:
            lines.append(f"  diagnostics attached: {scenario['has_decisions']}")

    lines.append("")
    lines.append("[checks]")
    checks = report["checks"]
    for key, value in checks.items():
        lines.append(f"  {key}: {'PASS' if value else 'FAIL'}")
    lines.append("")
    lines.append("overall: " + ("PASS" if all(checks.values()) else "FAIL"))
    return "\n".join(lines)


def main() -> int:
    same_origin = run_same_origin_scenario()
    disallowed = run_disallowed_origin_scenario()
    switched = run_restriction_switch_scenario()
    unrestricted = run_unrestricted_scenario()

    checks: dict[str, bool] = {
        # Same-origin relative redirect: two transport calls.
        "same_origin_calls_two": len(same_origin["transport_calls"]) == 2,
        "same_origin_allowed": all(
            "allowed" in decision for decision in same_origin["decisions"]
        ),
        # Disallowed origin: only the first call, rejected before dispatch.
        "disallowed_calls_one": len(disallowed["transport_calls"]) == 1,
        "disallowed_rejected": disallowed["rejected"],
        "disallowed_last_decision_rejected": bool(disallowed["decisions"])
        and disallowed["decisions"][-1].endswith("rejected"),
        # Switching restrictions: the second request is judged on its own.
        "switch_second_request_not_dispatched": (
            switched["requests"][1]["transport_calls"] == []
        ),
        "switch_second_request_rejected": switched["requests"][1]["rejected"],
        "switch_third_request_allowed": (
            len(switched["requests"][2]["transport_calls"]) == 2
        ),
        # Unrestricted requests keep the previous behaviour.
        "unrestricted_follows": len(unrestricted["transport_calls"]) == 2,
        "unrestricted_no_diagnostics": not unrestricted["has_decisions"],
    }
    diagnostics = [same_origin, disallowed, switched, unrestricted]
    checks.update(redaction_check(diagnostics))

    report = {"scenarios": diagnostics, "checks": checks}
    print(render(report))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
