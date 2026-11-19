# Redirect origin restriction: acceptance report

This report is the reproduction sheet for the redirect origin guard. It lists
the calls the mock transport received, the origin decision for each hop, and
whether the destination was followed or rejected. Everything here is produced
offline by `examples/origin_restriction/origin_restriction_check.py` and
asserted by `tests/client/test_origin_restriction.py`; no name resolution,
sockets or external services are involved.

## Summary

The client already resolves a redirect destination in `_redirect_url()`: an
absolute `Location` is used as-is, a scheme-only location inherits the host, and
a relative location is joined against the current request. The guard reuses that
resolved URL rather than parsing `Location` a second time, and compares origins
on **scheme, host and effective port** only.

A caller supplies the restriction per request through the `"origin_restriction"`
request extension. The guard reads it from the request each time, so no
restriction, resolution result or decision is cached on the client. Requests
without the extension take the previous redirect and error path unchanged.

The decision for a redirect is taken immediately after `_build_redirect_request`
returns — that is, **before** the next hop is dispatched — so a rejected
destination never reaches the transport. This holds for both `follow_redirects`
values: an allowed `next_request` is still returned when redirects are not
followed, and a rejected destination raises before `next_request` is set.

| Hop | Where the decision is taken | Transport reached? |
| --- | --- | --- |
| Initial request | `_send_handling_redirects`, before the first dispatch | Only if allowed |
| Redirect destination | After `_build_redirect_request`, before the next dispatch | Only if allowed |

## Reproduction 1 — same-origin relative redirect

Request: `https://svc:entry-password@example.org/start?session=entry-secret&step=1`
Restriction: `OriginRestriction([https://example.org])`

| seq | transport call | note |
| --- | --- | --- |
| 1 | `https://svc:entry-password@example.org/start?session=entry-secret&step=1` | initial request |
| 2 | `https://svc:entry-password@example.org/next?ticket=redirect-secret&step=2` | relative `Location: /next?...` resolved against the current request |

Decision records:

| seq | entry origin | target origin | result |
| --- | --- | --- | --- |
| 1 | `https://example.org` | `https://example.org` | allowed |
| 2 | `https://example.org` | `https://example.org` | allowed |

**Two transport calls**, as required.

## Reproduction 2 — destination outside the allow-list

Request: `https://example.org/jump?session=entry-secret&step=1`
Redirect: `Location: https://disallowed.example.org/target?ticket=redirect-secret&step=2`
Restriction: `OriginRestriction([https://example.org])`

| seq | transport call | note |
| --- | --- | --- |
| 1 | `https://example.org/jump?session=entry-secret&step=1` | initial request |

Decision records:

| seq | entry origin | target origin | result |
| --- | --- | --- | --- |
| 1 | `https://example.org` | `https://example.org` | allowed |
| 2 | `https://example.org` | `https://disallowed.example.org` | **rejected** |

Raised: `httpx.OriginNotAllowed: Origin not allowed: https://disallowed.example.org.`

**One transport call.** The rejection was recorded while preparing the second
hop; the disallowed request was never handed to the transport.

## Reproduction 3 — switching restrictions on one client

The same `Client` handles three requests in sequence, with two restrictions.

| request | restriction | transport calls | decisions | outcome |
| --- | --- | --- | --- | --- |
| 1 | `OriginRestriction([https://example.org])` | 2 | `example.org`→`example.org` allowed, `example.org`→`example.org` allowed | followed |
| 2 | `OriginRestriction([https://disallowed.example.org])` | **0** | `example.org`→`example.org` rejected | `OriginNotAllowed` |
| 3 | `OriginRestriction([https://disallowed.example.org])` | 2 | `disallowed.example.org`→`disallowed.example.org` allowed | followed |

Request 2 is the important one: had it reused request 1's restriction, its
initial `https://example.org/jump` request would have been dispatched and the
redirect to `disallowed.example.org` rejected only afterwards. Instead it was
rejected at the initial origin with zero transport calls, which shows the
second request was judged solely by its own restriction.

## Reproduction 4 — no restriction

Request: `https://example.org/jump` with `follow_redirects=True` and no
`"origin_restriction"` extension.

| seq | transport call |
| --- | --- |
| 1 | `https://example.org/jump` |
| 2 | `https://disallowed.example.org/target?ticket=redirect-secret&step=2` |

No `"origin_decisions"` extension is attached to the response or history. The
redirect is followed and errors propagate exactly as before.

## Redaction

Diagnostics carry only `Origin(scheme, host, port)`. The acceptance harness
assembles everything the diagnostics expose — decision strings, the rejection
message, and the `OriginRestriction` description — and confirms the following
are absent:

| value present in the test URLs | present in diagnostics? |
| --- | --- |
| `session=entry-secret` (initial request query) | no |
| `ticket=redirect-secret` (redirect query) | no |
| `entry-password` (request credentials) | no |
| `/start`, `/next` (paths) | no |

The transport call log, which is the evidence of *what was dispatched*, does
contain the full URLs; the guard's own records never do.

## Port and scheme comparison

| Allowed origin | Requested URL | Result |
| --- | --- | --- |
| `https://example.org` | `https://example.org:443/` | allowed (default port normalised) |
| `https://example.org:8443` | `https://example.org/` | rejected (effective port 443 ≠ 8443) |
| `https://example.org:8443` | `http://example.org:8443/` | rejected (scheme differs) |

## Running it

```console
$ python examples/origin_restriction/origin_restriction_check.py
...
[checks]
  same_origin_calls_two: PASS
  disallowed_calls_one: PASS
  ...
  entry_query_hidden: PASS
  redirect_query_hidden: PASS
  entry_password_hidden: PASS
  paths_hidden: PASS

overall: PASS
```

The regression suite is `tests/client/test_origin_restriction.py`
(36 cases, covering sync and async clients, allowed and rejected redirects, the
initial request, restriction switching, port/scheme comparison, requests built
with `build_request()`, streaming, unaffected default handling, and redaction).
