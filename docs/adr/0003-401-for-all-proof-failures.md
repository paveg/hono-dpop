# ADR-0003: 401 for all DPoP proof failures

## Status
Accepted

## Context
A naive read of HTTP semantics would map a malformed DPoP header (parse error, missing claim) to **400 Bad Request** and a replay or `ath` mismatch to **401 Unauthorized**. The two-status approach mirrors what a generic input-validation pipeline would do.

RFC 9449 §7.1 disagrees. DPoP is an OAuth-protected-resource scheme, and the `WWW-Authenticate` framework presumes a single status — **401** — paired with an `error=` parameter that distinguishes the failure mode. Returning 400 strands the `WWW-Authenticate` header in a status code where well-behaved clients are not required to look for it, and breaks interop with OAuth client libraries that key off 401 to trigger reauthentication or nonce-challenge handling.

## Decision
Every DPoP rejection — header missing, parse failure, signature invalid, claims invalid, `jti` replay, `ath` mismatch, missing access token — returns **HTTP 401** with `WWW-Authenticate: DPoP error="<code>"`.

The `error=` parameter discriminates the failure mode per RFC 9449 §7.1:

| Failure | `error=` value | `code` (extension) |
|---|---|---|
| Header missing / parse / signature / claims | `invalid_dpop_proof` | `INVALID_DPOP_PROOF` |
| `jti` replay | `invalid_dpop_proof` | `JTI_REPLAY` |
| `Authorization: DPoP` missing under `requireAccessToken` | `invalid_token` | `MISSING_ACCESS_TOKEN` |
| `ath` claim mismatch | `invalid_token` | `ATH_MISMATCH` |

All four error constructors in `src/errors.ts` set `status: 401`. Internal code-discrimination remains available via the `code` extension on the Problem Detail body.

## Consequences
**Positive**

- OAuth-aware clients receive a status they already handle, with the `WWW-Authenticate` header where the spec says to put it.
- Uniform status simplifies reverse-proxy and WAF rules ("DPoP middleware never emits 4xx other than 401").
- Future addition of `use_dpop_nonce` challenges (RFC 9449 §8) plugs into the same 401 path.

**Negative**

- A reader of the response status alone cannot distinguish "your proof is malformed" from "your token is wrong" — they must inspect the `error=` parameter or the Problem Detail `code`. This is the OAuth convention, but it differs from generic REST intuition.
- Logging dashboards that bucket 4xx by status code see all DPoP rejections collapsed. Operators wanting per-cause breakdown should index on the `code` field.
