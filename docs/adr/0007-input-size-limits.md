# ADR-0007: Application-layer size limits for proof header and access token

## Status
Accepted

## Context
RFC 9449 places no upper bound on `DPoP` header size or on the access token paired with `Authorization: DPoP <token>`. Without a limit, the middleware does work proportional to whatever bytes arrive:

- A multi-megabyte proof body forces base64url decoding and JSON parsing for nothing.
- A multi-megabyte access token forces a `TextEncoder.encode` + `crypto.subtle.digest("SHA-256", ...)` pass during `ath` verification, even when the proof itself is well-formed.

Edge-level limits (CDN, ingress) help but are not universal: self-hosted deployments behind nginx have generous defaults; some platforms accept multi-megabyte headers in principle.

We needed defaults that do not surprise legitimate clients but bound the worst-case work per request.

## Decision
Two options, both byte-counted via `TextEncoder` so multi-byte payloads cannot bypass the cap by character-counting:

| Option | Default | Rationale |
|--------|---------|-----------|
| `maxProofSize` | **8192 bytes** | A typical DPoP proof is 400–800 bytes (EC) or 600–1200 bytes (RSA-2048). 8 KB leaves ample headroom for RSA-4096 + nonce + ath, plus future header growth, while still rejecting "decoded MB of base64" attacks. |
| `maxAccessTokenSize` | **4096 bytes** | RFC 6750 recommends bearer tokens "be kept short"; common JWT access tokens are 500–2000 bytes. 4 KB matches the typical HTTP cookie/header byte budget per platform. Opaque or encrypted tokens may need raising. |

Both checks run **before** any decode or crypto:

- `maxProofSize` runs immediately after the header presence check, before `parseProof`.
- `maxAccessTokenSize` runs immediately after `resolveAccessToken`, before `computeAth`.

This ordering is the point: an attacker sending a 10 MB header pays only the cost of one `TextEncoder.encode` length read, not a base64url decode + JSON parse.

## Consequences
**Positive**
- Bounded work per request in absolute bytes, regardless of edge configuration.
- Defaults fit measured proof sizes across all 10 supported algorithms with significant headroom.
- Failures surface as 401 with a specific detail, not as opaque OOM or timeout.

**Negative**
- Operators with intentionally large opaque tokens (encrypted JWE access tokens above 4 KB) must raise `maxAccessTokenSize` explicitly. We log the chosen limit in the rejection detail to make this discoverable.
- The defaults are conservative; raising them is per-deployment policy, but lowering them silently could break legitimate clients. Document as defaults, not floors.
- These limits do not replace edge limits. They are application-layer defense-in-depth — operators should still apply network-layer caps so traffic does not even reach the worker.
