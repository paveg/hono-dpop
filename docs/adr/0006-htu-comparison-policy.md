# ADR-0006: htu comparison policy — strict by default, opt-in trailing-slash relaxation

## Status
Accepted

## Context
RFC 9449 §4.3 step 11 requires the proof's `htu` claim to match the request URI "ignoring any query and fragment parts". The spec is silent on other normalization concerns:

- Trailing slash: is `https://api.example.com/users` the same resource as `https://api.example.com/users/`?
- Path case: are `/Users` and `/users` the same?
- Default port elision: `https://api.example.com:443/x` vs `https://api.example.com/x`?
- Percent-encoding: `/users%2Falice` vs `/users/alice`?

In practice clients sign whatever URL they typed, and servers see whatever the framework reconstructs. The mismatch surface is real: Hono's `c.req.url` reconstructs from the WHATWG URL parser, which canonicalizes default ports and percent-encoding but preserves trailing slashes; some HTTP clients strip trailing slashes silently before signing.

We needed a default that fails closed (matching the spec literally) and an escape hatch for the most common operational pain (trailing slash mismatch) without opening every other normalization door at once.

## Decision
The middleware exposes one option:

```ts
htuComparison: "strict" | "trailing-slash-insensitive"  // default: "strict"
```

`strict` compares the URLs after stripping query and fragment via `new URL(...)` — exactly what the spec mandates and nothing else. `trailing-slash-insensitive` additionally strips a trailing `/` from non-root paths so `/api/users` and `/api/users/` compare equal. The root path `/` is preserved (`https://x/` stays `https://x/`) because `URL.toString()` always emits at least one slash and stripping it would produce a malformed URL.

We deliberately did **not** add path-case-insensitive, port-default-insensitive, or percent-decoding modes. Each opens a different vector: case-insensitive paths break case-sensitive resources (S3 keys, GitHub repos); percent-decoding lets `/users%2falice` match `/users/alice` and that is a routing decision, not a normalization decision.

## Consequences
**Positive**
- The default is RFC-literal — no operator can accidentally weaken htu binding by leaving the option unset.
- The one provided relaxation addresses ~90 % of real-world htu mismatch reports without ambiguity.
- Adding more policies later is additive: each is a new enum value with a known scope.

**Negative**
- Operators behind path-rewriting proxies still need `getRequestUrl` to reconstruct the canonical URL; this option does not help them.
- A client that signs `/x/` and a server that normalizes to `/x` will work under `trailing-slash-insensitive` but break under `strict`. The choice of mode becomes a coupling between client conventions and server config that is invisible at request time.
- The relaxation is symmetric: it would also accept `/x/` against a request `/x`, which is what we want for ergonomics but not what some strict-routing teams may expect.
