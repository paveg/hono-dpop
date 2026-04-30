# ADR-0005: Pluggable nonce provider with previous-nonce grace window

## Status
Accepted

## Context
RFC 9449 §8 lets a resource server force clients to include a server-issued `nonce` claim in their proofs, narrowing the replay window from `iatTolerance` (typically 60 s) to "one nonce, one request after challenge". The mechanism is:

1. RS responds 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a fresh `DPoP-Nonce` header.
2. Client retries the request with `nonce: <value>` in the proof claims.
3. RS validates the nonce, then optionally rotates and echoes a new one on success.

The spec does not prescribe how nonces are generated, stored, or rotated. Constraints differ wildly: a single Node process can hold nonces in a `Map`; a horizontally scaled deployment needs a shared store; Cloudflare Workers want native primitives.

We needed an interface narrow enough to fit any backend, with rotation semantics that do not race against in-flight clients.

## Decision
The interface (`src/stores/types.ts`) is two methods, deliberately mirroring `DPoPNonceStore`'s minimalism:

```ts
interface NonceProvider {
  issueNonce(c: Context): Promise<string>;
  isValid(candidate: string, c: Context): Promise<boolean>;
}
```

`issueNonce` returns the nonce to send to the client on a `use_dpop_nonce` challenge or a success-path echo. `isValid` is called with whatever the client sent (or empty string when the claim is missing) and answers whether to accept it.

The middleware:

- Calls `isValid` even when the claim is missing (with empty string), so request-handling time does not depend on whether the client supplied a nonce. This closes a small timing oracle for shared-store providers.
- Memoizes `issueNonce` per request so the error-path mint and the success-path echo share one provider RPC.
- Runs the nonce check **after** signature verification, so an unauthenticated attacker cannot flood the provider with mint requests.

The reference in-memory provider (`src/stores/memory-nonce-provider.ts`) implements **previous-nonce grace**: after rotation, the previous value remains valid for a configurable grace window (default 60 s). Without this, a client whose request was in flight at the moment of rotation would always fail the next request and need an extra round-trip.

## Consequences
**Positive**
- Backend-agnostic: a Cloudflare KV provider, a Redis provider, or a stateless HMAC-of-counter provider all fit the same shape.
- Constant-time wrt missing-vs-invalid nonce closes a timing-side-channel class without burdening the provider.
- The grace window prevents rotation from looking like an outage during normal traffic.

**Negative**
- Providers that want per-tenant or per-route nonce scopes have to encode that into the nonce string itself; the interface gives them only the Hono `Context`, not a structured scope.
- The `isValid` empty-string convention must be honored by every provider — a provider that returns `true` for `""` would silently disable the nonce challenge. This is documented but not type-enforced.
- The grace window is per-process state in the in-memory provider; horizontally scaled deployments need a shared-store provider where rotation timing is coordinated, otherwise grace windows differ across instances.
