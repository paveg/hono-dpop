# ADR-0002: RFC 9457 Problem Details for errors

## Status
Accepted

## Context
DPoP rejections need to convey three things to a client:

1. A machine-readable code (so a client library can map to a typed error).
2. A human-readable message (so an operator can debug from logs).
3. The RFC 9449 §7.1 `WWW-Authenticate: DPoP error="..."` header (so OAuth-aware clients react correctly).

The Hono ecosystem already has a Problem Details middleware (`hono-problem-details`) that handles content-type negotiation, schema, and serialization for RFC 9457. Forcing every consumer to install it would be heavy for the simple case; bundling it would couple this package to a transitive choice.

## Decision
Errors are modeled as `ProblemDetail` objects (`src/errors.ts`) carrying `type`, `title`, `status`, `detail`, an internal `code`, and a `wwwAuthError` for the `WWW-Authenticate` header.

`hono-problem-details` is declared as an **optional peer dependency**. At response time, `src/compat.ts` lazy-imports it once and caches the result:

```ts
try {
  cached = await import("hono-problem-details");
} catch {
  cached = null;
}
```

If present, the response is built via `problemDetails().getResponse()` and then the `WWW-Authenticate` header is set on the result. If absent, `problemResponse()` falls back to a hand-rolled `Response` with `Content-Type: application/problem+json; charset=utf-8` and the same header. Either path yields a spec-compliant response — the difference is whether the consumer's existing Problem Details infrastructure (e.g., logging, content negotiation) participates.

## Consequences
**Positive**

- Errors are spec-compliant out of the box with no required peer install.
- Consumers already using `hono-problem-details` get a uniform pipeline automatically — no `onError` plumbing required.
- The lazy-import pattern means non-users never pay the bundle cost on edge runtimes.

**Negative**

- Two response code paths must be kept in sync. Tests cover both.
- Detection is by dynamic `import()`, which a few bundlers handle awkwardly. Mitigated by the try/catch and by the fact that the fallback is the more common path.
- Callers wanting fully custom error shapes still need to pass `onError` — Problem Details is the default but not a lock-in.
