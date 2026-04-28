# hono-dpop

[![npm version](https://img.shields.io/npm/v/hono-dpop)](https://www.npmjs.com/package/hono-dpop)
[![CI](https://github.com/paveg/hono-dpop/actions/workflows/ci.yml/badge.svg)](https://github.com/paveg/hono-dpop/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/paveg/hono-dpop/graph/badge.svg)](https://codecov.io/gh/paveg/hono-dpop)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) proof-of-possession middleware for [Hono](https://hono.dev).

Validates the `DPoP` header on incoming requests: signature, `htm`/`htu`/`iat`, `jti` replay protection, and (optional) `ath` binding to a bearer access token. Pluggable replay-cache store. RFC 9457 Problem Details errors with RFC 9449 `WWW-Authenticate` semantics.

## Features

- Verifies the DPoP proof JWT (signature against the embedded JWK)
- Validates `htm` / `htu` / `iat` per RFC 9449 §4.3
- `jti` replay protection via pluggable store
- Optional `Authorization: DPoP <token>` extraction with `ath` claim verification
- Exposes `c.get("dpop")` containing `{ jkt, jti, jwk, htm, htu, iat, ath?, raw }`
- RFC 9457 Problem Details error responses with RFC 9449 `WWW-Authenticate: DPoP error="..."`
- Algorithms: ES256/384/512, RS256/384/512, PS256/384/512, EdDSA. `none` and `HS*` rejected.
- Web Crypto only — works on Node.js ≥20, Cloudflare Workers, Deno, Bun

## Install

```bash
npm  install hono-dpop
pnpm add     hono-dpop
yarn add     hono-dpop
bun  add     hono-dpop
```

Works on Node.js ≥20, Cloudflare Workers, Deno, and Bun. Pure Web Crypto — no native bindings, no platform-specific dependencies, runs unchanged on x64 / arm64 / Linux / macOS / Windows.

## Quick Start

```ts
import { Hono } from "hono";
import { dpop } from "hono-dpop";
import { memoryNonceStore } from "hono-dpop/stores/memory";

const app = new Hono();

app.use("/api/*", dpop({ nonceStore: memoryNonceStore() }));

app.get("/api/me", (c) => {
  const proof = c.get("dpop");
  // proof.jkt is the SHA-256 JWK thumbprint of the client's public key.
  // Compare against your access token's `cnf.jkt` claim to enforce binding.
  return c.json({ subject: "user-123", boundKeyThumbprint: proof?.jkt });
});
```

## Options

```ts
dpop({
  // Required: replay cache for jti
  nonceStore: memoryNonceStore(),

  // Allowed algorithms (default: all supported asymmetric)
  algorithms: ["ES256", "ES384", "EdDSA"],

  // Max clock skew on iat in seconds (default: 60)
  iatTolerance: 60,

  // How long a jti is remembered in milliseconds (default: 5 minutes)
  jtiTtl: 5 * 60_000,

  // Override request URL extraction for reverse-proxy scenarios
  // Default: c.req.url, with query/fragment stripped
  getRequestUrl: (c) => `https://api.example.com${c.req.path}`,

  // Override access-token extraction
  // Default: parses `Authorization: DPoP <token>`
  getAccessToken: (c) => c.req.header("X-Access-Token"),

  // Reject when access token is missing (default: false)
  requireAccessToken: true,

  // Custom error response (default: RFC 9457 Problem Details)
  onError: (error, c) => c.json({ error: error.code }, error.status),

  // Server-issued nonce challenge (RFC 9449 §8). When set, proofs missing or
  // with an invalid `nonce` claim are rejected with `error="use_dpop_nonce"`
  // and a fresh nonce in the `DPoP-Nonce` response header. Successful
  // responses also echo the current nonce.
  nonceProvider: memoryNonceProvider({ rotateAfter: 5 * 60_000 }),

  // DoS shield — reject inputs above these sizes before any decode work.
  maxProofSize: 8192,        // bytes (default: 8192)
  maxAccessTokenSize: 4096,  // bytes (default: 4096)

  // Inject a clock for tests / clock-skew compensation. Returns ms epoch.
  clock: () => Date.now(),

  // htu comparison policy. "strict" (default) requires exact equality after
  // URL normalization. "trailing-slash-insensitive" strips a trailing `/`
  // from non-root paths before comparison.
  htuComparison: "strict",

  // Allow proofs whose `iat` is in the future (default: false). When true,
  // only past staleness is rejected: `iat < now - iatTolerance`.
  allowFutureIat: false,
});
```

### Helpers

```ts
import { assertJktBinding, verifyJktBinding } from "hono-dpop";

// Throwing variant — pipes through the standard 401 + WWW-Authenticate path:
app.get("/api/me", (c) => {
  const proof = c.get("dpop")!;
  const claims = await verifyMyAccessToken(c.req.header("Authorization"));
  assertJktBinding(claims, proof.jkt); // throws DPoPProofError on mismatch
  return c.json({ ok: true });
});

// Boolean variant for explicit branching:
if (!verifyJktBinding(claims, proof.jkt)) {
  return c.text("binding failed", 401);
}
```

## Errors

All errors follow [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457) and include the [RFC 9449 §7.1](https://www.rfc-editor.org/rfc/rfc9449#section-7.1) `WWW-Authenticate: DPoP error="..."` header.

| Status | Code | `error=` | When |
|--------|------|----------|------|
| 401 | `INVALID_DPOP_PROOF` | `invalid_dpop_proof` | Header missing/malformed, signature invalid, claims invalid (htm, htu, iat, typ, alg, jwk), oversized proof or token, multiple `DPoP` headers |
| 401 | `MISSING_ACCESS_TOKEN` | `invalid_token` | `requireAccessToken: true` and `Authorization: DPoP` missing |
| 401 | `ATH_MISMATCH` | `invalid_token` | `ath` claim does not match SHA-256 of access token |
| 401 | `JTI_REPLAY` | `invalid_dpop_proof` | `jti` already used within `jtiTtl` window |
| 401 | `USE_NONCE` | `use_dpop_nonce` | `nonceProvider` is set and proof has no current `nonce` claim. Response carries a fresh `DPoP-Nonce` header and `nonce="..."` parameter on `WWW-Authenticate`. |

Every 401 also carries an `algs="<space-separated>"` parameter on `WWW-Authenticate` so clients can discover supported algorithms without trial-and-error (RFC 9449 §7.1).

When [hono-problem-details](https://github.com/paveg/hono-problem-details) is installed, error responses are generated using its `problemDetails().getResponse()`. Otherwise, a built-in fallback is used. No configuration needed — detection is automatic.

## Stores

The replay-cache `nonceStore` enforces RFC 9449 §11.1 — each `jti` is accepted at most once within its freshness window. Pick the backend that matches your runtime and consistency needs.

### Choosing a Store

| Store | Consistency | Durability | Atomic insert-if-absent | Native TTL | Setup | Best for |
|-------|-------------|------------|-------------------------|------------|-------|----------|
| `memory`            | strong (per process) | none (in-RAM) | yes (JS single thread) | manual sweep   | none                    | dev, tests, single-instance |
| `redis`             | strong               | yes           | yes (`SET NX EX`)      | yes (`EX`)     | provision Redis client  | multi-instance servers, Workers (Upstash) |
| `cloudflare-kv`     | eventual             | yes           | best-effort            | yes            | bind a KV namespace     | Workers when DO/D1 are overkill; tolerates rare replays |
| `cloudflare-d1`     | strong (single primary) | yes        | yes (`INSERT OR IGNORE`) | manual `purge()` | bind a D1 database    | Workers wanting strict atomicity without a DO |
| `durable-objects`   | strong (single writer) | yes         | yes (single-writer)    | manual `purge()` | DO class storage       | Workers needing per-tenant isolation + strict consistency |

### Memory Store

Built-in, suitable for single-instance deployments and development.

```ts
import { memoryNonceStore } from "hono-dpop/stores/memory";

const nonceStore = memoryNonceStore({
  ttl: 5 * 60_000, // milliseconds (default: 5 minutes)
  maxSize: 10_000, // optional FIFO bound
});
```

### Redis Store

Bring your own client (ioredis, node-redis, or @upstash/redis). Uses `SET key 1 NX EX <ttl>` for an atomic insert-if-absent in a single round-trip.

```ts
import Redis from "ioredis";
import { redisStore } from "hono-dpop/stores/redis";

const nonceStore = redisStore({
  client: new Redis(process.env.REDIS_URL!),
  ttl: 300,           // seconds, default 300
  keyPrefix: "dpop:jti:",
});
```

### Cloudflare KV Store

Works on Workers. KV is eventually consistent across edge POPs, so two requests can rarely both observe a jti as absent and both succeed — RFC 9449 explicitly tolerates best-effort enforcement here.

```ts
import { kvStore } from "hono-dpop/stores/cloudflare-kv";

// inside a Workers fetch handler with a KV binding `NONCE_KV`
const nonceStore = kvStore({ namespace: env.NONCE_KV });
```

### Cloudflare D1 Store

SQLite-backed strong consistency on Workers. Auto-creates the table on first use; call `purge()` from a scheduled handler to reclaim expired rows.

```ts
import { d1Store } from "hono-dpop/stores/cloudflare-d1";

// inside a Workers fetch handler with a D1 binding `DB`
const nonceStore = d1Store({ database: env.DB });
// optional: scheduled() { await nonceStore.purge(); }
```

### Durable Objects Store

Per-object single-writer guarantee → atomic without explicit locks. Ideal for per-tenant or per-key isolation.

```ts
import { durableObjectStore } from "hono-dpop/stores/durable-objects";

// inside a Durable Object class
const nonceStore = durableObjectStore({ storage: this.ctx.storage });
```

### Custom Store

```ts
import type { DPoPNonceStore } from "hono-dpop";

const customStore: DPoPNonceStore = {
  // Atomically: returns true if jti was NOT seen, false if already seen.
  async check(jti, expiresAt) { /* ... */ },
  async purge() { /* return number of removed entries */ },
};
```

### Nonce Provider (RFC 9449 §8)

Optional. When set, the middleware emits `use_dpop_nonce` challenges and validates the `nonce` claim on subsequent proofs.

```ts
import { dpop, memoryNonceProvider } from "hono-dpop";

app.use("/api/*", dpop({
  nonceStore: memoryNonceStore(),
  nonceProvider: memoryNonceProvider({
    rotateAfter: 5 * 60_000, // ms (default: 5 min)
    retainPrevious: true,    // accept the previous nonce too (default: true)
  }),
}));
```

For multi-instance deployments, implement `NonceProvider` against a shared store:

```ts
import type { NonceProvider } from "hono-dpop";

const customProvider: NonceProvider = {
  async issueNonce(c) { /* return a fresh nonce string */ },
  async isValid(nonce, c) { /* return true for currently/recently valid nonces */ },
};
```

## Benchmarks

```bash
pnpm vitest bench
```

Representative numbers from a recent run (Apple M-series, Node 24):

```
parseProof                       ~370,000 ops/sec
jwkThumbprint ES256              ~130,000 ops/sec
verifyProofSignature RS256       ~ 22,000 ops/sec
verifyProofSignature ES256       ~ 12,000 ops/sec
verifyProofSignature ES512       ~  1,100 ops/sec
memoryNonceStore.check (10k)   ~1,800,000 ops/sec
```

The store is a Map lookup, so its throughput is independent of population. Verification cost is dominated by the curve / modulus.

## Accessing the Verified Proof in Handlers

```ts
import type { DPoPEnv } from "hono-dpop";
import { Hono } from "hono";

const app = new Hono<DPoPEnv>();

app.get("/api/me", (c) => {
  const proof = c.get("dpop");
  if (!proof) return c.text("no proof", 401);
  return c.json({
    jkt: proof.jkt, // SHA-256 JWK thumbprint (RFC 7638), base64url
    jti: proof.jti,
    htm: proof.htm,
    htu: proof.htu,
    iat: proof.iat,
    ath: proof.ath,
  });
});
```

## What this middleware does NOT do

- It does **not** introspect or validate the access token. Use a separate middleware (e.g., your bearer/JWT verifier) to validate the access token, then call `assertJktBinding(claims, c.get("dpop")!.jkt)` to enforce DPoP binding.
- It does **not** verify multi-segment proxies. Use `getRequestUrl` to provide the canonical external URL when behind a reverse proxy.

## Documentation

- [ADR-0001: No jose dependency](./docs/adr/0001-no-jose-dependency.md)
- [ADR-0002: RFC 9457 Problem Details](./docs/adr/0002-rfc-9457-problem-details.md)
- [ADR-0003: 401 for all proof failures](./docs/adr/0003-401-for-all-proof-failures.md)
- [ADR-0004: jti replay via pluggable store](./docs/adr/0004-jti-replay-via-pluggable-store.md)
- [Threat model](./docs/security/threat-model.md)

## License

MIT
