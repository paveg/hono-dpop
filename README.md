# hono-dpop

[![npm version](https://img.shields.io/npm/v/hono-dpop)](https://www.npmjs.com/package/hono-dpop)
[![CI](https://github.com/paveg/hono-dpop/actions/workflows/ci.yml/badge.svg)](https://github.com/paveg/hono-dpop/actions/workflows/ci.yml)
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
});
```

## Errors

All errors follow [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457) and include the [RFC 9449 §7.1](https://www.rfc-editor.org/rfc/rfc9449#section-7.1) `WWW-Authenticate: DPoP error="..."` header.

| Status | Code | `error=` | When |
|--------|------|----------|------|
| 400 | `INVALID_DPOP_PROOF` | `invalid_dpop_proof` | Header missing/malformed, signature invalid, claims invalid (htm, htu, iat, typ, alg, jwk) |
| 401 | `MISSING_ACCESS_TOKEN` | `invalid_token` | `requireAccessToken: true` and `Authorization: DPoP` missing |
| 401 | `ATH_MISMATCH` | `invalid_token` | `ath` claim does not match SHA-256 of access token |
| 401 | `JTI_REPLAY` | `invalid_dpop_proof` | `jti` already used within `jtiTtl` window |

When [hono-problem-details](https://github.com/paveg/hono-problem-details) is installed, error responses are generated using its `problemDetails().getResponse()`. Otherwise, a built-in fallback is used. No configuration needed — detection is automatic.

## Stores

### Memory Store

Built-in, suitable for single-instance deployments and development.

```ts
import { memoryNonceStore } from "hono-dpop/stores/memory";

const nonceStore = memoryNonceStore({
  ttl: 5 * 60_000, // milliseconds (default: 5 minutes)
  maxSize: 10_000, // optional FIFO bound
});
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

- It does **not** introspect or validate the access token. Use a separate middleware (e.g., your bearer/JWT verifier) to validate the access token, then compare the access token's `cnf.jkt` claim against `c.get("dpop").jkt` to enforce DPoP binding.
- It does **not** issue server nonces (`use_dpop_nonce`). This may be added in a future release; for now the middleware accepts requests without a nonce challenge round-trip.
- It does **not** verify multi-segment proxies. Use `getRequestUrl` to provide the canonical external URL when behind a reverse proxy.

## License

MIT
