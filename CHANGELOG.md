# hono-dpop

## 0.3.0

### Minor Changes

- [#27](https://github.com/paveg/hono-dpop/pull/27) [`e8d79e6`](https://github.com/paveg/hono-dpop/commit/e8d79e6b6d9236f7c9b06aed0905c0a40b8891da) Thanks [@paveg](https://github.com/paveg)! - Drop Node.js 20 support; require Node.js 22 or newer.

  Node.js 20 reached end-of-life on 2026-04-30. The `engines.node` field has
  been bumped from `>=20` to `>=22`, and the CI matrix no longer tests against
  Node 20. Consumers still on Node 20 will see an `EBADENGINE` warning from
  npm/pnpm on install — upgrade to Node 22 LTS or Node 24.

  Also bumps `pnpm/action-setup` in CI workflows from v4 to v6.

## 0.2.1

### Patch Changes

- [#24](https://github.com/paveg/hono-dpop/pull/24) [`2df7423`](https://github.com/paveg/hono-dpop/commit/2df74232839c46257da5ab656d3f88cd2c5c000e) Thanks [@paveg](https://github.com/paveg)! - Internal release. No user-visible behavior change — published artifacts
  (`dist/`) are byte-equivalent for the public API surface.

  Aggregates dev-only work since `0.2.0`:

  - Migrate to Biome 2 (`@biomejs/biome` 1.9 → 2.4)
  - Refresh CI action versions: `actions/checkout` v6, `actions/setup-node` v6, `codecov/codecov-action` v6
  - Refresh dev dependencies (vitest, tsup, typescript transitive ranges)
  - Sync threat model with shipped features (size limits, nonce provider, jkt-binding helpers, clock injection)
  - Add ADRs 0005-0008 documenting post-launch design decisions
  - Add boundary test pinning `htm` case-sensitivity per RFC 9110 §9.1

## 0.2.0

### Minor Changes

- [#15](https://github.com/paveg/hono-dpop/pull/15) [`cfe8941`](https://github.com/paveg/hono-dpop/commit/cfe89415720c1cae6b49a9fa95437ce8b974325d) Thanks [@paveg](https://github.com/paveg)! - Tighten JWK validation and accept the RFC 9758 `Ed25519` JWS algorithm identifier:

  - Enforce RSA modulus length in 2048-4096 bit range. Defends against DoS amplification via giant moduli (16384-bit) causing slow signature verification, and against weak keys (1024-bit and below) being accepted.
  - Use own-property check for private-field detection (`Object.hasOwnProperty.call` rather than `in`) so a polluted `Object.prototype` cannot cause spurious rejection of valid public JWKs.
  - Accept `alg: "Ed25519"` (RFC 9758 fully-specified algorithm identifier) in addition to `alg: "EdDSA"` (RFC 8037). Both use the same Ed25519 crypto; verifiers should accept both for forward compatibility with newer DPoP clients. `assertAlgMatchesJwk` now requires `kty: "OKP"` AND `crv: "Ed25519"` for both alg names (was only checking `kty`).

- [#17](https://github.com/paveg/hono-dpop/pull/17) [`771a2a3`](https://github.com/paveg/hono-dpop/commit/771a2a37ad60fa07d240c344ecd7d81fa9d7f134) Thanks [@paveg](https://github.com/paveg)! - `memoryNonceStore()` now defaults `maxSize` to 100,000 entries (was previously unbounded). This prevents OOM under unique-jti flood without an explicit `maxSize` option.

  **Migration**: callers who relied on unbounded growth must now set `memoryNonceStore({ maxSize: <very large number> })` explicitly. Most callers will not need to change anything — the default is sized for typical workloads (peak ~333 jti/sec sustained for 5 minutes).

### Patch Changes

- [#16](https://github.com/paveg/hono-dpop/pull/16) [`ff38445`](https://github.com/paveg/hono-dpop/commit/ff38445df9f1bfaa8fff592ecf65afac2db98966) Thanks [@paveg](https://github.com/paveg)! - Middleware input-boundary hardening:

  - Always call `nonceProvider.isValid` even when the proof's `nonce` claim is missing, removing a small timing oracle that distinguished "missing nonce" from "invalid nonce".
  - Validate the `algorithms` option at factory time: passing an unsupported value (e.g. via a TypeScript escape hatch) now throws synchronously instead of silently being ignored at request time.

- [#14](https://github.com/paveg/hono-dpop/pull/14) [`e1a6fcc`](https://github.com/paveg/hono-dpop/commit/e1a6fcc9dc9e9add4fe867e4de2cb599c9558a7f) Thanks [@paveg](https://github.com/paveg)! - Add boundary tests asserting that `parseProof` tolerates extra JWS header fields (such as `kid`, `x5c`, `cty`) alongside the required `typ` / `alg` / `jwk`. No behavior change — these tests pin the existing tolerance as a contract so future tightening is a deliberate decision.

## 0.1.0

### Minor Changes

- [`2b694a4`](https://github.com/paveg/hono-dpop/commit/2b694a42caf844d80e94a443a9d1dc6730b3637f) Thanks [@paveg](https://github.com/paveg)! - Initial release.

  DPoP (RFC 9449) proof-of-possession middleware for Hono. Validates the
  DPoP proof JWT (signature, htm/htu/iat, jti replay), supports
  server-issued nonces (RFC 9449 §8), optional ath binding to bearer
  access tokens, and cnf.jkt thumbprint verification. Web Crypto only —
  no jose, no native deps. Runs on Node.js ≥20, Cloudflare Workers,
  Deno, Bun.

  Algorithms: ES256/384/512, RS256/384/512, PS256/384/512, EdDSA.
  `none` and HS\* rejected.

  Store backends: memory (in-process), Redis (BYO client), Cloudflare KV,
  Cloudflare D1, Durable Objects.

  RFC 9457 Problem Details errors with optional auto-detection of
  hono-problem-details. Pluggable: nonceStore, nonceProvider, algorithms,
  iatTolerance, jtiTtl, getRequestUrl, getAccessToken, requireAccessToken,
  maxProofSize, maxAccessTokenSize, clock, htuComparison, allowFutureIat,
  onError.
