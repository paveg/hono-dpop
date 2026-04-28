# CLAUDE.md

## Project

DPoP (Demonstrating Proof-of-Possession, [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) middleware for Hono. Resource-server side proof verification with pluggable replay-cache stores.

## Commands

- `pnpm test` — Run tests (vitest)
- `pnpm build` — Build ESM + CJS (tsup)
- `pnpm lint` — Check linting (biome)
- `pnpm lint:fix` — Auto-fix lint issues
- `pnpm format` — Format code
- `pnpm typecheck` — Type check (tsc --noEmit)
- `pnpm release` — Build + changeset publish

## Architecture

- `src/middleware.ts` — `dpop()` factory: header extraction, parse, signature/claims verification, jti replay check, optional access-token (`ath`) binding
- `src/verify.ts` — Pure proof verification: `parseProof`, `verifyProofSignature`, `verifyProofClaims`, `computeAth`
- `src/jwk.ts` — JWK validation, RFC 7638 thumbprint, WebCrypto algorithm mapping
- `src/base64url.ts` — `base64urlEncode` / `base64urlDecode` (no-pad)
- `src/errors.ts` — RFC 9457 Problem Details with `DPoPErrorCode` and RFC 9449 `WWW-Authenticate: DPoP error="..."` headers
- `src/stores/types.ts` — `DPoPNonceStore` interface (`check`, `purge`)
- `src/stores/memory.ts` — In-process replay cache with TTL sweep
- `src/types.ts` — `DPoPOptions`, `DPoPProof`, `DPoPEnv`, `DPoPVerifiedProof`

### Algorithms

ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA. `none`, `HS*` always rejected.

### Middleware options

| Option | Type | Description |
|--------|------|-------------|
| `nonceStore` | `DPoPNonceStore` | Required. Replay cache for `jti` |
| `getAccessToken` | `(c: Context) => string \| undefined \| Promise<...>` | Override for `Authorization: DPoP <token>` extraction |
| `iatTolerance` | `number` (seconds) | Freshness window for `iat` (default: `60`) |
| `jtiTtl` | `number` (ms) | How long a `jti` is remembered (default: `300000` = 5 min) |
| `algorithms` | `string[]` | Allowed `alg` values (default: all supported asymmetric) |
| `getRequestUrl` | `(c: Context) => string` | Override for reverse-proxy scenarios; default uses `c.req.url` |
| `requireAccessToken` | `boolean` | Reject when `Authorization: DPoP` missing (default: `false`) |
| `onError` | `(error: ProblemDetail, c: Context) => Response \| Promise<Response>` | Custom error response |

## Conventions

- Package manager: pnpm (not npm)
- Formatter/linter: Biome (tabs, double quotes, semicolons always, line width 100)
- Pre-commit hook: lefthook runs `biome check` on staged files
- Tests: vitest with v8 coverage (100% target excluding barrels and type-only files)
- TDD: write tests first, then implementation
- Error responses: RFC 9457 `application/problem+json` + RFC 9449 `WWW-Authenticate: DPoP` semantics
- Versioning: changesets (`pnpm changeset`)
- GitHub comments and code comments in English

## Decisions

- [ADR-0001: No jose dependency](./docs/adr/0001-no-jose-dependency.md) — Web Crypto only
- [ADR-0002: RFC 9457 Problem Details](./docs/adr/0002-rfc-9457-problem-details.md) — error format + optional hono-problem-details integration
- [ADR-0003: 401 for all proof failures](./docs/adr/0003-401-for-all-proof-failures.md) — RFC 9449 §7.1 convention
- [ADR-0004: jti replay via pluggable store](./docs/adr/0004-jti-replay-via-pluggable-store.md) — single-method `check(jti, expiresAt)` interface
- [Threat model](./docs/security/threat-model.md) — what we defend, what's left to the caller
