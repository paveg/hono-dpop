# DPoP Threat Model

This document enumerates the attacks that DPoP and `hono-dpop` are designed to resist, what the spec defends against, what this middleware actually enforces, and what remains the caller's job. It is organized by attacker goal so a reviewer can map a CVE-class attack to the corresponding code path.

The middleware is a **resource-server-side** DPoP verifier (RFC 9449). It does not issue access tokens, does not introspect them, and does not implement the authorization-server flows (`dpop_jkt` request parameter, server-issued nonces, etc.). Those concerns are out of scope and are listed in "Limitations / known gaps" below.

## Threat matrix

| # | Attacker goal | Spec defense | Our enforcement | Caller's job |
|---|---|---|---|---|
| 1 | Replay a captured DPoP proof on a second request | `jti` uniqueness window (RFC 9449 §11.1) | `nonceStore.check(jti, expiresAt)` in `src/middleware.ts`; atomicity required by interface | Choose a store with the durability and concurrency profile your topology needs |
| 2 | Use a stolen access token from a different client (no key) | DPoP binding via `cnf.jkt` (RFC 9449 §6) | Expose verified `jkt` on `c.get("dpop")` | Compare `proof.jkt` against the access token's `cnf.jkt` claim |
| 3 | Algorithm confusion (claim `ES256`, supply RSA jwk) | `typ`, `alg`, and `jwk` validation (RFC 9449 §4.2) | `assertAlgMatchesJwk` in `src/jwk.ts`; `typ === "dpop+jwt"` check in `parseProof` | — |
| 4 | Forge a proof using an attacker-chosen jwk in the header | Signature MUST verify against the embedded jwk | `verifyProofSignature` in `src/verify.ts`; the jwk that signs the proof is the jwk whose thumbprint becomes `jkt` | — |
| 5 | Submit a weak / symmetric / `none` algorithm | Reject anything outside the asymmetric whitelist | `SUPPORTED_ALGORITHMS` in `src/jwk.ts` lists only asymmetric algs; `parseProof` rejects unknown `alg` | — |
| 6 | Tamper with `htu` or `htm` to redirect a captured proof | `htu`/`htm` claims must match the request | `verifyProofClaims` compares against `c.req.method` and `c.req.url` | Provide an external URL via `getRequestUrl` if behind a reverse proxy that rewrites the URL |
| 7 | Replay a stale proof signed long ago | `iat` freshness window | `iatTolerance` (default 60 s) in `verifyProofClaims` | Tune for the tightest tolerance your clients can sustain |
| 8 | Bind a proof to one access token, present another | `ath` claim = SHA-256(access token) | `computeAth` + `timingSafeEqual` in `src/middleware.ts` when an access token is presented | Decide whether `requireAccessToken: true` is appropriate for the route |
| 9 | Smuggle a private key in the proof header | Proof must carry only the public jwk | `assertPublicJwk` rejects any of `d, p, q, dp, dq, qi, oth, k` | — |
| 10 | DoS via huge `DPoP` header or access token | — (gap) | `maxProofSize` (default 8192) + `maxAccessTokenSize` (default 4096) bound input before any decode | Tune the limits if your tokens are larger than 4 KB |
| 11 | MitM token / proof capture in transit | TLS | Out of scope | Use TLS 1.3 |
| 12 | Replay window wider than necessary | RFC 9449 §8 server-issued nonce | `nonceProvider` option emits `use_dpop_nonce` 401 + fresh `DPoP-Nonce` header on missing/invalid nonce; success path echoes the nonce | Provide a shared-store provider (Redis/KV) when running multi-instance |

The numbered rows below expand on each goal.

## Verification stages and what each rejects

Before the threat-by-threat sections, here is the full pipeline as it appears in `src/middleware.ts`, with the kinds of attacks each stage closes:

| Stage | Source | Rejects |
|---|---|---|
| Header presence | `c.req.header("DPoP")` | absent header |
| Header size guard | `maxProofSize` (default 8192 bytes) | proof header exceeding the byte cap, before any decode |
| Multi-header guard | `proofHeader.includes(", ")` | multiple `DPoP` headers (RFC 9449 §4.3 step 1) — Headers API joins with `", "`, which is a positive smuggling signal since proofs are base64url and contain no commas |
| Access-token resolution + size guard | `resolveAccessToken` + `maxAccessTokenSize` (default 4096) | oversized `Authorization: DPoP <token>` value, before `ath` SHA-256 work |
| `parseProof` — JWT shape | `src/verify.ts` | non-three-segment input, non-JSON header/payload, non-object header/payload |
| `parseProof` — `typ` | same | anything other than `"dpop+jwt"` |
| `parseProof` — `alg` | same | non-string, unknown, not in caller's allowlist |
| `parseProof` — `jwk` | `assertPublicJwk` in `src/jwk.ts` | missing jwk, wrong kty, missing required public params, **any private field (`d`/`p`/`q`/`dp`/`dq`/`qi`/`oth`/`k`)** |
| `parseProof` — alg/jwk match | `assertAlgMatchesJwk` in `src/jwk.ts` | EC alg + non-EC jwk, EC alg + wrong curve, RSA alg + non-RSA jwk, EdDSA + non-OKP |
| `parseProof` — claim shapes | `src/verify.ts` | missing `jti`, non-string `htm`/`htu`, non-integer or out-of-bounds `iat` (`MAX_IAT = 1e10`), non-string `ath`/`nonce` (when present) |
| `parseProof` — sig shape | `base64urlDecode(encSig)` | malformed base64url (early-fail before crypto) |
| `verifyProofClaims` — `htm` | `src/verify.ts` | proof's `htm` ≠ request method (case-sensitive per RFC 9110 §9.1) |
| `verifyProofClaims` — `htu` | `normalizeHtu` | unparseable URL on either side, mismatch after stripping query/fragment (with optional trailing-slash relaxation) |
| `verifyProofClaims` — `iat` | freshness check | `now - iat > iatTolerance`, or `iat - now > iatTolerance` unless `allowFutureIat: true` |
| `verifyProofSignature` | `crypto.subtle.verify` | signature does not verify against the embedded jwk |
| Nonce challenge (when `nonceProvider` set) | `nonceProvider.isValid` | missing or invalid `nonce` claim — emits `use_dpop_nonce` 401 with a fresh `DPoP-Nonce` header. Constant-time wrt missing-vs-invalid |
| Access-token presence | `requireAccessToken` | option set and `Authorization: DPoP` missing |
| `ath` matching | `computeAth` + `timingSafeEqual` | access token presented but proof has no `ath`, or `ath` does not match `SHA-256(token)` |
| `nonceStore.check` | `src/middleware.ts` | `jti` already recorded within its expiry |

Every one of these returns 401 with `WWW-Authenticate: DPoP error="..."`. See ADR-0003 for why 401 and not 400.

## 1. Replay of a captured proof

A `DPoP` header is a bearer credential for the duration of one request. A network observer or a malicious downstream service that captures it should not be able to repeat the request.

**Defense.** The proof carries a `jti`. The middleware computes `expiresAt = iat * 1000 + jtiTtl` and calls `nonceStore.check(jti, expiresAt)`. The store contract (`src/stores/types.ts`) is **atomic test-and-set**: exactly one concurrent caller may observe `true` for a given `jti`.

**Enforcement.** `src/middleware.ts` runs the store check after — and only after — signature, claims, and (if applicable) `ath` verification have all passed. The relevant ordering, taken from the source:

```
parseProof         ─►  reject malformed / wrong typ / wrong alg
verifyProofClaims  ─►  reject wrong htm / htu / iat
verifyProofSignature ─► reject signature mismatch
resolveAccessToken ─► extract Authorization: DPoP <token>
ath comparison     ─►  reject ath mismatch
nonceStore.check   ─►  finally — record this jti
```

This ordering means a rejected proof never poisons the cache, so an attacker cannot exhaust `jti` capacity with junk proofs. It also means that a network attacker observing failure latencies cannot infer which step failed beyond what the response code already reveals.

**Caller's job.** Replay protection is only as strong as the store. The built-in `memoryNonceStore` is process-local — fine for single-instance development, broken under horizontal scaling. Multi-instance deployments require a shared store (Redis with `SET NX PX`, Cloudflare KV with conditional put, a Durable Object, etc.). Implementers must verify their backend honors the atomicity clause; a naive `get`-then-`set` will pass single-thread tests and fail under concurrency.

**Memory-store specific note.** `src/stores/memory.ts` enforces an optional `maxSize` via FIFO eviction of the oldest entry. Under sustained load above `maxSize / jtiTtl` proofs per second, an attacker who can predict (or wait for) the eviction of a specific `jti` regains the ability to replay it. Pick `maxSize` generously, or use a backing store with native expiration (Redis with PX, Cloudflare KV with `expirationTtl`).

## 2. Stolen access token without the matching key

The whole point of DPoP is to make access tokens unusable on their own. An attacker who lifts a token from a log, a browser cache, or a referer header should be unable to call the API.

**Defense.** RFC 9449 §6 binds the access token to a key by including the key's thumbprint in `cnf.jkt`. The same key signs every DPoP proof.

**Enforcement.** This middleware computes the proof's `jkt` (RFC 7638 thumbprint via `jwkThumbprint` in `src/jwk.ts`) and exposes it on `c.get("dpop").jkt`.

**Caller's job.** This middleware does **not** introspect the access token — that is intentional and out of scope (your existing JWT/introspection middleware does it). The caller must compare `proof.jkt` against the access token's `cnf.jkt`. Without this comparison, DPoP degrades to a proof-of-liveness check and the binding is meaningless.

## 3. Algorithm confusion

A client may declare `alg: "ES256"` in the JWS header but supply an `RSA` jwk, exploiting verifier code that switches on `alg` and not on `kty`. Or vice versa.

**Defense.** Validate the jwk against the `alg` before importing the key.

**Enforcement.** `assertAlgMatchesJwk` in `src/jwk.ts` cross-checks:

- `ES256/384/512` → `kty: EC` with the matching `crv`
- `RS*` and `PS*` → `kty: RSA`
- `EdDSA` → `kty: OKP` with `crv: Ed25519`

`parseProof` additionally requires `typ === "dpop+jwt"` (RFC 9449 §4.2).

## 4. Forged jwk in the proof header

An attacker who can construct any keypair can produce a signed proof. The defense is that the proof's identity is tied to the embedded jwk: `jkt` is computed from that jwk, and it is what the access token must commit to.

**Defense.** The signature is verified against the jwk inside the proof header — there is no out-of-band public-key resolution.

**Enforcement.** `verifyProofSignature` calls `crypto.subtle.verify` with a `CryptoKey` imported from `parsed.header.jwk`. Threat #2 (binding at the access-token layer) closes the loop: forging your own jwk produces a `jkt` that does not match the legitimate token's `cnf.jkt`.

## 5. Weak or symmetric algorithm

`HS256` lets anyone holding the verifier secret forge proofs. `none` lets anyone forge them with no secret.

**Defense.** Whitelist asymmetric algorithms only.

**Enforcement.** `SUPPORTED_ALGORITHMS` in `src/jwk.ts` is exactly `[ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA]`. The `algorithms` middleware option can only narrow this list, never extend it: unknown values would never match the JWS header's `alg` because there is no entry in the `ALG` descriptor table to import the key with.

## 6. Tampered `htu` / `htm`

A captured proof for `POST /transfer` should not be replayable as `GET /balance`, nor against a different host.

**Defense.** `htu` and `htm` claims must match the actual request URI and method.

**Enforcement.** `verifyProofClaims` in `src/verify.ts` compares the proof's `htm` against `c.req.method` and the proof's `htu` against `c.req.url`. Both sides go through `normalizeHtu`, which parses with `new URL()` and clears `.search` and `.hash` per RFC 9449 §4.3 step 11 ("ignoring any query and fragment parts"). A non-parseable URL (in either the proof or the request) is itself a 401.

**Caller's job.** Behind a reverse proxy or load balancer that rewrites the URL, `c.req.url` will be the internal URL while clients sign the external one. Pass `getRequestUrl: (c) => "https://api.example.com" + c.req.path` (or read `X-Forwarded-Host` etc.) to bridge that gap. Misconfiguration here looks like blanket signature failures, not a security weakening — fail closed. If you forward to multiple upstream services, each must use the same canonical `htu` the client signed, or each must compute its own override consistently.

A subtle pitfall: if your proxy rewrites the path (e.g., strips a `/api` prefix), `c.req.path` is the internal path. Always reconstruct the external URL the client actually called, not the URL your handler observes.

## 7. Stale proofs

Without an `iat` window, an attacker who captures a proof has unbounded time to use it (subject only to the `jti` cache, which is itself bounded).

**Defense.** Reject proofs whose `iat` is too old (or too far in the future).

**Enforcement.** `iatTolerance` defaults to 60 seconds and is configurable. `verifyProofClaims` computes `now = Math.floor(Date.now() / 1000)` and rejects if `Math.abs(now - iat) > iatTolerance`.

**Caller's job.** Tune for clock skew. Mobile clients with bad NTP can drift several seconds; serverless cold starts can shift wall-clock time. A 60 s window is the spec's typical recommendation. Setting it tighter improves security marginally (the `jti` cache still bounds replay window), so the main reason to widen it is operability.

## 8. Wrong access token paired with the proof

Even with `jkt` binding (#2), an attacker who steals one access token and is somehow able to sign one proof should not be able to graft them together against a different victim's session.

**Defense.** The optional `ath` claim is the SHA-256 of the access token. Including it ties the proof to a specific token at signing time.

**Enforcement.** When `Authorization: DPoP <token>` is present (or a custom `getAccessToken` returns one), the middleware computes `expected = SHA-256(token)` (`computeAth` in `src/verify.ts`, base64url-no-pad) and compares it against `parsed.payload.ath` using a constant-time check (`timingSafeEqual`):

```ts
let diff = 0;
for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i] ^ bBytes[i];
return diff === 0;
```

A mismatch returns 401 with `error="invalid_token"` and code `ATH_MISMATCH`. Critically, when an access token is presented but the proof has **no** `ath` claim at all, that is also rejected (the proof must commit to the token it accompanies).

**Caller's job.** Decide whether your route requires an access token at all — set `requireAccessToken: true` to reject when the header is missing. Without a token presented, no `ath` check is possible (and the proof's `ath`, if any, is ignored — the spec's `ath` is conditional). If you have a public route on the same router that should not require an access token, scope the `dpop()` middleware to the protected paths only.

## 9. Private-key smuggling

A buggy verifier could accept a JWK with a `d` field (the EC/OKP private scalar) or RSA private factors, then either crash, leak the private key into logs, or use it as a verification key.

**Defense.** Reject any JWK that contains a private field.

**Enforcement.** `assertPublicJwk` in `src/jwk.ts` checks the explicit list `[d, p, q, dp, dq, qi, oth, k]` and throws before the key is imported or thumbprinted. `crypto.subtle.importKey` is called with `extractable: false` regardless.

## 10. Memory DoS via oversized proof or access token

A DPoP header has no inherent size limit. A 10 MB proof body forces base64url decoding and JSON parse work for nothing. A multi-megabyte `Authorization: DPoP <token>` value forces a TextEncoder + SHA-256 pass during `ath` verification.

**Defense.** None at the spec level. Deployments are expected to bound input at the edge as well, but the middleware no longer assumes that.

**Enforcement.** Both inputs are size-bounded before any decode or crypto:

- `maxProofSize` (default **8192 bytes**) caps the `DPoP` header — checked immediately after the presence check, before `parseProof`.
- `maxAccessTokenSize` (default **4096 bytes**) caps the resolved access-token string — checked before `computeAth` runs SHA-256 over it.

Both limits are byte-counted via `TextEncoder` so multi-byte payloads cannot bypass them by character-counting.

**Caller's job.** Tune the defaults if your access tokens are deliberately large (some opaque or encrypted tokens can exceed 4 KB). Continue to apply edge-level header caps as defense-in-depth — the middleware bounds reach the application layer; CDNs and ingresses bound reach the network layer.

## 11. MitM proof / token capture

The whole DPoP design assumes TLS. A network attacker on a plaintext channel sees both the access token and the proof, can decline to forward the request, and can replay either at leisure (subject only to `jti` and `iat`).

**Defense.** TLS.

**Enforcement.** Out of scope of this middleware.

**Caller's job.** Run TLS 1.3. If you terminate TLS at a load balancer and use plaintext between LB and origin, your trust boundary includes that internal network; treat it accordingly.

## Defense-in-depth notes

A few things the middleware does that are not threats by themselves but reduce the blast radius of bugs elsewhere:

- **Imported keys are non-extractable.** `crypto.subtle.importKey` is called with `extractable: false`. Even if a downstream handler grabs the `jwk` off the proof and tries to round-trip it through Web Crypto, the handle cannot leak material that the JWK does not already publish.
- **Signing input is recomputed from the original `raw` JWT.** `verifyProofSignature` re-splits `parsed.raw` rather than re-encoding the parsed `header` and `payload` objects. This avoids a "JSON re-serialization" class of bug where parsing-then-stringifying a header could change the byte sequence the signature was computed over (key reordering, whitespace, escape choices).
- **Base64url shape is validated during parse.** The signature segment is decoded once in `parseProof` so a malformed base64url body fails fast, before the more expensive `crypto.subtle.verify` runs.
- **`jti` cache writes happen after the access-token check.** A proof that fails `ath` matching does not occupy a slot in the replay cache. This matters for memory stores with bounded `maxSize`.
- **No mutation of the verified proof.** `c.set("dpop", verified)` exposes a freshly built object, not a reference into `parsed`. Handlers cannot accidentally mutate the parsed proof and corrupt later middleware decisions.

## Limitations / known gaps

These are honest gaps, not threat-model dismissals. Each is something a determined operator may need to mitigate at a different layer or wait for a future release.

- **No JWS header allowlist beyond `typ` / `alg` / `jwk`.** Extra header fields (e.g., `kid`, `x5c`) are tolerated and ignored. The spec does not mandate rejection, but a stricter posture would refuse anything unrecognized.
- **No structured logging hooks.** Failures throw `DPoPProofError` carrying the `ProblemDetail`, but there is no per-failure metric or hook beyond the optional `onError`. Operators wanting per-cause counters must instrument via `onError` themselves.
- **No `dpop_jkt` request-parameter handling.** RFC 9449 §10 binds an authorization request to a key by carrying the thumbprint in `dpop_jkt`. That is the authorization server's job; this middleware is resource-server-only and does not implement it. Pair `hono-dpop` with an AS that does.
- **`jtiTtl` and `iatTolerance` are independent.** The replay cache remembers a `jti` for `jtiTtl` (default 5 min) regardless of `iatTolerance` (default 60 s). This is conservative — a valid proof at the edge of the iat window still cannot be replayed for the full jti window — but operators tuning `iatTolerance` higher should keep `jtiTtl ≥ 2 × iatTolerance` to avoid a window where a captured proof is iat-valid but already evicted from the replay cache.

### Previously listed, now resolved

- ~~No server-issued nonce challenge~~ — implemented via `nonceProvider`. See threat #12, RFC 9449 §8.
- ~~No built-in proof-size cap~~ — implemented via `maxProofSize` and `maxAccessTokenSize`. See threat #10.
- ~~No automatic `cnf.jkt` comparison helper~~ — `assertJktBinding` and `verifyJktBinding` ship in `src/jkt-binding.ts`.
- ~~Time injection~~ — `clock` option exposed on the middleware for tests and clock-skew compensation.

## Closing the binding loop: comparing `jkt` to `cnf.jkt`

The single most common deployment mistake with DPoP is to install the proof verifier and stop there, leaving the access token unbound to the proof. The middleware deliberately does not perform this comparison — it cannot, since it does not know your access-token format — so the responsibility is the caller's.

A typical wiring with a JWT bearer verifier looks like:

```ts
import { Hono } from "hono";
import { dpop } from "hono-dpop";
import { memoryNonceStore } from "hono-dpop/stores/memory";
import type { DPoPEnv } from "hono-dpop";

const app = new Hono<DPoPEnv & { Variables: { token: { cnf?: { jkt?: string } } } }>();

app.use("/api/*", dpop({ nonceStore: memoryNonceStore(), requireAccessToken: true }));
app.use("/api/*", verifyJwtMiddleware()); // your existing bearer/JWT check, sets c.get("token")

app.use("/api/*", async (c, next) => {
  const proof = c.get("dpop");
  const token = c.get("token");
  if (!proof || token.cnf?.jkt !== proof.jkt) {
    return c.json(
      { type: "...", title: "DPoP binding failed", status: 401 },
      401,
      { "WWW-Authenticate": 'DPoP error="invalid_token"' },
    );
  }
  await next();
});
```

Without this third middleware, an attacker with a stolen access token only needs *any* valid proof signed by *any* key — which the attacker can produce trivially with their own keypair — and the access token will be accepted. The bearer-token check passes (the token is genuine) and the proof check passes (it is a valid proof signed by some key). Only the `jkt`/`cnf.jkt` comparison ties the two together.

A future helper in this package may take a token-extractor callback and perform the comparison automatically (see "Limitations / known gaps"). Until then, treat the example above as required wiring, not optional hardening.

## Operator checklist

A short list of things to verify before relying on this middleware in production:

- [ ] You compare `c.get("dpop").jkt` against your access token's `cnf.jkt` claim somewhere downstream. Without this, threat #2 is open.
- [ ] Your `nonceStore` is shared across all instances that can serve the same request. The default `memoryNonceStore` is not.
- [ ] If you use `memoryNonceStore` with a `maxSize`, you have headroom: peak QPS × `jtiTtl` is well below `maxSize`. Otherwise FIFO eviction can let a `jti` be replayed (threat #1).
- [ ] Your `nonceStore.check` implementation is genuinely atomic. Test it under contention (e.g., 100 concurrent calls with the same `jti` — exactly one must return `true`).
- [ ] If the middleware sits behind a reverse proxy that rewrites the URL or path, you have configured `getRequestUrl` to return the canonical external URL.
- [ ] You have edge-level header-size caps (CDN, ingress) as defense-in-depth, even though `maxProofSize` / `maxAccessTokenSize` already bound the application-layer reach.
- [ ] You serve only over TLS 1.3.
- [ ] Your access tokens carry a `cnf.jkt` claim. (If they do not, you are running DPoP with no binding.)
- [ ] You have decided whether to set `requireAccessToken: true`. The default of `false` is correct for routes that publish a `jkt` for later use; for protected APIs you almost always want it `true`.

## Out of scope

Listed explicitly so reviewers know what this middleware is *not* trying to do:

- **Access-token issuance and introspection.** The authorization-server side of DPoP (`dpop_jkt` request parameter, token-binding at issue time, refresh-token rotation) belongs in the AS. This package handles only the resource-server proof check.
- **Bearer-token validation.** The middleware reads the `Authorization: DPoP <token>` value to compute `ath`, but it does not parse or verify the token. Pair `dpop()` with your existing JWT verifier or introspection middleware; the verifier can then compare `cnf.jkt` against `c.get("dpop").jkt`.
- **Cross-request rate limiting.** The replay cache is not a rate limiter. Apply rate limits at a different layer if you need them.
- **Audit logging.** Successes are silent (only `c.set("dpop", verified)` happens). If you need an audit trail of every DPoP-protected request, do it in a downstream middleware that reads `c.get("dpop")`.
