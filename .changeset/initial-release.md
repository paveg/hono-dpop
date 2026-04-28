---
"hono-dpop": minor
---

Initial release.

DPoP (RFC 9449) proof-of-possession middleware for Hono. Validates the
DPoP proof JWT (signature, htm/htu/iat, jti replay), supports
server-issued nonces (RFC 9449 §8), optional ath binding to bearer
access tokens, and cnf.jkt thumbprint verification. Web Crypto only —
no jose, no native deps. Runs on Node.js ≥20, Cloudflare Workers,
Deno, Bun.

Algorithms: ES256/384/512, RS256/384/512, PS256/384/512, EdDSA.
`none` and HS* rejected.

Store backends: memory (in-process), Redis (BYO client), Cloudflare KV,
Cloudflare D1, Durable Objects.

RFC 9457 Problem Details errors with optional auto-detection of
hono-problem-details. Pluggable: nonceStore, nonceProvider, algorithms,
iatTolerance, jtiTtl, getRequestUrl, getAccessToken, requireAccessToken,
maxProofSize, maxAccessTokenSize, clock, htuComparison, allowFutureIat,
onError.
