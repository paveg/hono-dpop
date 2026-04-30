# ADR-0008: Accept both `EdDSA` and `Ed25519` JWS alg identifiers

## Status
Accepted

## Context
JWS originally identified Edwards-curve signatures as `EdDSA` (RFC 8037, 2017). The identifier is curve-agnostic by design: the same `EdDSA` string covers Ed25519 and Ed448 with the kty/crv distinguishing which.

RFC 9758 ("Fully-Specified Algorithms for JOSE and COSE", 2025) introduces curve-specific identifiers — `Ed25519` and `Ed448` — to make algorithm choice explicit at the alg level rather than implicit at the kty/crv level. The motivation is alg-confusion resistance: an `EdDSA` proof carrying an Ed25519 jwk and an `EdDSA` proof carrying an Ed448 jwk look identical to coarse alg-allowlists.

DPoP (RFC 9449) was finalized before RFC 9758. New clients written against current JOSE libraries may emit either identifier depending on library version. Old clients emit only `EdDSA`. Refusing one of them breaks interop without a corresponding security gain — we already cross-check kty/crv against alg in `assertAlgMatchesJwk`, so the alg-confusion concern that motivated RFC 9758 is closed independently.

## Decision
`SUPPORTED_ALGORITHMS` includes both identifiers and treats them as the same crypto:

```ts
"EdDSA",   // RFC 8037 — curve-agnostic Edwards-curve signature
"Ed25519", // RFC 9758 — fully-specified Edwards-curve signature
```

The `ALG` descriptor table (`src/jwk.ts`) maps both to the same WebCrypto `name: "Ed25519"` import params and verify params. `assertAlgMatchesJwk` accepts either alg with a `kty: "OKP", crv: "Ed25519"` jwk and rejects everything else.

We do not yet accept `Ed448` because no major library emits it for DPoP today and WebCrypto support is uneven.

## Consequences
**Positive**
- Forward-compatible with libraries adopting RFC 9758 without breaking pre-9758 clients.
- `assertAlgMatchesJwk` continues to be the single source of truth for alg/kty/crv consistency, regardless of which alg identifier the client chose.
- The `algorithms` middleware option can narrow to one identifier or the other if a deployment wants to enforce a specific convention.

**Negative**
- The alg surface grows by one identifier with no behavioral difference. Operators inspecting logs may see both for the same logical operation.
- A client that signs as `Ed25519` and sees a server narrowing to `["EdDSA"]` (or vice versa) gets a 401 with `algs="EdDSA"` in the `WWW-Authenticate` challenge — informative, but the client must be able to switch. We document this in the README's algorithms section.
- Future RFC 9758 identifiers (Ed448, ML-DSA-44, etc.) need explicit additions; the table-driven design makes this cheap, but each addition is a separate ADR-worthy decision because of WebCrypto availability constraints.
