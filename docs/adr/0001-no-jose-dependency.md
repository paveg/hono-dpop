# ADR-0001: No jose dependency

## Status
Accepted

## Context
DPoP proof verification needs JWS signature verification, JWK parsing, and SHA-256 (for `jkt` thumbprints and `ath`). The de-facto JWT/JOSE library in the JS ecosystem is `jose` (panva/jose). Adopting it would have given us a battle-tested implementation for free, but it carries weight we do not need.

Concretely:

- `jose` ships ~60 algorithms across signing, encryption, key wrap, and PBES2. DPoP only needs JWS verification with the asymmetric subset.
- DPoP RFC 9449 §3.1 requires the algorithm be asymmetric. Our supported surface is exactly 10 algs (`ES256/384/512`, `RS256/384/512`, `PS256/384/512`, `EdDSA`) — all expressible directly via `crypto.subtle.verify`.
- Targets include Cloudflare Workers, Deno, Bun, and Node ≥20. All four ship Web Crypto in the global scope. There is no portability gap to paper over.
- This package is intended to be cheap to install for edge deployments where every imported module costs cold-start time.

## Decision
Implement signature verification, JWK validation, and thumbprinting directly against Web Crypto. Do not depend on `jose` or any other JOSE library.

The implementation lives in `src/jwk.ts` (algorithm descriptors, `importPublicJwk`, `assertAlgMatchesJwk`) and `src/verify.ts` (proof parsing and `crypto.subtle.verify` calls). The total surface is small enough to audit in one sitting.

## Consequences
**Positive**

- Zero runtime dependencies; works unchanged on every Web-Crypto-capable runtime.
- Smaller bundle and faster cold start on Workers.
- The 10-algorithm whitelist is enforced by construction — there is no path through the code that touches `none` or `HS*`.
- Audit surface is the ~200 lines in `src/jwk.ts` and `src/verify.ts`, not a 10k-LOC dependency tree.

**Negative**

- No support for less common algorithms (e.g., `ES256K`, `Ed448`). If a caller needs these, they must fork or wait for upstream Web Crypto support.
- We own bugs in JWS parsing and base64url handling that `jose` would otherwise own. Mitigated by tests targeting 100% coverage and adversarial inputs.
- Future spec changes (e.g., new curves) require us to extend `ALG` in `src/jwk.ts` rather than getting them for free from a library upgrade.
