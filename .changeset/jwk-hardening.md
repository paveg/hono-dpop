---
"hono-dpop": minor
---

Tighten JWK validation and accept the RFC 9758 `Ed25519` JWS algorithm identifier:

- Enforce RSA modulus length in 2048-4096 bit range. Defends against DoS amplification via giant moduli (16384-bit) causing slow signature verification, and against weak keys (1024-bit and below) being accepted.
- Use own-property check for private-field detection (`Object.hasOwnProperty.call` rather than `in`) so a polluted `Object.prototype` cannot cause spurious rejection of valid public JWKs.
- Accept `alg: "Ed25519"` (RFC 9758 fully-specified algorithm identifier) in addition to `alg: "EdDSA"` (RFC 8037). Both use the same Ed25519 crypto; verifiers should accept both for forward compatibility with newer DPoP clients. `assertAlgMatchesJwk` now requires `kty: "OKP"` AND `crv: "Ed25519"` for both alg names (was only checking `kty`).
