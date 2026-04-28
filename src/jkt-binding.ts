import { DPoPErrors, DPoPProofError } from "./errors.js";

export interface AccessTokenClaimsWithCnf {
	cnf?: { jkt?: string };
}

/**
 * Returns true when the access token's `cnf.jkt` claim equals the proof
 * thumbprint exposed on `c.get("dpop").jkt`. Returns false on missing or
 * mismatched binding.
 *
 * Use this for explicit branching in route handlers. For the throwing
 * variant that integrates with the standard 401 + WWW-Authenticate
 * pipeline, see `assertJktBinding`.
 */
export function verifyJktBinding(
	accessTokenClaims: AccessTokenClaimsWithCnf,
	proofThumbprint: string,
): boolean {
	const bound = accessTokenClaims.cnf?.jkt;
	return typeof bound === "string" && bound === proofThumbprint;
}

/**
 * Throws `DPoPProofError` (formatted as 401 + `WWW-Authenticate: DPoP error="invalid_dpop_proof"`)
 * when the access token's `cnf.jkt` does not match the proof thumbprint, or when
 * `cnf.jkt` is missing entirely.
 *
 * Typical usage inside a route handler:
 * ```ts
 * const proof = c.get("dpop")!;
 * const claims = await verifyMyJwt(token);
 * assertJktBinding(claims, proof.jkt);
 * ```
 */
export function assertJktBinding(
	accessTokenClaims: AccessTokenClaimsWithCnf,
	proofThumbprint: string,
): void {
	if (!verifyJktBinding(accessTokenClaims, proofThumbprint)) {
		throw new DPoPProofError(
			DPoPErrors.invalidProof("access token cnf.jkt does not match DPoP proof thumbprint"),
		);
	}
}
