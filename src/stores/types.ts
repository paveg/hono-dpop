import type { Context } from "hono";

export interface DPoPNonceStore {
	/**
	 * Atomically check whether `jti` has been seen. If not seen, record it with the
	 * given expiration timestamp (Unix milliseconds) and return true. If already seen
	 * within its expiration window, return false (the request is a replay).
	 *
	 * Implementations MUST be atomic against concurrent calls with the same jti:
	 * exactly one concurrent caller must observe `true`.
	 */
	check(jti: string, expiresAt: number): Promise<boolean>;

	/**
	 * Physically remove expired entries. Returns the number of removed entries.
	 * Stores with native expiration may be a no-op returning 0.
	 */
	purge(): Promise<number>;
}

/**
 * Server-issued nonce provider (RFC 9449 §8). When configured on the middleware,
 * proofs without a current `nonce` claim are rejected with a `use_dpop_nonce`
 * challenge that includes a fresh nonce.
 */
export interface NonceProvider {
	/** Generate a nonce to send in the DPoP-Nonce response header / WWW-Authenticate challenge. */
	issueNonce(c: Context): string | Promise<string>;
	/** Validate a nonce claim from a client proof. Return true if currently or recently valid. */
	isValid(nonce: string, c: Context): boolean | Promise<boolean>;
}
