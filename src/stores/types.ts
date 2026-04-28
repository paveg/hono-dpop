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
