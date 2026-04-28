import type { DPoPNonceStore } from "./types.js";

const DEFAULT_KEY_PREFIX = "dpop:jti:";

/** Minimal KVNamespace subset used by kvStore (avoids @cloudflare/workers-types dependency). */
export interface KVNamespaceLike {
	get(key: string, options?: { type?: "text" }): Promise<string | null>;
	put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

export interface KVStoreOptions {
	/** Cloudflare Workers KV namespace binding. */
	namespace: KVNamespaceLike;
	/** Key prefix to namespace replay-cache entries (default: "dpop:jti:"). */
	keyPrefix?: string;
	/**
	 * Optional best-effort race-detection delay in milliseconds. When > 0 the store
	 * sleeps for this long after `put` and re-reads the key, returning false if the
	 * value disagrees with the one it just wrote. Default 0 (disabled) — KV's
	 * eventual consistency makes any value tunable but never fully reliable.
	 */
	raceWindowMs?: number;
}

/**
 * Cloudflare Workers KV-backed replay cache.
 *
 * IMPORTANT: KV is eventually consistent across edge locations. Two requests routed to
 * different POPs may both observe the key as absent and both succeed in `put`, allowing
 * a brief replay window. RFC 9449 §11.1 acknowledges this: jti enforcement is at-most-once
 * but is allowed to degrade to best-effort under partition. For strict atomicity, use
 * `d1Store` (single primary) or `durableObjectStore` (single-writer per object).
 *
 * Caches expire automatically via `expirationTtl` derived from the proof's `expiresAt`,
 * so `purge()` is a no-op returning 0. The KV minimum is 60 seconds — shorter requested
 * TTLs are clamped to that floor.
 */
export function kvStore(options: KVStoreOptions): DPoPNonceStore {
	const { namespace: kv, keyPrefix = DEFAULT_KEY_PREFIX, raceWindowMs = 0 } = options;

	return {
		async check(jti, expiresAt) {
			const remainingMs = expiresAt - Date.now();
			if (remainingMs <= 0) return false;
			const key = `${keyPrefix}${jti}`;

			const existing = await kv.get(key);
			if (existing !== null) return false;

			// KV minimum expirationTtl is 60s — clamp.
			const expirationTtl = Math.max(60, Math.ceil(remainingMs / 1000));
			const marker = crypto.randomUUID();
			await kv.put(key, marker, { expirationTtl });

			if (raceWindowMs > 0) {
				await new Promise((resolve) => setTimeout(resolve, raceWindowMs));
				const readback = await kv.get(key);
				if (readback !== marker) return false;
			}

			return true;
		},

		async purge() {
			// KV handles expiration automatically via expirationTtl — no manual purge needed
			return 0;
		},
	};
}
