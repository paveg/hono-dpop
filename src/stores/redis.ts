import type { DPoPNonceStore } from "./types.js";

const DEFAULT_TTL = 300; // 5 minutes in seconds — matches default jtiTtl
const DEFAULT_KEY_PREFIX = "dpop:jti:";

/** Minimal Redis client subset compatible with ioredis, node-redis, and @upstash/redis. */
export interface RedisClientLike {
	set(key: string, value: string, options?: { NX?: boolean; EX?: number }): Promise<string | null>;
}

export interface RedisStoreOptions {
	/** Redis client instance (ioredis, node-redis, or @upstash/redis). */
	client: RedisClientLike;
	/** Maximum TTL in seconds applied to each jti entry (default: 300 = 5 min). */
	ttl?: number;
	/** Key prefix to namespace replay-cache entries (default: "dpop:jti:"). */
	keyPrefix?: string;
}

/**
 * Redis-backed replay cache. Uses `SET key 1 NX EX <ttl>` for atomic insert-if-absent —
 * a single round-trip whose semantics match RFC 9449 §11.1: exactly one concurrent caller
 * sees `OK` (return true), the rest get `null` (return false).
 *
 * The TTL is the smaller of `expiresAt - now` and the configured `ttl` ceiling, so the
 * entry is auto-removed by Redis once the proof's freshness window closes. `purge()` is
 * therefore a no-op returning 0.
 */
export function redisStore(options: RedisStoreOptions): DPoPNonceStore {
	const { client, ttl = DEFAULT_TTL, keyPrefix = DEFAULT_KEY_PREFIX } = options;

	return {
		async check(jti, expiresAt) {
			const remainingSeconds = Math.ceil((expiresAt - Date.now()) / 1000);
			if (remainingSeconds <= 0) return false;
			const ex = Math.min(ttl, remainingSeconds);
			const result = await client.set(`${keyPrefix}${jti}`, "1", { NX: true, EX: ex });
			return result === "OK";
		},

		async purge() {
			// Redis handles expiration automatically via EX — no manual purge needed
			return 0;
		},
	};
}
