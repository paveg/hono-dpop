import type { DPoPNonceStore } from "./types.js";

const DEFAULT_KEY_PREFIX = "dpop:jti:";
const DEFAULT_TTL_MS = 5 * 60_000; // 5 minutes — matches default jtiTtl

/** Minimal DurableObjectStorage subset (avoids @cloudflare/workers-types dependency). */
export interface DurableObjectStorageLike {
	get<T>(key: string): Promise<T | undefined>;
	put<T>(key: string, value: T, options?: { allowUnconfirmed?: boolean }): Promise<void>;
	delete(key: string): Promise<boolean>;
	list<T>(options: { prefix: string }): Promise<Map<string, T>>;
}

interface JtiEntry {
	expiresAt: number;
}

export interface DurableObjectStoreOptions {
	/** Durable Object storage instance (from `this.ctx.storage` inside a DO class). */
	storage: DurableObjectStorageLike;
	/** Key prefix to namespace replay-cache entries (default: "dpop:jti:"). */
	keyPrefix?: string;
	/**
	 * Fallback TTL in milliseconds applied when `expiresAt` is in the past or missing
	 * (default: 300000 = 5 min). Normal callers always pass a future `expiresAt`.
	 */
	defaultTtl?: number;
}

/**
 * Durable Object storage-backed replay cache. DO storage has no native TTL, so each entry
 * stores its own `expiresAt` and is lazy-deleted on read. The DO single-writer guarantee
 * makes the read-then-write pattern atomic without explicit locking — concurrent requests
 * to the same Object are serialized by the runtime.
 *
 * `purge()` lists entries under `keyPrefix` and deletes those past their `expiresAt`,
 * returning the count removed. Run from a scheduled handler or alarm to bound storage.
 */
export function durableObjectStore(options: DurableObjectStoreOptions): DPoPNonceStore {
	const { storage, keyPrefix = DEFAULT_KEY_PREFIX, defaultTtl = DEFAULT_TTL_MS } = options;

	return {
		async check(jti, expiresAt) {
			const now = Date.now();
			const key = `${keyPrefix}${jti}`;
			const existing = await storage.get<JtiEntry>(key);
			if (existing !== undefined && existing.expiresAt > now) {
				return false;
			}
			const effectiveExpiresAt = expiresAt > now ? expiresAt : now + defaultTtl;
			await storage.put<JtiEntry>(key, { expiresAt: effectiveExpiresAt });
			return true;
		},

		async purge() {
			const now = Date.now();
			const entries = await storage.list<JtiEntry>({ prefix: keyPrefix });
			let count = 0;
			for (const [key, entry] of entries) {
				if (entry.expiresAt <= now) {
					await storage.delete(key);
					count++;
				}
			}
			return count;
		},
	};
}
