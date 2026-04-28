import type { DPoPNonceStore } from "./types.js";

export interface MemoryNonceStoreOptions {
	/** Maximum entries before FIFO eviction of the oldest entry. */
	maxSize?: number;
	/** Minimum interval between background sweeps, in milliseconds (default: 60_000). */
	sweepInterval?: number;
}

export interface MemoryNonceStore extends DPoPNonceStore {
	/** Number of entries currently held (including expired but not yet swept). */
	readonly size: number;
}

const DEFAULT_SWEEP_INTERVAL = 60_000;

export function memoryNonceStore(options: MemoryNonceStoreOptions = {}): MemoryNonceStore {
	const maxSize = options.maxSize;
	const sweepInterval = options.sweepInterval ?? DEFAULT_SWEEP_INTERVAL;
	const map = new Map<string, number>();
	let lastSweep = Number.NEGATIVE_INFINITY;

	const sweepIfDue = (now: number): void => {
		if (now - lastSweep < sweepInterval) return;
		lastSweep = now;
		for (const [jti, exp] of map) {
			if (exp <= now) map.delete(jti);
		}
	};

	return {
		get size() {
			return map.size;
		},

		async check(jti, expiresAt) {
			const now = Date.now();
			sweepIfDue(now);

			const existingExp = map.get(jti);
			if (existingExp !== undefined && existingExp > now) {
				return false;
			}
			map.set(jti, expiresAt);
			if (maxSize !== undefined && map.size > maxSize) {
				const oldest = map.keys().next().value;
				if (oldest !== undefined && oldest !== jti) map.delete(oldest);
			}
			return true;
		},

		async purge() {
			const now = Date.now();
			let count = 0;
			for (const [jti, exp] of map) {
				if (exp <= now) {
					map.delete(jti);
					count++;
				}
			}
			lastSweep = now;
			return count;
		},
	};
}
