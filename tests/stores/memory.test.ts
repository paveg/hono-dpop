import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { memoryNonceStore } from "../../src/stores/memory.js";

describe("memoryNonceStore", () => {
	beforeEach(() => vi.useFakeTimers());
	afterEach(() => vi.useRealTimers());

	it("returns true for new jti", async () => {
		const store = memoryNonceStore();
		expect(await store.check("a", Date.now() + 60_000)).toBe(true);
	});

	it("returns false on replay within window", async () => {
		const store = memoryNonceStore();
		const exp = Date.now() + 60_000;
		expect(await store.check("a", exp)).toBe(true);
		expect(await store.check("a", exp)).toBe(false);
	});

	it("treats expired jti as not seen on subsequent check", async () => {
		const store = memoryNonceStore({ sweepInterval: 0 });
		expect(await store.check("a", Date.now() + 1000)).toBe(true);
		vi.advanceTimersByTime(1001);
		expect(await store.check("a", Date.now() + 1000)).toBe(true);
	});

	it("FIFO eviction at maxSize", async () => {
		const store = memoryNonceStore({ maxSize: 2 });
		const exp = Date.now() + 60_000;
		await store.check("a", exp);
		await store.check("b", exp);
		await store.check("c", exp);
		expect(store.size).toBe(2);
		// "a" was oldest, evicted; can be re-acquired
		expect(await store.check("a", exp)).toBe(true);
	});

	it("size exposes current entry count", async () => {
		const store = memoryNonceStore();
		expect(store.size).toBe(0);
		await store.check("a", Date.now() + 1000);
		expect(store.size).toBe(1);
	});

	it("purge() removes expired and returns count", async () => {
		const store = memoryNonceStore();
		await store.check("a", Date.now() + 100);
		await store.check("b", Date.now() + 100);
		await store.check("c", Date.now() + 100_000);
		vi.advanceTimersByTime(200);
		expect(await store.purge()).toBe(2);
		expect(store.size).toBe(1);
	});

	it("purge() on empty returns 0", async () => {
		const store = memoryNonceStore();
		expect(await store.purge()).toBe(0);
	});

	it("sweep is throttled by sweepInterval", async () => {
		const store = memoryNonceStore({ sweepInterval: 5000 });
		// First check primes lastSweep with the no-op sweep
		await store.check("a", Date.now() + 100);
		vi.advanceTimersByTime(200); // a expires
		// Within sweepInterval — sweep skipped, "a" stays in map
		await store.check("b", Date.now() + 60_000);
		expect(store.size).toBe(2);
		vi.advanceTimersByTime(5001);
		// Past sweepInterval — sweep runs, removes expired "a"
		await store.check("c", Date.now() + 60_000);
		expect(store.size).toBe(2);
	});

	it("sweepInterval=0 sweeps every call", async () => {
		const store = memoryNonceStore({ sweepInterval: 0 });
		await store.check("a", Date.now() + 100);
		vi.advanceTimersByTime(200);
		await store.check("b", Date.now() + 60_000);
		expect(store.size).toBe(1);
	});

	it("re-adding the same just-set key when at maxSize does not evict it", async () => {
		const store = memoryNonceStore({ maxSize: 1 });
		await store.check("a", Date.now() + 60_000);
		// "a" is replayed within window — returns false, no eviction
		expect(await store.check("a", Date.now() + 60_000)).toBe(false);
		expect(store.size).toBe(1);
	});

	describe("boundary cases", () => {
		// Implementation uses `existingExp > now` for replay check, so an entry written
		// with `expiresAt === now` is treated as already expired the moment it lands.
		// First write succeeds (no prior entry); the immediate replay observes it expired
		// and writes a fresh entry returning true.
		it("expiresAt === clock() — first write true, replay also true (entry counts as expired)", async () => {
			const store = memoryNonceStore({ sweepInterval: Number.POSITIVE_INFINITY });
			const now = Date.now();
			expect(await store.check("a", now)).toBe(true);
			expect(await store.check("a", now)).toBe(true);
		});

		it("expiresAt === clock() + 1 — replay within window returns false", async () => {
			const store = memoryNonceStore({ sweepInterval: Number.POSITIVE_INFINITY });
			const exp = Date.now() + 1;
			expect(await store.check("a", exp)).toBe(true);
			expect(await store.check("a", exp)).toBe(false);
		});

		it("expiresAt = -1 is recorded but treated as already expired on replay", async () => {
			const store = memoryNonceStore({ sweepInterval: Number.POSITIVE_INFINITY });
			expect(await store.check("a", -1)).toBe(true);
			expect(await store.check("a", -1)).toBe(true);
		});

		it("expiresAt = 0 is recorded but treated as already expired on replay", async () => {
			const store = memoryNonceStore({ sweepInterval: Number.POSITIVE_INFINITY });
			expect(await store.check("a", 0)).toBe(true);
			expect(await store.check("a", 0)).toBe(true);
		});

		it("expiresAt = Number.MAX_SAFE_INTEGER blocks replay", async () => {
			const store = memoryNonceStore({ sweepInterval: Number.POSITIVE_INFINITY });
			expect(await store.check("a", Number.MAX_SAFE_INTEGER)).toBe(true);
			expect(await store.check("a", Number.MAX_SAFE_INTEGER)).toBe(false);
		});

		it("accepts empty string jti", async () => {
			const store = memoryNonceStore({ sweepInterval: Number.POSITIVE_INFINITY });
			expect(await store.check("", Date.now() + 60_000)).toBe(true);
			expect(await store.check("", Date.now() + 60_000)).toBe(false);
		});

		it("accepts very long jti (10000 chars)", async () => {
			const store = memoryNonceStore({ sweepInterval: Number.POSITIVE_INFINITY });
			const longJti = "x".repeat(10_000);
			expect(await store.check(longJti, Date.now() + 60_000)).toBe(true);
			expect(await store.check(longJti, Date.now() + 60_000)).toBe(false);
		});

		it("accepts jti containing newline and colon characters", async () => {
			const store = memoryNonceStore({ sweepInterval: Number.POSITIVE_INFINITY });
			const jti = "abc\ndef:ghi";
			expect(await store.check(jti, Date.now() + 60_000)).toBe(true);
			expect(await store.check(jti, Date.now() + 60_000)).toBe(false);
		});

		it("re-checks the same jti after expiration with a new expiresAt", async () => {
			const store = memoryNonceStore({ sweepInterval: 0 });
			expect(await store.check("a", Date.now() + 1000)).toBe(true);
			vi.advanceTimersByTime(1001);
			expect(await store.check("a", Date.now() + 5000)).toBe(true);
		});

		it("maxSize=1 evicts the previous entry when a new one is added", async () => {
			const store = memoryNonceStore({ maxSize: 1, sweepInterval: Number.POSITIVE_INFINITY });
			const exp = Date.now() + 60_000;
			expect(await store.check("a", exp)).toBe(true);
			expect(await store.check("b", exp)).toBe(true);
			expect(store.size).toBe(1);
			// "a" was evicted by FIFO policy and may now be re-acquired
			expect(await store.check("a", exp)).toBe(true);
		});

		it("maxSize=undefined retains 1000 entries without eviction", async () => {
			const store = memoryNonceStore({ sweepInterval: Number.POSITIVE_INFINITY });
			const exp = Date.now() + 60_000;
			for (let i = 0; i < 1000; i++) {
				expect(await store.check(`jti-${i}`, exp)).toBe(true);
			}
			expect(store.size).toBe(1000);
		});
	});

	describe("default maxSize", () => {
		it("default maxSize evicts after 100_000 entries", async () => {
			const store = memoryNonceStore();
			const exp = Date.now() + 60_000;
			for (let i = 0; i < 100_001; i++) {
				await store.check(`jti-${i}`, exp);
			}
			expect(store.size).toBe(100_000);
		});

		it("default eviction allows replay of evicted jti", async () => {
			const store = memoryNonceStore({ sweepInterval: Number.POSITIVE_INFINITY });
			const exp = Date.now() + 60_000;
			// First entry — will become the oldest and be evicted once we exceed cap
			expect(await store.check("first", exp)).toBe(true);
			for (let i = 0; i < 100_000; i++) {
				await store.check(`jti-${i}`, exp);
			}
			expect(store.size).toBe(100_000);
			// "first" was evicted by FIFO and may now be re-acquired (returns true)
			expect(await store.check("first", exp)).toBe(true);
		});

		it("explicit maxSize is honored over the default", async () => {
			const store = memoryNonceStore({ maxSize: 50 });
			const exp = Date.now() + 60_000;
			for (let i = 0; i < 60; i++) {
				await store.check(`jti-${i}`, exp);
			}
			expect(store.size).toBe(50);
		});
	});
});
