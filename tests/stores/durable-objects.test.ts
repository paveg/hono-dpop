import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { durableObjectStore } from "../../src/stores/durable-objects.js";

function createMockStorage() {
	const data = new Map<string, unknown>();
	return {
		data,
		async get<T>(key: string): Promise<T | undefined> {
			return data.get(key) as T | undefined;
		},
		async put<T>(key: string, value: T): Promise<void> {
			data.set(key, value);
		},
		async delete(key: string): Promise<boolean> {
			return data.delete(key);
		},
		async list<T>(options: { prefix: string }): Promise<Map<string, T>> {
			const result = new Map<string, T>();
			for (const [k, v] of data) {
				if (k.startsWith(options.prefix)) result.set(k, v as T);
			}
			return result;
		},
	};
}

describe("durableObjectStore", () => {
	beforeEach(() => vi.useFakeTimers());
	afterEach(() => vi.useRealTimers());

	it("returns true and stores entry on first sighting", async () => {
		const storage = createMockStorage();
		const store = durableObjectStore({ storage });
		expect(await store.check("a", Date.now() + 60_000)).toBe(true);
		expect(storage.data.has("dpop:jti:a")).toBe(true);
	});

	it("returns false on replay within window", async () => {
		const storage = createMockStorage();
		const store = durableObjectStore({ storage });
		const exp = Date.now() + 60_000;
		expect(await store.check("a", exp)).toBe(true);
		expect(await store.check("a", exp)).toBe(false);
	});

	it("returns true after the entry's expiresAt has passed (lazy re-acquire)", async () => {
		const storage = createMockStorage();
		const store = durableObjectStore({ storage });
		await store.check("a", Date.now() + 1_000);
		vi.advanceTimersByTime(1_001);
		expect(await store.check("a", Date.now() + 1_000)).toBe(true);
	});

	it("custom keyPrefix isolates entries", async () => {
		const storage = createMockStorage();
		const a = durableObjectStore({ storage, keyPrefix: "tenantA:" });
		const b = durableObjectStore({ storage, keyPrefix: "tenantB:" });
		const exp = Date.now() + 60_000;
		expect(await a.check("jti1", exp)).toBe(true);
		expect(await b.check("jti1", exp)).toBe(true);
		expect(storage.data.has("tenantA:jti1")).toBe(true);
		expect(storage.data.has("tenantB:jti1")).toBe(true);
	});

	it("falls back to defaultTtl when expiresAt is in the past", async () => {
		const storage = createMockStorage();
		const store = durableObjectStore({ storage, defaultTtl: 10_000 });
		const before = Date.now();
		expect(await store.check("a", before - 1)).toBe(true);
		const stored = storage.data.get("dpop:jti:a") as { expiresAt: number };
		expect(stored.expiresAt).toBeGreaterThanOrEqual(before + 10_000);
	});

	it("default defaultTtl is 5 minutes (300000 ms)", async () => {
		const storage = createMockStorage();
		const store = durableObjectStore({ storage });
		const before = Date.now();
		await store.check("a", 0); // forces fallback
		const stored = storage.data.get("dpop:jti:a") as { expiresAt: number };
		expect(stored.expiresAt).toBe(before + 300_000);
	});

	it("purge() removes only expired entries and returns count", async () => {
		const storage = createMockStorage();
		const store = durableObjectStore({ storage });
		await store.check("e1", Date.now() + 100);
		await store.check("e2", Date.now() + 200);
		await store.check("fresh", Date.now() + 60_000);
		vi.advanceTimersByTime(300);
		expect(await store.purge()).toBe(2);
		expect(storage.data.has("dpop:jti:fresh")).toBe(true);
	});

	it("purge() on empty storage returns 0", async () => {
		const storage = createMockStorage();
		const store = durableObjectStore({ storage });
		expect(await store.purge()).toBe(0);
	});

	it("purge() is scoped to keyPrefix — does not touch unrelated keys", async () => {
		const storage = createMockStorage();
		// Inject an unrelated entry that looks expired but lives outside the prefix
		await storage.put("other:foo", { expiresAt: Date.now() - 1 });
		const store = durableObjectStore({ storage });
		await store.check("a", Date.now() + 100);
		vi.advanceTimersByTime(200);
		expect(await store.purge()).toBe(1);
		expect(storage.data.has("other:foo")).toBe(true);
	});

	describe("boundary cases", () => {
		it("expiresAt = now + 1 → effectiveExpiresAt = expiresAt (no fallback)", async () => {
			const storage = createMockStorage();
			const store = durableObjectStore({ storage, defaultTtl: 999_999 });
			const exp = Date.now() + 1;
			expect(await store.check("a", exp)).toBe(true);
			const stored = storage.data.get("dpop:jti:a") as { expiresAt: number };
			expect(stored.expiresAt).toBe(exp);
		});

		// Implementation uses `expiresAt > now`, so equality falls through to defaultTtl.
		it("expiresAt = now → fallback to defaultTtl (uses strict >)", async () => {
			const storage = createMockStorage();
			const store = durableObjectStore({ storage, defaultTtl: 10_000 });
			const before = Date.now();
			expect(await store.check("a", before)).toBe(true);
			const stored = storage.data.get("dpop:jti:a") as { expiresAt: number };
			expect(stored.expiresAt).toBe(before + 10_000);
		});

		it("expiresAt = now - 1 → fallback to defaultTtl", async () => {
			const storage = createMockStorage();
			const store = durableObjectStore({ storage, defaultTtl: 10_000 });
			const before = Date.now();
			expect(await store.check("a", before - 1)).toBe(true);
			const stored = storage.data.get("dpop:jti:a") as { expiresAt: number };
			expect(stored.expiresAt).toBe(before + 10_000);
		});

		it("expiresAt = -1 → fallback to defaultTtl", async () => {
			const storage = createMockStorage();
			const store = durableObjectStore({ storage, defaultTtl: 10_000 });
			const before = Date.now();
			expect(await store.check("a", -1)).toBe(true);
			const stored = storage.data.get("dpop:jti:a") as { expiresAt: number };
			expect(stored.expiresAt).toBe(before + 10_000);
		});

		// Lazy expiration: an existing entry whose expiresAt is in the past does not
		// block a fresh check; the new put overwrites it in place.
		it("existing expired entry is replaced — new check returns true", async () => {
			const storage = createMockStorage();
			const store = durableObjectStore({ storage });
			await storage.put("dpop:jti:a", { expiresAt: Date.now() - 1_000 });
			expect(await store.check("a", Date.now() + 60_000)).toBe(true);
		});

		// JS implicit coercion: `"123" > 100` → numeric compare → true. Document this
		// behavior so silent type drift in storage payloads doesn't surprise callers.
		it('coerces existing entry expiresAt of type string via JS ">" comparison', async () => {
			const storage = createMockStorage();
			const futureMs = String(Date.now() + 60_000);
			await storage.put("dpop:jti:a", { expiresAt: futureMs as unknown as number });
			const store = durableObjectStore({ storage });
			// "<future-string>" > now → true (numeric coercion) → blocks as replay
			expect(await store.check("a", Date.now() + 60_000)).toBe(false);
		});

		it("purge() with custom keyPrefix ignores entries outside that prefix", async () => {
			const storage = createMockStorage();
			await storage.put("other:bar", { expiresAt: Date.now() - 1 });
			const store = durableObjectStore({ storage, keyPrefix: "tenant:" });
			await store.check("a", Date.now() + 100);
			vi.advanceTimersByTime(200);
			expect(await store.purge()).toBe(1);
			expect(storage.data.has("other:bar")).toBe(true);
			expect(storage.data.has("tenant:a")).toBe(false);
		});

		it('purge() with keyPrefix="" walks every key in storage', async () => {
			const storage = createMockStorage();
			await storage.put("foo", { expiresAt: Date.now() - 1 });
			await storage.put("bar", { expiresAt: Date.now() - 1 });
			await storage.put("baz", { expiresAt: Date.now() + 60_000 });
			const store = durableObjectStore({ storage, keyPrefix: "" });
			expect(await store.purge()).toBe(2);
			expect(storage.data.has("baz")).toBe(true);
		});
	});
});
