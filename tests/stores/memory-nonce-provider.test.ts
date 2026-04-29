import type { Context } from "hono";
import { describe, expect, it } from "vitest";
import { memoryNonceProvider } from "../../src/stores/memory-nonce-provider.js";

const fakeCtx = {} as Context;

describe("memoryNonceProvider", () => {
	it("issues a UUID nonce", async () => {
		const provider = memoryNonceProvider();
		const nonce = await provider.issueNonce(fakeCtx);
		expect(nonce).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
	});

	it("isValid accepts the current nonce", async () => {
		const provider = memoryNonceProvider();
		const nonce = await provider.issueNonce(fakeCtx);
		expect(await provider.isValid(nonce, fakeCtx)).toBe(true);
	});

	it("isValid rejects unknown nonces", async () => {
		const provider = memoryNonceProvider();
		expect(await provider.isValid("not-the-nonce", fakeCtx)).toBe(false);
	});

	it("rotates after rotateAfter ms and accepts both current and previous by default", async () => {
		let now = 1_000_000;
		const provider = memoryNonceProvider({ rotateAfter: 1000, clock: () => now });
		const first = await provider.issueNonce(fakeCtx);
		now += 1500;
		const second = await provider.issueNonce(fakeCtx);
		expect(second).not.toBe(first);
		expect(await provider.isValid(second, fakeCtx)).toBe(true);
		expect(await provider.isValid(first, fakeCtx)).toBe(true); // previous still accepted
	});

	it("retainPrevious=false rejects previous nonce after rotation", async () => {
		let now = 1_000_000;
		const provider = memoryNonceProvider({
			rotateAfter: 1000,
			retainPrevious: false,
			clock: () => now,
		});
		const first = await provider.issueNonce(fakeCtx);
		now += 1500;
		const second = await provider.issueNonce(fakeCtx);
		expect(await provider.isValid(first, fakeCtx)).toBe(false);
		expect(await provider.isValid(second, fakeCtx)).toBe(true);
	});

	it("does not rotate within rotateAfter window", async () => {
		let now = 1_000_000;
		const provider = memoryNonceProvider({ rotateAfter: 5000, clock: () => now });
		const a = await provider.issueNonce(fakeCtx);
		now += 100;
		const b = await provider.issueNonce(fakeCtx);
		expect(a).toBe(b);
	});

	it("isValid also triggers rotation when due", async () => {
		let now = 1_000_000;
		const provider = memoryNonceProvider({ rotateAfter: 1000, clock: () => now });
		const first = await provider.issueNonce(fakeCtx);
		now += 1500;
		// Trigger rotation via isValid (first becomes previous)
		expect(await provider.isValid(first, fakeCtx)).toBe(true);
		const second = await provider.issueNonce(fakeCtx);
		expect(second).not.toBe(first);
	});

	describe("boundary cases", () => {
		// rotateAfter=0 with `now - rotatedAt < rotateAfter` is `0 < 0` → false → rotation
		// triggers on every call (any positive delta also satisfies it).
		it("rotateAfter=0 issues a new nonce on every call", async () => {
			let now = 1_000_000;
			const provider = memoryNonceProvider({ rotateAfter: 0, clock: () => now });
			const a = await provider.issueNonce(fakeCtx);
			now += 1;
			const b = await provider.issueNonce(fakeCtx);
			now += 1;
			const c = await provider.issueNonce(fakeCtx);
			expect(a).not.toBe(b);
			expect(b).not.toBe(c);
		});

		it("clock advanced by 999ms (< rotateAfter=1000) keeps the same nonce", async () => {
			let now = 1_000_000;
			const provider = memoryNonceProvider({ rotateAfter: 1000, clock: () => now });
			const first = await provider.issueNonce(fakeCtx);
			now += 999;
			const second = await provider.issueNonce(fakeCtx);
			expect(second).toBe(first);
		});

		// Implementation uses `now - rotatedAt < rotateAfter`, so exactly `rotateAfter`
		// fails the guard and triggers rotation.
		it("clock advanced by exactly rotateAfter triggers rotation (uses strict <)", async () => {
			let now = 1_000_000;
			const provider = memoryNonceProvider({ rotateAfter: 1000, clock: () => now });
			const first = await provider.issueNonce(fakeCtx);
			now += 1000;
			const second = await provider.issueNonce(fakeCtx);
			expect(second).not.toBe(first);
		});

		it("retainPrevious=false: previous nonce becomes invalid after rotation", async () => {
			let now = 1_000_000;
			const provider = memoryNonceProvider({
				rotateAfter: 1000,
				retainPrevious: false,
				clock: () => now,
			});
			const first = await provider.issueNonce(fakeCtx);
			now += 1500;
			await provider.issueNonce(fakeCtx); // trigger rotation
			expect(await provider.isValid(first, fakeCtx)).toBe(false);
		});

		// Provider only retains a single previous nonce — after a second rotation the
		// oldest one is dropped and isValid returns false for it.
		it("retainPrevious=true keeps only one previous; the older one becomes invalid", async () => {
			let now = 1_000_000;
			const provider = memoryNonceProvider({
				rotateAfter: 1000,
				retainPrevious: true,
				clock: () => now,
			});
			const first = await provider.issueNonce(fakeCtx);
			now += 1500;
			const second = await provider.issueNonce(fakeCtx);
			// After 1st rotation: first is "previous" and accepted
			expect(await provider.isValid(first, fakeCtx)).toBe(true);
			now += 1500;
			const third = await provider.issueNonce(fakeCtx);
			// After 2nd rotation: second is now "previous"; first is forgotten
			expect(await provider.isValid(third, fakeCtx)).toBe(true);
			expect(await provider.isValid(second, fakeCtx)).toBe(true);
			expect(await provider.isValid(first, fakeCtx)).toBe(false);
		});

		// `now - rotatedAt < rotateAfter` is true for negative delta (-N < positive N),
		// so a backwards clock jump never triggers rotation.
		it("backwards clock jump does not trigger rotation", async () => {
			let now = 1_000_000;
			const provider = memoryNonceProvider({ rotateAfter: 1000, clock: () => now });
			const first = await provider.issueNonce(fakeCtx);
			now -= 5_000;
			const second = await provider.issueNonce(fakeCtx);
			expect(second).toBe(first);
		});

		it("isValid('') returns false when no empty nonce was issued", async () => {
			const provider = memoryNonceProvider();
			expect(await provider.isValid("", fakeCtx)).toBe(false);
		});

		it("isValid for an unrelated UUID returns false", async () => {
			const provider = memoryNonceProvider();
			expect(await provider.isValid("11111111-1111-1111-1111-111111111111", fakeCtx)).toBe(false);
		});
	});
});
