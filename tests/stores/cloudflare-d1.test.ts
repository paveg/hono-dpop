import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { d1Store } from "../../src/stores/cloudflare-d1.js";

interface D1DatabaseMock {
	rows: Map<string, { jti: string; expires_at: number }>;
	createTableCalls: number;
	prepare(sql: string): {
		bind(...params: unknown[]): {
			run(): Promise<{ success: boolean; meta: { changes: number } }>;
			first(): Promise<Record<string, unknown> | null>;
		};
		run(): Promise<{ success: boolean; meta: { changes: number } }>;
		first(): Promise<Record<string, unknown> | null>;
	};
}

function createMockD1(): D1DatabaseMock {
	const rows = new Map<string, { jti: string; expires_at: number }>();
	const counters = { createTableCalls: 0 };

	function createStatement(sql: string) {
		let boundParams: unknown[] = [];
		const stmt = {
			bind(...params: unknown[]) {
				boundParams = params;
				return stmt;
			},
			async run() {
				if (sql.startsWith("CREATE TABLE")) {
					counters.createTableCalls++;
					return { success: true, meta: { changes: 0 } };
				}
				if (sql.startsWith("INSERT OR IGNORE")) {
					const jti = boundParams[0] as string;
					const expires_at = boundParams[1] as number;
					if (rows.has(jti)) {
						return { success: true, meta: { changes: 0 } };
					}
					rows.set(jti, { jti, expires_at });
					return { success: true, meta: { changes: 1 } };
				}
				if (sql.startsWith("DELETE")) {
					const threshold = boundParams[0] as number;
					let deleted = 0;
					for (const [k, row] of rows) {
						if (row.expires_at < threshold) {
							rows.delete(k);
							deleted++;
						}
					}
					return { success: true, meta: { changes: deleted } };
				}
				return { success: true, meta: { changes: 0 } };
			},
			async first() {
				return null;
			},
		};
		return stmt;
	}

	return {
		rows,
		get createTableCalls() {
			return counters.createTableCalls;
		},
		prepare: (sql: string) => createStatement(sql),
	};
}

describe("d1Store", () => {
	beforeEach(() => vi.useFakeTimers());
	afterEach(() => vi.useRealTimers());

	it("returns true and inserts when jti is new", async () => {
		const db = createMockD1();
		const store = d1Store({ database: db });
		expect(await store.check("a", Date.now() + 60_000)).toBe(true);
		expect(db.rows.has("a")).toBe(true);
	});

	it("returns false on replay (PRIMARY KEY collision)", async () => {
		const db = createMockD1();
		const store = d1Store({ database: db });
		const exp = Date.now() + 60_000;
		expect(await store.check("a", exp)).toBe(true);
		expect(await store.check("a", exp)).toBe(false);
	});

	it("uses default tableName 'dpop_jti'", async () => {
		const db = createMockD1();
		const captured: string[] = [];
		const origPrepare = db.prepare;
		db.prepare = (sql: string) => {
			captured.push(sql);
			return origPrepare(sql);
		};
		const store = d1Store({ database: db });
		await store.check("a", Date.now() + 60_000);
		expect(captured.some((s) => s.includes("dpop_jti"))).toBe(true);
	});

	it("accepts custom tableName matching the regex", async () => {
		const db = createMockD1();
		const store = d1Store({ database: db, tableName: "my_dpop_replay_v2" });
		expect(await store.check("a", Date.now() + 60_000)).toBe(true);
	});

	it("rejects invalid tableName (SQL injection guard)", () => {
		const db = createMockD1();
		expect(() => d1Store({ database: db, tableName: "x; DROP TABLE users--" })).toThrow(
			/invalid table name/i,
		);
	});

	it("rejects tableName starting with a digit", () => {
		const db = createMockD1();
		expect(() => d1Store({ database: db, tableName: "1bad" })).toThrow(/invalid table name/i);
	});

	it("accepts identifiers starting with underscore", () => {
		const db = createMockD1();
		expect(() => d1Store({ database: db, tableName: "_priv" })).not.toThrow();
	});

	it("CREATE TABLE IF NOT EXISTS runs once per instance, not per call", async () => {
		const db = createMockD1();
		const store = d1Store({ database: db });
		await store.check("a", Date.now() + 60_000);
		await store.check("b", Date.now() + 60_000);
		await store.check("c", Date.now() + 60_000);
		expect(db.createTableCalls).toBe(1);
	});

	it("purge() deletes only rows with expires_at < now and returns count", async () => {
		const db = createMockD1();
		const store = d1Store({ database: db });
		await store.check("expired-1", Date.now() + 100);
		await store.check("expired-2", Date.now() + 200);
		await store.check("fresh", Date.now() + 60_000);
		vi.advanceTimersByTime(300);
		const removed = await store.purge();
		expect(removed).toBe(2);
		expect(db.rows.has("fresh")).toBe(true);
	});

	it("purge() on empty table returns 0", async () => {
		const db = createMockD1();
		const store = d1Store({ database: db });
		expect(await store.purge()).toBe(0);
	});

	describe("boundary cases", () => {
		it('accepts tableName "my_table_v2"', () => {
			const db = createMockD1();
			expect(() => d1Store({ database: db, tableName: "my_table_v2" })).not.toThrow();
		});

		it("rejects tableName containing quote and semicolon (SQL injection attempt)", () => {
			const db = createMockD1();
			expect(() => d1Store({ database: db, tableName: '"; DROP TABLE x;--' })).toThrow(
				/invalid table name/i,
			);
		});

		it('rejects "1bad" (starts with digit)', () => {
			const db = createMockD1();
			expect(() => d1Store({ database: db, tableName: "1bad" })).toThrow(/invalid table name/i);
		});

		it('rejects "a-b" (hyphen not allowed)', () => {
			const db = createMockD1();
			expect(() => d1Store({ database: db, tableName: "a-b" })).toThrow(/invalid table name/i);
		});

		it('rejects "" (empty tableName)', () => {
			const db = createMockD1();
			expect(() => d1Store({ database: db, tableName: "" })).toThrow(/invalid table name/i);
		});

		it('rejects "valid name" (whitespace not allowed)', () => {
			const db = createMockD1();
			expect(() => d1Store({ database: db, tableName: "valid name" })).toThrow(
				/invalid table name/i,
			);
		});

		it("accepts a 100-character tableName (regex has no length limit)", () => {
			const db = createMockD1();
			const longName = "a".repeat(100);
			expect(() => d1Store({ database: db, tableName: longName })).not.toThrow();
		});

		it("INSERT OR IGNORE with changes=1 returns true", async () => {
			const db = createMockD1();
			const store = d1Store({ database: db });
			expect(await store.check("a", Date.now() + 60_000)).toBe(true);
		});

		it("INSERT OR IGNORE with changes=0 returns false (replay)", async () => {
			const db = createMockD1();
			const store = d1Store({ database: db });
			const exp = Date.now() + 60_000;
			await store.check("a", exp);
			expect(await store.check("a", exp)).toBe(false);
		});

		it("purge() deletes only rows where expires_at < now and returns the count", async () => {
			const db = createMockD1();
			const store = d1Store({ database: db });
			await store.check("expired-a", Date.now() + 100);
			await store.check("expired-b", Date.now() + 200);
			await store.check("fresh", Date.now() + 60_000);
			vi.advanceTimersByTime(300);
			expect(await store.purge()).toBe(2);
			expect(db.rows.has("fresh")).toBe(true);
		});

		// `INSERT OR IGNORE` collides on PRIMARY KEY regardless of expires_at, so an
		// expired row blocks re-acquisition until purge() removes it. This is the
		// documented design — operators must run purge() periodically.
		it("expired row in table still blocks the same jti until purged", async () => {
			const db = createMockD1();
			const store = d1Store({ database: db });
			await store.check("a", Date.now() + 100);
			vi.advanceTimersByTime(1000);
			// Same jti, fresh window — but PRIMARY KEY collision still rejects it
			expect(await store.check("a", Date.now() + 60_000)).toBe(false);
			// After purge() the slot is freed
			await store.purge();
			expect(await store.check("a", Date.now() + 60_000)).toBe(true);
		});
	});
});
