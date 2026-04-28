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
});
