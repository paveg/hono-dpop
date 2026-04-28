import type { DPoPNonceStore } from "./types.js";

const DEFAULT_TABLE = "dpop_jti";
const TABLE_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Minimal D1Database subset used by d1Store (avoids @cloudflare/workers-types dependency). */
export interface D1DatabaseLike {
	prepare(sql: string): D1PreparedStatementLike;
}

export interface D1PreparedStatementLike {
	bind(...params: unknown[]): D1PreparedStatementLike;
	run(): Promise<{ success: boolean; meta: { changes: number } }>;
	first(): Promise<Record<string, unknown> | null>;
}

export interface D1StoreOptions {
	/** Cloudflare D1 database binding. */
	database: D1DatabaseLike;
	/** Table name (default: "dpop_jti"). Must match /^[A-Za-z_][A-Za-z0-9_]*$/. */
	tableName?: string;
}

/**
 * Cloudflare D1-backed replay cache. Uses `INSERT OR IGNORE` on a `jti` PRIMARY KEY for
 * an atomic insert-if-absent: D1 reports `meta.changes === 1` for fresh inserts, `0` for
 * collisions. Strong consistency from the SQLite primary makes this safe across
 * concurrent Worker invocations.
 *
 * Note: `INSERT OR IGNORE` does not honor TTL — an expired-but-not-yet-purged row will
 * still block re-acquisition of the same jti. Operators should call `purge()` periodically
 * (cron trigger or scheduled handler) to delete rows whose `expires_at < now`.
 *
 * The schema is created on demand via `CREATE TABLE IF NOT EXISTS` once per instance.
 */
export function d1Store(options: D1StoreOptions): DPoPNonceStore {
	const { database: db, tableName = DEFAULT_TABLE } = options;

	if (!TABLE_NAME_RE.test(tableName)) {
		throw new Error(`Invalid table name: "${tableName}". Must match ${TABLE_NAME_RE}`);
	}

	let initialized = false;

	const ensureTable = async (): Promise<void> => {
		if (initialized) return;
		await db
			.prepare(
				`CREATE TABLE IF NOT EXISTS ${tableName} (
				jti TEXT PRIMARY KEY,
				expires_at INTEGER NOT NULL
			)`,
			)
			.run();
		initialized = true;
	};

	return {
		async check(jti, expiresAt) {
			await ensureTable();
			const result = await db
				.prepare(`INSERT OR IGNORE INTO ${tableName} (jti, expires_at) VALUES (?, ?)`)
				.bind(jti, expiresAt)
				.run();
			return result.meta.changes === 1;
		},

		async purge() {
			await ensureTable();
			const result = await db
				.prepare(`DELETE FROM ${tableName} WHERE expires_at < ?`)
				.bind(Date.now())
				.run();
			return result.meta.changes;
		},
	};
}
