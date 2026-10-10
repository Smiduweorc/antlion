import { AntlionError } from "./errors.js";
import type { ReplayStore } from "./replay-store.js";

/** The one method of a Postgres client the store calls. A `pg` `Pool` or `Client` is one. */
export interface PostgresClientLike {
	query(text: string, values: unknown[]): Promise<{ rowCount: number | null }>;
}

export interface PostgresReplayStoreOptions {
	/**
	 * Required. A `pg` `Pool`, or anything with its `query(text, values)`. You
	 * own it: connecting, pool size, timeouts and closing are yours, and an
	 * error from it refuses the request it was serving.
	 */
	client: PostgresClientLike;
	/**
	 * Required. The table, as `name` or `schema.name`, in letters, digits and
	 * underscores. Antlion never creates or alters it; see
	 * {@link PostgresReplayStore} for the statement.
	 */
	table: string;
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

/**
 * A replay store shared by every process connected to one Postgres.
 *
 * Create the table once, the way you create your others:
 *
 * ```sql
 * CREATE TABLE dpop_replay (
 * 	key text PRIMARY KEY,
 * 	expires_at timestamptz NOT NULL
 * );
 * CREATE INDEX ON dpop_replay (expires_at);
 * ```
 *
 * Not `UNLOGGED`: an unlogged table is emptied after a crash, and every
 * proof still inside its window is then accepted once more.
 *
 * Each proof is one `INSERT ... ON CONFLICT (key) DO UPDATE ... WHERE` the
 * existing row has expired, so the key is recorded only if it is absent or
 * dead, atomically, inside Postgres. Expiry is on the database's clock, so
 * the nodes' clocks never meet here.
 *
 * Expired rows stay until {@link PostgresReplayStore.deleteExpired} removes
 * them. Antlion starts no timers, so schedule it yourself.
 */
export class PostgresReplayStore implements ReplayStore {
	readonly #client: PostgresClientLike;
	readonly #insert: string;
	readonly #delete: string;

	constructor(options: PostgresReplayStoreOptions) {
		const { client, table } = options;
		if (typeof client !== "object" || client === null || typeof client.query !== "function") {
			throw new AntlionError("invalid-options", "PostgresReplayStore client is required: a pg Pool or Client");
		}
		const parts = typeof table === "string" ? table.split(".") : [];
		if (parts.length < 1 || parts.length > 2 || !parts.every((part) => IDENTIFIER.test(part))) {
			throw new AntlionError(
				"invalid-options",
				"PostgresReplayStore table is required, as name or schema.name in letters, digits and underscores"
			);
		}
		const quoted = parts.map((part) => `"${part}"`).join(".");
		this.#client = client;
		this.#insert =
			`INSERT INTO ${quoted} AS t (key, expires_at) ` +
			"VALUES ($1::text, clock_timestamp() + $2::double precision * interval '1 millisecond') " +
			"ON CONFLICT (key) DO UPDATE SET expires_at = EXCLUDED.expires_at " +
			"WHERE t.expires_at <= clock_timestamp()";
		this.#delete = `DELETE FROM ${quoted} WHERE expires_at <= clock_timestamp()`;
	}

	async addIfAbsent(key: string, ttlSeconds: number): Promise<boolean> {
		const { rowCount } = await this.#client.query(this.#insert, [key, Math.ceil(ttlSeconds * 1000)]);
		if (rowCount === 1) return true;
		if (rowCount === 0) return false;
		throw new AntlionError(
			"replay-store-failed",
			`PostgresReplayStore expected 0 or 1 rows from the insert, received ${String(rowCount)}`
		);
	}

	/**
	 * Delete every expired row, and resolve how many went. Nothing breaks if
	 * you never call it, except that the table grows by one row per accepted
	 * request. Once a minute is plenty: a row is dead `maxProofAge` plus six
	 * seconds after it was written.
	 */
	async deleteExpired(): Promise<number> {
		const { rowCount } = await this.#client.query(this.#delete, []);
		return rowCount ?? 0;
	}
}
