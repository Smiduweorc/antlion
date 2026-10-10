/**
 * PostgresReplayStore against a real Postgres. Expiry is the server's, so
 * time passes for real here; there is no clock to swap.
 */

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { PostgresReplayStore } from "../../postgres.js";
import { notAntlion, replayStoreContract } from "../replay-contract.js";
import { serviceUrl, sleep } from "./env.js";

const url = serviceUrl("ANTLION_TEST_POSTGRES_URL");
// Enough connections that 50 concurrent inserts really are concurrent.
const pool = new pg.Pool({ connectionString: url, max: 20 });
const schema = `antlion_test_${crypto.randomUUID().replaceAll("-", "")}`;

let tables = 0;
async function freshTable(): Promise<string> {
	const table = `${schema}.replay_${tables++}`;
	// The statement the PostgresReplayStore doc comment tells people to run.
	await pool.query(`CREATE TABLE ${table} (key text PRIMARY KEY, expires_at timestamptz NOT NULL)`);
	await pool.query(`CREATE INDEX ON ${table} (expires_at)`);
	return table;
}

before(() => pool.query(`CREATE SCHEMA ${schema}`));
after(async () => {
	await pool.query(`DROP SCHEMA ${schema} CASCADE`);
	await pool.end();
});

replayStoreContract("PostgresReplayStore with pg", {
	fresh: async () => new PostgresReplayStore({ client: pool, table: await freshTable() }),
	async broken() {
		const store = new PostgresReplayStore({ client: pool, table: `${schema}.never_created` });
		return { store, isBackendError: (cause) => notAntlion(cause) && cause instanceof pg.DatabaseError };
	},
	elapse: sleep,
	shortTtl: 0.5,
});

test("the row Postgres holds expires after the TTL Antlion asked for, on the database's clock", async () => {
	const table = await freshTable();
	await new PostgresReplayStore({ client: pool, table }).addIfAbsent("jkt:hash", 66);
	const { rows } = await pool.query<{ ms: number }>(
		`SELECT extract(epoch FROM expires_at - clock_timestamp()) * 1000 AS ms FROM ${table} WHERE key = 'jkt:hash'`
	);
	const ms = Number(rows[0]?.ms);
	assert.ok(ms > 65_000 && ms <= 66_000, `expires in ${ms} ms`);
});

test("deleteExpired removes expired rows and keeps live ones", async () => {
	const table = await freshTable();
	const store = new PostgresReplayStore({ client: pool, table });
	await store.addIfAbsent("short-1", 0.2);
	await store.addIfAbsent("short-2", 0.2);
	await store.addIfAbsent("long", 66);
	assert.equal(await store.deleteExpired(), 0);
	await sleep(300);
	assert.equal(await store.deleteExpired(), 2);
	const { rows } = await pool.query<{ key: string }>(`SELECT key FROM ${table}`);
	assert.deepEqual(rows.map((row) => row.key), ["long"]);
	assert.equal(await store.addIfAbsent("long", 66), false);
});

test("an expired row nobody has deleted yet does not block the key", async () => {
	const table = await freshTable();
	const store = new PostgresReplayStore({ client: pool, table });
	assert.equal(await store.addIfAbsent("k", 0.2), true);
	await sleep(300);
	assert.equal(await store.addIfAbsent("k", 66), true);
	assert.equal(await store.addIfAbsent("k", 66), false);
});

test("50 concurrent adds racing an expired row admit exactly one", async () => {
	const table = await freshTable();
	const store = new PostgresReplayStore({ client: pool, table });
	await store.addIfAbsent("k", 0.2);
	await sleep(300);
	const results = await Promise.all(Array.from({ length: 50 }, () => store.addIfAbsent("k", 66)));
	assert.equal(results.filter(Boolean).length, 1);
});
