import { test } from "node:test";
import assert from "node:assert/strict";
import { AntlionError } from "../../index.js";
import { PostgresReplayStore, type PostgresClientLike } from "../../postgres.js";

/** A pg-shaped client that answers every query with `rowCount` and records what it was sent. */
function pg(rowCount: unknown): PostgresClientLike & { sent: [string, unknown[]][] } {
	const sent: [string, unknown[]][] = [];
	return {
		sent,
		async query(text: string, values: unknown[]) {
			sent.push([text, values]);
			return { rowCount } as { rowCount: number | null };
		},
	};
}

test("each proof is one parameterised upsert that only replaces an expired row", async () => {
	const client = pg(1);
	await new PostgresReplayStore({ client, table: "dpop_replay" }).addIfAbsent("jkt:hash", 66);
	const [[text, values]] = client.sent as [[string, unknown[]]];
	assert.equal(
		text,
		"INSERT INTO \"dpop_replay\" AS t (key, expires_at) " +
			"VALUES ($1::text, clock_timestamp() + $2::double precision * interval '1 millisecond') " +
			"ON CONFLICT (key) DO UPDATE SET expires_at = EXCLUDED.expires_at " +
			"WHERE t.expires_at <= clock_timestamp()"
	);
	assert.deepEqual(values, ["jkt:hash", 66_000]);
});

test("a schema-qualified table is quoted part by part", async () => {
	const client = pg(1);
	await new PostgresReplayStore({ client, table: "auth.dpop_replay" }).addIfAbsent("k", 1);
	assert.match(client.sent[0]?.[0] ?? "", /^INSERT INTO "auth"\."dpop_replay" AS t /);
});

test("one row means recorded, zero means already there", async () => {
	assert.equal(await new PostgresReplayStore({ client: pg(1), table: "t" }).addIfAbsent("k", 1), true);
	assert.equal(await new PostgresReplayStore({ client: pg(0), table: "t" }).addIfAbsent("k", 1), false);
});

test("any other row count is a replay-store-failed error, never an answer", async () => {
	for (const rowCount of [null, undefined, 2, -1, "1", true]) {
		const store = new PostgresReplayStore({ client: pg(rowCount), table: "t" });
		await assert.rejects(store.addIfAbsent("k", 1), (error: unknown) => {
			assert.ok(error instanceof AntlionError);
			assert.equal(error.code, "replay-store-failed");
			return true;
		});
	}
});

test("an error from the client comes back unchanged", async () => {
	const boom = new Error("relation \"t\" does not exist");
	const store = new PostgresReplayStore({ client: { query: async () => { throw boom; } }, table: "t" });
	await assert.rejects(store.addIfAbsent("k", 1), (error) => error === boom);
	await assert.rejects(store.deleteExpired(), (error) => error === boom);
});

test("deleteExpired deletes rows whose expiry has passed and resolves how many", async () => {
	const client = pg(7);
	assert.equal(await new PostgresReplayStore({ client, table: "t" }).deleteExpired(), 7);
	assert.deepEqual(client.sent, [["DELETE FROM \"t\" WHERE expires_at <= clock_timestamp()", []]]);
	assert.equal(await new PostgresReplayStore({ client: pg(null), table: "t" }).deleteExpired(), 0);
});

test("the client is required, and must have query", () => {
	for (const client of [undefined, null, {}, "postgres://localhost", { query: "no" }]) {
		assert.throws(
			() => new PostgresReplayStore({ client, table: "t" } as never),
			{ code: "invalid-options", message: /client is required/ }
		);
	}
});

test("the table is required, and nothing but a plain or schema-qualified identifier is accepted", () => {
	const accepted = ["t", "_t", "dpop_replay", "auth.dpop_replay", "T1", "a".repeat(63)];
	for (const table of accepted) assert.doesNotThrow(() => new PostgresReplayStore({ client: pg(1), table }));
	const refused = [
		undefined, null, 1, "", ".", "a.", ".a", "a.b.c", "1t", "a b", "t;drop table users", "\"t\"",
		"t--", "a-b", "a".repeat(64), "t\u00e9", "t\n",
	];
	for (const table of refused) {
		assert.throws(
			() => new PostgresReplayStore({ client: pg(1), table } as never),
			{ code: "invalid-options", message: /table is required/ },
			String(table)
		);
	}
});
