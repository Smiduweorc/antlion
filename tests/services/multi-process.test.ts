/**
 * Several Node processes, one proof, sent to all of them at once. With a
 * shared store exactly one accepts it. With a SingleProcessReplayStore in
 * each, every one accepts it, which is the failure the shared stores exist
 * to prevent and the reason the in-memory store's name says what it is.
 */

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { importKey, newAccessToken } from "lacewing";
import pg from "pg";
import { AUDIENCE, clientKey, ISSUER, proofFor } from "../helpers.js";
import { serviceUrl } from "./env.js";
import type { WorkerInput } from "./worker.js";

const WORKERS = 4;
const WORKER = fileURLToPath(new URL("./worker.ts", import.meta.url));
const redisUrl = serviceUrl("ANTLION_TEST_REDIS_URL");
const postgresUrl = serviceUrl("ANTLION_TEST_POSTGRES_URL");
const run = crypto.randomUUID().replaceAll("-", "");
const table = `antlion_test_mp_${run}`;
const pool = new pg.Pool({ connectionString: postgresUrl, max: 1 });

before(() => pool.query(`CREATE TABLE ${table} (key text PRIMARY KEY, expires_at timestamptz NOT NULL)`));
after(async () => {
	await pool.query(`DROP TABLE ${table}`);
	await pool.end();
});

/** A token bound to a fresh client key, a proof for it, and the issuer's public key. */
async function oneProof(): Promise<Pick<WorkerInput, "issuerJwk" | "token" | "proof">> {
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
	const key = await clientKey();
	const token = await newAccessToken()
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.subject("user-42")
		.expiresIn("5m")
		.claim("cnf", { jkt: key.jkt })
		.sign(await importKey(pair.privateKey, "ES256"));
	const issuerJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
	return { issuerJwk, token, proof: await proofFor(key, token) };
}

/** Start every worker, wait until all are connected, release them together, collect what each said. */
async function race(store: WorkerInput["store"], url: string, namespace: string): Promise<string[]> {
	const input: WorkerInput = { ...(await oneProof()), store, url, namespace };
	const workers: { child: ChildProcessWithoutNullStreams; lines: AsyncIterator<string> }[] = [];
	for (let i = 0; i < WORKERS; i++) {
		const child = spawn(process.execPath, ["--import", "tsx", WORKER, JSON.stringify(input)]);
		child.stderr.pipe(process.stderr);
		workers.push({ child, lines: createInterface({ input: child.stdout })[Symbol.asyncIterator]() });
	}
	for (const { lines } of workers) assert.equal((await lines.next()).value, "ready");
	for (const { child } of workers) child.stdin.write("go\n");
	const outcomes = await Promise.all(workers.map(async ({ lines }) => String((await lines.next()).value)));
	await Promise.all(workers.map(({ child }) => (child.exitCode === null ? once(child, "exit") : undefined)));
	for (const { child } of workers) assert.equal(child.exitCode, 0);
	return outcomes.sort();
}

test(`${WORKERS} processes sharing a RedisReplayStore accept one proof exactly once`, async () => {
	assert.deepEqual(await race("redis", redisUrl, `antlion-test:mp:${run}:`), [
		"accepted",
		...Array<string>(WORKERS - 1).fill("replayed"),
	]);
});

test(`${WORKERS} processes sharing a PostgresReplayStore accept one proof exactly once`, async () => {
	assert.deepEqual(await race("postgres", postgresUrl, table), [
		"accepted",
		...Array<string>(WORKERS - 1).fill("replayed"),
	]);
});

test(`${WORKERS} processes each with a SingleProcessReplayStore all accept the same proof`, async () => {
	assert.deepEqual(await race("single-process", "", ""), Array<string>(WORKERS).fill("accepted"));
});
