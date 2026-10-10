/**
 * One server process for the multi-process test. It builds its own profile
 * and its own store client, says "ready", waits for "go" on stdin so every
 * worker verifies at the same moment, then prints "accepted" or the refusal
 * code and exits.
 */

import type { webcrypto } from "node:crypto";
import process from "node:process";
import { accessTokenProfile, importKey } from "lacewing";
import { Redis } from "ioredis";
import pg from "pg";
import { AntlionError, defineDPoPProfile, SingleProcessReplayStore, verifyDPoPRequest, type ReplayStore } from "../../index.js";
import { PostgresReplayStore } from "../../postgres.js";
import { RedisReplayStore } from "../../redis.js";
import { AUDIENCE, ISSUER, ORIGIN, T0, URL_ } from "../helpers.js";

export interface WorkerInput {
	issuerJwk: webcrypto.JsonWebKey;
	token: string;
	proof: string;
	store: "redis" | "postgres" | "single-process";
	url: string;
	/** A Redis prefix or a Postgres table. */
	namespace: string;
}

const input = JSON.parse(process.argv[2] ?? "") as WorkerInput;

let replay: ReplayStore;
let close = async (): Promise<void> => {};
if (input.store === "redis") {
	const client = new Redis(input.url);
	replay = new RedisReplayStore({ client, prefix: input.namespace });
	close = async () => void (await client.quit());
} else if (input.store === "postgres") {
	const pool = new pg.Pool({ connectionString: input.url, max: 2 });
	replay = new PostgresReplayStore({ client: pool, table: input.namespace });
	close = () => pool.end();
} else {
	replay = new SingleProcessReplayStore({ maxEntries: 10 });
}

const dpop = defineDPoPProfile({
	token: accessTokenProfile({
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["ES256"],
		keys: await importKey(input.issuerJwk as never, "ES256"),
	}),
	origin: ORIGIN,
	replay,
	nonce: "off",
	now: () => T0,
});

// Warm the connection, so the race below is between verifications rather
// than between connection handshakes.
await replay.addIfAbsent(`warmup-${process.pid}`, 1);
process.stdout.write("ready\n");
await new Promise<void>((resolve) => process.stdin.once("data", () => resolve()));

const headers = new Headers({ authorization: `DPoP ${input.token}`, dpop: input.proof });
let outcome: string;
try {
	await verifyDPoPRequest(new Request(URL_, { headers }), dpop);
	outcome = "accepted";
} catch (error) {
	outcome = error instanceof AntlionError ? error.code : `error: ${String(error)}`;
}
process.stdout.write(`${outcome}\n`);
await close();
process.stdin.destroy();
