/**
 * RedisReplayStore against a real Redis, through both clients people use.
 * Expiry is the server's, so time passes for real here; there is no clock
 * to swap.
 */

import { after, test } from "node:test";
import assert from "node:assert/strict";
import { Redis } from "ioredis";
import { createClient } from "redis";
import { RedisReplayStore } from "../../redis.js";
import { notAntlion, replayStoreContract } from "../replay-contract.js";
import { serviceUrl, sleep } from "./env.js";

const url = serviceUrl("ANTLION_TEST_REDIS_URL");
const run = crypto.randomUUID();

const nodeRedis = await createClient({ url }).connect();
const ioredis = new Redis(url);
after(async () => {
	nodeRedis.destroy();
	ioredis.disconnect();
});

let namespaces = 0;
const prefix = (): string => `antlion-test:${run}:${namespaces++}:`;

replayStoreContract("RedisReplayStore with node-redis", {
	fresh: async () => new RedisReplayStore({ client: nodeRedis, prefix: prefix() }),
	async broken() {
		const closed = await createClient({ url }).connect();
		closed.destroy();
		return { store: new RedisReplayStore({ client: closed, prefix: prefix() }), isBackendError: notAntlion };
	},
	elapse: sleep,
	shortTtl: 0.5,
});

replayStoreContract("RedisReplayStore with ioredis", {
	fresh: async () => new RedisReplayStore({ client: ioredis, prefix: prefix() }),
	async broken() {
		const closed = new Redis(url);
		await closed.ping();
		closed.disconnect();
		return { store: new RedisReplayStore({ client: closed, prefix: prefix() }), isBackendError: notAntlion };
	},
	elapse: sleep,
	shortTtl: 0.5,
});

test("the key Redis holds is the prefix plus the replay key, set to expire after the TTL Antlion asked for", async () => {
	const namespace = prefix();
	await new RedisReplayStore({ client: ioredis, prefix: namespace }).addIfAbsent("jkt:hash", 66);
	assert.equal(await ioredis.get(`${namespace}jkt:hash`), "1");
	const pttl = await ioredis.pttl(`${namespace}jkt:hash`);
	assert.ok(pttl > 65_000 && pttl <= 66_000, `PTTL was ${pttl}`);
});

test("a key some other writer left under the prefix reads as a replay, never as a fresh proof", async () => {
	const namespace = prefix();
	await ioredis.set(`${namespace}jkt:hash`, "something else", "PX", 66_000);
	assert.equal(await new RedisReplayStore({ client: ioredis, prefix: namespace }).addIfAbsent("jkt:hash", 66), false);
});

test("two prefixes on one Redis are two stores", async () => {
	const a = new RedisReplayStore({ client: nodeRedis, prefix: prefix() });
	const b = new RedisReplayStore({ client: nodeRedis, prefix: prefix() });
	assert.equal(await a.addIfAbsent("k", 66), true);
	assert.equal(await b.addIfAbsent("k", 66), true);
	assert.equal(await a.addIfAbsent("k", 66), false);
});
