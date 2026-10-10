import { test } from "node:test";
import assert from "node:assert/strict";
import { AntlionError } from "../../index.js";
import { RedisReplayStore, type RedisClientLike } from "../../redis.js";

/** A node-redis-shaped client that answers every command with `reply` and records what it was sent. */
function nodeRedis(reply: unknown): RedisClientLike & { sent: string[][] } {
	const sent: string[][] = [];
	return {
		sent,
		async sendCommand(args: string[]) {
			sent.push(args);
			return reply;
		},
	};
}

test("each proof is one SET with the prefix, PX in milliseconds, and NX", async () => {
	const client = nodeRedis("OK");
	await new RedisReplayStore({ client, prefix: "dpop:" }).addIfAbsent("jkt:hash", 66);
	assert.deepEqual(client.sent, [["SET", "dpop:jkt:hash", "1", "PX", "66000", "NX"]]);
});

test("a fractional TTL is rounded up to the next millisecond, never down", async () => {
	const client = nodeRedis("OK");
	await new RedisReplayStore({ client, prefix: "p:" }).addIfAbsent("k", 0.0001);
	assert.equal(client.sent[0]?.[4], "1");
});

test("an ioredis client is driven through call, with the command name split from its arguments", async () => {
	const calls: [string, string[]][] = [];
	const ioredis = {
		async call(command: string, args: string[]) {
			calls.push([command, args]);
			return "OK";
		},
		// ioredis has a sendCommand too, taking a Command object; it must not be used.
		sendCommand() {
			throw new Error("sendCommand called on an ioredis client");
		},
	};
	assert.equal(await new RedisReplayStore({ client: ioredis, prefix: "p:" }).addIfAbsent("k", 6), true);
	assert.deepEqual(calls, [["SET", ["p:k", "1", "PX", "6000", "NX"]]]);
});

test("OK means recorded, null means already there", async () => {
	assert.equal(await new RedisReplayStore({ client: nodeRedis("OK"), prefix: "p:" }).addIfAbsent("k", 1), true);
	assert.equal(await new RedisReplayStore({ client: nodeRedis(null), prefix: "p:" }).addIfAbsent("k", 1), false);
});

test("any other reply is a replay-store-failed error, never an answer", async () => {
	for (const reply of [undefined, "ok", "QUEUED", 1, 0, true, false, ["OK"], {}]) {
		const store = new RedisReplayStore({ client: nodeRedis(reply), prefix: "p:" });
		await assert.rejects(store.addIfAbsent("k", 1), (error: unknown) => {
			assert.ok(error instanceof AntlionError);
			assert.equal(error.code, "replay-store-failed");
			return true;
		});
	}
});

test("an error from the client comes back unchanged", async () => {
	const boom = new Error("ECONNRESET");
	const store = new RedisReplayStore({ client: { sendCommand: async () => { throw boom; } }, prefix: "p:" });
	await assert.rejects(store.addIfAbsent("k", 1), (error) => error === boom);
});

test("the client is required, and must have call or sendCommand", () => {
	for (const client of [undefined, null, {}, "redis://localhost", { sendCommand: "no" }, { call: 1 }]) {
		assert.throws(
			() => new RedisReplayStore({ client, prefix: "p:" } as never),
			{ code: "invalid-options", message: /client is required/ }
		);
	}
});

test("the prefix is required and may not be empty", () => {
	for (const prefix of [undefined, null, "", 1]) {
		assert.throws(
			() => new RedisReplayStore({ client: nodeRedis("OK"), prefix } as never),
			{ code: "invalid-options", message: /prefix is required/ }
		);
	}
});
