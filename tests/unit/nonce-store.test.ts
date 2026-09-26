import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { AntlionError, SingleProcessReplayStore } from "../../index.js";
import { decodeCanonical } from "../../src/base64url.js";
import { AntlionError as InternalError, withRefusal } from "../../src/errors.js";
import { Nonces } from "../../src/nonce.js";

const SECRET = new Uint8Array(32).fill(5);
const T = 1_790_000_000_000;

test("a nonce checks true from the second it is issued until maxAge seconds later, inclusive", async () => {
	const nonces = new Nonces([SECRET], "https://api.example.com", 60, 5);
	const nonce = await nonces.issue(T);
	assert.equal(await nonces.check(nonce, T), true);
	assert.equal(await nonces.check(nonce, T + 60_999), true);
	assert.equal(await nonces.check(nonce, T + 61_000), false);
	assert.equal(await nonces.check(nonce, T - 5_000), true);
	assert.equal(await nonces.check(nonce, T - 5_001), false);
});

test("a nonce carries its issue second in its first eight bytes, big-endian", async () => {
	const nonce = await new Nonces([SECRET], "https://api.example.com", 60, 5).issue(T + 999);
	const bytes = decodeCanonical(nonce) as Uint8Array;
	assert.equal(bytes.length, 40);
	assert.equal(new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(0), BigInt(T / 1000));
});

test("a nonce issued and checked at any pair of instants is accepted exactly inside the window", async () => {
	const nonces = new Nonces([SECRET], "https://api.example.com", 30, 5);
	await fc.assert(
		fc.asyncProperty(fc.integer({ min: 0, max: 10_000_000 }), fc.integer({ min: -60_000, max: 60_000 }), async (issuedAt, delta) => {
			const nonce = await nonces.issue(T + issuedAt);
			const age = Math.floor((T + issuedAt + delta) / 1000) - Math.floor((T + issuedAt) / 1000);
			assert.equal(await nonces.check(nonce, T + issuedAt + delta), age <= 30 && age >= -5);
		}),
		{ numRuns: 300 }
	);
});

test("any string that is not an issued nonce checks false", async () => {
	const nonces = new Nonces([SECRET], "https://api.example.com", 60, 5);
	await fc.assert(
		fc.asyncProperty(fc.string({ maxLength: 80 }), async (value) => {
			assert.equal(await nonces.check(value, T), false);
		}),
		{ numRuns: 300 }
	);
});

test("SingleProcessReplayStore adds once, then refuses the same key until its TTL passes", async () => {
	let now = 0;
	const store = new SingleProcessReplayStore({ maxEntries: 10, now: () => now });
	assert.equal(await store.addIfAbsent("k", 10), true);
	assert.equal(await store.addIfAbsent("k", 10), false);
	now = 9_999;
	assert.equal(await store.addIfAbsent("k", 10), false);
	now = 10_000;
	assert.equal(await store.addIfAbsent("k", 10), true);
	assert.equal(store.size, 1);
});

test("SingleProcessReplayStore refuses to forget a live key when full, and says so", async () => {
	let now = 0;
	const store = new SingleProcessReplayStore({ maxEntries: 2, now: () => now });
	await store.addIfAbsent("a", 10);
	await store.addIfAbsent("b", 10);
	await assert.rejects(store.addIfAbsent("c", 10), (error: unknown) =>
		error instanceof AntlionError && error.code === "replay-store-full" && error.refusal === undefined
	);
	assert.equal(await store.addIfAbsent("a", 10), false, "a full store still answers for keys it holds");
	now = 10_000;
	assert.equal(await store.addIfAbsent("c", 10), true);
	assert.equal(store.size, 1);
});

test("SingleProcessReplayStore sweeps expired keys stranded behind a live one when it fills", async () => {
	let now = 0;
	const store = new SingleProcessReplayStore({ maxEntries: 2, now: () => now });
	await store.addIfAbsent("long", 100);
	await store.addIfAbsent("short", 1);
	now = 1_000;
	assert.equal(await store.addIfAbsent("new", 1), true);
	assert.equal(store.size, 2);
});

test("SingleProcessReplayStore drops expired keys from the front as time passes", async () => {
	let now = 0;
	const store = new SingleProcessReplayStore({ maxEntries: 100, now: () => now });
	for (let i = 0; i < 10; i++) await store.addIfAbsent(`k${i}`, 5);
	now = 5_000;
	await store.addIfAbsent("fresh", 5);
	assert.equal(store.size, 1);
});

test("SingleProcessReplayStore defaults its clock to Date.now", async () => {
	const real = Date.now;
	let now = 0;
	Date.now = () => now;
	try {
		const store = new SingleProcessReplayStore({ maxEntries: 1 });
		assert.equal(await store.addIfAbsent("k", 1), true);
		now = 999;
		assert.equal(await store.addIfAbsent("k", 1), false);
		now = 1_000;
		assert.equal(await store.addIfAbsent("k", 1), true);
	} finally {
		Date.now = real;
	}
});

test("SingleProcessReplayStore matches a model under random adds and clock moves", async () => {
	await fc.assert(
		fc.asyncProperty(
			fc.array(
				fc.oneof(
					fc.record({ add: fc.constantFrom("a", "b", "c", "d"), ttl: fc.integer({ min: 1, max: 5 }) }),
					fc.record({ advance: fc.integer({ min: 0, max: 4_000 }) })
				),
				{ maxLength: 60 }
			),
			async (steps) => {
				let now = 0;
				const store = new SingleProcessReplayStore({ maxEntries: 1_000, now: () => now });
				const model = new Map<string, number>();
				for (const step of steps) {
					if ("advance" in step) {
						now += step.advance;
						continue;
					}
					const live = (model.get(step.add) ?? -1) > now;
					assert.equal(await store.addIfAbsent(step.add, step.ttl), !live);
					if (!live) model.set(step.add, now + step.ttl * 1000);
				}
			}
		),
		{ numRuns: 300 }
	);
});

test("withRefusal keeps the code, message, cause and stack, and adds the response", () => {
	const cause = new Error("inner");
	const original = new InternalError("replayed", "DPoP proof has been used before", { cause });
	const refusal = { status: 401 as const, headers: { "WWW-Authenticate": "DPoP" } };
	const refused = withRefusal(original, refusal);
	assert.equal(refused.code, "replayed");
	assert.equal(refused.message, "antlion-lacewing: DPoP proof has been used before");
	assert.equal(refused.cause, cause);
	assert.equal(refused.stack, original.stack);
	assert.equal(refused.refusal, refusal);
	const bare = withRefusal(new InternalError("replayed", "x"), refusal);
	assert.equal("cause" in bare, false);
});
