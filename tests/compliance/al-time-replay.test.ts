/**
 * Freshness (AL-time, RFC 9449 section 11.1) and replay (AL-replay).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
	ath,
	bound,
	clientKey,
	profile,
	proofFor,
	refused,
	request,
	spyStore,
	T0,
	tokenFor,
	verifyDPoPRequest,
} from "../helpers.js";
import { AntlionError, SingleProcessReplayStore, type ReplayStore } from "../../index.js";

test("[AL-time.2] maxProofAge defaults to 60 seconds", () => {
	assert.equal(profile().maxProofAge, 60);
});

test("[AL-time.2] [9449-11.1.1] a proof exactly maxProofAge old is accepted, one millisecond more is not", async () => {
	const { key, token } = await bound();
	const iat = T0 - 60_000;
	const proof = (): Promise<string> => proofFor(key, token, {}, iat);
	assert.equal((await verifyDPoPRequest(request(token, await proof()), profile())).jkt, key.jkt);
	await refused(verifyDPoPRequest(request(token, await proof()), profile({ now: () => T0 + 1 })), "proof-expired");
});

test("[AL-time.2] a proof dated exactly five seconds ahead is accepted, one millisecond more is not", async () => {
	const { key, token } = await bound();
	const proof = (): Promise<string> => proofFor(key, token, {}, T0 + 5_000);
	assert.equal((await verifyDPoPRequest(request(token, await proof()), profile())).jkt, key.jkt);
	await refused(verifyDPoPRequest(request(token, await proof()), profile({ now: () => T0 - 1 })), "proof-in-future");
});

test("[AL-time.2] a fractional iat is compared as it is, not rounded", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, { payload: { iat: T0 / 1000 - 60.5 } });
	await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-expired");
	const inside = await proofFor(key, token, { payload: { iat: T0 / 1000 - 59.5 } });
	assert.equal((await verifyDPoPRequest(request(token, inside), profile())).jkt, key.jkt);
});

test("[AL-time.1] [AL-time.2] maxProofAge can be narrowed or widened to 300 seconds, and no further", async () => {
	const { key, token } = await bound();
	const old = await proofFor(key, token, {}, T0 - 300_000);
	assert.equal((await verifyDPoPRequest(request(token, old), profile({ maxProofAge: "5m" }))).jkt, key.jkt);
	const narrow = await proofFor(key, token, {}, T0 - 11_000);
	await refused(verifyDPoPRequest(request(token, narrow), profile({ maxProofAge: 10 })), "proof-expired");
	assert.throws(() => profile({ maxProofAge: 301 }), { code: "invalid-options" });
	assert.throws(() => profile({ maxProofAge: "6m" }), { code: "invalid-options" });
});

test("[AL-time.1] the future allowance is not an option", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, {}, T0 + 6_000);
	await refused(verifyDPoPRequest(request(token, proof), profile({ maxProofAge: 300 })), "proof-in-future");
});

test("[9449-11.1.1] the clock can go backwards without a proof being accepted twice", async () => {
	const { token, proof } = await bound();
	let now = T0;
	const dpop = profile({ now: () => now });
	await verifyDPoPRequest(request(token, proof), dpop);
	now = T0 - 3_000;
	await refused(verifyDPoPRequest(request(token, proof), dpop), "replayed");
});

test("[AL-replay.2] a proof is accepted once; the second use is refused as replayed", async () => {
	const { token, proof } = await bound();
	const dpop = profile();
	await verifyDPoPRequest(request(token, proof), dpop);
	const error = await refused(verifyDPoPRequest(request(token, proof), dpop), "replayed");
	assert.match(error.refusal?.headers["WWW-Authenticate"] ?? "", /error="invalid_dpop_proof"/);
});

test("[AL-replay.2] two copies of one proof arriving together: exactly one is accepted", async () => {
	const { token, proof } = await bound();
	const dpop = profile();
	const results = await Promise.allSettled(
		Array.from({ length: 8 }, () => verifyDPoPRequest(request(token, proof), dpop))
	);
	assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
	for (const r of results) {
		if (r.status === "rejected") assert.equal((r.reason as AntlionError).code, "replayed");
	}
});

test("[AL-replay.2] the TTL handed to the store is maxProofAge plus the future allowance plus one second", async () => {
	const store = spyStore();
	const { token, proof } = await bound();
	await verifyDPoPRequest(request(token, proof), profile({ replay: store }));
	assert.equal(store.calls[0]?.[1], 66);
	const again = await bound();
	await verifyDPoPRequest(request(again.token, again.proof), profile({ replay: store, maxProofAge: 300 }));
	assert.equal(store.calls[1]?.[1], 306);
});

test("[AL-replay.2] the store remembers a proof for as long as it could still pass the iat check", async () => {
	const { key, token } = await bound();
	// Dated as far ahead as allowed: it stays fresh until T0 + 5 s + 60 s.
	const proof = await proofFor(key, token, {}, T0 + 5_000);
	let now = T0;
	const replay = new SingleProcessReplayStore({ maxEntries: 10, now: () => now });
	const dpop = profile({ replay, now: () => now });
	await verifyDPoPRequest(request(token, proof), dpop);
	now = T0 + 65_000;
	await refused(verifyDPoPRequest(request(token, proof), dpop), "replayed");
	now = T0 + 65_001;
	await refused(verifyDPoPRequest(request(token, proof), dpop), "proof-expired");
});

test("[AL-replay.2] a store that throws refuses the request, with the store's error as the cause", async () => {
	const { token, proof } = await bound();
	const boom = new Error("connection reset");
	const failing: ReplayStore = { addIfAbsent: async () => { throw boom; } };
	const error = await refused(verifyDPoPRequest(request(token, proof), profile({ replay: failing })), "replay-store-failed");
	assert.equal(error.cause, boom);
	assert.equal(error.refusal?.status, 401);
});

test("[AL-replay.2] a store that resolves anything but a boolean refuses the request", async () => {
	for (const value of [undefined, null, 1, 0, "true", {}]) {
		const { token, proof } = await bound();
		const odd = { addIfAbsent: async () => value } as unknown as ReplayStore;
		await refused(verifyDPoPRequest(request(token, proof), profile({ replay: odd })), "replay-store-failed");
	}
});

test("[AL-replay.2] a store whose method is synchronous and throws still refuses", async () => {
	const { token, proof } = await bound();
	const sync = { addIfAbsent: () => { throw new Error("sync"); } } as unknown as ReplayStore;
	await refused(verifyDPoPRequest(request(token, proof), profile({ replay: sync })), "replay-store-failed");
});

test("[AL-replay.4] [9449-11.1.2] the replay key is jkt, a colon, and the SHA-256 of the jti", async () => {
	const store = spyStore();
	const key = await clientKey();
	const token = await tokenFor(key.jkt);
	const jti = "x".repeat(10_000);
	await verifyDPoPRequest(request(token, await proofFor(key, token, { payload: { jti } })), profile({ replay: store }));
	assert.equal(store.calls[0]?.[0], `${key.jkt}:${await ath(jti)}`);
	assert.equal(store.calls[0]?.[0].length, 87);
});

test("[AL-replay.4] the same jti from two different keys is two different proofs", async () => {
	const dpop = profile();
	for (let i = 0; i < 2; i++) {
		const key = await clientKey();
		const token = await tokenFor(key.jkt);
		const proof = await proofFor(key, token, { payload: { jti: "shared" } });
		assert.equal((await verifyDPoPRequest(request(token, proof), dpop)).jkt, key.jkt);
	}
});

test("[AL-replay.4] a new proof with a reused jti from the same key is refused as replayed", async () => {
	const key = await clientKey();
	const token = await tokenFor(key.jkt);
	const dpop = profile();
	await verifyDPoPRequest(request(token, await proofFor(key, token, { payload: { jti: "again" } })), dpop);
	const other = await proofFor(key, token, { payload: { jti: "again", htm: "POST" } });
	await refused(verifyDPoPRequest(request(token, other, { method: "POST" }), dpop), "replayed");
});
