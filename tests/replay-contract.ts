/**
 * The replay-store contract, run against every store Antlion ships. A store
 * passes when the same key is admitted once, admitted again only after its
 * TTL, admitted once under concurrency, and when its failure refuses the
 * request rather than letting it through.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { AntlionError, type ReplayStore } from "../index.js";
import { bound, profile, refused, request, verifyDPoPRequest } from "./helpers.js";

export interface ContractSubject {
	/** A store with nothing in it yet. */
	fresh(): Promise<ReplayStore>;
	/** A store whose backend fails, and a check that the failure is the backend's own error. */
	broken(): Promise<{ store: ReplayStore; isBackendError(cause: unknown): boolean }>;
	/** Let `ms` pass on the store's clock: a virtual one, or the server's real one. */
	elapse(ms: number): Promise<void>;
	/** A TTL in seconds short enough to wait out. */
	shortTtl: number;
}

const RACERS = 50;

export function replayStoreContract(name: string, subject: ContractSubject): void {
	test(`${name}: a key is admitted once, and its second add is refused`, async () => {
		const store = await subject.fresh();
		const key = `jkt-${crypto.randomUUID()}:jti`;
		assert.equal(await store.addIfAbsent(key, 66), true);
		assert.equal(await store.addIfAbsent(key, 66), false);
		assert.equal(await store.addIfAbsent(key, 66), false);
		assert.equal(await store.addIfAbsent(`${key}-other`, 66), true);
	});

	test(`${name}: a key is refused at half its TTL and admitted again once it has passed`, async () => {
		const store = await subject.fresh();
		const key = `jkt-${crypto.randomUUID()}:jti`;
		const ttlMs = subject.shortTtl * 1000;
		assert.equal(await store.addIfAbsent(key, subject.shortTtl), true);
		await subject.elapse(ttlMs / 2);
		assert.equal(await store.addIfAbsent(key, subject.shortTtl), false);
		await subject.elapse(ttlMs / 2 + ttlMs / 5);
		assert.equal(await store.addIfAbsent(key, subject.shortTtl), true);
		assert.equal(await store.addIfAbsent(key, subject.shortTtl), false);
	});

	test(`${name}: ${RACERS} concurrent adds of one key admit exactly one`, async () => {
		const store = await subject.fresh();
		const key = `jkt-${crypto.randomUUID()}:jti`;
		const results = await Promise.all(Array.from({ length: RACERS }, () => store.addIfAbsent(key, 66)));
		assert.equal(results.filter((added) => added === true).length, 1);
		assert.equal(results.filter((added) => added === false).length, RACERS - 1);
	});

	test(`${name}: a proof sent twice through verifyDPoPRequest is refused as replayed`, async () => {
		const dpop = profile({ replay: await subject.fresh() });
		const { key, token, proof } = await bound();
		assert.equal((await verifyDPoPRequest(request(token, proof), dpop)).jkt, key.jkt);
		await refused(verifyDPoPRequest(request(token, proof), dpop), "replayed");
	});

	test(`${name}: a store that fails refuses the request and hands back its own error as the cause`, async () => {
		const { store, isBackendError } = await subject.broken();
		const { token, proof } = await bound();
		const error = await refused(verifyDPoPRequest(request(token, proof), profile({ replay: store })), "replay-store-failed");
		assert.equal(error.refusal?.status, 401);
		assert.ok(isBackendError(error.cause), `unexpected cause: ${String(error.cause)}`);
	});
}

/** For subjects whose backend error is not an AntlionError. */
export function notAntlion(cause: unknown): boolean {
	return cause instanceof Error && !(cause instanceof AntlionError);
}
