import { test } from "node:test";
import assert from "node:assert/strict";
import { SingleProcessReplayStore, type AntlionError } from "../../index.js";
import { T0 } from "../helpers.js";
import { replayStoreContract } from "../replay-contract.js";

let now = T0;

replayStoreContract("SingleProcessReplayStore", {
	async fresh() {
		return new SingleProcessReplayStore({ maxEntries: 1000, now: () => now });
	},
	async broken() {
		const store = new SingleProcessReplayStore({ maxEntries: 1, now: () => now });
		await store.addIfAbsent("fills-it", 66);
		return { store, isBackendError: (cause) => (cause as AntlionError).code === "replay-store-full" };
	},
	async elapse(ms) {
		now += ms;
	},
	shortTtl: 1,
});

test("SingleProcessReplayStore admits a key again at the exact millisecond its TTL ends, and not one before", async () => {
	let at = T0;
	const store = new SingleProcessReplayStore({ maxEntries: 10, now: () => at });
	// A longer-lived key in front keeps the sweep from removing "k" first, so
	// the expiry comparison itself decides.
	assert.equal(await store.addIfAbsent("long", 306), true);
	assert.equal(await store.addIfAbsent("k", 66), true);
	at = T0 + 65_999;
	assert.equal(await store.addIfAbsent("k", 66), false);
	at = T0 + 66_000;
	assert.equal(await store.addIfAbsent("k", 66), true);
});
