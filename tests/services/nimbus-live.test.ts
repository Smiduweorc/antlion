/**
 * Nimbus OAuth 2.0 SDK (Java) as a live client of an Antlion server, for
 * ES256, PS256 and Ed25519 keys. Lives in the service suite because it needs
 * a JDK and the Nimbus jars; see tools/golden/nimbus/NimbusLiveClient.java.
 */

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { startLiveServer, type LiveServer } from "../live-server.js";

const NIMBUS = fileURLToPath(new URL("../../tools/golden/nimbus/", import.meta.url));
if (!existsSync(`${NIMBUS}lib`)) {
	throw new Error(
		"tools/golden/nimbus/lib is missing. Fetch the Nimbus jars first: " +
			"cd tools/golden/nimbus && mvn -q dependency:copy-dependencies -DoutputDirectory=lib"
	);
}

let live: LiveServer;
before(async () => {
	live = await startLiveServer();
});
after(() => live.close());

test("a Nimbus client gets a token, retries on the nonce challenge, and is refused for replay, staleness and another key", async () => {
	const { stdout } = await promisify(execFile)("java", ["-cp", "lib/*", "NimbusLiveClient.java", live.origin], {
		cwd: NIMBUS,
		timeout: 120_000,
	});
	const statuses = JSON.parse(stdout) as Record<string, number>;
	const expected: Record<string, number> = {};
	for (const alg of ["es256", "ps256", "ed25519"]) {
		Object.assign(expected, {
			[`${alg}_challenge`]: 401,
			[`${alg}_retry`]: 200,
			[`${alg}_replay`]: 401,
			[`${alg}_stale`]: 401,
			[`${alg}_other_key`]: 401,
		});
	}
	assert.deepEqual(statuses, expected);
	const perAlg = ["nonce-missing", "accepted", "replayed", "proof-expired", "jkt-mismatch"];
	assert.deepEqual(live.seen.map((entry) => entry.code), [...perAlg, ...perAlg, ...perAlg]);
});
