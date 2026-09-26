/**
 * "It won't compile" is a claim, and claims get proofs. This runs tsc over
 * tests/types/fixtures/, where every file holds one line the type system
 * must reject, and asserts each still fails with the error expected. A
 * successful compile is the failure here.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");

const FIXTURES: { file: string; code: string; tag: string; why: string }[] = [
	{ file: "profile-requires-replay.ts", code: "TS2345", tag: "AL-replay.1", why: "a profile without a replay store" },
	{ file: "profile-requires-nonce.ts", code: "TS2345", tag: "AL-nonce.1", why: "a profile that does not choose a nonce mode" },
	{ file: "nonce-required-needs-secrets.ts", code: "TS2345", tag: "AL-nonce.1", why: "nonces required with no secret" },
	{ file: "nonce-off-refuses-secrets.ts", code: "TS2345", tag: "AL-nonce.1", why: "nonce secrets with nonces off" },
	{ file: "forged-verified.ts", code: "TS2322", tag: "AL-bind.1", why: "a DPoPVerifiedJwt built by hand" },
	{ file: "no-proof-verifier.ts", code: "TS2305", tag: "AL-bind.1", why: "importing a proof-only verifier" },
	{ file: "legacy-not-forgeable.ts", code: "TS2741", tag: "AL-alg.2", why: "RS256 written as an object literal" },
];

const tsc = spawnSync(
	process.execPath,
	[join(ROOT, "node_modules", "typescript", "bin", "tsc"), "--noEmit", "-p", join(HERE, "tsconfig.json")],
	{ cwd: ROOT, encoding: "utf8" }
);
const output = `${tsc.stdout ?? ""}${tsc.stderr ?? ""}`;

test("the negative type fixtures still fail to compile", () => {
	assert.notEqual(tsc.status, 0, `tsc accepted the negative fixtures:\n${output}`);
});

for (const { file, code, tag, why } of FIXTURES) {
	test(`[${tag}] tsc rejects ${why} (${file}, ${code})`, () => {
		const lines = output.split("\n").filter((l) => l.includes(`fixtures/${file}`) || l.includes(`fixtures\\${file}`));
		assert.ok(lines.length > 0, `tsc reported no error for ${file}:\n${output}`);
		assert.ok(lines.some((l) => l.includes(code)), `expected ${code} in ${file}, got:\n${lines.join("\n")}`);
	});
}

test("the fixtures are the only thing tsc complains about", () => {
	// Otherwise every fixture could "fail" because the package itself stopped compiling.
	const strays = output
		.split("\n")
		.filter((l) => /error TS\d+/.test(l))
		.filter((l) => !l.includes("fixtures/") && !l.includes("fixtures\\"));
	assert.deepEqual(strays, []);
});

test("every fixture on disk is listed above", () => {
	assert.deepEqual(readdirSync(join(HERE, "fixtures")).sort(), FIXTURES.map((f) => f.file).sort());
});
