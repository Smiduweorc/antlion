/**
 * Requirements only documentation can meet. "The docs say so" is still a
 * claim, so these read the README that ships and fail if the warning is
 * edited away.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DPOP_REQUEST_HEADERS, DPOP_RESPONSE_HEADERS } from "../../index.js";

const README = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "README.md"), "utf8");

test("the CORS header names are exported, frozen, and named in the README", () => {
	assert.deepEqual(DPOP_REQUEST_HEADERS, ["Authorization", "DPoP"]);
	assert.deepEqual(DPOP_RESPONSE_HEADERS, ["WWW-Authenticate", "DPoP-Nonce"]);
	assert.equal(Object.isFrozen(DPOP_REQUEST_HEADERS), true);
	assert.equal(Object.isFrozen(DPOP_RESPONSE_HEADERS), true);
	assert.match(README, /DPOP_REQUEST_HEADERS/);
	assert.match(README, /DPOP_RESPONSE_HEADERS/);
	assert.match(README, /Access-Control-Allow-Headers/);
	assert.match(README, /Access-Control-Expose-Headers/);
});

test("the README says DPoP stops replay but not a compromised client", () => {
	assert.match(README, /\*\*It stops replay, not theft\.\*\*/);
	assert.match(README, /XSS running inside the client can still use the key/);
});

test("the README says DPoP hides nothing and is not stateless", () => {
	assert.match(README, /\*\*It hides nothing\.\*\*/);
	assert.match(README, /\*\*It isn't stateless\.\*\*/);
	assert.match(README, /there is no safe DPoP verifier that is stateless/);
});

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("the README links every guide, so none of them is unreachable", () => {
	const guides = readdirSync(join(ROOT, "guides")).filter((name) => name.endsWith(".md"));
	assert.ok(guides.length > 0);
	for (const name of guides) {
		assert.ok(README.includes(`](./guides/${name})`), `README must link guides/${name}`);
	}
});

test("TypeDoc includes every markdown document in the repo", () => {
	const config = JSON.parse(readFileSync(join(ROOT, "typedoc.json"), "utf8")) as {
		readme: string;
		projectDocuments: string[];
	};
	const covered = (path: string): boolean =>
		config.projectDocuments.some((entry) =>
			entry.endsWith("/*.md")
				? path.startsWith(entry.slice(0, -"*.md".length)) && !path.slice(entry.length - 4).includes("/")
				: entry === path
		);
	// Written by `npm run compliance` and gitignored: a fresh checkout has no
	// copy, so listing it would break `npm run docs`.
	const generated = new Set(["compliance-report.md"]);
	const documents = [
		...readdirSync(ROOT).filter((name) => name.endsWith(".md")),
		...readdirSync(join(ROOT, "guides")).filter((name) => name.endsWith(".md")).map((name) => `guides/${name}`),
	];
	for (const path of documents) {
		if (path === config.readme || generated.has(path)) continue;
		assert.ok(covered(path), `typedoc.json projectDocuments must include ${path}`);
	}
});
