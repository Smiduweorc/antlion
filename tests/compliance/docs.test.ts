/**
 * Requirements only documentation can meet. "The docs say so" is still a
 * claim, so these read the README that ships and fail if the warning is
 * edited away.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DPOP_REQUEST_HEADERS, DPOP_RESPONSE_HEADERS } from "../../index.js";

const README = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "README.md"), "utf8");

test("[AL-cors.1] the CORS header names are exported, frozen, and named in the README", () => {
	assert.deepEqual(DPOP_REQUEST_HEADERS, ["Authorization", "DPoP"]);
	assert.deepEqual(DPOP_RESPONSE_HEADERS, ["WWW-Authenticate", "DPoP-Nonce"]);
	assert.equal(Object.isFrozen(DPOP_REQUEST_HEADERS), true);
	assert.equal(Object.isFrozen(DPOP_RESPONSE_HEADERS), true);
	assert.match(README, /DPOP_REQUEST_HEADERS/);
	assert.match(README, /DPOP_RESPONSE_HEADERS/);
	assert.match(README, /Access-Control-Allow-Headers/);
	assert.match(README, /Access-Control-Expose-Headers/);
});

test("[AL-scope.1] the README says DPoP stops replay but not a compromised client", () => {
	assert.match(README, /\*\*It stops replay, not theft\.\*\*/);
	assert.match(README, /XSS running inside the client can still use the key/);
});

test("[AL-scope.1] the README says DPoP hides nothing and is not stateless", () => {
	assert.match(README, /\*\*It hides nothing\.\*\*/);
	assert.match(README, /\*\*It isn't stateless\.\*\*/);
	assert.match(README, /there is no safe DPoP verifier that is stateless/);
});
