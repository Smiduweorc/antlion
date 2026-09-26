/**
 * Proofs Antlion did not make: the worked examples in RFC 9449, proofs
 * signed by python-cryptography with thumbprints computed in Python
 * (tools/golden/pyca_dpop.py), and proofs made by Nimbus OAuth 2.0 SDK's
 * DefaultDPoPProofFactory with thumbprints computed by Nimbus
 * (tools/golden/nimbus/NimbusDPoP.java). They go through the proof module directly,
 * because their `iat` is fixed and their tokens were never issued by a
 * Lacewing profile.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { calculateJwkThumbprint, importJWK } from "jose";
import { PROOF_ALGORITHMS } from "../../src/algorithms.js";
import { sha256 } from "../../src/base64url.js";
import { AntlionError } from "../../src/errors.js";
import { normalizeHtu } from "../../src/htu.js";
import { checkProof } from "../../src/proof.js";

const GOLDEN = join(dirname(fileURLToPath(import.meta.url)), "golden");

// RFC 9449 figure 13, the "\" line wrapping of RFC 8792 removed.
const RFC9449_FIGURE_13 =
	"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19" +
	".eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9" +
	".2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA";
// RFC 9449 figure 2: a proof for the token endpoint, so it has no ath.
const RFC9449_FIGURE_2 =
	"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19" +
	".eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ" +
	".2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";
// The access token in figure 13, and the jkt in figures 8 and 9.
const RFC9449_TOKEN = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
const RFC9449_JKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

function expecting(method: string, uri: string): { algorithms: readonly string[]; method: string; htu: string } {
	return { algorithms: PROOF_ALGORITHMS, method, htu: normalizeHtu(uri) as string };
}

test("[AL-bind.2] [9449-6.1.1] RFC 9449 figure 13 verifies, and its key's thumbprint is the RFC's jkt", async () => {
	const proof = await checkProof(RFC9449_FIGURE_13, expecting("GET", "https://resource.example.org/protectedresource"));
	assert.equal(proof.jkt, RFC9449_JKT);
	assert.equal(proof.jti, "e1j3V_bKic8-LAEB");
	assert.equal(proof.iat, 1562262618);
	assert.equal(proof.ath, "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
});

test("[AL-req.3] RFC 9449 figure 13's ath is the SHA-256 of figure 13's token, computed the way Antlion computes it", async () => {
	assert.equal(await sha256(RFC9449_TOKEN), "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
});

test("[9449-4.3.8] [9449-4.3.9] RFC 9449 figure 13 is refused for any other method or URI", async () => {
	await assert.rejects(
		checkProof(RFC9449_FIGURE_13, expecting("POST", "https://resource.example.org/protectedresource")),
		{ code: "htm-mismatch" }
	);
	await assert.rejects(
		checkProof(RFC9449_FIGURE_13, expecting("GET", "https://resource.example.org/otherresource")),
		{ code: "htu-mismatch" }
	);
});

test("[9449-4.2.5] RFC 9449 figure 2, a token-endpoint proof with no ath, is refused by a resource server", async () => {
	await assert.rejects(
		checkProof(RFC9449_FIGURE_2, expecting("POST", "https://server.example.com/token")),
		(error: unknown) => error instanceof AntlionError && error.code === "malformed-proof" && /ath/.test(error.message)
	);
});

test("[AL-bind.2] the RFC 7638 section 3.1 key hashes to the RFC's thumbprint after a CryptoKey round trip", async () => {
	// Antlion hashes the CryptoKey jose verified with, not the header's JSON,
	// so an import and export must not change a member.
	const jwk = {
		kty: "RSA",
		n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		e: "AQAB",
		alg: "RS256",
		kid: "2011-04-29",
	};
	const key = await importJWK(jwk, "PS256", { extractable: true });
	assert.equal(await calculateJwkThumbprint(key as CryptoKey, "sha256"), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
});

const golden = readdirSync(GOLDEN).sort();

test("the python-cryptography and Nimbus fixtures are all present", () => {
	const kinds = ["ed25519", "eddsa", "es256", "ps256"];
	assert.deepEqual(golden, [...kinds.map((k) => `nimbus-${k}.json`), ...kinds.map((k) => `pyca-${k}.json`)]);
});

for (const file of golden) {
	test(`[AL-bind.2] [9449-4.3.6] ${file}: a proof from another implementation verifies, and the thumbprint matches its own`, async () => {
		const fixture = JSON.parse(readFileSync(join(GOLDEN, file), "utf8")) as {
			proof: string;
			method: string;
			htu: string;
			token: string;
			jkt: string;
		};
		const proof = await checkProof(fixture.proof, expecting(fixture.method, fixture.htu));
		assert.equal(proof.jkt, fixture.jkt);
		assert.equal(proof.ath, await sha256(fixture.token));
	});
}
