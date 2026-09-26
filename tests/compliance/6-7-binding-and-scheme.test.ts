/**
 * RFC 9449 section 6 (the `cnf.jkt` binding) and section 7 (the DPoP
 * authentication scheme, the challenge, and refusing Bearer).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
	bound,
	clientKey,
	profile,
	proofFor,
	refused,
	request,
	tokenFor,
	verifyDPoPRequest,
} from "../helpers.js";

test("[9449-6.1.1] [9449-7.1.1] a token whose cnf.jkt is the proof key's thumbprint verifies", async () => {
	for (const alg of ["ES256", "PS256", "EdDSA", "Ed25519"] as const) {
		const { key, token, proof } = await bound(alg);
		const result = await verifyDPoPRequest(request(token, proof), profile());
		assert.equal(result.jkt, key.jkt, alg);
		assert.equal(result.token.payload.sub, "user-42");
		assert.deepEqual(result.token.payload.cnf, { jkt: key.jkt });
		assert.equal(result.nextNonce, undefined);
	}
});

test("[9449-6.1.1] [AL-bind.4] a token with no cnf, or a cnf with no usable jkt, is refused", async () => {
	const key = await clientKey();
	const unbound = await tokenFor(null);
	const error = await refused(
		verifyDPoPRequest(request(unbound, await proofFor(key, unbound)), profile()),
		"token-unbound"
	);
	assert.match(error.refusal?.headers["WWW-Authenticate"] ?? "", /error="invalid_token"/);

	for (const cnf of [{}, { jkt: "" }, { jkt: 42 }, { jkt: null }, { "x5t#S256": key.jkt }, [key.jkt], key.jkt]) {
		const token = await tokenFor(null, { cnf });
		await refused(verifyDPoPRequest(request(token, await proofFor(key, token)), profile()), "token-unbound");
	}
});

test("[9449-6.1.1] a jkt that differs from the thumbprint by one character is refused", async () => {
	const key = await clientKey();
	const last = key.jkt.at(-1) === "A" ? "B" : "A";
	const token = await tokenFor(`${key.jkt.slice(0, -1)}${last}`);
	await refused(verifyDPoPRequest(request(token, await proofFor(key, token)), profile()), "jkt-mismatch");
});

test("[9449-7.1.1] a DPoP-scheme token with no DPoP header is refused", async () => {
	const { token } = await bound();
	const error = await refused(verifyDPoPRequest(request(token, null), profile()), "missing-proof");
	assert.match(error.refusal?.headers["WWW-Authenticate"] ?? "", /error="invalid_dpop_proof"/);
	await refused(verifyDPoPRequest(request(token, ""), profile()), "missing-proof");
});

test("[9449-7.1.1] a token the Lacewing profile refuses is refused, with Lacewing's error as the cause", async () => {
	const key = await clientKey();
	for (const token of ["not.a.jwt", "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU", "opaque"]) {
		const error = await refused(
			verifyDPoPRequest(request(token, await proofFor(key, token)), profile()),
			"token-invalid"
		);
		assert.match(error.refusal?.headers["WWW-Authenticate"] ?? "", /error="invalid_token"/);
		assert.equal((error.cause as { code?: string }).code, "JWT_INVALID");
	}
});

test("[9449-7.1.2] there is no partial result: a failure after every signature check still yields nothing", async () => {
	const { key, token } = await bound();
	const stale = await proofFor(key, token, {}, Date.UTC(2020, 0, 1));
	let result: unknown = "untouched";
	try {
		result = await verifyDPoPRequest(request(token, stale), profile());
	} catch {
		// expected
	}
	assert.equal(result, "untouched");
});

test("[9449-7.1.3] [9449-7.1.4] a refused request gets a 401 with a DPoP challenge naming the error and the algorithms", async () => {
	const { token, proof } = await bound();
	const error = await refused(verifyDPoPRequest(request(token, proof, { method: "POST" }), profile()), "htm-mismatch");
	assert.deepEqual(error.refusal, {
		status: 401,
		headers: { "WWW-Authenticate": "DPoP error=\"invalid_dpop_proof\", algs=\"ES256 PS256 EdDSA Ed25519\"" },
	});
});

test("[9449-7.2.2] [9449-7.1.4] a request with no credentials gets a challenge with no error parameter", async () => {
	const error = await refused(verifyDPoPRequest(request(null, null), profile()), "missing-authorization");
	assert.deepEqual(error.refusal, {
		status: 401,
		headers: { "WWW-Authenticate": "DPoP algs=\"ES256 PS256 EdDSA Ed25519\"" },
	});
	const empty = await refused(
		verifyDPoPRequest(request(null, null, { headers: [["authorization", ""]] }), profile()),
		"missing-authorization"
	);
	assert.equal(empty.refusal?.status, 401);
});

test("[9449-7.2.1] [AL-bind.3] a DPoP-bound token under the Bearer scheme is refused, with or without a proof", async () => {
	const { token, proof } = await bound();
	for (const scheme of ["Bearer", "bearer", "BEARER"]) {
		const error = await refused(verifyDPoPRequest(request(token, proof, { scheme }), profile()), "bearer-scheme");
		assert.deepEqual(error.refusal, {
			status: 401,
			headers: { "WWW-Authenticate": "DPoP algs=\"ES256 PS256 EdDSA Ed25519\"" },
		});
		await refused(verifyDPoPRequest(request(token, null, { scheme }), profile()), "bearer-scheme");
	}
});

test("[AL-hdr.3] the DPoP scheme matches in any case", async () => {
	const { key, token } = await bound();
	for (const scheme of ["DPoP", "dpop", "DPOP", "dPoP"]) {
		const result = await verifyDPoPRequest(request(token, await proofFor(key, token), { scheme }), profile());
		assert.equal(result.jkt, key.jkt, scheme);
	}
});

test("[AL-hdr.3] one or more spaces may follow the scheme, as RFC 9449 figure 12 writes it", async () => {
	const { key, token } = await bound();
	for (const gap of [" ", "  ", "     "]) {
		const req = request(null, await proofFor(key, token), { headers: [["authorization", `DPoP${gap}${token}`]] });
		assert.equal((await verifyDPoPRequest(req, profile())).jkt, key.jkt, JSON.stringify(gap));
	}
});

test("[AL-hdr.3] anything but spaces and one token68 after the scheme is a 400 invalid_request", async () => {
	const { token, proof } = await bound();
	for (const value of [
		`DPoP\t${token}`,
		`DPoP \t${token}`,
		` DPoP ${token}`,
		`DPoP ${token} `,
		`DPoP ${token} extra`,
		"DPoP",
		"DPoP ",
		`DPoPx ${token}`,
		`MAC ${token}`,
		token,
		`DPoP ${token}=x`,
	]) {
		// A WHATWG Headers trims the value on the way in; a Headers-like object
		// from another runtime might not, so the untrimmed values are handed
		// over as they are.
		const fields: Record<string, string> = { authorization: value, dpop: proof };
		const headers = { get: (name: string): string | null => fields[name] ?? null } as Headers;
		const req = { method: "GET", url: "/accounts/42", headers };
		const error = await refused(verifyDPoPRequest(req, profile()), "malformed-authorization");
		assert.deepEqual(error.refusal, {
			status: 400,
			headers: { "WWW-Authenticate": "DPoP error=\"invalid_request\", algs=\"ES256 PS256 EdDSA Ed25519\"" },
		});
	}
});

test("[AL-hdr.2] two Authorization headers are a 400, whichever schemes they use", async () => {
	const { token, proof } = await bound();
	for (const second of [`DPoP ${token}`, `Bearer ${token}`, "Basic dXNlcjpwYXNz"]) {
		const req = request(token, proof, { headers: [["authorization", second]] });
		const error = await refused(verifyDPoPRequest(req, profile()), "duplicate-authorization");
		assert.equal(error.refusal?.status, 400);
		assert.match(error.refusal?.headers["WWW-Authenticate"] ?? "", /error="invalid_request"/);
	}
});

test("[AL-hdr.2] an Authorization header over 16384 characters is refused before any parsing", async () => {
	const { proof } = await bound();
	const over = request("a".repeat(16_384 - "DPoP ".length + 1), proof);
	await refused(verifyDPoPRequest(over, profile()), "malformed-authorization");
	// At exactly the cap the header is parsed, and it is the token that fails.
	const atCap = request("a".repeat(16_384 - "DPoP ".length), proof);
	await refused(verifyDPoPRequest(atCap, profile()), "token-invalid");
});
