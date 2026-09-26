/**
 * RFC 9449 section 4: the proof's syntax (4.1, 4.2) and the twelve checks a
 * server makes (4.3). Each check has a test that breaks exactly that one
 * thing in an otherwise valid request.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
	ath,
	bound,
	clientKey,
	encodeJson,
	NONCE_SECRET,
	ORIGIN,
	PATH,
	profile,
	proofFor,
	refused,
	request,
	signRaw,
	T0,
	tokenFor,
	URL_,
	verifyDPoPRequest,
} from "../helpers.js";

test("[9449-4.1.1] [9449-4.3.2] a DPoP header that is not a compact JWS is refused", async () => {
	const { token } = await bound();
	for (const value of ["not-a-jwt", "a.b", "a.b.c.d", "a..c", "eyJ.eyJ.sig with space", "a.b.c="]) {
		await refused(verifyDPoPRequest(request(token, value), profile()), "malformed-proof");
	}
});

test("[9449-4.3.2] a proof whose header or payload is not a JSON object is refused", async () => {
	const { key, token } = await bound();
	const payload = encodeJson({ jti: "j", htm: "GET", htu: URL_, iat: T0 / 1000, ath: await ath(token) });
	const header = { typ: "dpop+jwt", alg: "ES256", jwk: key.jwk };
	for (const badHeader of [encodeJson([header]), encodeJson("dpop+jwt"), encodeJson(null), "bm90IGpzb24"]) {
		const proof = await signRaw(key, badHeader, payload);
		await refused(verifyDPoPRequest(request(token, proof), profile()), "malformed-proof");
	}
	for (const badPayload of [encodeJson([1]), encodeJson(42), "bm90IGpzb24"]) {
		const proof = await signRaw(key, header, badPayload);
		await refused(verifyDPoPRequest(request(token, proof), profile()), "malformed-proof");
	}
});

test("[9449-4.3.2] a proof segment in non-canonical base64url is refused", async () => {
	const { proof, token } = await bound();
	const [header, payload, signature] = proof.split(".") as [string, string, string];
	// "Q" and "R" both decode to the same bits once the trailing ones are dropped;
	// only one spelling is canonical. Flip the last character of the signature
	// to its non-canonical twin.
	const last = signature.at(-1) as string;
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const twin = alphabet[alphabet.indexOf(last) ^ 1] as string;
	const tampered = `${header}.${payload}.${signature.slice(0, -1)}${twin}`;
	await refused(verifyDPoPRequest(request(token, tampered), profile()), "malformed-proof");
});

test("[9449-4.3.2] a proof with invalid UTF-8 in its payload is refused", async () => {
	const { key, token } = await bound();
	const payload = Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]).toString("base64url");
	const proof = await signRaw(key, { typ: "dpop+jwt", alg: "ES256", jwk: key.jwk }, payload);
	await refused(verifyDPoPRequest(request(token, proof), profile()), "malformed-proof");
});

test("[9449-4.2.1] [9449-4.3.4] [AL-hdr.1] a proof whose typ is not dpop+jwt is refused", async () => {
	const { key, token } = await bound();
	for (const typ of ["JWT", "at+jwt", "dpop", "dpop+jwt ", "", 1, null]) {
		const proof = await proofFor(key, token, { header: { typ } });
		await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-typ");
	}
	const missing = await proofFor(key, token, { omitHeader: ["typ"] });
	await refused(verifyDPoPRequest(request(token, missing), profile()), "proof-typ");
});

test("[9449-4.2.1] [AL-hdr.1] typ is read the RFC 7515 way: any case, application/ prefix optional", async () => {
	const { key, token } = await bound();
	for (const typ of ["DPoP+JWT", "application/dpop+jwt", "Application/DPOP+jwt"]) {
		const proof = await proofFor(key, token, { header: { typ } });
		const result = await verifyDPoPRequest(request(token, proof), profile());
		assert.equal(result.jkt, key.jkt);
	}
});

test("[9449-4.2.2] [9449-4.3.5] [9449-11.6.1] none, HMAC and algorithms outside the FAPI set are refused", async () => {
	const { key, token } = await bound();
	for (const alg of ["none", "None", "HS256", "RS256", "ES384", "ES512", "PS384", "es256", "", 7]) {
		const proof = await proofFor(key, token, { header: { alg } });
		await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-algorithm");
	}
	const missing = await proofFor(key, token, { omitHeader: ["alg"] });
	await refused(verifyDPoPRequest(request(token, missing), profile()), "proof-algorithm");
});

test("[9449-4.3.5] a real ES384 proof, correctly signed, is refused because ES384 is not in the FAPI set", async () => {
	const key = await clientKey("ES384");
	const token = await tokenFor(key.jkt);
	const proof = await proofFor(key, token);
	await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-algorithm");
});

test("[9449-4.2.3] [9449-4.3.7] [AL-key.2] a jwk carrying any private member is refused", async () => {
	const { key, token } = await bound();
	for (const member of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) {
		const proof = await proofFor(key, token, { header: { jwk: { ...key.jwk, [member]: "AAAA" } } });
		await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-key");
	}
});

test("[9449-4.2.3] [AL-key.2] a real private EC JWK in the header is refused before the signature is tried", async () => {
	const key = await clientKey("ES256");
	const token = await tokenFor(key.jkt);
	const full = await crypto.subtle.exportKey("jwk", key.privateKey);
	const proof = await proofFor(key, token, { header: { jwk: full } });
	await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-key");
});

test("[9449-4.2.4] [9449-4.3.3] a proof missing jti, htm, htu or iat is refused", async () => {
	const { key, token } = await bound();
	for (const claim of ["jti", "htm", "htu", "iat"]) {
		const proof = await proofFor(key, token, { omitPayload: [claim] });
		await refused(verifyDPoPRequest(request(token, proof), profile()), "malformed-proof");
	}
});

test("[9449-4.2.4] [9449-4.3.3] claims of the wrong type are refused", async () => {
	const { key, token } = await bound();
	const cases: Record<string, unknown>[] = [
		{ jti: 1 },
		{ jti: "" },
		{ htm: ["GET"] },
		{ htu: { href: URL_ } },
		{ iat: String(T0 / 1000) },
		{ iat: null },
		{ ath: 0 },
	];
	for (const payload of cases) {
		const proof = await proofFor(key, token, { payload });
		await refused(verifyDPoPRequest(request(token, proof), profile()), "malformed-proof");
	}
	// JSON has no Infinity or NaN, but a huge exponent parses to Infinity.
	const header = { typ: "dpop+jwt", alg: "ES256", jwk: key.jwk };
	const payload = Buffer.from(
		`{"jti":"j","htm":"GET","htu":"${URL_}","iat":1e400,"ath":"${await ath(token)}"}`
	).toString("base64url");
	const infinite = await signRaw(key, header, payload);
	await refused(verifyDPoPRequest(request(token, infinite), profile()), "malformed-proof");
});

test("[9449-4.2.5] [AL-req.3] a proof with no ath is refused, even though every other check would pass", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, { omitPayload: ["ath"] });
	await refused(verifyDPoPRequest(request(token, proof), profile()), "malformed-proof");
});

test("[9449-4.3.1] [AL-hdr.2] two DPoP headers are refused", async () => {
	const { key, token, proof } = await bound();
	const second = await proofFor(key, token);
	const req = request(token, proof, { headers: [["dpop", second]] });
	assert.equal(req.headers.get("dpop"), `${second}, ${proof}`);
	await refused(verifyDPoPRequest(req, profile()), "duplicate-proof");
});

test("[9449-4.3.1] two copies of the same DPoP header are refused too", async () => {
	const { token, proof } = await bound();
	await refused(verifyDPoPRequest(request(token, proof, { headers: [["dpop", proof]] }), profile()), "duplicate-proof");
});

test("[9449-4.3.6] a proof whose signature does not verify under its own jwk is refused", async () => {
	const { key, token, proof } = await bound();
	const other = await clientKey("ES256");
	const [header, payload] = proof.split(".") as [string, string, string];
	const resigned = await signRaw(other, header, payload);
	await refused(verifyDPoPRequest(request(token, resigned), profile()), "proof-signature");

	// Same key, one payload byte changed after signing.
	const tampered = await proofFor(key, token);
	const [h, p, s] = tampered.split(".") as [string, string, string];
	const claims = JSON.parse(Buffer.from(p, "base64url").toString()) as Record<string, unknown>;
	claims.jti = "swapped";
	await refused(
		verifyDPoPRequest(request(token, `${h}.${encodeJson(claims)}.${s}`), profile()),
		"proof-signature"
	);
});

test("[9449-4.3.8] [AL-req.2] htm must equal the request method exactly", async () => {
	const { key, token } = await bound();
	for (const htm of ["POST", "get", "Get", "GET ", ""]) {
		const proof = await proofFor(key, token, { payload: { htm } });
		const code = htm === "" ? "malformed-proof" : "htm-mismatch";
		await refused(verifyDPoPRequest(request(token, proof), profile()), code);
	}
	const post = await proofFor(key, token, { payload: { htm: "POST" } });
	const result = await verifyDPoPRequest(request(token, post, { method: "POST" }), profile());
	assert.equal(result.jkt, key.jkt);
});

test("[9449-4.3.9] htu must name this request's URI", async () => {
	const { key, token } = await bound();
	for (const htu of [
		`${ORIGIN}/accounts/43`,
		`${ORIGIN}/accounts/42/`,
		`${ORIGIN}/accounts`,
		`${ORIGIN}${PATH}/more`,
		`https://evil.example.com${PATH}`,
		`http://api.example.com${PATH}`,
		`https://api.example.com:8443${PATH}`,
		PATH,
		`https://user@api.example.com${PATH}`,
		`ftp://api.example.com${PATH}`,
		"not a url",
	]) {
		const proof = await proofFor(key, token, { payload: { htu } });
		await refused(verifyDPoPRequest(request(token, proof), profile()), "htu-mismatch");
	}
});

test("[9449-4.3.9] the query and fragment are ignored on both sides", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, { payload: { htu: `${URL_}?page=2#top` } });
	const result = await verifyDPoPRequest(request(token, proof, { url: `${URL_}?page=3` }), profile());
	assert.equal(result.jkt, key.jkt);
});

test("[9449-4.3.13] htu is compared after RFC 3986 syntax- and scheme-based normalization", async () => {
	const { key, token } = await bound();
	for (const htu of [
		"HTTPS://API.EXAMPLE.COM/accounts/42",
		"https://api.example.com:443/accounts/42",
		"https://api.example.com/accounts/./42",
		"https://api.example.com/accounts/x/../42",
		"https://api.example.com/accounts/%2e/42",
		"https://api.example.com/%61ccounts/42",
		"https://api.example.com/accounts/%34%32",
	]) {
		const proof = await proofFor(key, token, { payload: { htu } });
		const result = await verifyDPoPRequest(request(token, proof), profile());
		assert.equal(result.jkt, key.jkt, htu);
	}
	const encoded = await proofFor(key, token, { payload: { htu: `${ORIGIN}/a%2fb` } });
	const lower = await verifyDPoPRequest(request(token, encoded, { url: `${ORIGIN}/a%2Fb` }), profile());
	assert.equal(lower.jkt, key.jkt, "percent-escape hex digits compare case-insensitively");
	const slash = await proofFor(key, token, { payload: { htu: `${ORIGIN}/a/b` } });
	await refused(
		verifyDPoPRequest(request(token, slash, { url: `${ORIGIN}/a%2Fb` }), profile()),
		"htu-mismatch"
	);
});

test("[9449-4.3.10] with nonces on, a nonce this server did not issue is refused", async () => {
	const { key, token } = await bound();
	const dpop = profile({ nonce: "required" });
	const other = profile({ nonce: "required", nonceSecrets: [new Uint8Array(32).fill(9)] });
	const foreign = (await refused(verifyDPoPRequest(request(token, await proofFor(key, token)), other), "nonce-missing"))
		.refusal?.headers["DPoP-Nonce"] as string;
	for (const nonce of [foreign, "made-up", "", 12, `${foreign}x`]) {
		const proof = await proofFor(key, token, { payload: { nonce } });
		await refused(verifyDPoPRequest(request(token, proof), dpop), "nonce-invalid");
	}
});

test("[9449-4.3.10] with nonces on, a nonce this server issued is accepted", async () => {
	const { key, token } = await bound();
	const dpop = profile({ nonce: "required" });
	const challenge = await refused(verifyDPoPRequest(request(token, await proofFor(key, token)), dpop), "nonce-missing");
	const nonce = challenge.refusal?.headers["DPoP-Nonce"] as string;
	const result = await verifyDPoPRequest(request(token, await proofFor(key, token, { payload: { nonce } })), dpop);
	assert.equal(result.jkt, key.jkt);
});

test("[9449-4.3.11] [9449-11.1.1] a proof older than maxProofAge is refused", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, {}, T0 - 61_000);
	await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-expired");
});

test("[9449-4.3.11] a proof dated more than five seconds ahead is refused", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, {}, T0 + 6_000);
	await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-in-future");
});

test("[9449-4.3.12] [AL-req.3] ath must be the hash of the token presented with it", async () => {
	const key = await clientKey();
	const token = await tokenFor(key.jkt);
	const otherToken = await tokenFor(key.jkt);
	const proof = await proofFor(key, token, { payload: { ath: await ath(otherToken) } });
	await refused(verifyDPoPRequest(request(token, proof), profile()), "ath-mismatch");
	for (const bad of ["x", (await ath(token)).toLowerCase() + "A", `${await ath(token)}=`]) {
		const other = await proofFor(key, token, { payload: { ath: bad } });
		await refused(verifyDPoPRequest(request(token, other), profile()), "ath-mismatch");
	}
});

test("[9449-4.3.12] a token bound to one key and a proof signed by another are refused", async () => {
	const holder = await clientKey();
	const thief = await clientKey();
	const token = await tokenFor(holder.jkt);
	const proof = await proofFor(thief, token);
	const error = await refused(verifyDPoPRequest(request(token, proof), profile()), "jkt-mismatch");
	assert.match(error.refusal?.headers["WWW-Authenticate"] ?? "", /error="invalid_token"/);
});

test("[9449-8.2.3] a nonce secret under 32 bytes is refused, so nonces stay unguessable", () => {
	assert.throws(
		() => profile({ nonce: "required", nonceSecrets: [NONCE_SECRET.slice(0, 31)] }),
		{ code: "invalid-options" }
	);
});

test("[AL-hdr.4] a header naming another key, or asking for JWS extensions, is refused", async () => {
	const { key, token } = await bound();
	const values: Record<string, unknown> = {
		jku: "https://evil.example.com/jwks",
		x5u: "https://evil.example.com/cert",
		x5c: ["MIIB"],
		x5t: "AAAA",
		"x5t#S256": "AAAA",
		crit: ["b64"],
		b64: false,
		zip: "DEF",
	};
	for (const [parameter, value] of Object.entries(values)) {
		const proof = await proofFor(key, token, { header: { [parameter]: value } });
		const error = await refused(verifyDPoPRequest(request(token, proof), profile()), "malformed-proof");
		assert.match(error.message, /forbidden parameter/, parameter);
	}
});

test("[AL-hdr.4] harmless extra header parameters, such as kid, are accepted", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, { header: { kid: "client-key-1", cty: "x" } });
	assert.equal((await verifyDPoPRequest(request(token, proof), profile())).jkt, key.jkt);
});
