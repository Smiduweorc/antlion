/**
 * Known attacks on a DPoP resource server, one test each, named for the
 * attack. Several are also covered spec-section by spec-section in
 * tests/compliance; this file exists so the list of attacks can be read in
 * one place, and so a new one has an obvious home.
 *
 * Every refusal is also checked for leaks: the message never contains the
 * token, the proof, or any part of either.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { base64url } from "jose";
import { generateKeyPair, newAccessToken } from "lacewing";
import { AntlionError, type AntlionErrorCode } from "../../index.js";
import {
	ath,
	AUDIENCE,
	bound,
	clientKey,
	ISSUER,
	ORIGIN,
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

async function attack(req: Request, code: AntlionErrorCode, secrets: string[]): Promise<void> {
	const dpop = profile();
	const error = await verifyDPoPRequest(req, dpop).then(
		() => assert.fail(`the attack verified; expected ${code}`),
		(caught: unknown) => caught
	);
	assert.ok(error instanceof AntlionError, String(error));
	assert.equal(error.code, code, error.message);
	for (const secret of secrets) {
		for (const part of secret.split(".")) {
			if (part.length >= 8) assert.ok(!error.message.includes(part), `message leaks request content: ${error.message}`);
		}
	}
	assert.ok(!JSON.stringify(error.refusal?.headers ?? {}).includes(code), "the wire refusal names the internal code");
}

test("stolen token, attacker's own key: a fresh proof signed by another key is refused", async () => {
	const { token } = await bound();
	const attacker = await clientKey();
	const proof = await proofFor(attacker, token);
	await attack(request(token, proof), "jkt-mismatch", [token, proof]);
});

test("stolen token and stolen proof, replayed", async () => {
	const { token, proof } = await bound();
	const dpop = profile();
	await verifyDPoPRequest(request(token, proof), dpop);
	await refused(verifyDPoPRequest(request(token, proof), dpop), "replayed");
});

test("downgrade: a DPoP-bound token sent as Bearer", async () => {
	const { token, proof } = await bound();
	await attack(request(token, proof, { scheme: "Bearer" }), "bearer-scheme", [token]);
});

test("unbound token under the DPoP scheme", async () => {
	const key = await clientKey();
	const token = await tokenFor(null);
	await attack(request(token, await proofFor(key, token)), "token-unbound", [token]);
});

test("self-issued token: signed by the attacker's key and bound to it, hoping the proof key verifies it", async () => {
	const attacker = await generateKeyPair("ES256", { extractable: true });
	const key = await clientKey();
	const token = await newAccessToken()
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.subject("admin")
		.expiresIn("5m")
		.claim("cnf", { jkt: key.jkt })
		.sign(attacker.privateKey);
	await attack(request(token, await proofFor(key, token)), "token-invalid", [token]);
});

test("proof made for another endpoint, or one that only shares a prefix", async () => {
	const { key, token } = await bound();
	for (const htu of [`${ORIGIN}/accounts/4`, `${ORIGIN}/accounts/42/admin`, `${ORIGIN}/`, "https://api.example.com.evil.example/accounts/42"]) {
		const proof = await proofFor(key, token, { payload: { htu } });
		await attack(request(token, proof), "htu-mismatch", [token, proof]);
	}
});

test("forwarded-host spoofing: the proof names the attacker's host and the request claims it", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, { payload: { htu: "https://evil.example.com/accounts/42" } });
	const headers: [string, string][] = [["x-forwarded-host", "evil.example.com"], ["forwarded", "host=evil.example.com"], ["host", "evil.example.com"]];
	await attack(request(token, proof, { headers }), "htu-mismatch", [token, proof]);
});

test("method swap: a GET proof presented on a DELETE", async () => {
	const { token, proof } = await bound();
	await attack(request(token, proof, { method: "DELETE" }), "htm-mismatch", [token, proof]);
});

test("alg none, and HMAC keyed with the public key in the header", async () => {
	const { key, token } = await bound();
	const payload = { jti: "j", htm: "GET", htu: URL_, iat: T0 / 1000, ath: await ath(token) };
	const none = `${base64url.encode(JSON.stringify({ typ: "dpop+jwt", alg: "none", jwk: key.jwk }))}.${base64url.encode(JSON.stringify(payload))}.`;
	await attack(request(token, none), "malformed-proof", [token]);
	const hmacHeader = { typ: "dpop+jwt", alg: "HS256", jwk: { kty: "oct", k: base64url.encode(JSON.stringify(key.jwk)) } };
	const hmac = `${base64url.encode(JSON.stringify(hmacHeader))}.${base64url.encode(JSON.stringify(payload))}.${base64url.encode(new Uint8Array(32))}`;
	await attack(request(token, hmac), "proof-algorithm", [token, hmac]);
});

test("key swap: the header carries the victim's public key, the signature is the attacker's", async () => {
	const victim = await clientKey();
	const attacker = await clientKey();
	const token = await tokenFor(victim.jkt);
	const proof = await signRaw(
		attacker,
		{ typ: "dpop+jwt", alg: "ES256", jwk: victim.jwk },
		{ jti: "j", htm: "GET", htu: URL_, iat: T0 / 1000, ath: await ath(token) }
	);
	await attack(request(token, proof), "proof-signature", [token, proof]);
});

test("ath stripped, or carried over from another token", async () => {
	const { key, token } = await bound();
	await attack(request(token, await proofFor(key, token, { omitPayload: ["ath"] })), "malformed-proof", [token]);
	await attack(request(token, await proofFor(key, token, { payload: { ath: await ath("old token") } })), "ath-mismatch", [token]);
});

test("pre-generated proof dated in the future, and a stale one", async () => {
	const { key, token } = await bound();
	await attack(request(token, await proofFor(key, token, {}, T0 + 3_600_000)), "proof-in-future", [token]);
	await attack(request(token, await proofFor(key, token, {}, T0 - 3_600_000)), "proof-expired", [token]);
});

test("header smuggling: two Authorization headers, or two DPoP headers", async () => {
	const { token, proof } = await bound();
	const { token: other, proof: otherProof } = await bound();
	await attack(request(token, proof, { headers: [["authorization", `DPoP ${other}`]] }), "duplicate-authorization", [token, other]);
	await attack(request(token, proof, { headers: [["dpop", otherProof]] }), "duplicate-proof", [proof, otherProof]);
});

test("JSON smuggling: a proof that names htu twice, the second for another endpoint", async () => {
	const { key, token } = await bound();
	const header = base64url.encode(JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk: key.jwk }));
	const payload = base64url.encode(
		`{"jti":"j","htm":"GET","htu":"${URL_}","iat":${T0 / 1000},"ath":"${await ath(token)}","htu":"${ORIGIN}/admin"}`
	);
	const proof = await signRaw(key, header, payload);
	await attack(request(token, proof), "malformed-proof", [token, proof]);
});

test("type confusion: the access token presented as the proof", async () => {
	const { token } = await bound();
	await attack(request(token, token), "proof-typ", [token]);
});

test("key-URL injection: jku, x5u and x5c pointing elsewhere", async () => {
	const { key, token } = await bound();
	for (const extra of [{ jku: "https://evil.example.com/jwks" }, { x5u: "https://evil.example.com/cert" }, { x5c: ["MIIB"] }]) {
		const proof = await proofFor(key, token, { header: extra });
		await attack(request(token, proof), "malformed-proof", [token, proof]);
	}
});

test("a private key in the proof header is refused rather than used", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, { header: { jwk: { ...key.jwk, d: base64url.encode(new Uint8Array(32)) } } });
	await attack(request(token, proof), "proof-key", [token, proof]);
});
