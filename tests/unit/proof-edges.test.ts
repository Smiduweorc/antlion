/**
 * Edges of proof parsing and of the checks around it that mutation testing
 * (npm run mutation) found no test pinning down.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { base64url } from "jose";
import { accessTokenProfile } from "lacewing";
import { AntlionError, type DPoPProfile } from "../../index.js";
import {
	ath,
	AUDIENCE,
	bound,
	clientKey,
	ISSUER,
	profile,
	refused,
	request,
	signRaw,
	T0,
	tokenFor,
	URL_,
	verifyDPoPRequest,
} from "../helpers.js";

const PAYLOAD = (): Record<string, unknown> => ({
	jti: crypto.randomUUID(),
	htm: "GET",
	htu: URL_,
	iat: T0 / 1000,
});

async function proofWithRawHeader(headerBytes: Uint8Array): Promise<{ token: string; proof: string }> {
	const key = await clientKey();
	const token = await tokenFor(key.jkt);
	const proof = await signRaw(key, base64url.encode(headerBytes), { ...PAYLOAD(), ath: await ath(token) });
	return { token, proof };
}

test("a proof header that is not valid UTF-8 is refused as malformed, with the decoder's error as the cause", async () => {
	const header = new TextEncoder().encode("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"x\":\"");
	const bytes = new Uint8Array([...header, 0xc3, 0x28, ...new TextEncoder().encode("\"}")]);
	const { token, proof } = await proofWithRawHeader(bytes);
	const error = await refused(verifyDPoPRequest(request(token, proof), profile()), "malformed-proof");
	assert.equal(error.message, "antlion-lacewing: DPoP proof header is not UTF-8");
	assert.ok(error.cause instanceof TypeError);
});

test("a proof header that starts with a byte order mark is refused rather than stripped", async () => {
	const key = await clientKey();
	const json = new TextEncoder().encode(JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk: key.jwk }));
	const { token, proof } = await proofWithRawHeader(new Uint8Array([0xef, 0xbb, 0xbf, ...json]));
	const error = await refused(verifyDPoPRequest(request(token, proof), profile()), "malformed-proof");
	assert.equal(error.message, "antlion-lacewing: DPoP proof header is not a JSON object, or names a member twice");
});

test("an RSA proof key is checked bit by bit: 2048 bits passes the key check, 2047 does not", async () => {
	const key = await clientKey("PS256");
	const token = await tokenFor(key.jkt);
	const withModulus = async (n: unknown): Promise<string> =>
		signRaw(key, { typ: "dpop+jwt", alg: "PS256", jwk: { ...key.jwk, n } }, { ...PAYLOAD(), ath: await ath(token) });
	const bytes = (first: number, length: number): string => {
		const n = new Uint8Array(length).fill(0xff);
		n[0] = first;
		return base64url.encode(n);
	};
	// 2048 bits passes the key check and then fails the signature, because
	// the modulus is not the one that signed.
	await refused(verifyDPoPRequest(request(token, await withModulus(bytes(0x80, 256))), profile()), "proof-signature");
	for (const n of [bytes(0x7f, 256), bytes(0xff, 255), `AA${bytes(0xff, 256)}`, "", 65537, undefined]) {
		const error = await refused(verifyDPoPRequest(request(token, await withModulus(n)), profile()), "proof-key");
		assert.equal(error.message, "antlion-lacewing: DPoP proof jwk RSA modulus is malformed or under 2048 bits");
	}
});

test("a proof whose signature does not verify carries jose's error as the cause", async () => {
	const { token, proof } = await bound();
	const [header, payload] = proof.split(".");
	const forged = `${header}.${payload}.${base64url.encode(new Uint8Array(64))}`;
	const error = await refused(verifyDPoPRequest(request(token, forged), profile()), "proof-signature");
	assert.ok(error.cause instanceof Error);
	assert.ok(!(error.cause instanceof AntlionError));
});

test("a token whose cnf is null is unbound, not a crash", async () => {
	const key = await clientKey();
	const token = await tokenFor(null, { cnf: null });
	const proof = await signRaw(key, { typ: "dpop+jwt", alg: "ES256", jwk: key.jwk }, { ...PAYLOAD(), ath: await ath(token) });
	await refused(verifyDPoPRequest(request(token, proof), profile()), "token-unbound");
});

test("a missing profile is invalid-options, not a TypeError", async () => {
	const { token, proof } = await bound();
	for (const missing of [undefined, null]) {
		await assert.rejects(
			verifyDPoPRequest(request(token, proof), missing as unknown as DPoPProfile),
			{ name: "AntlionError", code: "invalid-options" }
		);
	}
});

test("an AntlionError thrown by your own KeySource comes back as the same object", async () => {
	const { token, proof } = await bound();
	const yours = new AntlionError("invalid-options", "thrown by the caller's key source", {
		refusal: { status: 401, headers: { "WWW-Authenticate": "DPoP" } },
	});
	const throwing = accessTokenProfile({
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["ES256"],
		keys: { getVerificationKey: async () => { throw yours; } },
	});
	await assert.rejects(verifyDPoPRequest(request(token, proof), profile({ token: throwing })), (error) => error === yours);
});
