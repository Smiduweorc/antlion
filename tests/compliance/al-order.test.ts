/**
 * The fixed order (AL-dos.1) and the store coming last (AL-replay.3).
 *
 * Each test breaks two things at once and asserts the earlier check is the
 * one that answers. If two steps are ever swapped, the pair that straddles
 * them fails.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { accessTokenProfile, type KeySource } from "lacewing";
import {
	AUDIENCE,
	bound,
	clientKey,
	issuer,
	ISSUER,
	profile,
	proofFor,
	refused,
	request,
	signRaw,
	spyStore,
	T0,
	tokenFor,
	verifyDPoPRequest,
	type ProofParts,
} from "../helpers.js";
import type { AntlionErrorCode } from "../../index.js";

/** A Lacewing profile whose key source counts how often the token got that far. */
function countingTokenProfile(): { token: ReturnType<typeof accessTokenProfile>; lookups: () => number } {
	let lookups = 0;
	const keys: KeySource = {
		async getVerificationKey(header) {
			lookups++;
			return { alg: header.alg, key: issuer.publicKey.key };
		},
	};
	return {
		token: accessTokenProfile({ issuer: ISSUER, audience: AUDIENCE, algorithms: ["ES256"], keys }),
		lookups: () => lookups,
	};
}

test("[AL-dos.1] the Authorization header is read before the DPoP header", async () => {
	const { token } = await bound();
	await refused(verifyDPoPRequest(request(token, "garbage", { scheme: "Bearer" }), profile()), "bearer-scheme");
	await refused(verifyDPoPRequest(request(null, null), profile()), "missing-authorization");
});

test("[AL-dos.1] a proof over the size limit is refused before it is parsed", async () => {
	const { token } = await bound();
	const huge = `${"a".repeat(16_381)}.b.c`;
	const error = await refused(verifyDPoPRequest(request(token, huge), profile()), "malformed-proof");
	assert.match(error.message, /maximum length/);
	const atLimit = `${"e".repeat(16_380)}.b.c`;
	const parsed = await refused(verifyDPoPRequest(request(token, atLimit), profile()), "malformed-proof");
	assert.doesNotMatch(parsed.message, /maximum length/);
});

test("[AL-dos.1] typ is checked before alg, alg before the key, the key before the claims", async () => {
	const { key, token } = await bound();
	const cases: [ProofParts, AntlionErrorCode][] = [
		[{ header: { typ: "JWT", alg: "none" } }, "proof-typ"],
		[{ header: { alg: "HS256", jwk: { kty: "oct", k: "AAAA" } } }, "proof-algorithm"],
		[{ header: { jwk: { ...key.jwk, d: "AAAA" } }, omitPayload: ["jti"] }, "proof-key"],
		[{ omitPayload: ["jti"], payload: { htm: "POST" } }, "malformed-proof"],
	];
	for (const [parts, code] of cases) {
		const proof = await proofFor(key, token, parts);
		await refused(verifyDPoPRequest(request(token, proof, { method: "PUT" }), profile()), code);
	}
});

test("[AL-dos.1] htm is checked before htu, and htu before the signature", async () => {
	const { key, token } = await bound();
	const other = await clientKey();
	const both = await proofFor(key, token, { payload: { htm: "POST", htu: "https://evil.example.com/" } });
	await refused(verifyDPoPRequest(request(token, both), profile()), "htm-mismatch");
	const [h, p] = (await proofFor(key, token, { payload: { htu: "https://evil.example.com/" } })).split(".");
	const badSignature = await signRaw(other, h as string, p as string);
	await refused(verifyDPoPRequest(request(token, badSignature), profile()), "htu-mismatch");
});

test("[AL-dos.1] the access token is not looked at until the proof's signature has verified", async () => {
	const { key, token } = await bound();
	const counting = countingTokenProfile();
	const dpop = profile({ token: counting.token });
	const [h, p] = (await proofFor(key, token)).split(".");
	const forged = await signRaw(await clientKey(), h as string, p as string);
	await refused(verifyDPoPRequest(request(token, forged), dpop), "proof-signature");
	assert.equal(counting.lookups(), 0);
	await verifyDPoPRequest(request(token, await proofFor(key, token)), dpop);
	assert.equal(counting.lookups(), 1);
});

test("[AL-dos.1] the token is verified before the binding, the binding before ath, ath before freshness", async () => {
	const holder = await clientKey();
	const thief = await clientKey();
	const token = await tokenFor(holder.jkt);
	const stale = T0 - 3_600_000;
	// Token refused and everything after it wrong too: token-invalid.
	await refused(
		verifyDPoPRequest(request("bad.token.here", await proofFor(thief, token, { payload: { ath: "x" } }, stale)), profile()),
		"token-invalid"
	);
	// Wrong key, wrong ath, stale: the binding answers.
	await refused(
		verifyDPoPRequest(request(token, await proofFor(thief, token, { payload: { ath: "x" } }, stale)), profile()),
		"jkt-mismatch"
	);
	// Right key, wrong ath, stale: ath answers.
	await refused(
		verifyDPoPRequest(request(token, await proofFor(holder, token, { payload: { ath: "x" } }, stale)), profile()),
		"ath-mismatch"
	);
	// Right key and ath, stale, no nonce: freshness answers before the nonce.
	await refused(
		verifyDPoPRequest(request(token, await proofFor(holder, token, {}, stale)), profile({ nonce: "required" })),
		"proof-expired"
	);
});

test("[AL-replay.3] [AL-dos.1] the replay store is never consulted for a request that fails any earlier check", async () => {
	const store = spyStore();
	const dpop = profile({ replay: store });
	const holder = await clientKey();
	const token = await tokenFor(holder.jkt);
	const failures = [
		request(null, null),
		request(token, "not.a.proof"),
		request(token, await proofFor(holder, token, { payload: { htm: "POST" } })),
		request(token, await proofFor(await clientKey(), token)),
		request(token, await proofFor(holder, token, { payload: { ath: "x" } })),
		request(token, await proofFor(holder, token, {}, T0 - 120_000)),
		request(await tokenFor(null), await proofFor(holder, await tokenFor(null))),
	];
	for (const req of failures) {
		await verifyDPoPRequest(req, dpop).catch(() => undefined);
	}
	assert.equal(store.calls.length, 0);

	const nonces = spyStore();
	await refused(
		verifyDPoPRequest(request(token, await proofFor(holder, token)), profile({ replay: nonces, nonce: "required" })),
		"nonce-missing"
	);
	assert.equal(nonces.calls.length, 0);

	await verifyDPoPRequest(request(token, await proofFor(holder, token)), dpop);
	assert.equal(store.calls.length, 1);
});
