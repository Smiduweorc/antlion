/**
 * Every message Antlion writes, exactly. The code is what a caller branches
 * on, but people grep logs for the message, so a reworded message is a
 * change somebody notices. None of them repeats anything from the request.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { base64url } from "jose";
import { AntlionError, SingleProcessReplayStore, type DPoPRequest, type ReplayStore } from "../../index.js";
import {
	ath,
	bound,
	clientKey,
	encodeJson,
	NONCE_SECRET,
	profile,
	proofFor,
	request,
	signRaw,
	T0,
	tokenFor,
	verifyDPoPRequest,
} from "../helpers.js";

const P = "antlion-lacewing: ";

async function message(promise: Promise<unknown>): Promise<string> {
	try {
		await promise;
	} catch (error) {
		assert.ok(error instanceof AntlionError, String(error));
		return error.message;
	}
	assert.fail("expected a refusal");
}

test("request and profile mistakes say which part is wrong", async () => {
	const { token, proof } = await bound();
	const headers = new Headers({ authorization: `DPoP ${token}`, dpop: proof });
	const cases: [unknown, string][] = [
		[null, "verifyDPoPRequest() needs a request"],
		["GET /accounts/42", "verifyDPoPRequest() needs a request"],
		[{ method: "", url: "/", headers }, "request method must be a non-empty string"],
		[{ method: "GET", url: "/", headers: {} }, "request headers must be a Headers; on Node, build one from req.headersDistinct"],
		[{ method: "GET", url: 1, headers }, "request url must be a string"],
		[{ method: "GET", url: "ftp://x", headers }, "request url must be a path or an absolute http(s) URL"],
	];
	for (const [bad, expected] of cases) {
		assert.equal(await message(verifyDPoPRequest(bad as DPoPRequest, profile())), P + expected);
	}
	assert.equal(
		await message(verifyDPoPRequest(request(token, proof), {} as never)),
		`${P}verifyDPoPRequest() needs a profile from defineDPoPProfile()`
	);
});

test("header refusals name the header and the problem", async () => {
	const { token, proof } = await bound();
	const cases: [Request, string][] = [
		[request(null, proof), "no Authorization header"],
		[request(`${"a".repeat(16384)}`, proof), "Authorization header exceeds the maximum length"],
		[request(token, proof, { headers: [["authorization", "DPoP other"]] }), "more than one Authorization header"],
		[request(token, proof, { scheme: "Bearer" }), "Authorization uses the Bearer scheme on a DPoP route"],
		[request(token, proof, { scheme: "Basic" }), "Authorization header is not \"DPoP <token>\""],
		[request(token, null), "no DPoP header"],
		[request(token, proof, { headers: [["dpop", "x"]] }), "more than one DPoP header"],
	];
	for (const [req, expected] of cases) {
		assert.equal(await message(verifyDPoPRequest(req, profile())), P + expected);
	}
});

test("proof refusals say which part of the proof failed", async () => {
	const key = await clientKey();
	const token = await tokenFor(key.jkt);
	const good = await proofFor(key, token);
	const [h, p] = good.split(".") as [string, string];
	const header = { typ: "dpop+jwt", alg: "ES256", jwk: key.jwk };
	const payload = { jti: "j", htm: "GET", htu: "https://api.example.com/accounts/42", iat: T0 / 1000, ath: await ath(token) };
	const cases: [string, string][] = [
		[`${good}!`, "DPoP proof is not a compact JWS"],
		[`!${good}`, "DPoP proof is not a compact JWS"],
		[`${h}.${p}.A`, "DPoP proof signature is not canonical base64url"],
		[`R.${p}.AA`, "DPoP proof header is not canonical base64url"],
		[`${h}.R.AA`, "DPoP proof payload is not canonical base64url"],
		[`${base64url.encode(new Uint8Array([0xff]))}.${p}.AA`, "DPoP proof header is not UTF-8"],
		[`${encodeJson([1])}.${p}.AA`, "DPoP proof header is not a JSON object, or names a member twice"],
		[await signRaw(key, { ...header, typ: "JWT" }, payload), "DPoP proof typ is not dpop+jwt"],
		[await signRaw(key, { ...header, alg: "HS256" }, payload), "DPoP proof alg is not accepted"],
		[await signRaw(key, { ...header, jwk: undefined }, payload), "DPoP proof has no jwk header"],
		[await signRaw(key, { ...header, jwk: { ...key.jwk, d: "x" } }, payload), "DPoP proof jwk contains private key material"],
		[await signRaw(key, { ...header, jwk: { ...key.jwk, kty: "OKP" } }, payload), "DPoP proof jwk key type does not match alg"],
		[await signRaw(key, { ...header, jwk: { ...key.jwk, crv: "P-384" } }, payload), "DPoP proof jwk curve does not match alg"],
		[await signRaw(key, { ...header, jwk: { ...key.jwk, alg: "ES384" } }, payload), "DPoP proof jwk names a different alg"],
		[await signRaw(key, header, { ...payload, iat: "now" }), "DPoP proof iat claim is missing or not a number"],
		[await signRaw(key, header, { ...payload, htm: "POST" }), "DPoP proof htm does not match the request method"],
		[await signRaw(key, header, { ...payload, htu: "https://api.example.com/other" }), "DPoP proof htu does not match the request URI"],
		[`${h}.${p}.${base64url.encode(new Uint8Array(64))}`, "DPoP proof signature did not verify"],
	];
	for (const [proof, expected] of cases) {
		assert.equal(await message(verifyDPoPRequest(request(token, proof), profile())), P + expected, expected);
	}
});

test("token, binding and freshness refusals say what did not match", async () => {
	const key = await clientKey();
	const other = await clientKey();
	const signed = await tokenFor(key.jkt);
	const cases: [string, string][] = [
		[await tokenFor(null), "access token has no cnf.jkt"],
		[`${signed.slice(0, signed.lastIndexOf(".") + 1)}${"A".repeat(86)}`, "access token refused by the Lacewing profile"],
		[await tokenFor(other.jkt), "access token is bound to a different key than the proof"],
	];
	for (const [token, expected] of cases) {
		const proof = await proofFor(key, token);
		assert.equal(await message(verifyDPoPRequest(request(token, proof), profile())), P + expected);
	}
	const token = await tokenFor(key.jkt);
	const wrongAth = await proofFor(key, token, { payload: { ath: await ath("another token") } });
	assert.equal(await message(verifyDPoPRequest(request(token, wrongAth), profile())), `${P}DPoP proof ath does not match the access token`);
	const old = await proofFor(key, token, {}, T0 - 61_000);
	assert.equal(await message(verifyDPoPRequest(request(token, old), profile())), `${P}DPoP proof iat is too old`);
	const ahead = await proofFor(key, token, {}, T0 + 6_000);
	assert.equal(await message(verifyDPoPRequest(request(token, ahead), profile())), `${P}DPoP proof iat is too far in the future`);

	const nonces = profile({ nonce: "required", nonceSecrets: [NONCE_SECRET] });
	assert.equal(await message(verifyDPoPRequest(request(token, await proofFor(key, token)), nonces)), `${P}DPoP proof has no nonce`);
	const badNonce = await proofFor(key, token, { payload: { nonce: "AAAA" } });
	assert.equal(
		await message(verifyDPoPRequest(request(token, badNonce), nonces)),
		`${P}DPoP proof nonce is not one this server issued, or it expired`
	);
});

test("replay and store refusals say whether the proof was seen or the store failed", async () => {
	const { token, proof } = await bound();
	const dpop = profile();
	await verifyDPoPRequest(request(token, proof), dpop);
	assert.equal(await message(verifyDPoPRequest(request(token, proof), dpop)), `${P}DPoP proof has been used before`);

	const throwing: ReplayStore = { addIfAbsent: async () => { throw new Error("down"); } };
	const again = await bound();
	assert.equal(
		await message(verifyDPoPRequest(request(again.token, again.proof), profile({ replay: throwing }))),
		`${P}replay store errored; refusing`
	);
	const odd = { addIfAbsent: async () => "yes" } as unknown as ReplayStore;
	assert.equal(
		await message(verifyDPoPRequest(request(again.token, again.proof), profile({ replay: odd }))),
		`${P}replay store resolved something other than a boolean`
	);
});

test("SingleProcessReplayStore's own errors say what was wrong with it", async () => {
	assert.throws(() => new SingleProcessReplayStore({ maxEntries: 1, now: 5 as never }), {
		message: `${P}SingleProcessReplayStore now must be a function`,
	});
	const full = new SingleProcessReplayStore({ maxEntries: 2, now: () => T0 });
	await full.addIfAbsent("a", 66);
	await full.addIfAbsent("b", 66);
	await assert.rejects(full.addIfAbsent("c", 66), { message: `${P}SingleProcessReplayStore is holding 2 live proofs` });
});
