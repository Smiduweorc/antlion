/**
 * RFC 9449 sections 8 and 9 (server nonces) and 11.3 (nonce downgrade), and
 * the stateless design Antlion commits to (AL-nonce).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
	bound,
	clock,
	NONCE_SECRET,
	profile,
	proofFor,
	refused,
	request,
	T0,
	tokenProfile,
	verifyDPoPRequest,
	type ClientKey,
} from "../helpers.js";
import { defineDPoPProfile, SingleProcessReplayStore, type DPoPProfile, type DPoPVerifiedJwt } from "../../index.js";

async function nonceFrom(key: ClientKey, token: string, dpop: DPoPProfile): Promise<string> {
	const error = await refused(verifyDPoPRequest(request(token, await proofFor(key, token)), dpop), "nonce-missing");
	return error.refusal?.headers["DPoP-Nonce"] as string;
}

test("[9449-9.1] [AL-nonce.2] [9449-8.2.1] a proof without a nonce gets 401 use_dpop_nonce, a DPoP-Nonce and no-store", async () => {
	const { key, token } = await bound();
	const error = await refused(
		verifyDPoPRequest(request(token, await proofFor(key, token)), profile({ nonce: "required" })),
		"nonce-missing"
	);
	const headers = error.refusal?.headers ?? {};
	assert.equal(error.refusal?.status, 401);
	assert.equal(headers["WWW-Authenticate"], "DPoP error=\"use_dpop_nonce\", algs=\"ES256 PS256 EdDSA Ed25519\"");
	assert.equal(headers["Cache-Control"], "no-store");
	assert.equal(typeof headers["DPoP-Nonce"], "string");
	assert.deepEqual(Object.keys(headers).sort(), ["Cache-Control", "DPoP-Nonce", "WWW-Authenticate"]);
});

test("[9449-9.1] a nonce that does not verify gets the same challenge, with a fresh nonce", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, { payload: { nonce: "stale" } });
	const error = await refused(verifyDPoPRequest(request(token, proof), profile({ nonce: "required" })), "nonce-invalid");
	assert.match(error.refusal?.headers["WWW-Authenticate"] ?? "", /error="use_dpop_nonce"/);
	assert.equal(error.refusal?.headers["Cache-Control"], "no-store");
	assert.equal(typeof error.refusal?.headers["DPoP-Nonce"], "string");
});

test("[9449-8.2.2] [9449-8.2.1] only nonce refusals carry DPoP-Nonce, and never more than one", async () => {
	const { key, token } = await bound();
	const dpop = profile({ nonce: "required" });
	const htm = await refused(
		verifyDPoPRequest(request(token, await proofFor(key, token), { method: "POST" }), dpop),
		"htm-mismatch"
	);
	assert.deepEqual(Object.keys(htm.refusal?.headers ?? {}), ["WWW-Authenticate"]);
	const nonce = await nonceFrom(key, token, dpop);
	assert.equal(nonce.includes(","), false);
});

test("[9449-8.1.1] nonces are NQCHAR, base64url in fact", async () => {
	const { key, token } = await bound();
	const nonce = await nonceFrom(key, token, profile({ nonce: "required" }));
	assert.match(nonce, /^[A-Za-z0-9_-]{54}$/);
});

test("[9449-8.2.1] a verified request with nonces on hands back the next nonce, which verifies", async () => {
	const { key, token } = await bound();
	const dpop = profile({ nonce: "required" });
	const first = await verifyDPoPRequest(
		request(token, await proofFor(key, token, { payload: { nonce: await nonceFrom(key, token, dpop) } })),
		dpop
	);
	assert.equal(typeof first.nextNonce, "string");
	const second = await verifyDPoPRequest(
		request(token, await proofFor(key, token, { payload: { nonce: first.nextNonce } })),
		dpop
	);
	assert.equal(second.jkt, key.jkt);
});

test("[9449-11.3.1] with nonces on, a proof otherwise perfect but without a nonce is refused", async () => {
	const { key, token } = await bound();
	await refused(
		verifyDPoPRequest(request(token, await proofFor(key, token)), profile({ nonce: "required" })),
		"nonce-missing"
	);
});

test("[9449-8.2.3] nonces are unpredictable without the secret: two secrets, two different nonces", async () => {
	const { key, token } = await bound();
	const a = await nonceFrom(key, token, profile({ nonce: "required" }));
	const b = await nonceFrom(key, token, profile({ nonce: "required", nonceSecrets: [new Uint8Array(32).fill(8)] }));
	assert.notEqual(a, b);
	assert.equal(a.slice(0, 11), b.slice(0, 11), "the issue time is the same, so only the MAC differs");
});

test("[9449-9.2] [AL-nonce.1] a nonce from another origin sharing the secret is refused", async () => {
	const { key, token } = await bound();
	const elsewhere = defineDPoPProfile({
		token: tokenProfile(),
		origin: "https://other.example.com",
		replay: new SingleProcessReplayStore({ maxEntries: 10 }),
		nonce: "required",
		nonceSecrets: [NONCE_SECRET],
		now: () => T0,
	});
	const foreign = (
		await refused(
			verifyDPoPRequest(
				request(token, await proofFor(key, token, { payload: { htu: "https://other.example.com/accounts/42" } }), {
					url: "https://other.example.com/accounts/42",
				}),
				elsewhere
			),
			"nonce-missing"
		)
	).refusal?.headers["DPoP-Nonce"];
	const proof = await proofFor(key, token, { payload: { nonce: foreign } });
	await refused(verifyDPoPRequest(request(token, proof), profile({ nonce: "required" })), "nonce-invalid");
});

test("[AL-nonce.1] nonces are stateless: a second profile with the same secret and origin accepts them", async () => {
	const { key, token } = await bound();
	const issuedBy = profile({ nonce: "required" });
	const acceptedBy = profile({ nonce: "required" });
	const nonce = await nonceFrom(key, token, issuedBy);
	const result = await verifyDPoPRequest(request(token, await proofFor(key, token, { payload: { nonce } })), acceptedBy);
	assert.equal(result.jkt, key.jkt);
});

test("[AL-nonce.1] rotation: the first secret signs, and every listed secret verifies", async () => {
	const { key, token } = await bound();
	const oldSecret = NONCE_SECRET;
	const newSecret = new Uint8Array(32).fill(1);
	const oldNonce = await nonceFrom(key, token, profile({ nonce: "required", nonceSecrets: [oldSecret] }));
	const rotated = profile({ nonce: "required", nonceSecrets: [newSecret, oldSecret] });
	const accepted = await verifyDPoPRequest(
		request(token, await proofFor(key, token, { payload: { nonce: oldNonce } })),
		rotated
	);
	assert.equal(accepted.jkt, key.jkt);
	const newNonce = await nonceFrom(key, token, rotated);
	const onlyNew = profile({ nonce: "required", nonceSecrets: [newSecret] });
	assert.equal(
		(await verifyDPoPRequest(request(token, await proofFor(key, token, { payload: { nonce: newNonce } })), onlyNew)).jkt,
		key.jkt
	);
	await refused(
		verifyDPoPRequest(request(token, await proofFor(key, token, { payload: { nonce: oldNonce } })), onlyNew),
		"nonce-invalid"
	);
});

test("[AL-nonce.1] a nonce expires maxProofAge seconds after it was issued, edge inclusive", async () => {
	const { key, token } = await bound();
	const time = clock();
	const dpop = profile({ nonce: "required", now: time.now, maxProofAge: 30 });
	const nonce = await nonceFrom(key, token, dpop);
	const verifyAt = async (ms: number): Promise<DPoPVerifiedJwt> => {
		time.at(ms);
		return verifyDPoPRequest(request(token, await proofFor(key, token, { payload: { nonce } }, ms)), dpop);
	};
	assert.equal((await verifyAt(T0 + 30_999)).jkt, key.jkt);
	await refused(verifyAt(T0 + 31_000), "nonce-invalid");
});

test("[AL-nonce.1] a nonce issued up to five seconds ahead of this node's clock is accepted, and six is not", async () => {
	const { key, token } = await bound();
	const time = clock(T0 + 5_000);
	const ahead = profile({ nonce: "required", now: time.now });
	const nonce = await nonceFrom(key, token, ahead);
	const behind = (ms: number): DPoPProfile => profile({ nonce: "required", now: () => ms });
	const proofAt = async (ms: number): Promise<string> => proofFor(key, token, { payload: { nonce } }, ms);
	const ok = await verifyDPoPRequest(request(token, await proofAt(T0)), behind(T0));
	assert.equal(ok.jkt, key.jkt);
	await refused(verifyDPoPRequest(request(token, await proofAt(T0 - 1_000)), behind(T0 - 1_000)), "nonce-invalid");
});

test("[AL-nonce.1] a nonce with its MAC or its issue time altered is refused", async () => {
	const { key, token } = await bound();
	const dpop = profile({ nonce: "required" });
	const nonce = await nonceFrom(key, token, dpop);
	const bytes = Buffer.from(nonce, "base64url");
	const macFlipped = Buffer.from(bytes);
	macFlipped[20] = (macFlipped[20] as number) ^ 1;
	const timeFlipped = Buffer.from(bytes);
	timeFlipped[7] = (timeFlipped[7] as number) ^ 1;
	for (const forged of [macFlipped, timeFlipped, bytes.subarray(0, 39), Buffer.concat([bytes, Buffer.from([0])])]) {
		const proof = await proofFor(key, token, { payload: { nonce: forged.toString("base64url") } });
		await refused(verifyDPoPRequest(request(token, proof), dpop), "nonce-invalid");
	}
});

test("[AL-nonce.1] with nonces off, a nonce claim in the proof is ignored and no nonce is handed back", async () => {
	const { key, token } = await bound();
	const result = await verifyDPoPRequest(
		request(token, await proofFor(key, token, { payload: { nonce: "from the authorization server" } })),
		profile()
	);
	assert.equal(result.nextNonce, undefined);
});
