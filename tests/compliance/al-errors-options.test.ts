/**
 * What a refusal tells whom (AL-err), and what the constructors refuse
 * (AL-opt).
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
	NONCE_SECRET,
	ORIGIN,
	profile,
	proofFor,
	refused,
	request,
	tokenFor,
	tokenProfile,
	verifyDPoPRequest,
} from "../helpers.js";
import {
	AntlionError,
	defineDPoPProfile,
	SingleProcessReplayStore,
	type AntlionErrorCode,
	type DPoPProfile,
	type DPoPProfileOptions,
} from "../../index.js";

const WIRE_ERRORS = new Set(["invalid_request", "invalid_token", "invalid_dpop_proof", "use_dpop_nonce"]);

test("[AL-err.1] every refusal says only an RFC error value and the algorithms, whatever the code", async () => {
	const { key, token, proof } = await bound();
	const cases = [
		request(null, null),
		request(token, proof, { scheme: "Bearer" }),
		request(token, "a.b.c"),
		request(token, await proofFor(key, token, { payload: { htu: "https://evil.example.com/" } })),
		request(token, await proofFor(key, token, { header: { typ: "JWT" } })),
		request("not.a.token", await proofFor(key, "not.a.token")),
	];
	for (const req of cases) {
		const error = (await verifyDPoPRequest(req, profile()).catch((e: unknown) => e)) as AntlionError;
		assert.ok(error instanceof AntlionError);
		const challenge = error.refusal?.headers["WWW-Authenticate"] ?? "";
		assert.match(challenge, /^DPoP (error="([a-z_]+)", )?algs="[A-Za-z0-9 ]+"$/);
		const wire = /error="([a-z_]+)"/.exec(challenge)?.[1];
		if (wire !== undefined) assert.ok(WIRE_ERRORS.has(wire), wire);
		assert.doesNotMatch(challenge, /error_description/);
	}
});

test("[AL-err.1] error messages never repeat the token, the proof, or a claim value", async () => {
	const key = await clientKey();
	const token = await tokenFor(key.jkt);
	const marker = "SECRET-MARKER-7f3a";
	const nonces = profile({ nonce: "required" });
	const cases: [string, DPoPProfile][] = [
		[await proofFor(key, token, { payload: { htu: `https://${marker}.example.com/` } }), profile()],
		[await proofFor(key, token, { payload: { htm: marker } }), profile()],
		[await proofFor(key, token, { payload: { ath: marker } }), profile()],
		[await proofFor(key, token, { header: { typ: marker } }), profile()],
		[await proofFor(key, token, { header: { alg: marker } }), profile()],
		[await proofFor(key, token, { payload: { nonce: marker } }), nonces],
		[await proofFor(key, token, { payload: { jti: marker } }, 0), nonces],
	];
	for (const [proof, dpop] of cases) {
		const error = await verifyDPoPRequest(request(token, proof), dpop).catch((e: unknown) => e);
		assert.ok(error instanceof AntlionError, String(error));
		const text = `${error.message} ${JSON.stringify(error.refusal)}`;
		assert.equal(text.includes(marker), false, text);
		assert.equal(text.includes(token), false);
		assert.equal(text.includes(proof), false);
	}
});

test("[AL-err.1] every message starts with the package name", async () => {
	const error = await refused(verifyDPoPRequest(request(null, null), profile()), "missing-authorization");
	assert.match(error.message, /^antlion-lacewing: /);
	assert.equal(error.name, "AntlionError");
	assert.ok(error instanceof Error);
});

test("[AL-err.2] an error from your own code that Lacewing does not catch comes back unchanged", async () => {
	const { proof, token: jwt } = await bound();
	const mine = new RangeError("key service unavailable");
	const keys: KeySource = {
		getVerificationKey: async () => {
			throw mine;
		},
	};
	const token = accessTokenProfile({ issuer: ISSUER, audience: AUDIENCE, algorithms: ["ES256"], keys });
	assert.equal(await verifyDPoPRequest(request(jwt, proof), profile({ token })).catch((e: unknown) => e), mine);

	const clockDown = new Error("clock unavailable");
	const now = (): number => {
		throw clockDown;
	};
	const again = await bound();
	assert.equal(
		await verifyDPoPRequest(request(again.token, again.proof), profile({ now })).catch((e: unknown) => e),
		clockDown
	);
});

test("[AL-err.2] a claimValidator that throws is a Lacewing refusal, so it arrives as token-invalid with your error as the root cause", async () => {
	const mine = new RangeError("tenant lookup failed");
	const token = accessTokenProfile({
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["ES256"],
		keys: issuer.publicKey,
		claimValidators: {
			sub: () => {
				throw mine;
			},
		},
	});
	const { proof, token: jwt } = await bound();
	const error = await refused(verifyDPoPRequest(request(jwt, proof), profile({ token })), "token-invalid");
	assert.equal((error.cause as { code?: string }).code, "JWT_CLAIM_VALIDATION_FAILED");
	assert.equal((error.cause as { cause?: unknown }).cause, mine);
});

test("[AL-err.2] a refusal raised inside a claimValidator by Lacewing's own error class becomes token-invalid", async () => {
	const token = accessTokenProfile({
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["ES256"],
		keys: issuer.publicKey,
		subject: "someone-else",
	});
	const { proof, token: jwt } = await bound();
	const error = await refused(verifyDPoPRequest(request(jwt, proof), profile({ token })), "token-invalid");
	assert.equal((error.cause as { code?: string }).code, "JWT_CLAIM_VALIDATION_FAILED");
});

test("[AL-err.2] invalid-request and invalid-options carry no refusal: they are bugs in the calling code", async () => {
	const req = await refusedSync(() =>
		verifyDPoPRequest({ method: "GET", url: "/", headers: {} as Headers }, profile())
	);
	assert.equal(req.code, "invalid-request");
	assert.equal(req.refusal, undefined);
	const options = await refusedSync(() => verifyDPoPRequest(request(null, null), {} as never));
	assert.equal(options.code, "invalid-options");
	assert.equal(options.refusal, undefined);
});

async function refusedSync(run: () => Promise<unknown>): Promise<AntlionError> {
	const error = await run().catch((e: unknown) => e);
	assert.ok(error instanceof AntlionError, String(error));
	return error;
}

test("[AL-err.2] a request object that is not a request is refused as invalid-request, before any header is read", async () => {
	const headers = new Headers();
	const cases: unknown[] = [
		null,
		"GET /",
		{ method: "", url: "/", headers },
		{ method: 1, url: "/", headers },
		{ method: "GET", url: 1, headers },
		{ method: "GET", url: "relative/path", headers },
		{ method: "GET", url: "ftp://api.example.com/", headers },
		{ method: "GET", url: "*", headers },
		{ method: "GET", url: "/", headers: { authorization: "DPoP x" } },
		{ method: "GET", url: "/" },
	];
	for (const req of cases) {
		const error = await refusedSync(() => verifyDPoPRequest(req as never, profile()));
		assert.equal(error.code, "invalid-request", JSON.stringify(req));
	}
});

function base(): DPoPProfileOptions {
	return {
		token: tokenProfile(),
		origin: ORIGIN,
		replay: new SingleProcessReplayStore({ maxEntries: 10 }),
		nonce: "off",
	};
}

function invalid(options: unknown, pattern: RegExp): void {
	assert.throws(
		() => defineDPoPProfile(options as DPoPProfileOptions),
		(error: unknown) =>
			error instanceof AntlionError &&
			(error.code satisfies AntlionErrorCode) === "invalid-options" &&
			pattern.test(error.message)
	);
}

test("[AL-opt.1] token, origin, replay and nonce are each required", () => {
	invalid(undefined, /options are required/);
	invalid({ ...base(), token: undefined }, /Lacewing profile/);
	invalid({ ...base(), token: { typ: "at+jwt" } }, /Lacewing profile/);
	invalid({ ...base(), origin: undefined }, /origin is required/);
	invalid({ ...base(), replay: undefined }, /addIfAbsent/);
	invalid({ ...base(), replay: { addIfAbsent: "yes" } }, /addIfAbsent/);
	invalid({ ...base(), nonce: undefined }, /nonce is required/);
	invalid({ ...base(), nonce: "optional" }, /nonce is required/);
	invalid({ ...base(), nonce: "Required" }, /nonce is required/);
});

test("[AL-opt.1] origin must be exactly scheme://host[:port], and the message says what was meant", () => {
	invalid({ ...base(), origin: "https://api.example.com/" }, /did you mean "https:\/\/api\.example\.com"/);
	invalid({ ...base(), origin: "https://API.example.com" }, /did you mean "https:\/\/api\.example\.com"/);
	invalid({ ...base(), origin: "https://api.example.com:443" }, /did you mean "https:\/\/api\.example\.com"/);
	invalid({ ...base(), origin: "https://api.example.com/v1" }, /did you mean/);
	invalid({ ...base(), origin: "https://user:pw@api.example.com" }, /did you mean/);
	invalid({ ...base(), origin: "api.example.com" }, /not a URL/);
	invalid({ ...base(), origin: "ftp://api.example.com" }, /http or https/);
	for (const origin of ["https://api.example.com", "http://localhost:3000", "https://[::1]:8443"]) {
		assert.equal(defineDPoPProfile({ ...base(), origin }).origin, origin);
	}
});

test("[AL-opt.1] maxProofAge must be whole seconds from 1 to 300", () => {
	for (const maxProofAge of [0, -1, 301, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "0s", "5 minutes", "1w", ""]) {
		invalid({ ...base(), maxProofAge }, /maxProofAge/);
	}
	assert.equal(defineDPoPProfile({ ...base(), maxProofAge: 1 }).maxProofAge, 1);
	assert.equal(defineDPoPProfile({ ...base(), maxProofAge: "300s" }).maxProofAge, 300);
	assert.equal(defineDPoPProfile({ ...base(), maxProofAge: "5m" }).maxProofAge, 300);
});

test("[AL-opt.1] nonce secrets are required with nonces on, refused with nonces off, and 32 bytes or more", () => {
	const required = { ...base(), nonce: "required" };
	invalid(required, /needs nonceSecrets/);
	invalid({ ...required, nonceSecrets: [] }, /needs nonceSecrets/);
	invalid({ ...required, nonceSecrets: NONCE_SECRET }, /needs nonceSecrets/);
	invalid({ ...required, nonceSecrets: ["a".repeat(64)] }, /at least 32/);
	invalid({ ...required, nonceSecrets: [NONCE_SECRET, new Uint8Array(31)] }, /at least 32/);
	invalid({ ...base(), nonceSecrets: [NONCE_SECRET] }, /nonce is "off"/);
	assert.equal(defineDPoPProfile({ ...required, nonceSecrets: [NONCE_SECRET] } as DPoPProfileOptions).nonce, "required");
});

test("[AL-opt.1] a nonce secret is copied, so changing the caller's array later changes nothing", async () => {
	const secret = new Uint8Array(32).fill(3);
	const dpop = defineDPoPProfile({ ...base(), nonce: "required", nonceSecrets: [secret], now: () => 0 });
	const { key, token } = await bound();
	const nonce = (
		await refused(verifyDPoPRequest(request(token, await proofFor(key, token, {}, 0)), dpop), "nonce-missing")
	).refusal?.headers["DPoP-Nonce"];
	secret.fill(4);
	const result = await verifyDPoPRequest(request(token, await proofFor(key, token, { payload: { nonce } }, 0)), dpop);
	assert.equal(result.jkt, key.jkt);
});

test("[AL-opt.1] now must be a function; it defaults to Date.now", async () => {
	invalid({ ...base(), now: 12 }, /now must be a function/);
	const { key, token } = await bound();
	const proof = await proofFor(key, token, {}, Date.now());
	const result = await verifyDPoPRequest(request(token, proof), defineDPoPProfile(base()));
	assert.equal(result.jkt, key.jkt);
});

test("[AL-opt.1] a profile is frozen", () => {
	const dpop = defineDPoPProfile(base());
	assert.equal(Object.isFrozen(dpop), true);
	assert.equal(dpop.nonce, "off");
	assert.equal(dpop.maxProofAge, 60);
});

test("[AL-opt.1] SingleProcessReplayStore requires maxEntries, a whole number from 1, and a function for now", () => {
	for (const maxEntries of [undefined, 0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "10"]) {
		assert.throws(
			() => new SingleProcessReplayStore({ maxEntries } as never),
			(error: unknown) => error instanceof AntlionError && error.code === "invalid-options" && /maxEntries/.test(error.message)
		);
	}
	assert.throws(() => new SingleProcessReplayStore({ maxEntries: 1, now: "now" as never }), { code: "invalid-options" });
});
