/**
 * Fuzzing past what a WHATWG Headers would ever let through: raw strings
 * with lone surrogates and control characters, correctly signed proofs
 * whose segments are arbitrary bytes, and values far over every size limit.
 * For every input the outcome is a typed AntlionError, never a crash, a
 * hang, or a different kind of error.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { base64url } from "jose";
import { AntlionError, type DPoPRequest } from "../../index.js";
import { ath, bound, clientKey, profile, signRaw, T0, tokenFor, URL_, verifyDPoPRequest } from "../helpers.js";

/** A Headers-shaped object that hands back exactly the strings given, which Headers itself would refuse to hold. */
function rawHeaders(values: Record<string, string>): Headers {
	return { get: (name: string) => values[name.toLowerCase()] ?? null } as unknown as Headers;
}

async function refusedCleanly(promise: Promise<unknown>, needsRefusal = true): Promise<void> {
	const error = await promise.then(
		() => assert.fail("fuzzed input verified"),
		(caught: unknown) => caught
	);
	assert.ok(error instanceof AntlionError, `not an AntlionError: ${String(error)}`);
	if (needsRefusal) assert.ok(error.refusal !== undefined, `no refusal for ${error.code}`);
}

// Any UTF-16 code units, lone surrogates included, plus the characters that
// break naive parsers.
const anyString = (maxLength: number): fc.Arbitrary<string> =>
	fc.oneof(
		fc.string({ unit: "binary", maxLength }),
		fc.string({ unit: fc.constantFrom("\u0000", "\r", "\n", "\t", " ", ",", ".", "\ud800", "\udfff", "\ufeff", "A", "-", "_"), maxLength }),
	);

test("any raw Authorization value, including lone surrogates and control characters, is refused cleanly", async () => {
	const { proof } = await bound();
	await fc.assert(
		fc.asyncProperty(anyString(300), async (value) => {
			const req: DPoPRequest = { method: "GET", url: URL_, headers: rawHeaders({ authorization: value, dpop: proof }) };
			await refusedCleanly(verifyDPoPRequest(req, profile()));
		}),
		{ numRuns: 400 }
	);
});

test("any raw DPoP value after a real token, including lone surrogates and control characters, is refused cleanly", async () => {
	const { token } = await bound();
	await fc.assert(
		fc.asyncProperty(anyString(300), async (value) => {
			const req: DPoPRequest = { method: "GET", url: URL_, headers: rawHeaders({ authorization: `DPoP ${token}`, dpop: value }) };
			await refusedCleanly(verifyDPoPRequest(req, profile()));
		}),
		{ numRuns: 400 }
	);
});

test("a correctly signed proof whose header or payload is arbitrary bytes is refused cleanly", async () => {
	const key = await clientKey();
	const token = await tokenFor(key.jkt);
	const goodHeader = base64url.encode(JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk: key.jwk }));
	const goodPayload = base64url.encode(JSON.stringify({ jti: "j", htm: "GET", htu: URL_, iat: T0 / 1000, ath: await ath(token) }));
	await fc.assert(
		fc.asyncProperty(fc.uint8Array({ minLength: 1, maxLength: 200 }), fc.boolean(), async (bytes, inHeader) => {
			const raw = base64url.encode(bytes);
			const proof = await signRaw(key, inHeader ? raw : goodHeader, inHeader ? goodPayload : raw);
			await refusedCleanly(verifyDPoPRequest(new Request(URL_, { headers: { authorization: `DPoP ${token}`, dpop: proof } }), profile()));
		}),
		{ numRuns: 300 }
	);
});

test("values over every size limit are refused by the length check, before anything is decoded", async () => {
	const key = await clientKey();
	const token = await tokenFor(key.jkt);
	const header = { typ: "dpop+jwt", alg: "ES256", jwk: key.jwk };
	const payload = { jti: "j", htm: "GET", htu: URL_, iat: T0 / 1000, ath: await ath(token) };
	const huge = "A".repeat(1_000_000);
	const cases: DPoPRequest[] = [
		{ method: "GET", url: URL_, headers: rawHeaders({ authorization: `DPoP ${huge}`, dpop: "x" }) },
		{ method: "GET", url: URL_, headers: rawHeaders({ authorization: `DPoP ${token}`, dpop: huge }) },
		{ method: "GET", url: URL_, headers: rawHeaders({ authorization: `DPoP ${token}`, dpop: `${huge}.${huge}.${huge}` }) },
		{
			method: "GET",
			url: URL_,
			headers: rawHeaders({ authorization: `DPoP ${token}`, dpop: await signRaw(key, header, { ...payload, jti: "j".repeat(20_000) }) }),
		},
		{
			method: "GET",
			url: URL_,
			headers: rawHeaders({ authorization: `DPoP ${token}`, dpop: await signRaw(key, { ...header, pad: "p".repeat(20_000) }, payload) }),
		},
	];
	for (const req of cases) {
		await refusedCleanly(verifyDPoPRequest(req, profile()));
		// The length is checked before anything is decoded, so it is the
		// length check that refuses, whatever else is wrong.
		await assert.rejects(verifyDPoPRequest(req, profile()), { message: /exceeds the maximum length$/ });
	}
});

test("any request method and url is either refused with a response or reported as invalid-request", async () => {
	const { token, proof } = await bound();
	await fc.assert(
		fc.asyncProperty(fc.oneof(anyString(20), fc.constant("GET")), fc.oneof(anyString(100), fc.webUrl()), async (method, url) => {
			const req: DPoPRequest = { method, url, headers: rawHeaders({ authorization: `DPoP ${token}`, dpop: proof }) };
			const error = await verifyDPoPRequest(req, profile()).then(
				() => undefined,
				(caught: unknown) => caught
			);
			// GET on the exact URL the proof was made for verifies; every other
			// combination is a typed refusal.
			if (error === undefined) return;
			assert.ok(error instanceof AntlionError, `not an AntlionError: ${String(error)}`);
			assert.ok(error.code === "invalid-request" || error.refusal !== undefined, error.code);
		}),
		{ numRuns: 400 }
	);
});
