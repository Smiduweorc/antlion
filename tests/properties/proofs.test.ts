/**
 * Invariants under random input. Mutate a valid request and it must be
 * refused; feed garbage and it must be refused cleanly, as an AntlionError
 * with a response to send, never as a crash and never as a success.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { AntlionError } from "../../index.js";
import { bound, clientKey, profile, proofFor, request, signRaw, T0, tokenFor, verifyDPoPRequest } from "../helpers.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";

async function outcome(promise: Promise<unknown>): Promise<AntlionError> {
	const result = await promise.then(
		() => assert.fail("a mutated or garbage request verified"),
		(error: unknown) => error
	);
	assert.ok(result instanceof AntlionError, `not an AntlionError: ${String(result)}`);
	assert.ok(result.refusal !== undefined, `refusal missing for ${result.code}`);
	return result;
}

test("[9449-4.3.6] changing any one character of a valid proof gets it refused", async () => {
	const { token, proof } = await bound();
	await fc.assert(
		fc.asyncProperty(
			fc.nat({ max: proof.length - 1 }),
			fc.constantFrom(...ALPHABET),
			async (index, replacement) => {
				fc.pre(proof[index] !== replacement);
				const mutated = proof.slice(0, index) + replacement + proof.slice(index + 1);
				await outcome(verifyDPoPRequest(request(token, mutated), profile()));
			}
		),
		{ numRuns: 300 }
	);
});

test("[9449-4.3.12] changing any one character of the access token gets the request refused", async () => {
	const { key, token } = await bound();
	await fc.assert(
		fc.asyncProperty(
			fc.nat({ max: token.length - 1 }),
			fc.constantFrom(...ALPHABET.slice(0, -1)),
			async (index, replacement) => {
				fc.pre(token[index] !== replacement);
				const mutated = token.slice(0, index) + replacement + token.slice(index + 1);
				// A fresh proof over the original token: ath or Lacewing must catch it.
				const proof = await proofFor(key, token);
				await outcome(verifyDPoPRequest(request(mutated, proof), profile()));
			}
		),
		{ numRuns: 100 }
	);
});

test("[9449-4.3.2] any string in the DPoP header is refused cleanly", async () => {
	const { token } = await bound();
	await fc.assert(
		fc.asyncProperty(fc.string({ unit: "binary-ascii", minLength: 1, maxLength: 400 }), async (value) => {
			let headers: Headers;
			try {
				headers = new Headers({ authorization: `DPoP ${token}`, dpop: value });
			} catch {
				fc.pre(false);
				return;
			}
			fc.pre((headers.get("dpop") ?? "") !== "");
			await outcome(verifyDPoPRequest({ method: "GET", url: "/accounts/42", headers }, profile()));
		}),
		{ numRuns: 500 }
	);
});

test("[AL-hdr.3] any string in the Authorization header is refused cleanly", async () => {
	const { proof } = await bound();
	await fc.assert(
		fc.asyncProperty(fc.string({ unit: "binary-ascii", maxLength: 200 }), async (value) => {
			let headers: Headers;
			try {
				headers = new Headers({ authorization: value, dpop: proof });
			} catch {
				fc.pre(false);
				return;
			}
			await outcome(verifyDPoPRequest({ method: "GET", url: "/accounts/42", headers }, profile()));
		}),
		{ numRuns: 500 }
	);
});

test("[9449-4.3.3] correctly signed proofs with arbitrary JSON header and payload values are refused cleanly", async () => {
	const key = await clientKey();
	const token = await tokenFor(key.jkt);
	const claim = fc.oneof(fc.jsonValue(), fc.constant(undefined));
	await fc.assert(
		fc.asyncProperty(
			fc.record({ typ: claim, alg: claim, jwk: claim, crit: claim }, { requiredKeys: [] }),
			fc.record({ jti: claim, htm: claim, htu: claim, iat: claim, ath: claim, nonce: claim }, { requiredKeys: [] }),
			async (header, payload) => {
				const proof = await signRaw(key, header, payload);
				await outcome(verifyDPoPRequest(request(token, proof), profile({ nonce: "required" })));
			}
		),
		{ numRuns: 300 }
	);
});

test("[AL-time.2] a proof is accepted exactly when its iat is within [now - maxProofAge, now + 5]", async () => {
	const { key, token } = await bound();
	await fc.assert(
		fc.asyncProperty(fc.integer({ min: -400_000, max: 400_000 }), async (offsetMs) => {
			const iat = (T0 + offsetMs) / 1000;
			const proof = await proofFor(key, token, { payload: { iat } });
			const inside = offsetMs >= -60_000 && offsetMs <= 5_000;
			const result = await verifyDPoPRequest(request(token, proof), profile()).then(
				() => "accepted",
				(error: AntlionError) => error.code
			);
			assert.equal(result, inside ? "accepted" : offsetMs < 0 ? "proof-expired" : "proof-in-future", String(offsetMs));
		}),
		{ numRuns: 200 }
	);
});
