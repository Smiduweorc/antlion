/**
 * Proofs from a real client. oauth4webapi (panva, 3.8.x) holds the key and
 * signs a proof per request; its fetch is pointed at verifyDPoPRequest, so
 * every header it sends and every header Antlion answers with goes over the
 * same boundary it would in production.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as oauth from "oauth4webapi";
import { tokenFor, tokenProfile, URL_, ORIGIN } from "../helpers.js";
import { AntlionError, defineDPoPProfile, SingleProcessReplayStore, verifyDPoPRequest, type DPoPProfile } from "../../index.js";

/** A fetch that answers every request by running Antlion on it. */
function resourceServer(dpop: DPoPProfile): { fetch: typeof fetch; requests: Request[] } {
	const requests: Request[] = [];
	const serve = async (input: Parameters<typeof fetch>[0], init?: RequestInit): Promise<Response> => {
		const req = new Request(input, init);
		requests.push(req);
		try {
			const { token, nextNonce } = await verifyDPoPRequest(req, dpop);
			const headers = new Headers({ "content-type": "application/json" });
			if (nextNonce !== undefined) {
				headers.set("DPoP-Nonce", nextNonce);
				headers.set("Cache-Control", "no-store");
			}
			return new Response(JSON.stringify({ sub: token.payload.sub }), { status: 200, headers });
		} catch (error) {
			if (error instanceof AntlionError && error.refusal !== undefined) {
				return new Response(null, error.refusal);
			}
			throw error;
		}
	};
	return { fetch: serve as typeof fetch, requests };
}

function dpopProfile(nonce: "off" | "required"): DPoPProfile {
	const common = { token: tokenProfile(), origin: ORIGIN, replay: new SingleProcessReplayStore({ maxEntries: 100 }) };
	return nonce === "off"
		? defineDPoPProfile({ ...common, nonce })
		: defineDPoPProfile({ ...common, nonce, nonceSecrets: [crypto.getRandomValues(new Uint8Array(32))] });
}

const client: oauth.Client = { client_id: "antlion-interop" };

for (const alg of ["ES256", "PS256", "Ed25519"] as const) {
	test(`[9449-7.1.1] [AL-bind.2] an oauth4webapi ${alg} client's requests verify`, async () => {
		const keyPair = await oauth.generateKeyPair(alg);
		const handle = oauth.DPoP(client, keyPair);
		const token = await tokenFor(await handle.calculateThumbprint());
		const server = resourceServer(dpopProfile("off"));
		for (const method of ["GET", "POST"]) {
			const response = await oauth.protectedResourceRequest(token, method, new URL(`${URL_}?page=1`), new Headers(), null, {
				DPoP: handle,
				[oauth.customFetch]: server.fetch,
			});
			assert.equal(response.status, 200, `${alg} ${method}`);
			assert.deepEqual(await response.json(), { sub: "user-42" });
		}
		const header = JSON.parse(
			Buffer.from((server.requests[0]?.headers.get("dpop") ?? "").split(".")[0] as string, "base64url").toString()
		) as { alg: string };
		assert.equal(header.alg, alg, "oauth4webapi writes Ed25519 proofs as alg Ed25519, never EdDSA");
	});
}

test("[9449-9.1] [AL-nonce.2] oauth4webapi reads Antlion's use_dpop_nonce challenge and its retry verifies", async () => {
	const keyPair = await oauth.generateKeyPair("ES256");
	const handle = oauth.DPoP(client, keyPair);
	const token = await tokenFor(await handle.calculateThumbprint());
	const server = resourceServer(dpopProfile("required"));
	const call = (): Promise<Response> =>
		oauth.protectedResourceRequest(token, "GET", new URL(URL_), new Headers(), null, {
			DPoP: handle,
			[oauth.customFetch]: server.fetch,
		});

	const challenge = await call().catch((e: unknown) => e);
	assert.ok(challenge instanceof oauth.WWWAuthenticateChallengeError, String(challenge));
	assert.equal(challenge.status, 401);
	assert.equal(oauth.isDPoPNonceError(challenge), true);

	const retried = await call();
	assert.equal(retried.status, 200);
	// The 200 carried the next nonce; oauth4webapi stored it, so a third call
	// needs no challenge either.
	assert.equal((await call()).status, 200);
	assert.equal(server.requests.length, 3);
});

test("[9449-7.2.1] a DPoP-bound token sent by oauth4webapi as Bearer is refused", async () => {
	const keyPair = await oauth.generateKeyPair("ES256");
	const handle = oauth.DPoP(client, keyPair);
	const token = await tokenFor(await handle.calculateThumbprint());
	const server = resourceServer(dpopProfile("off"));
	const error = await oauth
		.protectedResourceRequest(token, "GET", new URL(URL_), new Headers(), null, { [oauth.customFetch]: server.fetch })
		.catch((e: unknown) => e);
	assert.ok(error instanceof oauth.WWWAuthenticateChallengeError, String(error));
	assert.equal(error.status, 401);
	assert.equal(error.cause[0]?.scheme, "dpop");
});
