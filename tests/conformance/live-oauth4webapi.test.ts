/**
 * oauth4webapi as a real client over a real socket: it obtains a DPoP-bound
 * token, calls protected routes, is challenged for a nonce, retries, and is
 * refused when it is stale, replayed, or holding another key's token.
 */

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import * as oauth from "oauth4webapi";
import { startLiveServer, type LiveServer } from "../live-server.js";
import { ISSUER } from "../helpers.js";

let live: LiveServer;
before(async () => {
	live = await startLiveServer();
});
after(() => live.close());

const client: oauth.Client = { client_id: "antlion-live" };
const insecure = { [oauth.allowInsecureRequests]: true };

async function obtainToken(handle: oauth.DPoPHandle): Promise<string> {
	const as: oauth.AuthorizationServer = { issuer: ISSUER, token_endpoint: `${live.origin}/token` };
	const response = await oauth.clientCredentialsGrantRequest(as, client, oauth.None(), new URLSearchParams(), {
		DPoP: handle,
		...insecure,
	});
	const tokens = await oauth.processClientCredentialsResponse(as, client, response);
	assert.equal(tokens.token_type, "dpop");
	return tokens.access_token;
}

function call(token: string, handle: oauth.DPoPHandle | undefined, path: string, method = "GET"): Promise<Response> {
	return oauth.protectedResourceRequest(token, method, new URL(path, live.origin), new Headers(), null, {
		...(handle === undefined ? {} : { DPoP: handle }),
		...insecure,
	});
}

for (const alg of ["ES256", "PS256", "Ed25519"] as const) {
	test(`an oauth4webapi ${alg} client gets a token, is challenged for a nonce, retries, and reaches two routes`, async () => {
		const handle = oauth.DPoP(client, await oauth.generateKeyPair(alg));
		const token = await obtainToken(handle);

		const challenge = await call(token, handle, "/accounts/42").catch((error: unknown) => error);
		assert.ok(oauth.isDPoPNonceError(challenge), String(challenge));

		const first = await call(token, handle, "/accounts/42");
		assert.equal(first.status, 200);
		assert.deepEqual(await first.json(), { sub: "interop", path: "/accounts/42" });
		// The 200 carried the next nonce, so this one is accepted without a challenge.
		const second = await call(token, handle, "/accounts/42/statements?page=2", "POST");
		assert.equal(second.status, 200);
	});
}

test("a proof oauth4webapi sent is refused when replayed over the wire", async () => {
	const handle = oauth.DPoP(client, await oauth.generateKeyPair("ES256"));
	const token = await obtainToken(handle);
	await call(token, handle, "/accounts/42").catch(() => undefined);
	assert.equal((await call(token, handle, "/accounts/42")).status, 200);

	const accepted = live.seen.filter((entry) => entry.code === "accepted").at(-1)?.dpop as string;
	const replay = await fetch(new URL("/accounts/42", live.origin), {
		headers: { authorization: `DPoP ${token}`, dpop: accepted },
	});
	assert.equal(replay.status, 401);
	assert.match(replay.headers.get("www-authenticate") ?? "", /error="invalid_dpop_proof"/);
	assert.equal(live.seen.at(-1)?.code, "replayed");
});

test("an oauth4webapi client whose clock is an hour slow is refused as stale, before any nonce is asked for", async () => {
	const slow: oauth.Client = { ...client, [oauth.clockSkew]: -3600 };
	const handle = oauth.DPoP(slow, await oauth.generateKeyPair("ES256"));
	const token = await obtainToken(handle);
	const refused = await call(token, handle, "/accounts/42").catch((error: unknown) => error);
	assert.ok(refused instanceof oauth.WWWAuthenticateChallengeError, String(refused));
	assert.equal(live.seen.at(-1)?.code, "proof-expired");
});

test("a token obtained for one key is refused when another oauth4webapi key presents it", async () => {
	const owner = oauth.DPoP(client, await oauth.generateKeyPair("ES256"));
	const thief = oauth.DPoP(client, await oauth.generateKeyPair("ES256"));
	const token = await obtainToken(owner);
	await call(token, thief, "/accounts/42").catch(() => undefined);
	const refused = await call(token, thief, "/accounts/42").catch((error: unknown) => error);
	assert.ok(refused instanceof oauth.WWWAuthenticateChallengeError, String(refused));
	assert.equal(refused.status, 401);
	assert.equal(live.seen.at(-1)?.code, "jkt-mismatch");
});

test("the same token sent by oauth4webapi as Bearer is refused", async () => {
	const handle = oauth.DPoP(client, await oauth.generateKeyPair("ES256"));
	const token = await obtainToken(handle);
	const refused = await call(token, undefined, "/accounts/42").catch((error: unknown) => error);
	assert.ok(refused instanceof oauth.WWWAuthenticateChallengeError, String(refused));
	assert.equal(live.seen.at(-1)?.code, "bearer-scheme");
});
