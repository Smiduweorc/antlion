// Runs against dist/ after `npm run build`, importing by package name so the
// "exports" map in package.json is what resolves each path. A wrong path or a
// missing .js specifier fails here instead of in someone's install.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import process from "node:process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const manifest = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

test("every exports entry points at a built file and its declarations", () => {
	for (const [subpath, target] of Object.entries(manifest.exports)) {
		assert.ok(existsSync(join(ROOT, target.default)), `${subpath}: ${target.default}`);
		assert.ok(existsSync(join(ROOT, target.types)), `${subpath}: ${target.types}`);
	}
});

test("the root export is exactly the public surface", async () => {
	const antlion = await import(manifest.name);
	assert.deepEqual(Object.keys(antlion).sort(), [
		"AntlionError",
		"DPOP_REQUEST_HEADERS",
		"DPOP_RESPONSE_HEADERS",
		"SingleProcessReplayStore",
		"defineDPoPProfile",
		"verifyDPoPRequest",
	]);
});

test("the legacy export is exactly legacyRS256Proofs", async () => {
	const legacy = await import(`${manifest.name}/legacy`);
	assert.deepEqual(Object.keys(legacy), ["legacyRS256Proofs"]);
});

test("the node export is exactly fromNodeRequest", async () => {
	const node = await import(`${manifest.name}/node`);
	assert.deepEqual(Object.keys(node), ["fromNodeRequest"]);
	const request = node.fromNodeRequest({ method: "GET", url: "/r", headersDistinct: { dpop: ["a", "b"] } });
	assert.equal(request.headers.get("dpop"), "a, b");
});

test("the built package verifies a request end to end", async () => {
	const { accessTokenProfile, generateKeyPair, newAccessToken } = await import("lacewing");
	const { calculateJwkThumbprint, base64url } = await import("jose");
	const { defineDPoPProfile, SingleProcessReplayStore, verifyDPoPRequest, AntlionError } = await import(manifest.name);

	const { crypto, TextEncoder, Headers, Request } = globalThis;
	const issuer = await generateKeyPair("ES256");
	const client = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
	const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", client.publicKey);
	const jwk = { kty, crv, x, y };
	const token = await newAccessToken()
		.issuer("https://auth.example.com")
		.audience("https://api.example.com")
		.subject("dist")
		.expiresIn("5m")
		.claim("cnf", { jkt: await calculateJwkThumbprint(jwk) })
		.sign(issuer.privateKey);

	const encoder = new TextEncoder();
	const ath = base64url.encode(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(token))));
	const header = base64url.encode(JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk }));
	const payload = base64url.encode(
		JSON.stringify({
			jti: crypto.randomUUID(),
			htm: "GET",
			htu: "https://api.example.com/r",
			iat: Math.floor(Date.now() / 1000),
			ath,
		})
	);
	const input = `${header}.${payload}`;
	const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, client.privateKey, encoder.encode(input));
	const proof = `${input}.${base64url.encode(new Uint8Array(signature))}`;

	const dpop = defineDPoPProfile({
		token: accessTokenProfile({
			issuer: "https://auth.example.com",
			audience: "https://api.example.com",
			algorithms: ["ES256"],
			keys: issuer.publicKey,
		}),
		origin: "https://api.example.com",
		replay: new SingleProcessReplayStore({ maxEntries: 10 }),
		nonce: "off",
	});
	const headers = new Headers({ authorization: `DPoP ${token}`, dpop: proof });
	const result = await verifyDPoPRequest(new Request("https://api.example.com/r", { headers }), dpop);
	assert.equal(result.token.payload.sub, "dist");

	const replay = await verifyDPoPRequest(new Request("https://api.example.com/r", { headers }), dpop).catch((e) => e);
	assert.ok(replay instanceof AntlionError);
	assert.equal(replay.code, "replayed");
});

test("the built legacy entry enables RS256 proofs on the profile that asks", async () => {
	const { legacyRS256Proofs } = await import(`${manifest.name}/legacy`);
	const { defineDPoPProfile, SingleProcessReplayStore } = await import(manifest.name);
	const { accessTokenProfile, generateKeyPair } = await import("lacewing");
	const issuer = await generateKeyPair("ES256");
	const dpop = defineDPoPProfile({
		token: accessTokenProfile({
			issuer: "https://auth.example.com",
			audience: "https://api.example.com",
			algorithms: ["ES256"],
			keys: issuer.publicKey,
		}),
		origin: "https://api.example.com",
		replay: new SingleProcessReplayStore({ maxEntries: 10 }),
		nonce: "off",
		legacyAlgorithms: [legacyRS256Proofs()],
	});
	assert.deepEqual(dpop.algorithms, ["ES256", "PS256", "EdDSA", "Ed25519", "RS256"]);
});

test("importing the package does nothing: no output, no globals", async () => {
	const { spawnSync } = await import("node:child_process");
	const script = `
		const before = new Set(Object.getOwnPropertyNames(globalThis));
		await import(${JSON.stringify(manifest.name)});
		await import(${JSON.stringify(`${manifest.name}/legacy`)});
		await import(${JSON.stringify(`${manifest.name}/node`)});
		const added = Object.getOwnPropertyNames(globalThis).filter((n) => !before.has(n));
		process.stdout.write(JSON.stringify(added));
	`;
	const run = spawnSync(process.execPath, ["--input-type=module", "-e", script], { cwd: ROOT, encoding: "utf8" });
	assert.equal(run.status, 0, run.stderr);
	assert.equal(run.stderr, "");
	assert.equal(run.stdout, "[]");
});
