/**
 * Guarantees that hold because of how the package is built: what it
 * exports, where embedded-key verification lives, which algorithms exist,
 * and what the request URL is built from.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SignJWT, generateKeyPair, exportKeyJWK } from "lacewing";
import * as antlion from "../../index.js";
import * as legacy from "../../legacy.js";
import {
	AUDIENCE,
	bound,
	clientKey,
	ISSUER,
	ORIGIN,
	PATH,
	profile,
	proofFor,
	refused,
	request,
	signRaw,
	T0,
	tokenFor,
	URL_,
	verifyDPoPRequest,
} from "../helpers.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("[AL-bind.1] the package exports one verifier and nothing that checks a proof alone", () => {
	assert.deepEqual(Object.keys(antlion).sort(), [
		"AntlionError",
		"DPOP_REQUEST_HEADERS",
		"DPOP_RESPONSE_HEADERS",
		"SingleProcessReplayStore",
		"defineDPoPProfile",
		"verifyDPoPRequest",
	]);
	assert.deepEqual(Object.keys(legacy), ["legacyRS256Proofs"]);
});

test("[AL-bind.1] a verified result is frozen and carries the token Lacewing verified", async () => {
	const { key, token, proof } = await bound();
	const result = await verifyDPoPRequest(request(token, proof), profile());
	assert.equal(Object.isFrozen(result), true);
	assert.equal(result.jkt, key.jkt);
	assert.equal(result.token.header.typ, "at+jwt");
	assert.equal(result.token.payload.iss, ISSUER);
});

test("[AL-key.1] EmbeddedJWK is imported by src/proof.ts and no other source file", () => {
	const importers: string[] = [];
	const walk = (dir: string): void => {
		for (const entry of readdirSync(dir, { withFileTypes: true })) {
			const path = join(dir, entry.name);
			if (entry.isDirectory()) walk(path);
			else if (path.endsWith(".ts") && readFileSync(path, "utf8").includes("EmbeddedJWK")) {
				importers.push(path.slice(ROOT.length + 1).replaceAll("\\", "/"));
			}
		}
	};
	walk(join(ROOT, "src"));
	for (const file of ["index.ts", "legacy.ts"]) {
		if (readFileSync(join(ROOT, file), "utf8").includes("EmbeddedJWK")) importers.push(file);
	}
	assert.deepEqual(importers, ["src/proof.ts"]);
});

test("[AL-key.1] ESLint refuses EmbeddedJWK outside src/proof.ts", () => {
	const config = readFileSync(join(ROOT, "eslint.config.mjs"), "utf8");
	assert.match(config, /importNames: \["EmbeddedJWK"\]/);
	assert.match(config, /files: \["src\/proof\.ts"\],\s*rules: \{\s*"no-restricted-imports": "off"/);
});

test("[AL-key.1] an access token that carries its own jwk and is signed by it is refused", async () => {
	// The attacker's token names the attacker's key in its header and binds
	// itself to the same key. Accepted only if the token were checked against
	// its embedded key, which is the forgery this guards against.
	const attacker = await generateKeyPair("ES256", { extractable: true });
	const jwk = await exportKeyJWK(attacker.publicKey);
	const client = await clientKey();
	const forged = await new SignJWT("at+jwt")
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.subject("admin")
		.expiresIn("5m")
		.claim("cnf", { jkt: client.jkt })
		.sign(attacker.privateKey);
	const [, payload, signature] = forged.split(".") as [string, string, string];
	const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "at+jwt", jwk })).toString("base64url");
	const withJwk = `${header}.${payload}.${signature}`;
	await refused(verifyDPoPRequest(request(withJwk, await proofFor(client, withJwk)), profile()), "token-invalid");
	await refused(verifyDPoPRequest(request(forged, await proofFor(client, forged)), profile()), "token-invalid");
});

test("[AL-alg.1] the default algorithms are exactly the FAPI 2.0 set, Ed25519 under both names", () => {
	assert.deepEqual(profile().algorithms, ["ES256", "PS256", "EdDSA", "Ed25519"]);
	assert.equal(Object.isFrozen(profile().algorithms), true);
});

test("[AL-alg.1] alg must match the jwk's key type and curve", async () => {
	const { token } = await bound();
	const ec = await clientKey("ES256");
	const ed = await clientKey("Ed25519");
	const rsa = await clientKey("PS256");
	const p384 = await clientKey("ES384");
	const cases: [typeof ec, string, Record<string, string>][] = [
		[ec, "EdDSA", ec.jwk],
		[ec, "PS256", ec.jwk],
		[ed, "ES256", ed.jwk],
		[rsa, "ES256", rsa.jwk],
		[p384, "ES256", p384.jwk],
		[ed, "EdDSA", { ...ed.jwk, crv: "Ed448" }],
		[ed, "EdDSA", { ...ed.jwk, crv: "X25519" }],
	];
	for (const [key, alg, jwk] of cases) {
		const proof = await signRaw(key, { typ: "dpop+jwt", alg, jwk }, {
			jti: "j",
			htm: "GET",
			htu: URL_,
			iat: T0 / 1000,
			ath: "x",
		});
		await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-key");
	}
	const missing = await proofFor(ec, token, { omitHeader: ["jwk"] });
	await refused(verifyDPoPRequest(request(token, missing), profile()), "proof-key");
	for (const jwk of ["string", [ec.jwk], null]) {
		await refused(verifyDPoPRequest(request(token, await proofFor(ec, token, { header: { jwk } })), profile()), "proof-key");
	}
});

test("[AL-alg.1] an RSA key under 2048 bits is refused, and one with a zero-padded modulus too", async () => {
	const small = (await crypto.subtle.generateKey(
		{ name: "RSA-PSS", modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"]
	)) as { publicKey: CryptoKey; privateKey: CryptoKey };
	const full = (await crypto.subtle.exportKey("jwk", small.publicKey)) as Record<string, string>;
	const key = { alg: "PS256" as const, privateKey: small.privateKey, jwk: { kty: "RSA", n: full.n as string, e: full.e as string }, jkt: "" };
	const token = await tokenFor("unused");
	await refused(verifyDPoPRequest(request(token, await proofFor(key, token)), profile()), "proof-key");

	const rsa = await clientKey("PS256");
	const padded = Buffer.concat([Buffer.from([0]), Buffer.from(rsa.jwk.n as string, "base64url")]).toString("base64url");
	const proof = await proofFor(rsa, token, { header: { jwk: { ...rsa.jwk, n: padded } } });
	await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-key");
});

test("[AL-alg.1] a jwk that names a different alg is refused", async () => {
	const { key, token } = await bound("Ed25519");
	const proof = await proofFor(key, token, { header: { jwk: { ...key.jwk, alg: "EdDSA" } } });
	await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-key");
	const same = await proofFor(key, token, { header: { jwk: { ...key.jwk, alg: "Ed25519" } } });
	assert.equal((await verifyDPoPRequest(request(token, same), profile())).jkt, key.jkt);
});

test("[AL-alg.2] an RS256 proof is refused unless the profile took legacyRS256Proofs()", async () => {
	const key = await clientKey("RS256");
	const token = await tokenFor(key.jkt);
	await refused(verifyDPoPRequest(request(token, await proofFor(key, token)), profile()), "proof-algorithm");
	const dpop = profile({ legacyAlgorithms: [legacy.legacyRS256Proofs()] });
	assert.deepEqual(dpop.algorithms, ["ES256", "PS256", "EdDSA", "Ed25519", "RS256"]);
	assert.equal((await verifyDPoPRequest(request(token, await proofFor(key, token)), dpop)).jkt, key.jkt);
	// Enabling it for one profile leaves every other profile as it was.
	await refused(verifyDPoPRequest(request(token, await proofFor(key, token)), profile()), "proof-algorithm");
	const challenge = await refused(verifyDPoPRequest(request(null, null), dpop), "missing-authorization");
	assert.equal(challenge.refusal?.headers["WWW-Authenticate"], "DPoP algs=\"ES256 PS256 EdDSA Ed25519 RS256\"");
});

test("[AL-alg.2] legacyAlgorithms takes only what antlion-lacewing/legacy returns", () => {
	for (const entry of [{ name: "RS384" }, { name: "HS256" }, "RS256", null]) {
		assert.throws(() => profile({ legacyAlgorithms: [entry as never] }), { code: "invalid-options" });
	}
	assert.throws(() => profile({ legacyAlgorithms: "RS256" as never }), { code: "invalid-options" });
});

test("[AL-req.1] Host, X-Forwarded-Host, X-Forwarded-Proto and Forwarded are never read", async () => {
	const { key, token } = await bound();
	const lying = await proofFor(key, token, { payload: { htu: `https://evil.example.com${PATH}` } });
	const headers: [string, string][] = [
		["host", "evil.example.com"],
		["x-forwarded-host", "evil.example.com"],
		["x-forwarded-proto", "https"],
		["forwarded", "host=evil.example.com;proto=https"],
	];
	const fromEvil = request(token, lying, { url: `https://evil.example.com${PATH}`, headers });
	await refused(verifyDPoPRequest(fromEvil, profile()), "htu-mismatch");
	const honest = await proofFor(key, token);
	const result = await verifyDPoPRequest(request(token, honest, { url: `http://10.0.0.7:8080${PATH}`, headers }), profile());
	assert.equal(result.jkt, key.jkt);
});

test("[AL-req.1] a path-only url is joined to the configured origin, query and fragment dropped", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token);
	const headers = new Headers({ authorization: `DPoP ${token}`, dpop: proof });
	const result = await verifyDPoPRequest({ method: "GET", url: `${PATH}?x=1#y`, headers }, profile());
	assert.equal(result.jkt, key.jkt);
});

test("[AL-req.1] a path starting with // stays a path on the configured origin", async () => {
	const { key, token } = await bound();
	const proof = await proofFor(key, token, { payload: { htu: `${ORIGIN}//evil.example.com/x` } });
	const headers = new Headers({ authorization: `DPoP ${token}`, dpop: proof });
	const result = await verifyDPoPRequest({ method: "GET", url: "//evil.example.com/x", headers }, profile());
	assert.equal(result.jkt, key.jkt);
	const lying = await proofFor(key, token, { payload: { htu: "https://evil.example.com/x" } });
	const again = new Headers({ authorization: `DPoP ${token}`, dpop: lying });
	await refused(verifyDPoPRequest({ method: "GET", url: "//evil.example.com/x", headers: again }, profile()), "htu-mismatch");
});

test("[AL-replay.1] the in-memory store is named for one process, and a profile has no store by default", () => {
	assert.equal(antlion.SingleProcessReplayStore.name, "SingleProcessReplayStore");
	assert.throws(() => profile({ replay: undefined as never }), { code: "invalid-options" });
});

test("[AL-alg.1] a jwk whose kty is wrong for alg is refused as a key problem, even when its crv would fit", async () => {
	const { key, token } = await bound("ES256");
	const proof = await proofFor(key, token, { header: { jwk: { ...key.jwk, kty: "OKP" } } });
	await refused(verifyDPoPRequest(request(token, proof), profile()), "proof-key");
});
