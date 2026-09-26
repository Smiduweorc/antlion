/**
 * Builders shared by the suites. Proofs are signed here with WebCrypto
 * directly rather than through jose, so a test can put anything at all in a
 * header or payload (duplicate members, forbidden parameters, the wrong
 * `typ`) and still produce a real signature over it.
 */

import assert from "node:assert/strict";
import type { webcrypto } from "node:crypto";
import { base64url, calculateJwkThumbprint } from "jose";
import { accessTokenProfile, generateKeyPair, newAccessToken, type ExpectedJwtProfile } from "lacewing";
import {
	AntlionError,
	defineDPoPProfile,
	SingleProcessReplayStore,
	verifyDPoPRequest,
	type AntlionErrorCode,
	type DPoPProfile,
	type DPoPProfileOptions,
	type DPoPVerifiedJwt,
	type ReplayStore,
} from "../index.js";

export const ISSUER = "https://auth.example.com";
export const AUDIENCE = "https://api.example.com";
export const ORIGIN = "https://api.example.com";
export const PATH = "/accounts/42";
export const URL_ = `${ORIGIN}${PATH}`;

/** The access-token issuer, a Lacewing ES256 key. */
export const issuer = await generateKeyPair("ES256", { extractable: true });

export function tokenProfile(): ExpectedJwtProfile {
	return accessTokenProfile({
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["ES256"],
		keys: issuer.publicKey,
	});
}

export type ProofAlg = "ES256" | "PS256" | "EdDSA" | "Ed25519" | "RS256" | "ES384";

export interface ClientKey {
	readonly alg: ProofAlg;
	readonly privateKey: CryptoKey;
	/** The public JWK, with only the members RFC 7638 hashes. */
	readonly jwk: Record<string, string>;
	readonly jkt: string;
}

function webCryptoParams(alg: ProofAlg): {
	generate: webcrypto.RsaHashedKeyGenParams | webcrypto.EcKeyGenParams | webcrypto.Algorithm;
	sign: webcrypto.RsaPssParams | webcrypto.EcdsaParams | webcrypto.Algorithm;
} {
	switch (alg) {
	case "ES256":
		return { generate: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" } };
	case "ES384":
		return { generate: { name: "ECDSA", namedCurve: "P-384" }, sign: { name: "ECDSA", hash: "SHA-384" } };
	case "PS256":
		return {
			generate: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
			sign: { name: "RSA-PSS", saltLength: 32 },
		};
	case "RS256":
		return {
			generate: {
				name: "RSASSA-PKCS1-v1_5",
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256",
			},
			sign: { name: "RSASSA-PKCS1-v1_5" },
		};
	case "EdDSA":
	case "Ed25519":
		return { generate: { name: "Ed25519" }, sign: { name: "Ed25519" } };
	}
}

const MEMBERS: Record<string, readonly string[]> = {
	EC: ["crv", "kty", "x", "y"],
	OKP: ["crv", "kty", "x"],
	RSA: ["e", "kty", "n"],
};

export async function clientKey(alg: ProofAlg = "ES256"): Promise<ClientKey> {
	const pair = (await crypto.subtle.generateKey(webCryptoParams(alg).generate, true, [
		"sign",
		"verify",
	])) as webcrypto.CryptoKeyPair;
	const full = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Record<string, string>;
	const jwk = Object.fromEntries((MEMBERS[full.kty as string] ?? []).map((m) => [m, full[m] as string]));
	return { alg, privateKey: pair.privateKey, jwk, jkt: await calculateJwkThumbprint(jwk) };
}

export const encodeJson = (value: unknown): string => base64url.encode(JSON.stringify(value));

/** Sign `header.payload` as given. Either part may be an object or a raw base64url string. */
export async function signRaw(
	key: ClientKey,
	header: Record<string, unknown> | string,
	payload: Record<string, unknown> | string
): Promise<string> {
	const input = `${typeof header === "string" ? header : encodeJson(header)}.${
		typeof payload === "string" ? payload : encodeJson(payload)
	}`;
	const signature = await crypto.subtle.sign(
		webCryptoParams(key.alg).sign,
		key.privateKey,
		new TextEncoder().encode(input)
	);
	return `${input}.${base64url.encode(new Uint8Array(signature))}`;
}

export async function ath(token: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
	return base64url.encode(new Uint8Array(digest));
}

/** A fixed instant, in milliseconds, that every virtual clock starts at. */
export const T0 = Date.UTC(2026, 8, 26, 12, 0, 0);

export interface ProofParts {
	header?: Record<string, unknown>;
	payload?: Record<string, unknown>;
	/** Keys to delete from the default header or payload. */
	omitHeader?: string[];
	omitPayload?: string[];
}

/** A valid proof for `token`, unless `parts` says otherwise. */
export async function proofFor(
	key: ClientKey,
	token: string,
	parts: ProofParts = {},
	iatMs: number = T0
): Promise<string> {
	const header: Record<string, unknown> = { typ: "dpop+jwt", alg: key.alg, jwk: key.jwk, ...parts.header };
	const payload: Record<string, unknown> = {
		jti: crypto.randomUUID(),
		htm: "GET",
		htu: URL_,
		iat: Math.floor(iatMs / 1000),
		ath: await ath(token),
		...parts.payload,
	};
	for (const name of parts.omitHeader ?? []) delete header[name];
	for (const name of parts.omitPayload ?? []) delete payload[name];
	return signRaw(key, header, payload);
}

/** A Lacewing access token bound to `jkt` (or to nothing, with `null`). */
export async function tokenFor(jkt: string | null, extra: Record<string, unknown> = {}): Promise<string> {
	let builder = newAccessToken().issuer(ISSUER).audience(AUDIENCE).subject("user-42").expiresIn("5m");
	if (jkt !== null) builder = builder.claim("cnf", { jkt });
	for (const [name, value] of Object.entries(extra)) builder = builder.claim(name, value);
	return builder.sign(issuer.privateKey);
}

export function request(
	token: string | null,
	proof: string | null,
	options: { method?: string; url?: string; scheme?: string; headers?: [string, string][] } = {}
): Request {
	const headers = new Headers(options.headers);
	if (token !== null) headers.append("authorization", `${options.scheme ?? "DPoP"} ${token}`);
	if (proof !== null) headers.append("dpop", proof);
	return new Request(options.url ?? URL_, { method: options.method ?? "GET", headers });
}

/** A virtual clock: `clock.now` reads it, `clock.at` moves it. */
export function clock(start: number = T0): { now: () => number; at: (ms: number) => void } {
	let current = start;
	return { now: () => current, at: (ms) => (current = ms) };
}

/** A replay store that records every call, so a test can assert it was never reached. */
export function spyStore(inner: ReplayStore = new SingleProcessReplayStore({ maxEntries: 1000 })): ReplayStore & {
	calls: [string, number][];
} {
	const calls: [string, number][] = [];
	return {
		calls,
		addIfAbsent(key, ttl) {
			calls.push([key, ttl]);
			return inner.addIfAbsent(key, ttl);
		},
	};
}

export const NONCE_SECRET = new Uint8Array(32).fill(7);

type Overrides = Partial<Omit<DPoPProfileOptions, "nonce" | "nonceSecrets">> &
	({ nonce?: "off" } | { nonce: "required"; nonceSecrets?: readonly Uint8Array[] });

/** A profile with nonces off, a fresh store and the clock at {@link T0}, unless overridden. */
export function profile(overrides: Overrides = {}): DPoPProfile {
	const { nonce, nonceSecrets, ...rest } = { nonceSecrets: undefined, ...overrides };
	const base = {
		token: tokenProfile(),
		origin: ORIGIN,
		replay: new SingleProcessReplayStore({ maxEntries: 1000 }),
		now: () => T0,
		...rest,
	};
	return nonce === "required"
		? defineDPoPProfile({ ...base, nonce, nonceSecrets: nonceSecrets ?? [NONCE_SECRET] })
		: defineDPoPProfile({ ...base, nonce: "off" });
}

/** A key, a token bound to it, and a valid proof for that token. */
export async function bound(alg: ProofAlg = "ES256"): Promise<{ key: ClientKey; token: string; proof: string }> {
	const key = await clientKey(alg);
	const token = await tokenFor(key.jkt);
	return { key, token, proof: await proofFor(key, token) };
}

/** Assert that verifying refuses with `code`, and return the error. */
export async function refused(
	promise: Promise<DPoPVerifiedJwt>,
	code: AntlionErrorCode
): Promise<AntlionError> {
	try {
		await promise;
	} catch (error) {
		assert.ok(error instanceof AntlionError, `expected an AntlionError, got ${String(error)}`);
		assert.equal(error.code, code, error.message);
		return error;
	}
	assert.fail(`expected a ${code} refusal, but the request verified`);
}

export { verifyDPoPRequest };
