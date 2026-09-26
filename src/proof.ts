/**
 * The DPoP proof itself (RFC 9449 sections 4.2 and 4.3).
 *
 * This is the only module that imports `EmbeddedJWK`, and ESLint refuses it
 * anywhere else. Verifying against a key the JWT carries in its own header
 * is right for a proof and a forgery for anything else, so the access token
 * never comes near this file.
 *
 * Checks run cheapest first, and the signature last: size, shape, `typ`,
 * `alg` against the allowlist and the key, the claims, `htm`, `htu`, then
 * the signature. The thumbprint comes from the key jose verified with, never
 * from input.
 */

import { calculateJwkThumbprint, compactVerify, EmbeddedJWK } from "jose";
import { getAlgorithmProperties } from "lacewing/extension";
import { decodeCanonical } from "./base64url.js";
import { AntlionError } from "./errors.js";
import { normalizeHtu } from "./htu.js";

// The cap Lacewing puts on a token and on an Authorization header. A PS256
// proof with a 4096-bit key and a 2 KB URL is under 6 KB.
const MAX_PROOF_LENGTH = 16384;

const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

// Members only a private JWK has (RFC 7518 section 6), and `k`, which is all
// a symmetric one is.
const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

// Header parameters that point at another key or change how the JWS is
// processed. The proof's key is `jwk` and nothing else; Antlion implements
// no JWS extensions, so `crit` and `b64` have nothing to mean.
const FORBIDDEN_HEADER = ["jku", "x5u", "x5c", "x5t", "x5t#S256", "crit", "b64", "zip"] as const;

export interface ProofExpectation {
	/** Accepted `alg` values, exact case. */
	readonly algorithms: readonly string[];
	/** The request method, compared exactly. */
	readonly method: string;
	/** The request's URI after {@link normalizeHtu}. */
	readonly htu: string;
}

export interface CheckedProof {
	/** RFC 7638 SHA-256 thumbprint of the key that verified the signature. */
	readonly jkt: string;
	readonly jti: string;
	readonly iat: number;
	readonly ath: string;
	readonly nonce: unknown;
}

function malformed(message: string): AntlionError {
	return new AntlionError("malformed-proof", message);
}

function decodeJsonObject(segment: string, what: string): Record<string, unknown> {
	const bytes = decodeCanonical(segment);
	if (bytes === undefined) throw malformed(`DPoP proof ${what} is not canonical base64url`);
	let parsed: unknown;
	try {
		parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
	} catch (cause) {
		throw new AntlionError("malformed-proof", `DPoP proof ${what} is not UTF-8 JSON`, { cause });
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw malformed(`DPoP proof ${what} is not a JSON object`);
	}
	return parsed as Record<string, unknown>;
}

// RFC 7515 section 4.1.9: the "application/" prefix may be left off, and
// media types compare case-insensitively. Lacewing reads a token's `typ` the
// same way.
function isDPoPTyp(typ: unknown): boolean {
	if (typeof typ !== "string") return false;
	const lower = typ.toLowerCase();
	return lower === "dpop+jwt" || lower === "application/dpop+jwt";
}

function modulusBits(n: unknown): number {
	const bytes = typeof n === "string" ? decodeCanonical(n) : undefined;
	if (bytes === undefined || bytes.length === 0 || bytes[0] === 0) return 0;
	return (bytes.length - 1) * 8 + Math.floor(Math.log2(bytes[0] as number)) + 1;
}

function checkKey(jwk: unknown, alg: string): void {
	if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) {
		throw new AntlionError("proof-key", "DPoP proof has no jwk header");
	}
	const key = jwk as Record<string, unknown>;
	if (PRIVATE_MEMBERS.some((member) => member in key)) {
		throw new AntlionError("proof-key", "DPoP proof jwk contains private key material");
	}
	const expected = getAlgorithmProperties(alg);
	if (key.kty !== expected.kty) {
		throw new AntlionError("proof-key", "DPoP proof jwk key type does not match alg");
	}
	if (expected.crv !== undefined && key.crv !== expected.crv) {
		throw new AntlionError("proof-key", "DPoP proof jwk curve does not match alg");
	}
	if (expected.kty === "RSA" && modulusBits(key.n) < expected.minKeyBits) {
		throw new AntlionError(
			"proof-key",
			`DPoP proof jwk RSA modulus is malformed or under ${expected.minKeyBits} bits`
		);
	}
	if (key.alg !== undefined && key.alg !== alg) {
		throw new AntlionError("proof-key", "DPoP proof jwk names a different alg");
	}
}

function requireString(payload: Record<string, unknown>, claim: string): string {
	const value = payload[claim];
	if (typeof value !== "string" || value.length === 0) {
		throw malformed(`DPoP proof ${claim} claim is missing or not a string`);
	}
	return value;
}

/**
 * Check a proof against the request it arrived with, and return what the
 * later checks need. Anything wrong is an {@link AntlionError}.
 */
export async function checkProof(proof: string, expected: ProofExpectation): Promise<CheckedProof> {
	if (proof.length > MAX_PROOF_LENGTH) throw malformed("DPoP proof exceeds the maximum length");
	if (!COMPACT_JWS.test(proof)) throw malformed("DPoP proof is not a compact JWS");

	const [rawHeader, rawPayload, rawSignature] = proof.split(".") as [string, string, string];
	const header = decodeJsonObject(rawHeader, "header");
	const payload = decodeJsonObject(rawPayload, "payload");
	if (decodeCanonical(rawSignature) === undefined) {
		throw malformed("DPoP proof signature is not canonical base64url");
	}

	if (!isDPoPTyp(header.typ)) throw new AntlionError("proof-typ", "DPoP proof typ is not dpop+jwt");
	const alg = header.alg;
	if (typeof alg !== "string" || !expected.algorithms.includes(alg)) {
		throw new AntlionError("proof-algorithm", "DPoP proof alg is not accepted");
	}
	for (const parameter of FORBIDDEN_HEADER) {
		if (parameter in header) throw malformed("DPoP proof header carries a forbidden parameter");
	}
	checkKey(header.jwk, alg);

	const jti = requireString(payload, "jti");
	const htm = requireString(payload, "htm");
	const htu = requireString(payload, "htu");
	const ath = requireString(payload, "ath");
	const iat = payload.iat;
	if (typeof iat !== "number" || !Number.isFinite(iat)) {
		throw malformed("DPoP proof iat claim is missing or not a number");
	}

	if (htm !== expected.method) {
		throw new AntlionError("htm-mismatch", "DPoP proof htm does not match the request method");
	}
	if (normalizeHtu(htu) !== expected.htu) {
		throw new AntlionError("htu-mismatch", "DPoP proof htu does not match the request URI");
	}

	let key: CryptoKey;
	try {
		({ key } = await compactVerify(proof, EmbeddedJWK, { algorithms: [alg] }));
	} catch (cause) {
		throw new AntlionError("proof-signature", "DPoP proof signature did not verify", { cause });
	}

	return {
		jkt: await calculateJwkThumbprint(key, "sha256"),
		jti,
		iat,
		ath,
		nonce: payload.nonce,
	};
}
