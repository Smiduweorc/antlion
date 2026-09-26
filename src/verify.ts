/**
 * The one way to verify a DPoP request.
 *
 * Order, fixed, stopping at the first refusal:
 *
 * | Step | Check | Code on failure |
 * | --- | --- | --- |
 * | 1 | exactly one `Authorization: DPoP <token>` header | `missing-authorization`, `bearer-scheme`, `duplicate-authorization`, `malformed-authorization` |
 * | 2 | exactly one `DPoP` header | `missing-proof`, `duplicate-proof` |
 * | 3 | proof size, shape, `typ`, `alg`, key, claims | `malformed-proof`, `proof-typ`, `proof-algorithm`, `proof-key` |
 * | 4 | `htm`, then `htu` | `htm-mismatch`, `htu-mismatch` |
 * | 5 | proof signature, against its own `jwk` | `proof-signature` |
 * | 6 | the access token, by your Lacewing profile | `token-invalid` |
 * | 7 | `cnf.jkt` equals the proof key's thumbprint | `token-unbound`, `jkt-mismatch` |
 * | 8 | `ath` equals the SHA-256 of the token | `ath-mismatch` |
 * | 9 | `iat` no older than `maxProofAge`, at most 5 s ahead | `proof-expired`, `proof-in-future` |
 * | 10 | the nonce, when nonces are required | `nonce-missing`, `nonce-invalid` |
 * | 11 | the replay store has not seen `jkt` + `jti` | `replayed`, `replay-store-failed` |
 *
 * Nothing reaches the replay store before both signatures and the binding
 * have passed, so unauthenticated garbage cannot fill it or probe it.
 */

import { JWTError, jwtVerify, type VerifiedJwt } from "lacewing";
import { readHeaderValue } from "lacewing/extension";
import { sha256 } from "./base64url.js";
import { AntlionError, withRefusal, type AntlionErrorCode, type DPoPRefusal } from "./errors.js";
import { normalizeHtu } from "./htu.js";
import { FUTURE_SKEW_SECONDS, type DPoPProfile } from "./profile.js";
import { checkProof } from "./proof.js";

/**
 * The parts of a request Antlion reads. A WHATWG `Request` already is one.
 *
 * On Node's own `http` (and Express, Fastify, Koa), build `headers` from
 * `req.headersDistinct`, not `req.headers`: Node keeps only the first of two
 * `Authorization` headers in `req.headers`, so a duplicate would never be
 * seen. `url` may be the request path (`req.url`) or an absolute URL; only
 * its path is used, and the origin always comes from the profile.
 */
export interface DPoPRequest {
	readonly method: string;
	readonly url: string;
	readonly headers: Headers;
}

/**
 * Proof that the access token verified under your Lacewing profile, that it
 * is bound to the key that signed the proof, and that the proof was made for
 * this request and has not been seen before. Only
 * {@link verifyDPoPRequest} makes one.
 */
export type DPoPVerifiedJwt = {
	/** The access token, exactly as your Lacewing profile verified it. */
	readonly token: VerifiedJwt;
	/** The RFC 7638 thumbprint of the client's key, equal to the token's `cnf.jkt`. */
	readonly jkt: string;
	/**
	 * With nonces on, a fresh nonce to send as `DPoP-Nonce` on your response
	 * (with `Cache-Control: no-store`), so the client never waits for a 401
	 * to learn it. Undefined with nonces off.
	 */
	readonly nextNonce: string | undefined;
} & { readonly __brand: "DPoPVerifiedJwt" };

// RFC 9449 figure 12, `"DPoP" 1*SP token68`, with the scheme matched in any
// case (RFC 9110 section 11.1). SP is a space; a tab is not one.
const DPOP_CREDENTIALS = /^DPoP +([A-Za-z0-9\-._~+/]+=*)$/i;
// Lacewing's cap on an Authorization header.
const MAX_AUTHORIZATION_LENGTH = 16384;

type WireError = "invalid_request" | "invalid_token" | "invalid_dpop_proof" | "use_dpop_nonce" | undefined;

// RFC 6750 section 3.1 and RFC 9449 sections 7.1 and 9. A request that
// brought no DPoP credentials at all gets a challenge with no error; one that
// is malformed gets a 400.
function wireErrorFor(code: AntlionErrorCode): { status: 400 | 401; error: WireError } {
	switch (code) {
	case "missing-authorization":
	case "bearer-scheme":
		return { status: 401, error: undefined };
	case "duplicate-authorization":
	case "malformed-authorization":
		return { status: 400, error: "invalid_request" };
	case "token-invalid":
	case "token-unbound":
	case "jkt-mismatch":
		return { status: 401, error: "invalid_token" };
	case "nonce-missing":
	case "nonce-invalid":
		return { status: 401, error: "use_dpop_nonce" };
	default:
		return { status: 401, error: "invalid_dpop_proof" };
	}
}

async function refusalFor(code: AntlionErrorCode, profile: DPoPProfile): Promise<DPoPRefusal> {
	const { status, error } = wireErrorFor(code);
	const algs = `algs="${profile.algorithms.join(" ")}"`;
	const headers: Record<string, string> = {
		"WWW-Authenticate": error === undefined ? `DPoP ${algs}` : `DPoP error="${error}", ${algs}`,
	};
	if (error === "use_dpop_nonce" && profile.nonces !== undefined) {
		headers["DPoP-Nonce"] = await profile.nonces.issue(profile.now());
		headers["Cache-Control"] = "no-store";
	}
	return Object.freeze({ status, headers: Object.freeze(headers) });
}

// Only the path comes from the request; the origin is always the profile's.
function readRequest(request: DPoPRequest, origin: string): { method: string; htu: string } {
	if (typeof request !== "object" || request === null) {
		throw new AntlionError("invalid-request", "verifyDPoPRequest() needs a request");
	}
	const { method, url, headers } = request;
	if (typeof method !== "string" || method.length === 0) {
		throw new AntlionError("invalid-request", "request method must be a non-empty string");
	}
	if (typeof (headers as Headers | undefined)?.get !== "function") {
		throw new AntlionError(
			"invalid-request",
			"request headers must be a Headers; on Node, build one from req.headersDistinct"
		);
	}
	if (typeof url !== "string") throw new AntlionError("invalid-request", "request url must be a string");
	let path = url;
	if (!url.startsWith("/")) {
		const absolute = normalizeHtu(url);
		if (absolute === undefined) {
			throw new AntlionError("invalid-request", "request url must be a path or an absolute http(s) URL");
		}
		path = new URL(absolute).pathname;
	}
	// A URL parser cannot fail on an origin the profile accepted followed by
	// a path: the authority ends at the first "/", and a path takes anything.
	return { method, htu: normalizeHtu(origin + path) as string };
}

function readToken(request: DPoPRequest): string {
	const value = readHeaderValue(request, "authorization", "verifyDPoPRequest");
	if (value === undefined || value === "") {
		throw new AntlionError("missing-authorization", "no Authorization header");
	}
	if (value.length > MAX_AUTHORIZATION_LENGTH) {
		throw new AntlionError("malformed-authorization", "Authorization header exceeds the maximum length");
	}
	// token68 has no comma, so a comma is two headers joined by Headers.
	if (value.includes(",")) {
		throw new AntlionError("duplicate-authorization", "more than one Authorization header");
	}
	if (value.split(" ", 1)[0]?.toLowerCase() === "bearer") {
		throw new AntlionError("bearer-scheme", "Authorization uses the Bearer scheme on a DPoP route");
	}
	const match = DPOP_CREDENTIALS.exec(value);
	if (match === null) {
		throw new AntlionError("malformed-authorization", "Authorization header is not \"DPoP <token>\"");
	}
	return match[1] as string;
}

function readProof(request: DPoPRequest): string {
	const value = readHeaderValue(request, "dpop", "verifyDPoPRequest");
	if (value === undefined || value === "") throw new AntlionError("missing-proof", "no DPoP header");
	// A compact JWS has no comma either.
	if (value.includes(",")) throw new AntlionError("duplicate-proof", "more than one DPoP header");
	return value;
}

function readJkt(payload: Record<string, unknown>): string {
	const cnf = payload.cnf;
	const jkt =
		typeof cnf === "object" && cnf !== null && !Array.isArray(cnf)
			? (cnf as Record<string, unknown>).jkt
			: undefined;
	if (typeof jkt !== "string" || jkt.length === 0) {
		throw new AntlionError("token-unbound", "access token has no cnf.jkt");
	}
	return jkt;
}

async function verifyToken(token: string, profile: DPoPProfile): Promise<VerifiedJwt> {
	try {
		return await jwtVerify(token, profile.token);
	} catch (error) {
		// Only Lacewing's own refusals become ours. Anything else came from
		// your code (a KeySource you wrote, say) and comes back unchanged.
		if (error instanceof JWTError) {
			throw new AntlionError("token-invalid", "access token refused by the Lacewing profile", {
				cause: error,
			});
		}
		throw error;
	}
}

async function checkFreshness(
	profile: DPoPProfile,
	iat: number,
	nonce: unknown,
	nowMs: number
): Promise<void> {
	const age = nowMs / 1000 - iat;
	if (age > profile.maxProofAge) throw new AntlionError("proof-expired", "DPoP proof iat is too old");
	if (-age > FUTURE_SKEW_SECONDS) {
		throw new AntlionError("proof-in-future", "DPoP proof iat is too far in the future");
	}
	if (profile.nonces === undefined) return;
	if (nonce === undefined) throw new AntlionError("nonce-missing", "DPoP proof has no nonce");
	if (typeof nonce !== "string" || !(await profile.nonces.check(nonce, nowMs))) {
		throw new AntlionError("nonce-invalid", "DPoP proof nonce is not one this server issued, or it expired");
	}
}

async function recordOnce(profile: DPoPProfile, jkt: string, jti: string): Promise<void> {
	const key = `${jkt}:${await sha256(jti)}`;
	// Long enough to outlive every proof that could still pass the iat check,
	// plus one second because both window edges are inclusive.
	const ttlSeconds = profile.maxProofAge + FUTURE_SKEW_SECONDS + 1;
	let added: unknown;
	try {
		added = await profile.replay.addIfAbsent(key, ttlSeconds);
	} catch (cause) {
		throw new AntlionError("replay-store-failed", "replay store errored; refusing", { cause });
	}
	if (added === false) throw new AntlionError("replayed", "DPoP proof has been used before");
	if (added !== true) {
		throw new AntlionError("replay-store-failed", "replay store resolved something other than a boolean");
	}
}

/**
 * Verify the access token, the DPoP proof and the binding between them, or
 * throw. There is no partial result and no way to check a proof alone.
 *
 * A refusal is an {@link AntlionError} whose `refusal` holds the status and
 * headers to send. Its `code` is for your logs; the client learns only what
 * RFC 9449 says it may.
 *
 * @example
 * ```ts
 * try {
 *   const { token, nextNonce } = await verifyDPoPRequest(request, dpop);
 *   // token.payload.sub, ...
 * } catch (error) {
 *   if (error instanceof AntlionError && error.refusal !== undefined) {
 *     return new Response(null, error.refusal);
 *   }
 *   throw error;
 * }
 * ```
 */
export async function verifyDPoPRequest(
	request: DPoPRequest,
	profile: DPoPProfile
): Promise<DPoPVerifiedJwt> {
	if (profile?.__brand !== "DPoPProfile") {
		throw new AntlionError("invalid-options", "verifyDPoPRequest() needs a profile from defineDPoPProfile()");
	}
	const { method, htu } = readRequest(request, profile.origin);

	try {
		const token = readToken(request);
		const proof = await checkProof(readProof(request), {
			algorithms: profile.algorithms,
			method,
			htu,
		});
		const verified = await verifyToken(token, profile);

		if (readJkt(verified.payload) !== proof.jkt) {
			throw new AntlionError("jkt-mismatch", "access token is bound to a different key than the proof");
		}
		if ((await sha256(token)) !== proof.ath) {
			throw new AntlionError("ath-mismatch", "DPoP proof ath does not match the access token");
		}

		const nowMs = profile.now();
		await checkFreshness(profile, proof.iat, proof.nonce, nowMs);
		await recordOnce(profile, proof.jkt, proof.jti);

		return Object.freeze({
			token: verified,
			jkt: proof.jkt,
			nextNonce: profile.nonces === undefined ? undefined : await profile.nonces.issue(nowMs),
		}) as DPoPVerifiedJwt;
	} catch (error) {
		if (error instanceof AntlionError && error.refusal === undefined) {
			throw withRefusal(error, await refusalFor(error.code, profile));
		}
		throw error;
	}
}
