import type { DurationSeconds, ExpectedJwtProfile } from "lacewing";
import { getAlgorithmProperties, parseDuration } from "lacewing/extension";
import { PROOF_ALGORITHMS, type LegacyProofAlgorithm } from "./algorithms.js";
import { AntlionError } from "./errors.js";
import { Nonces } from "./nonce.js";
import type { ReplayStore } from "./replay-store.js";

const DEFAULT_MAX_PROOF_AGE_SECONDS = 60;
// oauth4webapi accepts a proof up to 300 seconds from now, fixed. Antlion is
// never looser than that.
const MAX_PROOF_AGE_CAP_SECONDS = 300;
// How far ahead of the server a client's clock may run: Lacewing's default
// clock skew. Fixed, because widening it only helps a proof made in advance.
export const FUTURE_SKEW_SECONDS = 5;
const MIN_NONCE_SECRET_BYTES = 32;

/** The options every profile takes, whatever its nonce mode. See {@link DPoPProfileOptions}. */
export interface DPoPProfileBaseOptions {
	/**
	 * Your Lacewing access-token profile, from `accessTokenProfile()` or
	 * `defineProfile()`. It verifies the access token exactly as it does
	 * without Antlion; Antlion adds its checks and loosens none of Lacewing's.
	 */
	token: ExpectedJwtProfile;
	/**
	 * The origin your clients sign against, as `scheme://host[:port]`, spelled
	 * the way the URL parser prints it (lowercase host, no default port, no
	 * trailing slash). `htu` must equal this plus the request's path. `Host`,
	 * `X-Forwarded-*` and `Forwarded` are never read.
	 */
	origin: string;
	/**
	 * Where accepted proofs are remembered. {@link SingleProcessReplayStore}
	 * for one process; past that, a store every process shares.
	 */
	replay: ReplayStore;
	/**
	 * How old a proof's `iat` may be, as seconds or a string like `"30s"`.
	 * Defaults to 60 seconds, and may be raised to at most 300. Also how long
	 * a server nonce stays valid. A client clock running up to 5 seconds
	 * ahead is always allowed, and that is not configurable.
	 */
	maxProofAge?: number | string;
	/** From `antlion-lacewing/legacy`, and only if a client can't sign anything FAPI allows. */
	legacyAlgorithms?: readonly LegacyProofAlgorithm[];
	/** Swappable clock in milliseconds, for `iat` and nonces. Defaults to `Date.now`. */
	now?: () => number;
}

/**
 * Options for {@link defineDPoPProfile}. `token`, `origin`, `replay` and
 * `nonce` have no default, because only you know the answer.
 *
 * `nonce: "required"` makes every client carry a nonce this server issued,
 * which stops proofs being made ahead of time with a lying clock and costs a
 * round trip whenever a client's nonce is stale. `nonce: "off"` trusts the
 * client's `iat`.
 */
export type DPoPProfileOptions = DPoPProfileBaseOptions &
	(
		| { nonce: "off"; nonceSecrets?: never }
		| {
				nonce: "required";
				/**
				 * Secrets for signing nonces, each at least 32 random bytes. The
				 * first signs new nonces and all of them verify, so rotation is
				 * putting a new one first and removing the old one `maxProofAge`
				 * later. Every node behind one origin needs the same list.
				 */
				nonceSecrets: readonly Uint8Array[];
		  }
	);

/** A DPoP profile. Only {@link defineDPoPProfile} makes one. */
export interface DPoPProfile {
	readonly __brand: "DPoPProfile";
	readonly token: ExpectedJwtProfile;
	readonly origin: string;
	readonly replay: ReplayStore;
	readonly nonce: "required" | "off";
	readonly maxProofAge: DurationSeconds;
	/** The proof `alg` values accepted, in the order the challenge lists them. */
	readonly algorithms: readonly string[];
	/** @internal */
	readonly nonces: Nonces | undefined;
	/** @internal */
	readonly now: () => number;
}

function invalid(message: string, cause?: unknown): AntlionError {
	return new AntlionError("invalid-options", message, cause === undefined ? {} : { cause });
}

function checkOrigin(origin: unknown): string {
	if (typeof origin !== "string") throw invalid("origin is required, as \"https://api.example.com\"");
	let url: URL;
	try {
		url = new URL(origin);
	} catch (cause) {
		throw invalid("origin is not a URL", cause);
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") {
		throw invalid("origin must be an http or https origin");
	}
	if (url.username !== "" || url.password !== "" || url.origin !== origin) {
		throw invalid(`origin must be exactly scheme://host[:port]; did you mean "${url.origin}"?`);
	}
	return origin;
}

function checkMaxProofAge(value: number | string | undefined): DurationSeconds {
	let seconds: DurationSeconds;
	try {
		seconds = parseDuration(value ?? DEFAULT_MAX_PROOF_AGE_SECONDS);
	} catch (cause) {
		throw invalid("maxProofAge must be whole seconds or a string like \"30s\"", cause);
	}
	if (seconds < 1 || seconds > MAX_PROOF_AGE_CAP_SECONDS) {
		throw invalid(`maxProofAge must be between 1 and ${MAX_PROOF_AGE_CAP_SECONDS} seconds`);
	}
	return seconds;
}

function checkAlgorithms(legacy: readonly LegacyProofAlgorithm[] | undefined): readonly string[] {
	if (legacy === undefined) return PROOF_ALGORITHMS;
	if (!Array.isArray(legacy)) throw invalid("legacyAlgorithms must be an array");
	const names = new Set(PROOF_ALGORITHMS);
	for (const entry of legacy as readonly unknown[]) {
		const name = (entry as { name?: unknown } | null)?.name;
		if (name !== "RS256") {
			throw invalid("legacyAlgorithms only takes what antlion-lacewing/legacy returns");
		}
		try {
			getAlgorithmProperties(name);
		} catch (cause) {
			throw invalid("RS256 is not enabled; get it from legacyRS256Proofs()", cause);
		}
		names.add(name);
	}
	return Object.freeze([...names]);
}

function checkNonceSecrets(secrets: unknown): readonly Uint8Array<ArrayBuffer>[] {
	if (!Array.isArray(secrets) || secrets.length === 0) {
		throw invalid("nonce \"required\" needs nonceSecrets, a non-empty array of Uint8Array");
	}
	return Object.freeze(
		secrets.map((secret: unknown) => {
			if (!(secret instanceof Uint8Array) || secret.length < MIN_NONCE_SECRET_BYTES) {
				throw invalid(
					`each nonce secret must be a Uint8Array of at least ${MIN_NONCE_SECRET_BYTES} random bytes`
				);
			}
			return secret.slice();
		})
	);
}

/**
 * Build the profile that {@link verifyDPoPRequest} enforces. Throws
 * `invalid-options` for anything missing or out of range, with a message
 * naming the fix.
 *
 * @example
 * ```ts
 * const dpop = defineDPoPProfile({
 *   token: accessTokenProfile({ issuer, audience, algorithms: ["ES256"], keys: { jwksUri } }),
 *   origin: "https://api.example.com",
 *   replay: new SingleProcessReplayStore({ maxEntries: 100_000 }),
 *   nonce: "off",
 * });
 * ```
 */
export function defineDPoPProfile(options: DPoPProfileOptions): DPoPProfile {
	if (typeof options !== "object" || options === null) throw invalid("options are required");
	const { token, replay, nonce, now } = options;

	if (typeof token !== "object" || token === null || !Array.isArray(token.alg) || typeof token.typ !== "string") {
		throw invalid("token must be a Lacewing profile from accessTokenProfile() or defineProfile()");
	}
	const origin = checkOrigin(options.origin);
	if (typeof replay !== "object" || replay === null || typeof replay.addIfAbsent !== "function") {
		throw invalid("replay is required: a store with addIfAbsent(key, ttlSeconds)");
	}
	if (nonce !== "required" && nonce !== "off") {
		throw invalid("nonce is required: \"required\" or \"off\"");
	}
	if (nonce === "off" && options.nonceSecrets !== undefined) {
		throw invalid("nonceSecrets is set but nonce is \"off\"; pick one");
	}
	if (now !== undefined && typeof now !== "function") throw invalid("now must be a function");
	const maxProofAge = checkMaxProofAge(options.maxProofAge);

	return Object.freeze({
		__brand: "DPoPProfile",
		token,
		origin,
		replay,
		nonce,
		maxProofAge,
		algorithms: checkAlgorithms(options.legacyAlgorithms),
		nonces:
			nonce === "required"
				? new Nonces(checkNonceSecrets(options.nonceSecrets), origin, maxProofAge, FUTURE_SKEW_SECONDS)
				: undefined,
		now: now ?? Date.now,
	});
}
