/**
 * Why Antlion refused.
 *
 * `invalid-options` and `invalid-request` are bugs in the calling code (a
 * profile or store built wrong, a request object that is not a request) and
 * carry no {@link DPoPRefusal}; answer them with a 500. `replay-store-full`
 * comes from {@link SingleProcessReplayStore} and reaches you as the `cause`
 * of a `replay-store-failed`. Every other code is a refused request, and the
 * error's `refusal` says what to send back.
 */
export type AntlionErrorCode =
	| "invalid-options"
	| "invalid-request"
	| "missing-authorization"
	| "bearer-scheme"
	| "duplicate-authorization"
	| "malformed-authorization"
	| "missing-proof"
	| "duplicate-proof"
	| "malformed-proof"
	| "proof-typ"
	| "proof-algorithm"
	| "proof-key"
	| "htm-mismatch"
	| "htu-mismatch"
	| "proof-signature"
	| "token-invalid"
	| "token-unbound"
	| "jkt-mismatch"
	| "ath-mismatch"
	| "proof-expired"
	| "proof-in-future"
	| "nonce-missing"
	| "nonce-invalid"
	| "replayed"
	| "replay-store-failed"
	| "replay-store-full";

const PREFIX = "antlion-lacewing: ";

/**
 * The response to send for a refused request: the status, and the headers
 * that go with it. `WWW-Authenticate` is always present. `DPoP-Nonce` and
 * `Cache-Control: no-store` are present when the client has to retry with a
 * fresh nonce (RFC 9449 sections 8.2 and 9).
 *
 * The body is yours to choose. It should not say which check failed; the
 * client already gets everything RFC 9449 lets it act on.
 */
export interface DPoPRefusal {
	readonly status: 400 | 401;
	readonly headers: Readonly<Record<string, string>>;
}

/**
 * Everything Antlion throws, so a refusal can be told apart from your own
 * code failing without matching on message text. A Lacewing refusal of the
 * access token arrives as `token-invalid` with the Lacewing error as its
 * `cause`; that includes a `claimValidators` function that threw, which
 * Lacewing counts as a failed claim. An error from your code that Lacewing
 * does not catch (a `KeySource` you wrote, the `now` clock) comes back
 * unchanged. Messages never repeat request content.
 */
export class AntlionError extends Error {
	override readonly name = "AntlionError";
	readonly code: AntlionErrorCode;
	/** What to send the client. Undefined for `invalid-options`, `invalid-request` and `replay-store-full`. */
	readonly refusal: DPoPRefusal | undefined;

	constructor(
		code: AntlionErrorCode,
		message: string,
		options: { cause?: unknown; refusal?: DPoPRefusal } = {}
	) {
		super(PREFIX + message, "cause" in options ? { cause: options.cause } : undefined);
		this.code = code;
		this.refusal = options.refusal;
	}
}

/**
 * The same refusal with its response attached. Checks deep in the proof
 * don't know the profile, so the response (which needs the profile's
 * algorithms, and sometimes a fresh nonce) is added on the way out.
 */
export function withRefusal(error: AntlionError, refusal: DPoPRefusal): AntlionError {
	const options = "cause" in error ? { cause: error.cause, refusal } : { refusal };
	const refused = new AntlionError(error.code, error.message.slice(PREFIX.length), options);
	refused.stack = error.stack;
	return refused;
}
