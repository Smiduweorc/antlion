import { base64url } from "jose";

const ALPHABET = /^[A-Za-z0-9_-]+$/;

/**
 * Decode base64url the way RFC 7515 section 2 writes it: no padding, no
 * whitespace, and only the canonical spelling of each value. jose's decoder
 * forgives padding and stray trailing bits; Lacewing refuses both in a token
 * (RFC 8725 section 3.7), and a proof gets the same treatment. Undefined for
 * anything else.
 */
export function decodeCanonical(value: string): Uint8Array | undefined {
	if (!ALPHABET.test(value) || value.length % 4 === 1) return undefined;
	const bytes = base64url.decode(value);
	return base64url.encode(bytes) === value ? bytes : undefined;
}

export const encode = base64url.encode;

/** base64url of the SHA-256 of `text`'s UTF-8 bytes: `ath`, and replay keys. */
export async function sha256(text: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return base64url.encode(new Uint8Array(digest));
}
