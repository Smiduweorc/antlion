/**
 * Stateless server nonces (RFC 9449 section 9).
 *
 * A nonce is the second it was issued in, plus an HMAC-SHA-256 over that
 * second and the profile's origin. Nothing is remembered, so every node
 * holding the same secret accepts the same nonces, and a nonce issued for
 * one origin is refused by another that happens to share the secret.
 *
 * The first secret signs; every secret verifies. Rotating is putting a new
 * secret first and dropping the old one once `maxProofAge` has passed.
 *
 * A nonce is accepted until it is `maxProofAge` old: the same limit a proof's
 * `iat` gets, measured on the server's clock instead of the client's. One
 * issued up to five seconds "in the future" is accepted too, for nodes whose
 * clocks disagree by that much, which is the same allowance `iat` gets.
 */

import { decodeCanonical, encode } from "./base64url.js";

const ISSUED_BYTES = 8;
const MAC_BYTES = 32;

export class Nonces {
	readonly #secrets: readonly Uint8Array<ArrayBuffer>[];
	readonly #origin: string;
	readonly #maxAge: number;
	readonly #futureSkew: number;
	#keys: Promise<CryptoKey[]> | undefined;

	constructor(secrets: readonly Uint8Array<ArrayBuffer>[], origin: string, maxAge: number, futureSkew: number) {
		this.#secrets = secrets;
		this.#origin = origin;
		this.#maxAge = maxAge;
		this.#futureSkew = futureSkew;
	}

	async issue(nowMs: number): Promise<string> {
		const issued = Math.floor(nowMs / 1000);
		// The profile refuses an empty secret list, so there is a first key.
		const signing = (await this.#importKeys())[0] as CryptoKey;
		const mac = await crypto.subtle.sign("HMAC", signing, this.#signedBytes(issued));
		const nonce = new Uint8Array(ISSUED_BYTES + MAC_BYTES);
		new DataView(nonce.buffer).setBigUint64(0, BigInt(issued));
		nonce.set(new Uint8Array(mac), ISSUED_BYTES);
		return encode(nonce);
	}

	async check(nonce: string, nowMs: number): Promise<boolean> {
		const bytes = decodeCanonical(nonce);
		if (bytes === undefined || bytes.length !== ISSUED_BYTES + MAC_BYTES) return false;

		const issued = Number(new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(0));
		const age = Math.floor(nowMs / 1000) - issued;
		if (age > this.#maxAge || age < -this.#futureSkew) return false;

		const data = this.#signedBytes(issued);
		const mac = new Uint8Array(bytes.subarray(ISSUED_BYTES));
		for (const key of await this.#importKeys()) {
			// subtle.verify compares in constant time.
			if (await crypto.subtle.verify("HMAC", key, mac, data)) return true;
		}
		return false;
	}

	#signedBytes(issued: number): Uint8Array<ArrayBuffer> {
		return new TextEncoder().encode(`${this.#origin} ${issued}`);
	}

	#importKeys(): Promise<CryptoKey[]> {
		this.#keys ??= Promise.all(
			this.#secrets.map((secret) =>
				crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, [
					"sign",
					"verify",
				])
			)
		);
		return this.#keys;
	}
}
